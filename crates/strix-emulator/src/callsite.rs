//! Symbolic forward dataflow at decoder call sites.
//!
//! Brute-force argument fuzzing (`run_function_fuzzed`) tries a fixed
//! schedule of `(dst, src, len)` shapes; that's enough for many
//! decoders but misses two important cases:
//!
//! * The decoder reads its input from a fixed pointer in `.rdata`
//!   (or `__cstring` / `__const`) that the *caller* materializes with
//!   a `lea reg, [rip+disp]`. The fuzzer points `src` at our scratch
//!   buffer (all zeros), so the decoder reads zeros and writes
//!   nothing observable.
//! * The decoder's length argument is a concrete immediate that the
//!   caller supplies (`mov edx, 16`). The fuzzer's length-16 / 64 /
//!   256 schedule sometimes lands on the right size, but if the
//!   decoder iterates exactly `len` times and `len` doesn't match,
//!   we either read past the encoded blob or stop short.
//!
//! Rather than trying to emulate the entire caller from its entry
//! (which requires a working CRT init and an indirect-call resolver),
//! we walk the basic block that *contains* the call instruction
//! forward from its start, tracking a small abstract register state
//! through `mov` / `lea` / `xor reg,reg` / `add reg, imm`. By the
//! time we reach the call, we typically have concrete values (or
//! known-pointer-into-rdata values) for the arg-passing registers.
//! We bake those into an `ArgSet` and run the decoder directly.
//!
//! What we deliberately don't do:
//!
//! * Cross-block dataflow. A loop-hoisted load of the source pointer
//!   above the call's block won't be picked up. In practice the
//!   compiler emits the arg setup in the same block as the call.
//! * Full SSA / phi handling. Branches that merge with different
//!   values are treated as Unknown.
//! * Memory tracking. Reads from `[rsp+disp]` for spilled args are
//!   not resolved (we'd need to also track stack writes); we fall
//!   back to scratch pointers for those.

use std::collections::BTreeMap;

use iced_x86::{ConditionCode, Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use strix_format::ParsedInput;

use crate::analyzer::{CodeAnalyzer, Function};

/// A single direct-call site targeting a candidate decoder.
#[derive(Debug, Clone, Copy)]
pub struct CallSite {
    /// Virtual address of the function containing the call.
    pub caller_va: u64,
    /// Virtual address of the basic block containing the call.
    pub block_start: u64,
    /// Virtual address of the call instruction itself.
    pub call_ip: u64,
    /// Virtual address one past the call instruction. Useful for
    /// callers that want to skip the call site when iterating.
    pub next_ip: u64,
}

/// Find every direct call site targeting `target` across the
/// discovered function set.
///
/// Limits the per-callee result to `max_per_target` so a single
/// helper called from hundreds of sites doesn't dominate emulation
/// wall-clock — the first few sites typically expose every distinct
/// decoded blob anyway.
pub fn find_call_sites(
    analyzer: &CodeAnalyzer<'_>,
    funcs: &BTreeMap<u64, Function>,
    target: u64,
    max_per_target: usize,
) -> Vec<CallSite> {
    let mut out = Vec::new();
    for (&caller_va, func) in funcs {
        if caller_va == target {
            continue;
        }
        if !func.callees.contains(&target) {
            continue;
        }
        for block in func.blocks.values() {
            let Some(bytes) = analyzer.bytes_at_va(block.start) else {
                continue;
            };
            let len = (block.end - block.start) as usize;
            let len = len.min(bytes.len());
            let dec_bytes = &bytes[..len];
            let decoder = Decoder::with_ip(
                analyzer.bitness(),
                dec_bytes,
                block.start,
                DecoderOptions::NONE,
            );
            for insn in decoder {
                if insn.mnemonic() == Mnemonic::Call && direct_call_target(&insn) == Some(target) {
                    out.push(CallSite {
                        caller_va,
                        block_start: block.start,
                        call_ip: insn.ip(),
                        next_ip: insn.next_ip(),
                    });
                    if out.len() >= max_per_target {
                        return out;
                    }
                }
            }
        }
    }
    out
}

/// Abstract value of a register at a program point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AbsVal {
    /// We don't know what's in this register.
    Unknown,
    /// We know an exact 64-bit value (immediate, computed lea target,
    /// loaded constant).
    Concrete(u64),
    /// Register holds a pointer into the binary's address space —
    /// e.g. `lea rcx, [rip+disp]` resolves to a real VA. Same as
    /// Concrete but flagged so callers can distinguish "this is a
    /// pointer at an encoded blob" from "this is a small integer".
    Pointer(u64),
}

impl AbsVal {
    fn as_value(self) -> Option<u64> {
        match self {
            AbsVal::Concrete(v) | AbsVal::Pointer(v) => Some(v),
            AbsVal::Unknown => None,
        }
    }
}

/// Per-call-site register state at the moment of the call.
#[derive(Debug, Default, Clone, Copy)]
pub struct ResolvedRegs {
    /// Resolved RDI value (SysV arg 0).
    pub rdi: AbsValPub,
    /// Resolved RSI value (SysV arg 1).
    pub rsi: AbsValPub,
    /// Resolved RDX value (SysV arg 2, Win64 arg 1).
    pub rdx: AbsValPub,
    /// Resolved RCX value (SysV arg 3, Win64 arg 0).
    pub rcx: AbsValPub,
    /// Resolved R8 value (SysV arg 4, Win64 arg 2).
    pub r8: AbsValPub,
    /// Resolved R9 value (SysV arg 5, Win64 arg 3).
    pub r9: AbsValPub,
}

/// Public mirror of `AbsVal` exposed in [`ResolvedRegs`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum AbsValPub {
    /// Unknown value (default).
    #[default]
    Unknown,
    /// Concrete integer / immediate.
    Concrete(u64),
    /// Pointer into the binary's virtual address space.
    Pointer(u64),
}

impl From<AbsVal> for AbsValPub {
    fn from(v: AbsVal) -> Self {
        match v {
            AbsVal::Unknown => AbsValPub::Unknown,
            AbsVal::Concrete(x) => AbsValPub::Concrete(x),
            AbsVal::Pointer(x) => AbsValPub::Pointer(x),
        }
    }
}

impl AbsValPub {
    /// Materialize the abstract value as a concrete `u64`, falling
    /// back to `default` when Unknown.
    pub fn or(self, default: u64) -> u64 {
        match self {
            AbsValPub::Unknown => default,
            AbsValPub::Concrete(v) | AbsValPub::Pointer(v) => v,
        }
    }

    /// Did dataflow yield a concrete value?
    pub fn is_known(self) -> bool {
        !matches!(self, AbsValPub::Unknown)
    }
}

/// Resolve register values at the moment a `call` instruction
/// executes by forward-decoding the basic block from `block_start`
/// up to (and including, for effects) the instruction just before
/// `call_ip`.
///
/// The `bytes_for_va` callback is invoked when an instruction reads
/// memory from a known VA — used to resolve `mov reg, [rip+disp]`
/// into the loaded constant. The callback should return the section
/// bytes at that VA, or None if the address isn't mapped to anything
/// readable.
pub fn resolve_call_site_regs(
    analyzer: &CodeAnalyzer<'_>,
    site: CallSite,
    bytes_for_va: impl Fn(u64, usize) -> Option<Vec<u8>>,
) -> ResolvedRegs {
    let mut state = RegState::default();
    sweep_call_block(analyzer, site, &bytes_for_va, &mut state);
    state_to_resolved(&state)
}

/// Like [`resolve_call_site_regs`] but extends the sweep one
/// basic-block back through the function's CFG. When the call
/// block alone yields no concrete arg values (or partial ones)
/// because the relevant `mov` / `lea` happened a block earlier
/// (loop header → loop body → call, or check → call), the
/// predecessor's effects supply the missing pieces.
///
/// For multiple incoming predecessors the result keeps only
/// register values that are concretely equal across every
/// predecessor — anything that diverges between branches is
/// downgraded to Unknown, which is the safe conservative
/// behavior for a register read at a join point.
pub fn resolve_call_site_regs_cross_block(
    analyzer: &CodeAnalyzer<'_>,
    func: &Function,
    site: CallSite,
    bytes_for_va: impl Fn(u64, usize) -> Option<Vec<u8>>,
) -> ResolvedRegs {
    // First pass: dataflow within the call's own block.
    let mut local_state = RegState::default();
    sweep_call_block(analyzer, site, &bytes_for_va, &mut local_state);

    // Collect every block whose successors mention site.block_start.
    let preds: Vec<u64> = func
        .blocks
        .values()
        .filter(|b| b.start != site.block_start && b.successors.contains(&site.block_start))
        .map(|b| b.start)
        .collect();

    if preds.is_empty() {
        return state_to_resolved(&local_state);
    }

    // Build a per-predecessor "state at the end of the predecessor,
    // followed by the call block's effects up to the call". We sweep
    // each predecessor in full, then re-sweep the call block from
    // its start so any reload / overwrite in the call block wins
    // over the predecessor's hand-off value.
    let mut per_pred_states: Vec<RegState> = Vec::with_capacity(preds.len());
    for pred_start in &preds {
        let Some(pred_block) = func.blocks.get(pred_start) else {
            continue;
        };
        let mut s = RegState::default();
        sweep_block_range(
            analyzer,
            pred_block.start,
            pred_block.end,
            None,
            &bytes_for_va,
            &mut s,
        );
        sweep_call_block(analyzer, site, &bytes_for_va, &mut s);
        per_pred_states.push(s);
    }

    if per_pred_states.is_empty() {
        return state_to_resolved(&local_state);
    }

    // Merge: keep register values that agree across every pred-
    // state. Disagreements become Unknown. If there's only one
    // predecessor, this is just per_pred_states[0]. Each
    // per_pred_state already includes the call block's effects
    // (sweep_call_block was applied after each predecessor sweep),
    // so this is the authoritative final state.
    let merged = merge_states(&per_pred_states);
    state_to_resolved(&merged)
}

fn sweep_call_block(
    analyzer: &CodeAnalyzer<'_>,
    site: CallSite,
    bytes_for_va: &impl Fn(u64, usize) -> Option<Vec<u8>>,
    state: &mut RegState,
) {
    sweep_block_range(
        analyzer,
        site.block_start,
        site.next_ip,
        Some(site.call_ip),
        bytes_for_va,
        state,
    );
}

fn sweep_block_range(
    analyzer: &CodeAnalyzer<'_>,
    start: u64,
    end: u64,
    stop_at: Option<u64>,
    bytes_for_va: &impl Fn(u64, usize) -> Option<Vec<u8>>,
    state: &mut RegState,
) {
    let Some(block_bytes) = analyzer.bytes_at_va(start) else {
        return;
    };
    let len = end.saturating_sub(start) as usize;
    let len = len.min(block_bytes.len());
    let dec_bytes = &block_bytes[..len];
    let decoder = Decoder::with_ip(analyzer.bitness(), dec_bytes, start, DecoderOptions::NONE);
    for insn in decoder {
        if let Some(stop) = stop_at
            && insn.ip() == stop
        {
            return;
        }
        apply_effect(state, &insn, bytes_for_va);
    }
}

fn state_to_resolved(state: &RegState) -> ResolvedRegs {
    ResolvedRegs {
        rdi: state.get(Register::RDI).into(),
        rsi: state.get(Register::RSI).into(),
        rdx: state.get(Register::RDX).into(),
        rcx: state.get(Register::RCX).into(),
        r8: state.get(Register::R8).into(),
        r9: state.get(Register::R9).into(),
    }
}

/// Merge a list of register states: for each register, keep the
/// value if it's identical across every state that has one;
/// otherwise drop to Unknown. An empty input returns an empty
/// state.
fn merge_states(states: &[RegState]) -> RegState {
    if states.is_empty() {
        return RegState::default();
    }
    if states.len() == 1 {
        return states[0].clone();
    }
    // Collect every register that any state has tracked.
    let mut all_regs: std::collections::BTreeSet<Register> = std::collections::BTreeSet::new();
    for s in states {
        for r in s.vals.keys() {
            all_regs.insert(*r);
        }
    }
    let mut out = RegState::default();
    for r in all_regs {
        let mut agreed: Option<AbsVal> = None;
        let mut all_match = true;
        for s in states {
            let v = s.vals.get(&r).copied().unwrap_or(AbsVal::Unknown);
            match agreed {
                None => agreed = Some(v),
                Some(prev) if prev == v => {}
                Some(_) => {
                    all_match = false;
                    break;
                }
            }
        }
        if all_match
            && let Some(v) = agreed
            && !matches!(v, AbsVal::Unknown)
        {
            out.vals.insert(r, v);
        }
    }
    out
}

/// Collect unique rip-relative `lea reg, [rip+disp]` targets from
/// the basic block containing `site.call_ip` plus any single
/// immediate predecessor block. These VAs are typical candidates
/// for "encoded data in .rdata" that the caller is about to pass
/// (directly, or via a memcpy/inline init) to the decoder.
///
/// Each entry has the resolved VA and a guard that the address
/// lies in a non-executable section (real rdata, not code).
pub fn collect_rdata_pointers(
    analyzer: &CodeAnalyzer<'_>,
    func: &Function,
    site: CallSite,
    parsed: &ParsedInput,
) -> Vec<u64> {
    let mut out: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();

    let in_rdata = |va: u64| {
        parsed.sections.iter().any(|s| {
            !s.executable && va >= s.virtual_address && va < s.virtual_address + s.file_size
        })
    };

    // Walk the call block.
    scan_block_for_rdata_leas(
        analyzer,
        site.block_start,
        site.next_ip,
        &in_rdata,
        &mut out,
    );

    // Walk single-predecessor block(s).
    for block in func.blocks.values() {
        if block.start == site.block_start {
            continue;
        }
        if !block.successors.contains(&site.block_start) {
            continue;
        }
        scan_block_for_rdata_leas(analyzer, block.start, block.end, &in_rdata, &mut out);
    }
    out.into_iter().collect()
}

fn scan_block_for_rdata_leas(
    analyzer: &CodeAnalyzer<'_>,
    start: u64,
    end: u64,
    in_rdata: &impl Fn(u64) -> bool,
    out: &mut std::collections::BTreeSet<u64>,
) {
    let Some(block_bytes) = analyzer.bytes_at_va(start) else {
        return;
    };
    let len = end.saturating_sub(start) as usize;
    let len = len.min(block_bytes.len());
    let dec_bytes = &block_bytes[..len];
    let decoder = Decoder::with_ip(analyzer.bitness(), dec_bytes, start, DecoderOptions::NONE);
    for insn in decoder {
        if insn.mnemonic() != Mnemonic::Lea {
            continue;
        }
        if !insn.is_ip_rel_memory_operand() {
            continue;
        }
        let va = insn.ip_rel_memory_address();
        if in_rdata(va) {
            out.insert(va);
        }
    }
}

/// Build a `bytes_for_va` callback over a `ParsedInput` and its raw
/// bytes. Honors section bounds; returns None for VAs outside any
/// mapped section.
pub fn make_va_reader<'a>(
    bytes: &'a [u8],
    parsed: &'a ParsedInput,
) -> impl Fn(u64, usize) -> Option<Vec<u8>> + 'a {
    move |va: u64, len: usize| -> Option<Vec<u8>> {
        for sec in &parsed.sections {
            if va >= sec.virtual_address && va < sec.virtual_address + sec.file_size {
                let off_in_sec = (va - sec.virtual_address) as usize;
                let file_off = sec.file_offset as usize + off_in_sec;
                let avail = (sec.file_size as usize).saturating_sub(off_in_sec);
                let take = len.min(avail);
                if file_off + take > bytes.len() {
                    return None;
                }
                return Some(bytes[file_off..file_off + take].to_vec());
            }
        }
        None
    }
}

// ---------- internals ----------

/// Tracked register state during a block-local forward sweep.
///
/// We track register values plus a small stack-slot map keyed by
/// `(base_reg, displacement)`. The slot map is critical for the
/// spill/reload patterns the MSVC and gcc/clang compilers emit when
/// passing pointers across other calls — e.g.:
///
/// ```text
/// call HeapAlloc           ; rax = heap pointer
/// mov [rsp+0x28], rax      ; spill
/// ... unrelated work ...
/// mov rcx, [rsp+0x28]      ; reload heap pointer
/// call decoder
/// ```
///
/// Without slot tracking we lose `rax`'s identity after the spill;
/// with it we can carry the value back to the reload and into the
/// argument register.
#[derive(Debug, Default, Clone)]
struct RegState {
    /// Map from `Register` (cast to its iced-x86 index) to abstract
    /// value. Default for any unmapped register is Unknown.
    vals: BTreeMap<Register, AbsVal>,
    /// Stack-slot map. Keys are `(base_reg, displacement)`. We only
    /// track Rsp/Rbp-based slots — the spill/reload patterns the
    /// compiler emits always go through one of those two.
    slots: BTreeMap<SlotKey, AbsVal>,
}

/// Stack-slot identity. Keyed by the base register (RSP or RBP) and
/// the displacement. Same `(base, disp)` from two different code
/// points refers to the same slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SlotKey {
    /// `[rsp + disp]` (disp interpreted as signed i64).
    Rsp(i64),
    /// `[rbp + disp]`.
    Rbp(i64),
}

impl RegState {
    fn get(&self, r: Register) -> AbsVal {
        // Canonicalize to the 64-bit full-width register so reads of
        // EDX after writes to RDX (or vice versa) see the same value.
        let full = full_reg(r);
        self.vals.get(&full).copied().unwrap_or(AbsVal::Unknown)
    }

    fn set(&mut self, r: Register, v: AbsVal) {
        let full = full_reg(r);
        if matches!(v, AbsVal::Unknown) {
            self.vals.remove(&full);
        } else {
            self.vals.insert(full, v);
        }
    }

    fn store_slot(&mut self, key: SlotKey, v: AbsVal) {
        if matches!(v, AbsVal::Unknown) {
            self.slots.remove(&key);
        } else {
            self.slots.insert(key, v);
        }
    }

    fn load_slot(&self, key: SlotKey) -> AbsVal {
        self.slots.get(&key).copied().unwrap_or(AbsVal::Unknown)
    }

    /// Drop every Rsp-relative slot tracked so far. Called when rsp
    /// changes (push, pop, add/sub rsp) so we don't end up reading
    /// the wrong cell after the displacement shifts under us.
    fn invalidate_rsp_slots(&mut self) {
        self.slots.retain(|k, _| !matches!(k, SlotKey::Rsp(_)));
    }
}

/// Recognize a `[base + disp]` simple-stack memory operand.
///
/// Returns `Some(SlotKey)` if the operand is a clean
/// `[rsp + disp]` or `[rbp + disp]` (no index register, scale=1).
fn slot_key_for_memory(insn: &Instruction) -> Option<SlotKey> {
    if insn.memory_index() != Register::None {
        return None;
    }
    let disp = insn.memory_displacement64() as i64;
    match full_reg(insn.memory_base()) {
        Register::RSP => Some(SlotKey::Rsp(disp)),
        Register::RBP => Some(SlotKey::Rbp(disp)),
        _ => None,
    }
}

/// Map any sub-width register (EAX, AX, AL) to its full-width form
/// (RAX). Writes to 32-bit registers zero-extend to 64; writes to
/// 16/8-bit subviews don't, but for the conservative purposes here
/// we treat 16/8-bit writes as clobbering the whole register
/// (Unknown), which is safer than pretending we still know it.
fn full_reg(r: Register) -> Register {
    match r {
        Register::RAX | Register::EAX | Register::AX | Register::AL | Register::AH => Register::RAX,
        Register::RBX | Register::EBX | Register::BX | Register::BL | Register::BH => Register::RBX,
        Register::RCX | Register::ECX | Register::CX | Register::CL | Register::CH => Register::RCX,
        Register::RDX | Register::EDX | Register::DX | Register::DL | Register::DH => Register::RDX,
        Register::RSI | Register::ESI | Register::SI | Register::SIL => Register::RSI,
        Register::RDI | Register::EDI | Register::DI | Register::DIL => Register::RDI,
        Register::RBP | Register::EBP | Register::BP | Register::BPL => Register::RBP,
        Register::RSP | Register::ESP | Register::SP | Register::SPL => Register::RSP,
        Register::R8 | Register::R8D | Register::R8W | Register::R8L => Register::R8,
        Register::R9 | Register::R9D | Register::R9W | Register::R9L => Register::R9,
        Register::R10 | Register::R10D | Register::R10W | Register::R10L => Register::R10,
        Register::R11 | Register::R11D | Register::R11W | Register::R11L => Register::R11,
        Register::R12 | Register::R12D | Register::R12W | Register::R12L => Register::R12,
        Register::R13 | Register::R13D | Register::R13W | Register::R13L => Register::R13,
        Register::R14 | Register::R14D | Register::R14W | Register::R14L => Register::R14,
        Register::R15 | Register::R15D | Register::R15W | Register::R15L => Register::R15,
        other => other,
    }
}

/// Did the instruction write a 64-bit (or 32-bit zero-extending)
/// result, or did it write a narrow subview that we can't safely
/// reason about?
fn writes_full_width(r: Register) -> bool {
    matches!(
        r,
        Register::RAX
            | Register::EAX
            | Register::RBX
            | Register::EBX
            | Register::RCX
            | Register::ECX
            | Register::RDX
            | Register::EDX
            | Register::RSI
            | Register::ESI
            | Register::RDI
            | Register::EDI
            | Register::RBP
            | Register::EBP
            | Register::RSP
            | Register::ESP
            | Register::R8
            | Register::R8D
            | Register::R9
            | Register::R9D
            | Register::R10
            | Register::R10D
            | Register::R11
            | Register::R11D
            | Register::R12
            | Register::R12D
            | Register::R13
            | Register::R13D
            | Register::R14
            | Register::R14D
            | Register::R15
            | Register::R15D
    )
}

/// Apply one instruction's effect to the register state. Conservative:
/// anything we don't recognize as a clean transfer is treated as an
/// Unknown clobber of the destination.
fn apply_effect(
    state: &mut RegState,
    insn: &Instruction,
    bytes_for_va: &impl Fn(u64, usize) -> Option<Vec<u8>>,
) {
    use Mnemonic as M;
    match insn.mnemonic() {
        M::Mov | M::Movzx | M::Movsx | M::Movsxd => handle_mov(state, insn, bytes_for_va),
        M::Lea => handle_lea(state, insn),
        M::Xor => handle_xor(state, insn),
        M::Add | M::Sub => handle_add_sub(state, insn),
        M::Push | M::Pop => {
            // Pop clobbers the destination; push doesn't change regs.
            // Both shift rsp, so any rsp-relative slot we tracked is
            // now off by a word — drop the lot.
            if insn.mnemonic() == M::Pop && insn.op0_kind() == OpKind::Register {
                let dst = insn.op0_register();
                state.set(dst, AbsVal::Unknown);
            }
            state.invalidate_rsp_slots();
        }
        M::Cmp | M::Test => {
            // Flag-only effects.
        }
        M::Nop => {}
        // Conditional moves: optimistically treat as a transfer if the
        // source is concrete and the destination would be Unknown.
        // This is a guess but harmless — if we're wrong, the run
        // produces no strings.
        _ if insn.condition_code() != ConditionCode::None => {
            // CMOVxx: only update dst if both operands are known.
            handle_mov(state, insn, bytes_for_va);
        }
        _ => {
            // Any other instruction with a register destination
            // clobbers it to Unknown. iced-x86 doesn't expose explicit
            // def/use info cheaply, but for the patterns we care about
            // (arg-setup before a call) clobbering on unrecognized
            // ops is safe.
            if insn.op_count() >= 1 && insn.op0_kind() == OpKind::Register {
                let dst = insn.op0_register();
                state.set(dst, AbsVal::Unknown);
            }
        }
    }
}

fn handle_mov(
    state: &mut RegState,
    insn: &Instruction,
    bytes_for_va: &impl Fn(u64, usize) -> Option<Vec<u8>>,
) {
    if insn.op_count() < 2 {
        return;
    }
    // ----- Memory destination: stack-slot stores. -----
    if insn.op0_kind() == OpKind::Memory {
        if let Some(key) = slot_key_for_memory(insn) {
            let src_val = match insn.op1_kind() {
                OpKind::Register => state.get(insn.op1_register()),
                OpKind::Immediate8 | OpKind::Immediate8to16 => {
                    AbsVal::Concrete(insn.immediate8() as i8 as i64 as u64)
                }
                OpKind::Immediate8to32 => AbsVal::Concrete(insn.immediate8to32() as i64 as u64),
                OpKind::Immediate8to64 => AbsVal::Concrete(insn.immediate8to64() as u64),
                OpKind::Immediate16 => AbsVal::Concrete(insn.immediate16() as u64),
                OpKind::Immediate32 => AbsVal::Concrete(insn.immediate32() as u64),
                OpKind::Immediate32to64 => AbsVal::Concrete(insn.immediate32to64() as u64),
                OpKind::Immediate64 => AbsVal::Concrete(insn.immediate64()),
                _ => AbsVal::Unknown,
            };
            state.store_slot(key, src_val);
        }
        return;
    }
    // ----- Register destination: immediate / register / memory load. -----
    if insn.op0_kind() != OpKind::Register {
        return;
    }
    let dst = insn.op0_register();
    if !writes_full_width(dst) {
        // Sub-width move — can't reason cleanly. Clobber.
        state.set(dst, AbsVal::Unknown);
        return;
    }
    let value = match insn.op1_kind() {
        OpKind::Immediate8 | OpKind::Immediate8to16 => {
            Some(AbsVal::Concrete(insn.immediate8() as i8 as i64 as u64))
        }
        OpKind::Immediate8to32 => Some(AbsVal::Concrete(insn.immediate8to32() as i64 as u64)),
        OpKind::Immediate8to64 => Some(AbsVal::Concrete(insn.immediate8to64() as u64)),
        OpKind::Immediate16 => Some(AbsVal::Concrete(insn.immediate16() as u64)),
        OpKind::Immediate32 => Some(AbsVal::Concrete(insn.immediate32() as u64)),
        OpKind::Immediate32to64 => Some(AbsVal::Concrete(insn.immediate32to64() as u64)),
        OpKind::Immediate64 => Some(AbsVal::Concrete(insn.immediate64())),
        OpKind::Register => {
            let src = insn.op1_register();
            Some(state.get(src))
        }
        OpKind::Memory => {
            // RIP-relative load? Try to materialize the loaded
            // constant from the binary's .rdata / .data.
            if insn.is_ip_rel_memory_operand() {
                let va = insn.ip_rel_memory_address();
                let size = insn.memory_size().info().size().min(8);
                if let Some(bytes) = bytes_for_va(va, size)
                    && bytes.len() == size
                    && size > 0
                {
                    let mut buf = [0u8; 8];
                    buf[..size].copy_from_slice(&bytes);
                    return state.set(dst, AbsVal::Concrete(u64::from_le_bytes(buf)));
                }
                None
            } else {
                slot_key_for_memory(insn).map(|key| state.load_slot(key))
            }
        }
        _ => None,
    };
    state.set(dst, value.unwrap_or(AbsVal::Unknown));
}

fn handle_lea(state: &mut RegState, insn: &Instruction) {
    if insn.op_count() < 2 || insn.op0_kind() != OpKind::Register {
        return;
    }
    let dst = insn.op0_register();
    if !writes_full_width(dst) {
        state.set(dst, AbsVal::Unknown);
        return;
    }
    // RIP-relative lea: deterministically resolves to a VA in the
    // binary — typically the pointer to encoded data in .rdata.
    if insn.is_ip_rel_memory_operand() {
        let va = insn.ip_rel_memory_address();
        state.set(dst, AbsVal::Pointer(va));
        return;
    }
    // Base + index*scale + displacement with a known base register.
    let base = insn.memory_base();
    let index = insn.memory_index();
    let disp = insn.memory_displacement64();
    if matches!(base, Register::None) && matches!(index, Register::None) {
        // Pure displacement (absolute address).
        state.set(dst, AbsVal::Pointer(disp));
        return;
    }
    // Otherwise, conservative clobber.
    state.set(dst, AbsVal::Unknown);
}

fn handle_xor(state: &mut RegState, insn: &Instruction) {
    if insn.op_count() < 2 {
        return;
    }
    if insn.op0_kind() != OpKind::Register || insn.op1_kind() != OpKind::Register {
        // Otherwise treat as a clobber.
        if insn.op0_kind() == OpKind::Register {
            let dst = insn.op0_register();
            state.set(dst, AbsVal::Unknown);
        }
        return;
    }
    let dst = insn.op0_register();
    let src = insn.op1_register();
    if full_reg(dst) == full_reg(src) {
        // xor reg, reg → reg = 0
        state.set(dst, AbsVal::Concrete(0));
    } else {
        state.set(dst, AbsVal::Unknown);
    }
}

fn handle_add_sub(state: &mut RegState, insn: &Instruction) {
    if insn.op_count() < 2 || insn.op0_kind() != OpKind::Register {
        return;
    }
    let dst = insn.op0_register();
    // Any arithmetic on rsp shifts the slot identities — drop them
    // so we don't read the wrong cell later in the block.
    if full_reg(dst) == Register::RSP {
        state.invalidate_rsp_slots();
    }
    if !writes_full_width(dst) {
        state.set(dst, AbsVal::Unknown);
        return;
    }
    let cur = state.get(dst);
    let Some(cur_val) = cur.as_value() else {
        state.set(dst, AbsVal::Unknown);
        return;
    };
    let imm = match insn.op1_kind() {
        OpKind::Immediate8 | OpKind::Immediate8to16 => Some(insn.immediate8() as i8 as i64 as u64),
        OpKind::Immediate8to32 => Some(insn.immediate8to32() as i64 as u64),
        OpKind::Immediate8to64 => Some(insn.immediate8to64() as u64),
        OpKind::Immediate16 => Some(insn.immediate16() as u64),
        OpKind::Immediate32 => Some(insn.immediate32() as u64),
        OpKind::Immediate32to64 => Some(insn.immediate32to64() as u64),
        OpKind::Immediate64 => Some(insn.immediate64()),
        _ => None,
    };
    let Some(imm) = imm else {
        state.set(dst, AbsVal::Unknown);
        return;
    };
    let new_val = match insn.mnemonic() {
        Mnemonic::Add => cur_val.wrapping_add(imm),
        Mnemonic::Sub => cur_val.wrapping_sub(imm),
        _ => return,
    };
    // Preserve Pointer-ness so the user can still recognize this as
    // a pointer into .rdata (decoder might start at base+offset).
    let new_abs = match cur {
        AbsVal::Pointer(_) => AbsVal::Pointer(new_val),
        _ => AbsVal::Concrete(new_val),
    };
    state.set(dst, new_abs);
}

/// Static call target if `insn` is a direct near `call`.
fn direct_call_target(insn: &Instruction) -> Option<u64> {
    if insn.mnemonic() != Mnemonic::Call {
        return None;
    }
    match insn.op0_kind() {
        OpKind::NearBranch16 => Some(insn.near_branch16() as u64),
        OpKind::NearBranch32 => Some(insn.near_branch32() as u64),
        OpKind::NearBranch64 => Some(insn.near_branch64()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use strix_core::InputMetadata;
    use strix_format::{ParsedInput, Section};

    fn parsed_with(
        code: &[u8],
        code_va: u64,
        rdata: &[u8],
        rdata_va: u64,
    ) -> (Vec<u8>, ParsedInput) {
        // Layout the input file as: [code][rdata], record their file
        // offsets in the section list so the analyzer can resolve VAs.
        let mut bytes = Vec::new();
        let code_off = 0u64;
        bytes.extend_from_slice(code);
        let rdata_off = bytes.len() as u64;
        bytes.extend_from_slice(rdata);

        let parsed = ParsedInput {
            metadata: InputMetadata {
                format: "sc64".into(),
                arch: Some("x86_64".into()),
                bits: Some(64),
                size: bytes.len() as u64,
                language: None,
            },
            sections: vec![
                Section {
                    name: ".text".into(),
                    file_offset: code_off,
                    file_size: code.len() as u64,
                    virtual_address: code_va,
                    executable: true,
                    writable: false,
                },
                Section {
                    name: ".rdata".into(),
                    file_offset: rdata_off,
                    file_size: rdata.len() as u64,
                    virtual_address: rdata_va,
                    executable: false,
                    writable: false,
                },
            ],
            entry: Some(code_va),
            warnings: Vec::new(),
            scan_window: None,
            imports: Vec::new(),
        };
        (bytes, parsed)
    }

    #[test]
    fn resolves_mov_imm_into_register() {
        // mov ecx, 0x10
        // mov edx, 0x20
        // call rel32 (target = 0x2000)
        // We expect rcx=0x10, rdx=0x20 at the call site.
        let code: Vec<u8> = vec![
            0xB9, 0x10, 0x00, 0x00, 0x00, // mov ecx, 0x10
            0xBA, 0x20, 0x00, 0x00, 0x00, // mov edx, 0x20
            0xE8, 0xF1, 0x0F, 0x00, 0x00, // call +0xFF1 → 0x2000 from next_ip 0x100F
            0xC3, // ret
        ];
        let (bytes, parsed) = parsed_with(&code, 0x1000, &[], 0x2000);
        let analyzer = CodeAnalyzer::new(&bytes, &parsed);
        let site = CallSite {
            caller_va: 0x1000,
            block_start: 0x1000,
            call_ip: 0x100A,
            next_ip: 0x100F,
        };
        let reader = make_va_reader(&bytes, &parsed);
        let regs = resolve_call_site_regs(&analyzer, site, reader);
        assert_eq!(regs.rcx, AbsValPub::Concrete(0x10));
        assert_eq!(regs.rdx, AbsValPub::Concrete(0x20));
    }

    #[test]
    fn resolves_lea_rip_relative_to_pointer() {
        // lea rcx, [rip+0x10]   ; 48 8D 0D 10 00 00 00  (7 bytes)
        // ret                    ; C3
        // ...
        let mut code = vec![0x48, 0x8D, 0x0D, 0x10, 0x00, 0x00, 0x00, 0xC3];
        // Pad to make code length predictable.
        while code.len() < 0x18 {
            code.push(0x90);
        }
        let (bytes, parsed) = parsed_with(&code, 0x1000, &[], 0x2000);
        let analyzer = CodeAnalyzer::new(&bytes, &parsed);
        // Treat the lea-then-ret as a "block" — we resolve at the ret IP.
        let site = CallSite {
            caller_va: 0x1000,
            block_start: 0x1000,
            call_ip: 0x1007, // the ret position
            next_ip: 0x1008,
        };
        let reader = make_va_reader(&bytes, &parsed);
        let regs = resolve_call_site_regs(&analyzer, site, reader);
        // rip-relative target = next_ip(0x1007) + disp(0x10) = 0x1017
        assert_eq!(regs.rcx, AbsValPub::Pointer(0x1017));
    }

    #[test]
    fn xor_reg_reg_zeroes_register() {
        // xor edx, edx
        // ret
        let code = vec![0x31, 0xD2, 0xC3];
        let (bytes, parsed) = parsed_with(&code, 0x1000, &[], 0x2000);
        let analyzer = CodeAnalyzer::new(&bytes, &parsed);
        let site = CallSite {
            caller_va: 0x1000,
            block_start: 0x1000,
            call_ip: 0x1002,
            next_ip: 0x1003,
        };
        let reader = make_va_reader(&bytes, &parsed);
        let regs = resolve_call_site_regs(&analyzer, site, reader);
        assert_eq!(regs.rdx, AbsValPub::Concrete(0));
    }

    #[test]
    fn cross_block_dataflow_chains_through_predecessor() {
        // Two-block function:
        //   prologue block @ 0x1000:
        //     mov ecx, 0xDEAD       ; B9 AD DE 00 00  (5 bytes)
        //     jmp +0                 ; EB 00          (2 bytes; target = 0x1007)
        //   call block @ 0x1007:
        //     call rel32 (target=0x2000)  ; E8 .. (5 bytes)
        //     ret                        ; C3
        //
        // Block-local dataflow on the call block alone sees only
        // the call. Cross-block dataflow walks the prologue block
        // first and picks up rcx=0xDEAD.
        // Call IP = 0x1007. Call next_ip = 0x100C. Target =
        // next_ip + disp = 0x2000, so disp = 0xFF4.
        let code: Vec<u8> = vec![
            0xB9, 0xAD, 0xDE, 0x00, 0x00, // mov ecx, 0xDEAD
            0xEB, 0x00, // jmp +0 -> 0x1007
            0xE8, 0xF4, 0x0F, 0x00, 0x00, // call 0x2000
            0xC3, // ret
        ];
        let (bytes, parsed) = parsed_with(&code, 0x1000, &[], 0x2000);
        let analyzer = CodeAnalyzer::new(&bytes, &parsed);
        let funcs = analyzer.discover_from_entry(0x1000);
        let func = funcs.values().next().expect("at least one function");
        let site = CallSite {
            caller_va: func.entry,
            block_start: 0x1007,
            call_ip: 0x1007,
            next_ip: 0x100C,
        };
        let reader = make_va_reader(&bytes, &parsed);

        // Block-local dataflow should see nothing — the mov is in
        // the previous block.
        let local = resolve_call_site_regs(&analyzer, site, &reader);
        assert_eq!(local.rcx, AbsValPub::Unknown);

        // Cross-block dataflow should resolve rcx = 0xDEAD.
        let cross = resolve_call_site_regs_cross_block(&analyzer, func, site, &reader);
        assert_eq!(cross.rcx, AbsValPub::Concrete(0xDEAD));
    }

    #[test]
    fn stack_spill_and_reload_preserves_value() {
        // mov rcx, 0xAA              ; 48 c7 c1 AA 00 00 00  (7 bytes)
        // mov [rsp+0x20], rcx        ; 48 89 4c 24 20         (5 bytes)
        // xor ecx, ecx               ; 31 c9                  (2 bytes) -- clobber rcx
        // mov rcx, [rsp+0x20]        ; 48 8b 4c 24 20         (5 bytes) -- reload
        // ret                        ; c3
        let code: Vec<u8> = vec![
            0x48, 0xC7, 0xC1, 0xAA, 0x00, 0x00, 0x00, // mov rcx, 0xAA
            0x48, 0x89, 0x4C, 0x24, 0x20, // mov [rsp+0x20], rcx
            0x31, 0xC9, // xor ecx, ecx
            0x48, 0x8B, 0x4C, 0x24, 0x20, // mov rcx, [rsp+0x20]
            0xC3, // ret
        ];
        let (bytes, parsed) = parsed_with(&code, 0x1000, &[], 0x2000);
        let analyzer = CodeAnalyzer::new(&bytes, &parsed);
        let site = CallSite {
            caller_va: 0x1000,
            block_start: 0x1000,
            call_ip: 0x1014, // the ret
            next_ip: 0x1015,
        };
        let reader = make_va_reader(&bytes, &parsed);
        let regs = resolve_call_site_regs(&analyzer, site, reader);
        // The reload should pull 0xAA back into rcx despite the xor.
        assert_eq!(regs.rcx, AbsValPub::Concrete(0xAA));
    }
}
