//! Dedicated stack-string pattern matcher.
//!
//! Many decoders build short strings by emitting a sequence of
//! immediate-store-to-stack instructions:
//!
//! ```asm
//! mov byte [rsp+0], 'H'
//! mov byte [rsp+1], 'i'
//! mov byte [rsp+2], '!'
//! mov byte [rsp+3], 0
//! ```
//!
//! We detect these via pattern analysis on the disassembly,
//! independent of full CPU emulation. The matcher runs entirely on
//! iced-x86 — no Unicorn required — so it's available even when the
//! `unicorn` feature is off, and it catches stack strings inside
//! functions our brute-force emulator can't get into (faults early,
//! indirect entry, etc.).
//!
//! # Algorithm
//!
//! For each discovered function:
//!
//! 1. Walk every instruction in every basic block.
//! 2. Recognize stores of the form `mov [rsp/esp + disp], imm8/16/32/64`.
//! 3. Accumulate per-stack-offset byte values in a sorted map.
//! 4. After processing the function, scan the map for runs of
//!    contiguous printable bytes of length >= `min_len`. Emit each
//!    as a `RecoveredStackString`.
//!
//! # What this doesn't handle (yet)
//!
//! * **rsp tracking.** We treat the stack pointer as a fixed
//!   reference. If a function manipulates `rsp` mid-flow (e.g.
//!   `sub rsp, N` before the stores), the recovered strings may be
//!   at "wrong" offsets, but the *byte order* between adjacent
//!   stores is preserved — which is what matters for the printable
//!   run.
//! * **Register-relative stores.** `mov [rbp+N], imm` and stores via
//!   other base registers are not recognized. Adding the standard
//!   x86 base registers here is a localized one-line change.
//! * **Multi-instruction patterns.** A common pattern is
//!   `mov eax, 0x6c6c6548; mov [rsp], eax` (writes "Hell" via a
//!   register). That requires tracking immediate-into-register
//!   followed by register-into-stack — out of scope for this first
//!   pass, but the natural follow-on.

#![allow(missing_docs)]

use std::collections::{BTreeMap, BTreeSet};

use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};

use crate::analyzer::{CodeAnalyzer, Function};
use strix_format::ParsedInput;

/// A stack string recovered by pattern analysis.
#[derive(Debug, Clone)]
pub struct RecoveredStackString {
    /// The recovered text.
    pub value: String,
    /// Virtual address of the function in which the string was built.
    pub function_va: u64,
    /// Offset relative to whatever the stack pointer was on function
    /// entry (sign-extended; can be negative for downward-growing
    /// stacks).
    pub stack_offset: i64,
    /// Whether the string was emitted by writes inside a loop body —
    /// a "tight" string. Computed from the function CFG via natural-
    /// loop detection over back-edges. False for straight-line
    /// stack-string builds.
    pub is_tight: bool,
}

/// Scan all functions in `parsed` for stack-string patterns.
pub fn extract(input: &[u8], parsed: &ParsedInput, min_len: usize) -> Vec<RecoveredStackString> {
    let analyzer = CodeAnalyzer::new(input, parsed);
    let funcs = analyzer.discover_all();
    let mut out = Vec::new();
    for (&entry, func) in &funcs {
        let loop_blocks = detect_loop_bodies(func);
        collect_stack_strings_in_function(&analyzer, func, entry, &loop_blocks, min_len, &mut out);
    }
    out
}

/// Public re-export of [`detect_loop_bodies`] for callers outside
/// this module (the emulation pipeline uses it to classify
/// emulated stack writes as tight when their writing IP lies in a
/// loop-body block).
pub fn detect_loop_bodies_public(func: &Function) -> BTreeSet<u64> {
    detect_loop_bodies(func)
}

/// Identify the set of basic-block start VAs that lie inside a
/// natural loop in `func`.
///
/// A natural loop is induced by a back-edge: an intra-function
/// successor edge whose target lies at or before the source block's
/// start. For each such back-edge `source -> target`, every block
/// whose start VA is in `[target, source.start]` (inclusive) is
/// considered part of the loop body.
///
/// This is a deliberately conservative approximation — it captures
/// the common cases (counted XOR loops, RC4 inner loops, byte-by-
/// byte transformers) without the bookkeeping cost of a full
/// dominator / SCC pass. Irreducible loops and multi-entry loops
/// are not handled.
fn detect_loop_bodies(func: &Function) -> BTreeSet<u64> {
    let mut loop_blocks: BTreeSet<u64> = BTreeSet::new();
    let block_starts: Vec<u64> = func.blocks.keys().copied().collect();
    for (&source_start, block) in &func.blocks {
        for &succ in &block.successors {
            // Back-edge: successor jumps to or before this block's start.
            if succ > source_start {
                continue;
            }
            if !func.blocks.contains_key(&succ) {
                continue;
            }
            // Every block whose start is in [succ, source_start] is
            // a loop-body block — including the loop header (`succ`)
            // and the back-edge's source itself.
            for &b in &block_starts {
                if b >= succ && b <= source_start {
                    loop_blocks.insert(b);
                }
            }
        }
    }
    loop_blocks
}

fn collect_stack_strings_in_function(
    analyzer: &CodeAnalyzer<'_>,
    func: &Function,
    func_entry: u64,
    loop_blocks: &BTreeSet<u64>,
    min_len: usize,
    out: &mut Vec<RecoveredStackString>,
) {
    let ptr_size: i64 = if analyzer.bitness() == 64 { 8 } else { 4 };

    // We flush stack strings *per basic block* rather than accumulating
    // across the whole function. Different branches commonly write
    // different content to the same stack offset (e.g. error-message
    // dispatchers), and we'd lose information by letting one block
    // overwrite another in a shared map.
    for block in func.blocks.values() {
        let Some(bytes_at) = analyzer.bytes_at_va(block.start) else {
            continue;
        };
        let block_size = (block.end.saturating_sub(block.start)) as usize;
        let block_size = block_size.min(bytes_at.len());
        let decoder = Decoder::with_ip(
            analyzer.bitness(),
            &bytes_at[..block_size],
            block.start,
            DecoderOptions::NONE,
        );

        // Per-block state: stack map, register-immediate cache,
        // virtual ESP. All reset between blocks.
        let mut stack: BTreeMap<i64, u8> = BTreeMap::new();
        let mut reg_imms: BTreeMap<Register, Vec<u8>> = BTreeMap::new();
        let mut vrsp: i64 = 0;

        for insn in decoder {
            // --- push patterns ---
            if insn.mnemonic() == Mnemonic::Push {
                vrsp -= ptr_size;
                if let Some(bytes) = push_immediate_bytes(&insn, ptr_size as usize) {
                    for (i, &b) in bytes.iter().enumerate() {
                        stack.insert(vrsp + i as i64, b);
                    }
                } else if insn.op_count() == 1 && insn.op0_kind() == OpKind::Register {
                    let reg = canon_reg(insn.op0_register());
                    if let Some(bytes) = reg_imms.get(&reg).cloned() {
                        let n = bytes.len().min(ptr_size as usize);
                        for (i, &b) in bytes.iter().take(n).enumerate() {
                            stack.insert(vrsp + i as i64, b);
                        }
                    }
                }
                continue;
            }
            if insn.mnemonic() == Mnemonic::Pop {
                vrsp += ptr_size;
                // Pop into reg invalidates the tracked value.
                if insn.op_count() == 1 && insn.op0_kind() == OpKind::Register {
                    reg_imms.remove(&canon_reg(insn.op0_register()));
                }
                continue;
            }

            // --- stack-pointer arithmetic ---
            if let Some(delta) = sp_arithmetic_delta(&insn) {
                vrsp += delta;
                continue;
            }

            // --- direct immediate-to-stack store ---
            if let Some((base, disp, value_bytes)) = stack_immediate_store(&insn) {
                let off = match base {
                    StackBase::Sp => vrsp + disp,
                    StackBase::Bp => disp,
                };
                for (i, &b) in value_bytes.iter().enumerate() {
                    stack.insert(off + i as i64, b);
                }
                continue;
            }

            // --- immediate-to-register (cache it) ---
            if let Some((reg, bytes)) = immediate_to_register(&insn) {
                reg_imms.insert(reg, bytes);
                continue;
            }

            // --- SIMD load from rdata: movdqu/movaps/etc xmm,
            //     [rip+disp]. Read the literal bytes out of the
            //     binary's data section and cache them under the
            //     XMM register so the subsequent stack-store can
            //     pick them up.
            if let Some((reg, bytes)) = simd_load_from_data(&insn, analyzer) {
                reg_imms.insert(reg, bytes);
                continue;
            }

            // --- xor reg, reg (zero) ---
            if let Some(reg) = xor_self(&insn) {
                reg_imms.insert(reg, vec![0u8; 8]);
                continue;
            }

            // --- register store to [rsp/esp/rbp/ebp + disp] ---
            if let Some((base, disp, reg, store_bytes)) = stack_store_from_register(&insn) {
                if let Some(bytes) = reg_imms.get(&reg) {
                    let off = match base {
                        StackBase::Sp => vrsp + disp,
                        StackBase::Bp => disp,
                    };
                    for i in 0..store_bytes {
                        if let Some(&b) = bytes.get(i) {
                            stack.insert(off + i as i64, b);
                        }
                    }
                }
                continue;
            }

            // --- fallback: invalidate any register written by an
            //     instruction we didn't recognize ---
            if insn.op_count() >= 1 && insn.op0_kind() == OpKind::Register {
                let written = canon_reg(insn.op0_register());
                reg_imms.remove(&written);
            }
        }

        // Flush whatever the block left on its virtual stack. Mark
        // emitted strings as tight if the writing block is inside a
        // detected loop body.
        let is_tight = loop_blocks.contains(&block.start);
        flush_runs(&stack, func_entry, is_tight, min_len, out);
    }
}

/// If `insn` is `push imm`, return the byte representation padded out
/// to one stack slot (sign-extended for imm8 push).
fn push_immediate_bytes(insn: &Instruction, ptr_size: usize) -> Option<Vec<u8>> {
    if insn.mnemonic() != Mnemonic::Push || insn.op_count() != 1 {
        return None;
    }
    let raw = match insn.op0_kind() {
        OpKind::Immediate8 => vec![insn.immediate8()],
        OpKind::Immediate8to16 => (insn.immediate8to16() as u16).to_le_bytes().to_vec(),
        OpKind::Immediate8to32 => (insn.immediate8to32() as u32).to_le_bytes().to_vec(),
        OpKind::Immediate8to64 => (insn.immediate8to64() as u64).to_le_bytes().to_vec(),
        OpKind::Immediate16 => insn.immediate16().to_le_bytes().to_vec(),
        OpKind::Immediate32 | OpKind::Immediate32to64 => insn.immediate32().to_le_bytes().to_vec(),
        OpKind::Immediate64 => insn.immediate64().to_le_bytes().to_vec(),
        _ => return None,
    };
    // Zero-extend (or sign-extend for negatives — already handled by
    // the i16/i32/i64 casts above) to the stack slot size so we lay
    // bytes into the correct number of slots.
    let mut out = vec![0u8; ptr_size];
    let copy = raw.len().min(ptr_size);
    out[..copy].copy_from_slice(&raw[..copy]);
    Some(out)
}

/// If `insn` is `sub rsp/esp, imm` or `add rsp/esp, imm`, return the
/// signed delta to apply to the virtual stack pointer. Returns
/// `None` for unrecognized forms.
fn sp_arithmetic_delta(insn: &Instruction) -> Option<i64> {
    if insn.op_count() != 2 {
        return None;
    }
    if insn.op0_kind() != OpKind::Register {
        return None;
    }
    let dst = insn.op0_register();
    if !matches!(dst, Register::RSP | Register::ESP | Register::SP) {
        return None;
    }
    let imm = match insn.op1_kind() {
        OpKind::Immediate8 => insn.immediate8() as i64,
        OpKind::Immediate8to16 => insn.immediate8to16() as i64,
        OpKind::Immediate8to32 => insn.immediate8to32() as i64,
        OpKind::Immediate8to64 => insn.immediate8to64(),
        OpKind::Immediate16 => insn.immediate16() as i16 as i64,
        OpKind::Immediate32 | OpKind::Immediate32to64 => insn.immediate32() as i32 as i64,
        OpKind::Immediate64 => insn.immediate64() as i64,
        _ => return None,
    };
    match insn.mnemonic() {
        Mnemonic::Sub => Some(-imm),
        Mnemonic::Add => Some(imm),
        _ => None,
    }
}

/// Recognize `mov reg, imm` and return the canonical destination
/// register and little-endian immediate bytes.
fn immediate_to_register(insn: &Instruction) -> Option<(Register, Vec<u8>)> {
    if insn.mnemonic() != Mnemonic::Mov {
        return None;
    }
    if insn.op_count() != 2 {
        return None;
    }
    if insn.op0_kind() != OpKind::Register {
        return None;
    }
    let dst = canon_reg(insn.op0_register());
    match insn.op1_kind() {
        OpKind::Immediate8 => Some((dst, vec![insn.immediate8()])),
        OpKind::Immediate16 => Some((dst, insn.immediate16().to_le_bytes().to_vec())),
        OpKind::Immediate32 | OpKind::Immediate32to64 => {
            Some((dst, insn.immediate32().to_le_bytes().to_vec()))
        }
        OpKind::Immediate64 => Some((dst, insn.immediate64().to_le_bytes().to_vec())),
        OpKind::Immediate8to16 => {
            let v = insn.immediate8to16();
            Some((dst, (v as u16).to_le_bytes().to_vec()))
        }
        OpKind::Immediate8to32 => {
            let v = insn.immediate8to32();
            Some((dst, (v as u32).to_le_bytes().to_vec()))
        }
        OpKind::Immediate8to64 => {
            let v = insn.immediate8to64();
            Some((dst, (v as u64).to_le_bytes().to_vec()))
        }
        _ => None,
    }
}

/// Recognize `xor reg, reg` and return the canonical register.
fn xor_self(insn: &Instruction) -> Option<Register> {
    if insn.mnemonic() != Mnemonic::Xor {
        return None;
    }
    if insn.op_count() != 2 {
        return None;
    }
    if insn.op0_kind() != OpKind::Register || insn.op1_kind() != OpKind::Register {
        return None;
    }
    let a = canon_reg(insn.op0_register());
    let b = canon_reg(insn.op1_register());
    if a == b { Some(a) } else { None }
}

/// Recognize `mov [rsp/esp/rbp/ebp + disp], reg` and return
/// `(base, disp, canonical_register, store_size_in_bytes)`.
fn stack_store_from_register(insn: &Instruction) -> Option<(StackBase, i64, Register, usize)> {
    // Accept the GPR `mov` plus the common SIMD-store mnemonics
    // (movdqu/movdqa for ints, movups/movaps for floats, and their
    // VEX-prefixed AVX variants). Anything else can't be a clean
    // register-to-stack store we'd want to track.
    if !matches!(
        insn.mnemonic(),
        Mnemonic::Mov
            | Mnemonic::Movdqu
            | Mnemonic::Movdqa
            | Mnemonic::Movups
            | Mnemonic::Movaps
            | Mnemonic::Vmovdqu
            | Mnemonic::Vmovdqa
            | Mnemonic::Vmovups
            | Mnemonic::Vmovaps
    ) {
        return None;
    }
    if insn.op_count() != 2 {
        return None;
    }
    if insn.op0_kind() != OpKind::Memory {
        return None;
    }
    if insn.op1_kind() != OpKind::Register {
        return None;
    }
    let base = match insn.memory_base() {
        Register::RSP | Register::ESP | Register::SP => StackBase::Sp,
        Register::RBP | Register::EBP | Register::BP => StackBase::Bp,
        _ => return None,
    };
    if insn.memory_index() != Register::None {
        return None;
    }
    let disp = insn.memory_displacement64() as i64;
    let src = canon_reg(insn.op1_register());
    let size = register_byte_width(insn.op1_register())?;
    Some((base, disp, src, size))
}

/// SIMD load from a fixed binary address:
///   `movdqu/movdqa/movups/movaps/vmov* xmm/ymm, [rip+disp]`
///   `movdqu/movdqa/movups/movaps/vmov* xmm/ymm, [abs]`     (32-bit)
/// Read the corresponding chunk of bytes out of the binary's mapped
/// data sections via `CodeAnalyzer::data_at_va` and return them
/// keyed by destination register.
fn simd_load_from_data(
    insn: &Instruction,
    analyzer: &CodeAnalyzer<'_>,
) -> Option<(Register, Vec<u8>)> {
    if !matches!(
        insn.mnemonic(),
        Mnemonic::Movdqu
            | Mnemonic::Movdqa
            | Mnemonic::Movups
            | Mnemonic::Movaps
            | Mnemonic::Vmovdqu
            | Mnemonic::Vmovdqa
            | Mnemonic::Vmovups
            | Mnemonic::Vmovaps
    ) {
        return None;
    }
    if insn.op_count() != 2 {
        return None;
    }
    if insn.op0_kind() != OpKind::Register {
        return None;
    }
    if insn.op1_kind() != OpKind::Memory {
        return None;
    }
    let dst = canon_reg(insn.op0_register());
    let size = register_byte_width(insn.op0_register())?;

    let va = if insn.is_ip_rel_memory_operand() {
        insn.ip_rel_memory_address()
    } else if insn.memory_base() == Register::None && insn.memory_index() == Register::None {
        insn.memory_displacement64()
    } else {
        return None;
    };
    let bytes = analyzer.data_at_va(va, size)?;
    if bytes.len() < size {
        return None;
    }
    Some((dst, bytes[..size].to_vec()))
}

/// Byte width of the register's view (1 for AL, 2 for AX, 4 for EAX, 8 for RAX, 16 for XMM, 32 for YMM, 64 for ZMM).
fn register_byte_width(reg: Register) -> Option<usize> {
    if reg.is_gpr8() {
        return Some(1);
    }
    if reg.is_gpr16() {
        return Some(2);
    }
    if reg.is_gpr32() {
        return Some(4);
    }
    if reg.is_gpr64() {
        return Some(8);
    }
    if reg.is_xmm() {
        return Some(16);
    }
    if reg.is_ymm() {
        return Some(32);
    }
    if reg.is_zmm() {
        return Some(64);
    }
    None
}

/// Normalize a register to its full-width canonical form so that
/// `EAX`, `AX`, and `AL` all share a tracking slot with `RAX`.
fn canon_reg(reg: Register) -> Register {
    // iced-x86's `full_register` returns the full-width 64-bit
    // (or 32-bit on x86) parent register.
    reg.full_register()
}

/// Scan the per-offset map for contiguous printable runs.
fn flush_runs(
    stack: &BTreeMap<i64, u8>,
    func_entry: u64,
    is_tight: bool,
    min_len: usize,
    out: &mut Vec<RecoveredStackString>,
) {
    let mut current: Option<(i64, String)> = None;
    let mut prev_off: Option<i64> = None;
    let emit = |cur: Option<(i64, String)>, out: &mut Vec<RecoveredStackString>| {
        if let Some((start, s)) = cur
            && s.len() >= min_len
        {
            out.push(RecoveredStackString {
                value: s,
                function_va: func_entry,
                stack_offset: start,
                is_tight,
            });
        }
    };
    for (&off, &byte) in stack {
        let printable = is_printable(byte);
        let contiguous = prev_off.is_some_and(|p| off == p + 1);
        match (&mut current, printable && contiguous) {
            (Some((_, s)), true) => s.push(byte as char),
            _ => {
                emit(current.take(), out);
                if printable {
                    let mut s = String::new();
                    s.push(byte as char);
                    current = Some((off, s));
                }
            }
        }
        prev_off = Some(off);
    }
    emit(current, out);
}

/// What stack-relative base register is in use, so the caller can
/// decide whether to fold `vrsp` into the offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StackBase {
    /// `[rsp/esp + disp]` — combine with the running virtual ESP.
    Sp,
    /// `[rbp/ebp + disp]` — use disp directly (we don't track rbp).
    Bp,
}

/// Recognize `mov [rsp/esp/rbp/ebp + disp], imm` and return
/// `(base, disp, little_endian_imm_bytes)`.
fn stack_immediate_store(insn: &Instruction) -> Option<(StackBase, i64, Vec<u8>)> {
    if insn.mnemonic() != Mnemonic::Mov {
        return None;
    }
    if insn.op_count() != 2 {
        return None;
    }
    if insn.op0_kind() != OpKind::Memory {
        return None;
    }
    let base = match insn.memory_base() {
        Register::RSP | Register::ESP | Register::SP => StackBase::Sp,
        Register::RBP | Register::EBP | Register::BP => StackBase::Bp,
        _ => return None,
    };
    if insn.memory_index() != Register::None {
        return None;
    }
    let disp = insn.memory_displacement64() as i64;
    let bytes = match insn.op1_kind() {
        OpKind::Immediate8 => vec![insn.immediate8()],
        OpKind::Immediate16 => insn.immediate16().to_le_bytes().to_vec(),
        OpKind::Immediate32 | OpKind::Immediate32to64 => insn.immediate32().to_le_bytes().to_vec(),
        OpKind::Immediate64 => insn.immediate64().to_le_bytes().to_vec(),
        OpKind::Immediate8to16 => (insn.immediate8to16() as u16).to_le_bytes().to_vec(),
        OpKind::Immediate8to32 => (insn.immediate8to32() as u32).to_le_bytes().to_vec(),
        OpKind::Immediate8to64 => (insn.immediate8to64() as u64).to_le_bytes().to_vec(),
        _ => return None,
    };
    Some((base, disp, bytes))
}

#[inline]
fn is_printable(b: u8) -> bool {
    (0x20..=0x7E).contains(&b) || b == b'\t'
}

#[cfg(test)]
mod tests {
    use super::*;
    use strix_core::InputMetadata;
    use strix_format::{ParsedInput, Section};

    fn parsed_for(bytes: &[u8], va: u64) -> ParsedInput {
        parsed_for_bits(bytes, va, 64)
    }

    fn parsed_for_bits(bytes: &[u8], va: u64, bits: u8) -> ParsedInput {
        let (format, arch) = if bits == 64 {
            ("sc64", "x86_64")
        } else {
            ("sc32", "x86")
        };
        ParsedInput {
            metadata: InputMetadata {
                format: format.into(),
                arch: Some(arch.into()),
                bits: Some(bits),
                size: bytes.len() as u64,
                language: None,
            },
            sections: vec![Section {
                name: ".text".into(),
                file_offset: 0,
                file_size: bytes.len() as u64,
                virtual_address: va,
                executable: true,
                writable: false,
            }],
            entry: Some(va),
            warnings: Vec::new(),
            scan_window: None,
            imports: Vec::new(),
        }
    }

    /// Hand-coded shellcode writing "STACK" via byte-imm stores.
    /// Pattern matcher should recover it without any emulation.
    #[test]
    fn recovers_stack_string_via_byte_imm() {
        // sub rsp, 8                 ; 48 83 EC 08
        // mov byte [rsp], 'S'        ; C6 04 24 53
        // mov byte [rsp+1], 'T'      ; C6 44 24 01 54
        // mov byte [rsp+2], 'A'      ; C6 44 24 02 41
        // mov byte [rsp+3], 'C'      ; C6 44 24 03 43
        // mov byte [rsp+4], 'K'      ; C6 44 24 04 4B
        // add rsp, 8                 ; 48 83 C4 08
        // ret                        ; C3
        let code: Vec<u8> = vec![
            0x48, 0x83, 0xEC, 0x08, 0xC6, 0x04, 0x24, 0x53, 0xC6, 0x44, 0x24, 0x01, 0x54, 0xC6,
            0x44, 0x24, 0x02, 0x41, 0xC6, 0x44, 0x24, 0x03, 0x43, 0xC6, 0x44, 0x24, 0x04, 0x4B,
            0x48, 0x83, 0xC4, 0x08, 0xC3,
        ];
        let parsed = parsed_for(&code, 0x1000);
        let recovered = extract(&code, &parsed, 4);
        assert!(
            recovered.iter().any(|s| s.value == "STACK"),
            "expected STACK, got {:?}",
            recovered
        );
    }

    /// Recovers a string built via a 32-bit immediate store
    /// (`mov dword [rsp+0], 0x6c6c6548` = "Hell" little-endian).
    #[test]
    fn recovers_stack_string_via_dword_imm() {
        // sub rsp, 8                              ; 48 83 EC 08
        // mov dword [rsp], 0x6c6c6548             ; C7 04 24 48 65 6C 6C   ("Hell")
        // mov dword [rsp+4], 0x21216f             ; C7 44 24 04 6F 21 21 00  ("o!!\\0")
        // add rsp, 8                              ; 48 83 C4 08
        // ret                                     ; C3
        let code: Vec<u8> = vec![
            0x48, 0x83, 0xEC, 0x08, 0xC7, 0x04, 0x24, 0x48, 0x65, 0x6C, 0x6C, 0xC7, 0x44, 0x24,
            0x04, 0x6F, 0x21, 0x21, 0x00, 0x48, 0x83, 0xC4, 0x08, 0xC3,
        ];
        let parsed = parsed_for(&code, 0x2000);
        let recovered = extract(&code, &parsed, 4);
        assert!(
            recovered.iter().any(|s| s.value == "Hello!!"),
            "expected Hello!!, got {:?}",
            recovered
        );
    }

    /// A function with no stack stores produces no stack strings.
    #[test]
    fn empty_function_produces_nothing() {
        let code: Vec<u8> = vec![0xC3]; // ret
        let parsed = parsed_for(&code, 0x3000);
        let recovered = extract(&code, &parsed, 4);
        assert!(recovered.is_empty());
    }

    /// Recovers a string built via the two-instruction pattern
    /// (`mov eax, imm32; mov [rsp+N], eax`) — the common pattern
    /// shellcode and many compilers use to avoid embedding the
    /// immediate directly in the memory-store encoding.
    #[test]
    fn recovers_stack_string_via_reg_then_store() {
        // 48 83 EC 08              ; sub rsp, 8
        // B8 48 65 6C 6C           ; mov eax, 0x6c6c6548 ("Hell")
        // 89 04 24                 ; mov [rsp], eax
        // B8 6F 21 21 00           ; mov eax, 0x21216f ("o!!\0")
        // 89 44 24 04              ; mov [rsp+4], eax
        // 48 83 C4 08              ; add rsp, 8
        // C3                       ; ret
        let code: Vec<u8> = vec![
            0x48, 0x83, 0xEC, 0x08, 0xB8, 0x48, 0x65, 0x6C, 0x6C, 0x89, 0x04, 0x24, 0xB8, 0x6F,
            0x21, 0x21, 0x00, 0x89, 0x44, 0x24, 0x04, 0x48, 0x83, 0xC4, 0x08, 0xC3,
        ];
        let parsed = parsed_for(&code, 0x5000);
        let recovered = extract(&code, &parsed, 4);
        assert!(
            recovered.iter().any(|s| s.value == "Hello!!"),
            "expected Hello!!, got {:?}",
            recovered
        );
    }

    /// Recovers a string built via the classic shellcode push pattern.
    /// Stack grows down, so the *later* push lands at a lower address;
    /// to spell "Hello", you push "o\0\0\0" first, then "Hell".
    #[test]
    fn recovers_stack_string_via_push_pattern() {
        // 68 6F 00 00 00    ; push 0x0000006F  ("o\0\0\0")
        // 68 48 65 6C 6C    ; push 0x6C6C6548  ("Hell")
        // C3                ; ret
        let code: Vec<u8> = vec![
            0x68, 0x6F, 0x00, 0x00, 0x00, 0x68, 0x48, 0x65, 0x6C, 0x6C, 0xC3,
        ];
        let parsed = parsed_for_bits(&code, 0x6000, 32);
        let recovered = extract(&code, &parsed, 4);
        assert!(
            recovered.iter().any(|s| s.value == "Hello"),
            "expected Hello, got {:?}",
            recovered
        );
    }

    /// Recovers a string built via the standard compiler pattern of
    /// `mov dword [ebp-N], imm32` stores using the frame pointer.
    /// This is what most C/C++ compilers emit for short string
    /// literals in stack-local buffers.
    #[test]
    fn recovers_stack_string_via_ebp_relative() {
        // mov dword [ebp-0x20], 0x61766e49  ("Inva")    ; C7 45 E0 49 6E 76 61
        // mov dword [ebp-0x1c], 0x2064696c  ("lid ")    ; C7 45 E4 6C 69 64 20
        // mov dword [ebp-0x18], 0x61746164  ("data")    ; C7 45 E8 64 61 74 61
        // ret
        let code: Vec<u8> = vec![
            0xC7, 0x45, 0xE0, 0x49, 0x6E, 0x76, 0x61, 0xC7, 0x45, 0xE4, 0x6C, 0x69, 0x64, 0x20,
            0xC7, 0x45, 0xE8, 0x64, 0x61, 0x74, 0x61, 0xC3,
        ];
        let parsed = parsed_for_bits(&code, 0x7000, 32);
        let recovered = extract(&code, &parsed, 4);
        assert!(
            recovered.iter().any(|s| s.value == "Invalid data"),
            "expected 'Invalid data', got {:?}",
            recovered
        );
    }

    /// A stack string emitted from inside a self-loop (the block
    /// has a back-edge to itself) should be classified as tight.
    /// Straight-line stack strings should NOT be tight.
    #[test]
    fn tight_classification_marks_loop_body_strings() {
        // Loop block, single basic block ending in a conditional
        // back-edge to itself:
        //   mov byte [rsp+0], 'L'   ; C6 04 24 4C
        //   mov byte [rsp+1], 'O'   ; C6 44 24 01 4F
        //   mov byte [rsp+2], 'O'   ; C6 44 24 02 4F
        //   mov byte [rsp+3], 'P'   ; C6 44 24 03 50
        //   test eax, eax           ; 85 C0
        //   jne -23                 ; 75 E9  (back to start)
        //   ret                     ; C3
        let code: Vec<u8> = vec![
            0xC6, 0x04, 0x24, 0x4C, // mov byte [rsp+0], 'L'
            0xC6, 0x44, 0x24, 0x01, 0x4F, // mov byte [rsp+1], 'O'
            0xC6, 0x44, 0x24, 0x02, 0x4F, // mov byte [rsp+2], 'O'
            0xC6, 0x44, 0x24, 0x03, 0x50, // mov byte [rsp+3], 'P'
            0x85, 0xC0, // test eax, eax
            0x75, 0xE9, // jne -23
            0xC3, // ret
        ];
        let parsed = parsed_for(&code, 0x8000);
        let recovered = extract(&code, &parsed, 4);
        let loop_str = recovered
            .iter()
            .find(|s| s.value == "LOOP")
            .expect("expected LOOP in recovered stack strings");
        assert!(
            loop_str.is_tight,
            "LOOP should be classified as tight (block has a back-edge)"
        );
    }

    /// A straight-line stack string (no back-edges anywhere) must
    /// NOT be classified as tight.
    #[test]
    fn tight_classification_skips_straight_line_strings() {
        // From recovers_stack_string_via_byte_imm — purely linear flow.
        let code: Vec<u8> = vec![
            0x48, 0x83, 0xEC, 0x08, 0xC6, 0x04, 0x24, 0x53, 0xC6, 0x44, 0x24, 0x01, 0x54, 0xC6,
            0x44, 0x24, 0x02, 0x41, 0xC6, 0x44, 0x24, 0x03, 0x43, 0xC6, 0x44, 0x24, 0x04, 0x4B,
            0x48, 0x83, 0xC4, 0x08, 0xC3,
        ];
        let parsed = parsed_for(&code, 0x9000);
        let recovered = extract(&code, &parsed, 4);
        let stack_str = recovered
            .iter()
            .find(|s| s.value == "STACK")
            .expect("expected STACK in recovered stack strings");
        assert!(
            !stack_str.is_tight,
            "STACK is straight-line; should not be tight"
        );
    }

    /// Non-contiguous stores don't combine into a single run.
    /// Writing "AB" at [rsp] then "XY" at [rsp+10] should yield two
    /// separate runs, not "ABXY".
    /// SIMD pattern: load a 16-byte chunk from .rdata into XMM0,
    /// store it to the stack, recover the printable run.
    ///
    /// Layout (single section, two regions):
    ///   .text  at 0x10000 — the code
    ///   data appended after the code at file offset = code.len()
    ///   the data lives at VA = 0x10000 + data_file_offset (since
    ///   parsed_for sets file_offset=0, file_size=bytes.len(),
    ///   virtual_address=VA — i.e. file and VA share a base).
    #[test]
    fn recovers_stack_string_via_simd_load_from_rdata() {
        // Place the literal "Hello, World!\x00\x00\x00" (16 bytes)
        // at offset 0x20 from the start of the section.
        let mut code: Vec<u8> = Vec::new();
        // movdqu xmm0, [rip + 0x12]  ; F3 0F 6F 05 12 00 00 00
        //   next_ip = 0x8, disp = 0x12, target = 0x8 + 0x12 = 0x1A
        // Hmm wait — we need the data to be at a known location.
        // Easier: use `movdqu xmm0, [abs]` style? That's not
        // directly encodable in 64-bit. Use rip-relative and set
        // the disp so the target lands inside our data region.
        //
        // Place data at section offset 0x20 (VA = 0x10020).
        // mov starts at VA = 0x10000, length 8, next_ip = 0x10008.
        // disp = 0x10020 - 0x10008 = 0x18.
        code.extend_from_slice(&[0xF3, 0x0F, 0x6F, 0x05, 0x18, 0x00, 0x00, 0x00]); // movdqu xmm0, [rip+0x18]
        // movdqu [rsp], xmm0         ; F3 0F 7F 04 24 (5 bytes)
        code.extend_from_slice(&[0xF3, 0x0F, 0x7F, 0x04, 0x24]);
        // ret  ; C3
        code.push(0xC3);
        // Pad with nops to reach offset 0x20.
        while code.len() < 0x20 {
            code.push(0x90);
        }
        // The 16-byte literal.
        let literal = b"Hello, World!\x00\x00\x00";
        code.extend_from_slice(literal);
        // Section spans the whole buffer.
        let parsed = parsed_for(&code, 0x10000);
        let recovered = extract(&code, &parsed, 4);
        assert!(
            recovered.iter().any(|s| s.value == "Hello, World!"),
            "expected 'Hello, World!' in SIMD recovered set, got {:?}",
            recovered
        );
    }

    #[test]
    fn non_contiguous_stores_dont_merge() {
        let code: Vec<u8> = vec![
            // mov word [rsp], 0x4241  ("AB")
            0x66, 0xC7, 0x04, 0x24, 0x41, 0x42, // mov word [rsp+10], 0x5958 ("XY")
            0x66, 0xC7, 0x44, 0x24, 0x0A, 0x58, 0x59, 0xC3,
        ];
        let parsed = parsed_for(&code, 0x4000);
        // min_len=2 to catch each pair
        let recovered = extract(&code, &parsed, 2);
        let values: Vec<&str> = recovered.iter().map(|s| s.value.as_str()).collect();
        assert!(values.contains(&"AB"), "expected AB in {:?}", values);
        assert!(values.contains(&"XY"), "expected XY in {:?}", values);
        // And they should NOT have merged.
        assert!(!values.contains(&"ABXY"));
    }
}
