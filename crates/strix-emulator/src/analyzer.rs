//! Code-flow analyzer built on `iced_x86`.
//!
//! Discovers functions, basic blocks, and call-graph edges in an
//! executable. This is the analog of vivisect's analyzer in the
//! intermediate code-flow representation the higher-level extractors
//! consume.
//!
//! Two discovery strategies are combined:
//!
//! * **Recursive descent.** Start from a set of known entry points
//!   (the binary's entry, exports, hard-coded VAs) and follow direct
//!   calls. Cheap, accurate, but misses functions only reached via
//!   indirect calls or referenced only from data.
//! * **Prologue linear sweep.** Walk every executable byte and flag
//!   addresses that look like function starts based on the common
//!   x86/x86_64 prologue patterns. Catches functions the recursive
//!   pass misses, at the cost of occasional false positives.
//!
//! What this layer deliberately does *not* do (yet): indirect-call
//! resolution, switch-table reconstruction, tail-call detection,
//! non-returning function tracking. Each of those is a future pass.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, OpKind};
use strix_format::{ParsedInput, Section};

/// The terminating semantics of a basic block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockKind {
    /// Falls through to the next instruction; no branch instruction at
    /// the end. Typically only the implicit last block of a function.
    Fallthrough,
    /// Ends in an unconditional jump.
    Branch,
    /// Ends in a conditional jump (two successors).
    CondBranch,
    /// Ends in a call (one successor — the following instruction —
    /// plus an inter-function call edge tracked separately).
    Call,
    /// Ends in a return.
    Return,
    /// Ends in an indirect branch or call we can't statically resolve.
    Indirect,
}

/// A basic block: a maximal straight-line sequence of instructions
/// with one entry and one exit.
#[derive(Debug, Clone)]
pub struct BasicBlock {
    /// Virtual address of the first instruction.
    pub start: u64,
    /// Virtual address one past the last instruction (exclusive).
    pub end: u64,
    /// Successor block start addresses inside the same function.
    pub successors: Vec<u64>,
    /// How the block terminates.
    pub kind: BlockKind,
}

/// A discovered function: its entry point, basic-block decomposition,
/// and the set of callees it directly calls.
#[derive(Debug, Clone)]
pub struct Function {
    /// Virtual address of the function entry.
    pub entry: u64,
    /// Basic blocks keyed by start VA.
    pub blocks: BTreeMap<u64, BasicBlock>,
    /// Direct-call targets observed during analysis.
    pub callees: BTreeSet<u64>,
    /// Imported functions called via indirect `call [iat_entry]` or
    /// `call [rip+disp]` where the displacement lands on a known
    /// IAT entry. Keyed by the IAT entry's virtual address; the
    /// matching `Import { library, name }` lives in `parsed.imports`.
    /// Used by the scorer as a negative signal (decoders rarely
    /// touch imports).
    pub imported_callees: BTreeSet<u64>,
}

impl Function {
    /// Number of instructions across all blocks (cheap proxy for size).
    ///
    /// Computed from the byte ranges, not by re-decoding.
    pub fn byte_size(&self) -> u64 {
        self.blocks
            .values()
            .map(|b| b.end.saturating_sub(b.start))
            .sum()
    }
}

/// Analyzer over a parsed binary.
///
/// Holds borrowed references to the binary bytes and its parse, so
/// constructing one is free and discarding one is free.
pub struct CodeAnalyzer<'a> {
    bytes: &'a [u8],
    parsed: &'a ParsedInput,
    bitness: u32,
}

impl<'a> CodeAnalyzer<'a> {
    /// Construct a new analyzer.
    pub fn new(bytes: &'a [u8], parsed: &'a ParsedInput) -> Self {
        let bitness = u32::from(parsed.metadata.bits.unwrap_or(64));
        Self {
            bytes,
            parsed,
            bitness,
        }
    }

    /// Bitness of the binary (32 or 64).
    pub fn bitness(&self) -> u32 {
        self.bitness
    }

    /// Find the executable section that contains the given virtual
    /// address, if any.
    pub fn section_for_va(&self, va: u64) -> Option<&'a Section> {
        self.parsed.sections.iter().find(|s| {
            s.executable && va >= s.virtual_address && va < s.virtual_address + s.file_size
        })
    }

    /// Return a slice of code bytes starting at `va`, bounded by the
    /// end of the containing executable section. `None` if no
    /// executable section contains `va`.
    pub fn bytes_at_va(&self, va: u64) -> Option<&'a [u8]> {
        let sec = self.section_for_va(va)?;
        let file_off = (va - sec.virtual_address) + sec.file_offset;
        let start = file_off as usize;
        let end = (sec.file_offset + sec.file_size) as usize;
        if start >= self.bytes.len() || end > self.bytes.len() {
            return None;
        }
        Some(&self.bytes[start..end])
    }

    /// Read up to `len` bytes from the binary at virtual address
    /// `va`, regardless of section permissions. Returns `None` when
    /// `va` isn't in any mapped section.
    ///
    /// Used by the stack-string pattern matcher for SIMD-load
    /// constants like `movdqu xmm, [rip+rdata_disp]` where the
    /// source bytes live in `.rdata` / `__const`.
    pub fn data_at_va(&self, va: u64, len: usize) -> Option<&'a [u8]> {
        for sec in &self.parsed.sections {
            if va >= sec.virtual_address && va < sec.virtual_address + sec.file_size {
                let off_in_sec = (va - sec.virtual_address) as usize;
                let file_off = sec.file_offset as usize + off_in_sec;
                let avail = (sec.file_size as usize).saturating_sub(off_in_sec);
                let take = len.min(avail);
                if file_off + take > self.bytes.len() {
                    return None;
                }
                return Some(&self.bytes[file_off..file_off + take]);
            }
        }
        None
    }

    /// Decode instructions at `va` until the end of the containing
    /// section. Returns `None` if `va` isn't in executable code.
    pub fn instructions_at(&self, va: u64) -> Option<impl Iterator<Item = Instruction> + 'a> {
        let bytes = self.bytes_at_va(va)?;
        let decoder = Decoder::with_ip(self.bitness, bytes, va, DecoderOptions::NONE);
        Some(decoder.into_iter())
    }

    /// Discover functions by recursive descent from `entry`, following
    /// direct calls.
    ///
    /// Functions are keyed by their entry VA. Each function has its
    /// basic blocks populated.
    pub fn discover_from_entry(&self, entry: u64) -> BTreeMap<u64, Function> {
        let mut out: BTreeMap<u64, Function> = BTreeMap::new();
        let mut worklist: VecDeque<u64> = VecDeque::new();
        worklist.push_back(entry);

        while let Some(func_entry) = worklist.pop_front() {
            if out.contains_key(&func_entry) {
                continue;
            }
            let Some(func) = self.analyze_function(func_entry) else {
                continue;
            };
            for &callee in &func.callees {
                if !out.contains_key(&callee) {
                    worklist.push_back(callee);
                }
            }
            out.insert(func_entry, func);
        }
        out
    }

    /// Find candidate function entry points via prologue-pattern
    /// linear sweep over executable sections.
    ///
    /// The patterns recognized today:
    ///
    /// * x86-64: `push rbp; mov rbp, rsp` (`55 48 89 e5`)
    /// * x86-64: `push rbx` followed by `sub rsp, imm` (frame setup)
    /// * x86-32: `push ebp; mov ebp, esp` (`55 89 e5`)
    /// * either: `sub rsp/esp, imm` directly (frameless prologue)
    ///
    /// False positives are possible (a `push rbp` can appear mid-
    /// function); callers should treat the results as candidates, not
    /// guarantees.
    pub fn find_prologues(&self) -> Vec<u64> {
        let mut prologues = Vec::new();
        for sec in &self.parsed.sections {
            if !sec.executable {
                continue;
            }
            let start = sec.file_offset as usize;
            let end = (sec.file_offset + sec.file_size) as usize;
            if start >= self.bytes.len() || end > self.bytes.len() {
                continue;
            }
            let code = &self.bytes[start..end];
            let base_va = sec.virtual_address;
            for (i, _) in code.iter().enumerate() {
                if matches_prologue(&code[i..], self.bitness) {
                    prologues.push(base_va + i as u64);
                }
            }
        }
        prologues
    }

    /// Combine recursive descent (from the entry point if available)
    /// and prologue sweep to produce the broadest possible function
    /// list.
    pub fn discover_all(&self) -> BTreeMap<u64, Function> {
        let mut out = match self.parsed.entry {
            Some(e) => self.discover_from_entry(e),
            None => BTreeMap::new(),
        };
        for prologue_va in self.find_prologues() {
            if out.contains_key(&prologue_va) {
                continue;
            }
            if let Some(func) = self.analyze_function(prologue_va) {
                // Merge any callees discovered from this prologue
                // function into the worklist.
                let mut worklist: VecDeque<u64> = func.callees.iter().copied().collect();
                out.insert(prologue_va, func);
                while let Some(v) = worklist.pop_front() {
                    if out.contains_key(&v) {
                        continue;
                    }
                    if let Some(f2) = self.analyze_function(v) {
                        worklist.extend(f2.callees.iter().copied());
                        out.insert(v, f2);
                    }
                }
            }
        }
        out
    }

    /// Analyze a single function starting at `entry`, computing its
    /// basic-block decomposition.
    ///
    /// Returns `None` if `entry` is not in an executable region.
    pub fn analyze_function(&self, entry: u64) -> Option<Function> {
        let sec = self.section_for_va(entry)?;
        let sec_end_va = sec.virtual_address + sec.file_size;

        // Worklist of block starts we still need to explore.
        let mut block_worklist: VecDeque<u64> = VecDeque::new();
        block_worklist.push_back(entry);
        // Block-start VAs we've already finalized.
        let mut blocks: BTreeMap<u64, BasicBlock> = BTreeMap::new();
        let mut callees: BTreeSet<u64> = BTreeSet::new();
        let mut imported_callees: BTreeSet<u64> = BTreeSet::new();

        while let Some(block_start) = block_worklist.pop_front() {
            if blocks.contains_key(&block_start) {
                continue;
            }
            if block_start < sec.virtual_address || block_start >= sec_end_va {
                // Block jumped outside this function's section —
                // treat as tail call / external; don't follow.
                continue;
            }

            // Decode instructions until we hit a terminator. Track the
            // block-end VA via iced's `next_ip()`.
            let bytes = self.bytes_at_va(block_start)?;
            let decoder = Decoder::with_ip(self.bitness, bytes, block_start, DecoderOptions::NONE);

            let mut successors: Vec<u64> = Vec::new();
            let mut kind = BlockKind::Fallthrough;
            let mut block_end = block_start;
            for insn in decoder {
                block_end = insn.next_ip();
                // Stop the block at any flow-control instruction or
                // before we step into another known block.
                match insn.flow_control() {
                    FlowControl::ConditionalBranch => {
                        kind = BlockKind::CondBranch;
                        if let Some(t) = direct_branch_target(&insn) {
                            successors.push(t);
                            block_worklist.push_back(t);
                        }
                        // Fallthrough successor.
                        successors.push(insn.next_ip());
                        block_worklist.push_back(insn.next_ip());
                        break;
                    }
                    FlowControl::UnconditionalBranch => {
                        kind = BlockKind::Branch;
                        if let Some(t) = direct_branch_target(&insn) {
                            successors.push(t);
                            block_worklist.push_back(t);
                        }
                        break;
                    }
                    FlowControl::IndirectBranch => {
                        kind = BlockKind::Indirect;
                        break;
                    }
                    FlowControl::Return => {
                        kind = BlockKind::Return;
                        break;
                    }
                    FlowControl::Call => {
                        kind = BlockKind::Call;
                        if let Some(t) = direct_branch_target(&insn) {
                            // Direct calls that land on a PLT-style
                            // import thunk (`jmp [rip+got]`) should
                            // count as imported callees, not as
                            // ordinary function calls. The PLT itself
                            // is still recorded in `callees` so the
                            // call graph stays complete.
                            if let Some(iat_va) = self.is_plt_thunk(t) {
                                imported_callees.insert(iat_va);
                            }
                            callees.insert(t);
                        }
                        // Calls fall through.
                        successors.push(insn.next_ip());
                        block_worklist.push_back(insn.next_ip());
                        break;
                    }
                    FlowControl::IndirectCall => {
                        // Try to resolve `call [rip+disp]` (PE64) or
                        // `call [abs]` (PE32) against the known IAT
                        // entries. When it matches, record the IAT
                        // VA so the scorer can use "talks to imports"
                        // as a negative signal for decoder-ness.
                        if let Some(iat_va) = self.resolve_indirect_call_target(&insn) {
                            imported_callees.insert(iat_va);
                        }
                        kind = BlockKind::Call;
                        successors.push(insn.next_ip());
                        block_worklist.push_back(insn.next_ip());
                        break;
                    }
                    FlowControl::Interrupt
                    | FlowControl::Exception
                    | FlowControl::XbeginXabortXend => {
                        // Treat as block terminator without successors.
                        kind = BlockKind::Indirect;
                        break;
                    }
                    FlowControl::Next => {
                        // Fall through; continue accumulating.
                    }
                }
                // Bound block size to avoid runaway decoding on bad
                // input.
                if block_end - block_start > 0x10_000 {
                    kind = BlockKind::Indirect;
                    break;
                }
            }

            blocks.insert(
                block_start,
                BasicBlock {
                    start: block_start,
                    end: block_end,
                    successors,
                    kind,
                },
            );
        }

        if blocks.is_empty() {
            return None;
        }

        // Post-process: split any blocks where a later-discovered
        // block-start VA falls inside an earlier block's range.
        split_overlapping_blocks(&mut blocks);

        Some(Function {
            entry,
            blocks,
            callees,
            imported_callees,
        })
    }

    /// Try to resolve an indirect `call [mem]` instruction to a
    /// known IAT entry.
    ///
    /// PE64 emits `FF 15 disp32` which iced reports as a rip-relative
    /// memory operand. PE32 uses absolute addressing; iced reports a
    /// displacement-only operand (base = None, index = None). In both
    /// cases the effective target VA is compared against
    /// `parsed.imports[*].iat_va` for a match.
    fn resolve_indirect_call_target(&self, insn: &Instruction) -> Option<u64> {
        if insn.op0_kind() != OpKind::Memory {
            return None;
        }
        // The effective address is the memory_displacement64 for both
        // rip-relative (iced folds rip into the displacement) and
        // absolute addressing — but only when there's no index
        // register involved.
        if insn.memory_index() != iced_x86::Register::None {
            return None;
        }
        let target = if insn.is_ip_rel_memory_operand() {
            insn.ip_rel_memory_address()
        } else if insn.memory_base() == iced_x86::Register::None {
            // Absolute addressing: the displacement IS the address.
            insn.memory_displacement64()
        } else {
            // Register-relative or base-indexed: can't resolve
            // statically.
            return None;
        };
        // Match against the known import table.
        if self.parsed.imports.iter().any(|imp| imp.iat_va == target) {
            Some(target)
        } else {
            None
        }
    }

    /// If `va` looks like a PLT-style import thunk
    /// (`jmp qword ptr [rip+got_disp]`, optionally followed by a
    /// push/jmp lazy-resolver stub), return the GOT VA the thunk
    /// dispatches through. The GOT VA is matched against
    /// `parsed.imports` by the caller.
    ///
    /// ELF PLT entries are 16 bytes:
    ///   `jmp qword ptr [rip+got_disp]`  (6 bytes)
    ///   `push imm32`                   (5 bytes)
    ///   `jmp .plt0`                    (5 bytes)
    /// The first instruction is the only one we need. Some binaries
    /// also emit a `.plt.got` section with just the jmp.
    ///
    /// Returns `None` if `va` doesn't decode to a `jmp [rip+disp]`
    /// (or `jmp [abs]` on 32-bit), or if the resolved GOT VA isn't
    /// in our imports table.
    pub fn is_plt_thunk(&self, va: u64) -> Option<u64> {
        let bytes = self.bytes_at_va(va)?;
        // A PLT thunk's first instruction is at most 7 bytes
        // (FF 25 disp32, or FF 25 disp32 with REX). Bound the
        // decode so we don't accidentally walk into adjacent code.
        let look = bytes.get(..8).unwrap_or(bytes);
        let mut decoder = Decoder::with_ip(self.bitness, look, va, DecoderOptions::NONE);
        let insn = decoder.decode();
        if insn.is_invalid() {
            return None;
        }
        if insn.mnemonic() != iced_x86::Mnemonic::Jmp {
            return None;
        }
        if insn.op0_kind() != OpKind::Memory {
            return None;
        }
        if insn.memory_index() != iced_x86::Register::None {
            return None;
        }
        let target = if insn.is_ip_rel_memory_operand() {
            insn.ip_rel_memory_address()
        } else if insn.memory_base() == iced_x86::Register::None {
            insn.memory_displacement64()
        } else {
            return None;
        };
        if self.parsed.imports.iter().any(|imp| imp.iat_va == target) {
            Some(target)
        } else {
            None
        }
    }
}

/// If a block contains another block's start address as an interior
/// address, split it. Necessary because back-edges from later in the
/// function may target the middle of an earlier-emitted block.
fn split_overlapping_blocks(blocks: &mut BTreeMap<u64, BasicBlock>) {
    let starts: Vec<u64> = blocks.keys().copied().collect();
    let mut splits: Vec<(u64, u64)> = Vec::new(); // (host_block_start, split_at)
    for &host in &starts {
        let host_block = &blocks[&host];
        for &probe in &starts {
            if probe <= host_block.start || probe >= host_block.end {
                continue;
            }
            splits.push((host, probe));
        }
    }
    for (host, split_at) in splits {
        let Some(mut original) = blocks.remove(&host) else {
            continue;
        };
        let new_kind = original.kind;
        let new_successors = std::mem::take(&mut original.successors);
        let new_end = original.end;
        let upper = BasicBlock {
            start: split_at,
            end: new_end,
            successors: new_successors,
            kind: new_kind,
        };
        original.end = split_at;
        original.successors = vec![split_at];
        original.kind = BlockKind::Fallthrough;
        blocks.insert(host, original);
        blocks.entry(split_at).or_insert(upper);
    }
}

/// Return the static branch/call target of `insn`, if it's a direct
/// near branch.
fn direct_branch_target(insn: &Instruction) -> Option<u64> {
    if !matches!(
        insn.flow_control(),
        FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch | FlowControl::Call
    ) {
        return None;
    }
    match insn.op0_kind() {
        OpKind::NearBranch16 => Some(insn.near_branch16() as u64),
        OpKind::NearBranch32 => Some(insn.near_branch32() as u64),
        OpKind::NearBranch64 => Some(insn.near_branch64()),
        _ => None,
    }
}

/// Heuristic: does `code` start with a recognized function prologue
/// for the given bitness?
fn matches_prologue(code: &[u8], bitness: u32) -> bool {
    match bitness {
        64 => is_x86_64_prologue(code),
        _ => is_x86_prologue(code),
    }
}

fn is_x86_64_prologue(c: &[u8]) -> bool {
    // push rbp ; mov rbp, rsp
    if c.len() >= 4 && c[0] == 0x55 && c[1] == 0x48 && c[2] == 0x89 && c[3] == 0xE5 {
        return true;
    }
    // push rbx (53) followed by sub rsp, imm
    if c.len() >= 5 && c[0] == 0x53 && c[1] == 0x48 && c[2] == 0x83 && c[3] == 0xEC {
        return true;
    }
    // Frameless: sub rsp, imm8  ->  48 83 ec XX
    if c.len() >= 4 && c[0] == 0x48 && c[1] == 0x83 && c[2] == 0xEC {
        return true;
    }
    // Frameless: sub rsp, imm32 -> 48 81 ec XX XX XX XX
    if c.len() >= 7 && c[0] == 0x48 && c[1] == 0x81 && c[2] == 0xEC {
        return true;
    }
    // push r12-r15 (41 54..57) commonly the first instruction.
    if c.len() >= 2 && c[0] == 0x41 && (0x54..=0x57).contains(&c[1]) {
        return true;
    }
    false
}

fn is_x86_prologue(c: &[u8]) -> bool {
    // push ebp ; mov ebp, esp
    if c.len() >= 3 && c[0] == 0x55 && c[1] == 0x89 && c[2] == 0xE5 {
        return true;
    }
    // Frameless: sub esp, imm8 -> 83 ec XX
    if c.len() >= 3 && c[0] == 0x83 && c[1] == 0xEC {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use strix_core::InputMetadata;
    use strix_format::{ParsedInput, Section};

    fn parsed_for(bytes: &[u8], va: u64) -> ParsedInput {
        ParsedInput {
            metadata: InputMetadata {
                format: "sc64".into(),
                arch: Some("x86_64".into()),
                bits: Some(64),
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
            symbols: Default::default(),
        }
    }

    #[test]
    fn discovers_simple_function() {
        // Two instructions then ret:
        //   mov rax, 0x42  (7 bytes: 48 c7 c0 42 00 00 00)
        //   ret            (1 byte:  c3)
        let code: Vec<u8> = vec![
            0x48, 0xC7, 0xC0, 0x42, 0x00, 0x00, 0x00, // mov rax, 0x42
            0xC3, // ret
        ];
        let parsed = parsed_for(&code, 0x1000);
        let analyzer = CodeAnalyzer::new(&code, &parsed);
        let funcs = analyzer.discover_from_entry(0x1000);
        assert_eq!(funcs.len(), 1);
        let f = &funcs[&0x1000];
        assert_eq!(f.blocks.len(), 1);
        let block = f.blocks.values().next().unwrap();
        assert_eq!(block.start, 0x1000);
        assert_eq!(block.end, 0x1008);
        assert_eq!(block.kind, BlockKind::Return);
        assert!(f.callees.is_empty());
    }

    #[test]
    fn discovers_conditional_branch() {
        // xor eax, eax            (2 bytes: 31 c0)
        // je +1                   (2 bytes: 74 01)
        // nop                     (1 byte : 90)
        // ret                     (1 byte : c3)
        let code: Vec<u8> = vec![0x31, 0xC0, 0x74, 0x01, 0x90, 0xC3];
        let parsed = parsed_for(&code, 0x2000);
        let analyzer = CodeAnalyzer::new(&code, &parsed);
        let funcs = analyzer.discover_from_entry(0x2000);
        let f = &funcs[&0x2000];
        // We expect at least: the head block (ends at je), the taken
        // target block, and the fallthrough block.
        assert!(f.blocks.len() >= 2, "got {} blocks", f.blocks.len());
        let head = &f.blocks[&0x2000];
        assert_eq!(head.kind, BlockKind::CondBranch);
        assert_eq!(head.successors.len(), 2);
    }

    #[test]
    fn discovers_call_target_as_function() {
        // Function A at 0x3000:
        //   call B (5 bytes: e8 06 00 00 00)  -> targets 0x3000 + 5 + 6 = 0x300B
        //   ret    (1 byte: c3)
        // Five bytes of filler.
        // Function B at 0x300B:
        //   mov eax, 1   (5 bytes: b8 01 00 00 00)
        //   ret          (1 byte: c3)
        let code: Vec<u8> = vec![
            0xE8, 0x06, 0x00, 0x00, 0x00, // call +6 (target = 0x300B)
            0xC3, // ret
            0x90, 0x90, 0x90, 0x90, 0x90, // pad to 0x300B
            0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
            0xC3, // ret
        ];
        let parsed = parsed_for(&code, 0x3000);
        let analyzer = CodeAnalyzer::new(&code, &parsed);
        let funcs = analyzer.discover_from_entry(0x3000);
        assert!(funcs.contains_key(&0x3000));
        assert!(
            funcs.contains_key(&0x300B),
            "expected callee at 0x300B in {:#x?}",
            funcs.keys().collect::<Vec<_>>()
        );
        assert!(funcs[&0x3000].callees.contains(&0x300B));
    }

    #[test]
    fn prologue_sweep_finds_classic_x86_64() {
        // Two functions with the canonical x86-64 prologue.
        let mut code = Vec::new();
        // Function 1 at 0x0:
        code.extend_from_slice(&[0x55, 0x48, 0x89, 0xE5]); // push rbp; mov rbp, rsp
        code.extend_from_slice(&[0xC9, 0xC3]); // leave; ret
        // Padding
        code.extend_from_slice(&[0x90; 4]);
        // Function 2 at 0xA:
        code.extend_from_slice(&[0x55, 0x48, 0x89, 0xE5]); // push rbp; mov rbp, rsp
        code.extend_from_slice(&[0xC9, 0xC3]);

        let parsed = parsed_for(&code, 0x4000);
        let analyzer = CodeAnalyzer::new(&code, &parsed);
        let prologues = analyzer.find_prologues();
        assert!(prologues.contains(&0x4000));
        assert!(prologues.contains(&0x400A));
    }

    #[test]
    fn discover_all_combines_recursive_and_sweep() {
        // Entry function at 0x0 doesn't call the second one — only the
        // sweep can find it.
        let mut code = Vec::new();
        // Function 1 at 0x0: just `ret`.
        code.push(0xC3);
        // Padding
        code.extend_from_slice(&[0x90; 7]);
        // Function 2 at 0x8 with classic prologue:
        code.extend_from_slice(&[0x55, 0x48, 0x89, 0xE5, 0xC9, 0xC3]);

        let parsed = parsed_for(&code, 0x5000);
        let analyzer = CodeAnalyzer::new(&code, &parsed);
        let funcs = analyzer.discover_all();
        assert!(funcs.contains_key(&0x5000), "missing entry function");
        assert!(
            funcs.contains_key(&0x5008),
            "missing prologue-discovered function"
        );
    }

    #[test]
    fn indirect_call_resolves_against_iat() {
        // A single function that does:
        //   call qword ptr [rip+disp]   ; FF 15 disp32
        //   ret
        // The displacement is wired to land on an IAT VA we list in
        // parsed.imports. The resolved IAT VA should appear in the
        // function's imported_callees set.
        // Layout: .text at 0x401000 holds the code; we'll place a
        // fake IAT entry at 0x402000.
        const TEXT_VA: u64 = 0x4010_0000;
        const IAT_VA: u64 = 0x4020_0000;
        // call instruction is at TEXT_VA, length 6 (FF 15 + 4-byte disp).
        // next_ip = TEXT_VA + 6 = 0x40100006.
        // displacement = IAT_VA - next_ip = 0x100_0000 - 6 = 0xFF_FFFA
        // Hmm wait: IAT_VA - next_ip = 0x4020_0000 - 0x4010_0006 = 0x000F_FFFA
        let disp: u32 = (IAT_VA - (TEXT_VA + 6)) as u32;
        let disp_bytes = disp.to_le_bytes();
        let code: Vec<u8> = vec![
            0xFF,
            0x15,
            disp_bytes[0],
            disp_bytes[1],
            disp_bytes[2],
            disp_bytes[3],
            0xC3, // ret
        ];
        let parsed = ParsedInput {
            metadata: InputMetadata {
                format: "pe".into(),
                arch: Some("x86_64".into()),
                bits: Some(64),
                size: code.len() as u64,
                language: None,
            },
            sections: vec![Section {
                name: ".text".into(),
                file_offset: 0,
                file_size: code.len() as u64,
                virtual_address: TEXT_VA,
                executable: true,
                writable: false,
            }],
            entry: Some(TEXT_VA),
            warnings: Vec::new(),
            scan_window: None,
            imports: vec![strix_format::Import {
                library: "kernel32.dll".to_string(),
                name: "VirtualAlloc".to_string(),
                iat_va: IAT_VA,
            }],
            symbols: Default::default(),
        };
        let analyzer = CodeAnalyzer::new(&code, &parsed);
        let f = analyzer.analyze_function(TEXT_VA).expect("function");
        assert!(
            f.imported_callees.contains(&IAT_VA),
            "expected imported_callees to contain {IAT_VA:#x}, got {:#x?}",
            f.imported_callees
        );
    }

    #[test]
    fn analyze_function_bounds_runaway() {
        // A function that's just `nop` forever with no ret. analyze_function
        // should bail at the size limit rather than scanning the whole
        // section.
        let code = vec![0x90u8; 0x12_000];
        let parsed = parsed_for(&code, 0x6000);
        let analyzer = CodeAnalyzer::new(&code, &parsed);
        let f = analyzer.analyze_function(0x6000).expect("function");
        // Should have exactly one bounded block.
        let block = f.blocks.values().next().unwrap();
        assert!(block.end - block.start <= 0x10_001, "block ran past bound");
    }
}
