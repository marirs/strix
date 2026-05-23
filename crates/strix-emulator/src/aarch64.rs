//! AArch64 function discovery via the `bad64` disassembler.
//!
//! Mirrors the x86 [`crate::analyzer::CodeAnalyzer`] for AArch64
//! binaries. The goal is to feed the rest of the pipeline (stack-
//! string pattern matching, candidate scoring, eventual decoded-
//! string emulation) the same [`crate::analyzer::Function`] shape
//! it already understands.
//!
//! Discovery strategy follows the same two-phase approach as the
//! x86 path:
//!
//! 1. **Recursive descent** from the binary's entry point (when
//!    known), following `bl` instructions to their direct targets.
//! 2. **Prologue linear sweep** over executable sections looking
//!    for canonical AArch64 prologue patterns:
//!    `stp x29, x30, [sp, #-imm]!` (frame setup), or `sub sp, sp,
//!    #imm` followed by an `stp`. Catches functions not reached by
//!    the recursive pass.
//!
//! What this module deliberately does *not* do yet:
//!
//! * Indirect-branch resolution (`br xN`, `blr xN`). AArch64 PLT
//!   entries use these for late-binding imports; resolving them
//!   needs adrp+ldr+br pattern matching which is more involved.
//! * Switch-table reconstruction.
//! * Tail-call detection.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use bad64::{Imm, Op, Operand, Reg, decode};
use strix_format::{ParsedInput, Section};

use crate::analyzer::{BasicBlock, BlockKind, Function};

/// Analyzer over an AArch64 binary.
///
/// Holds borrowed references to the binary bytes and its parse, so
/// constructing one is free.
pub struct AArch64Analyzer<'a> {
    bytes: &'a [u8],
    parsed: &'a ParsedInput,
}

impl<'a> AArch64Analyzer<'a> {
    /// Construct a new analyzer.
    pub fn new(bytes: &'a [u8], parsed: &'a ParsedInput) -> Self {
        Self { bytes, parsed }
    }

    /// Find the executable section that contains the given virtual
    /// address, if any.
    pub fn section_for_va(&self, va: u64) -> Option<&'a Section> {
        self.parsed.sections.iter().find(|s| {
            s.executable && va >= s.virtual_address && va < s.virtual_address + s.file_size
        })
    }

    /// Bytes from `va` to the end of its containing executable
    /// section.
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

    /// Bytes at a VA without the executable-only filter — used for
    /// `.rodata` loads.
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

    /// Discover functions by recursive descent from `entry`,
    /// following `bl` direct calls. Returns the function set
    /// keyed by entry VA.
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
    /// linear sweep. AArch64 instructions are 4-byte aligned so we
    /// only need to check every 4-byte boundary.
    pub fn find_prologues(&self) -> Vec<u64> {
        let mut prologues = Vec::new();
        for sec in &self.parsed.sections {
            if !sec.executable || sec.file_size < 4 {
                continue;
            }
            let start = sec.file_offset as usize;
            let end = (sec.file_offset + sec.file_size) as usize;
            if start >= self.bytes.len() || end > self.bytes.len() {
                continue;
            }
            let code = &self.bytes[start..end];
            let base_va = sec.virtual_address;
            let mut off = 0;
            while off + 4 <= code.len() {
                let chunk = &code[off..off + 4];
                if matches_aarch64_prologue(chunk) {
                    prologues.push(base_va + off as u64);
                }
                off += 4;
            }
        }
        prologues
    }

    /// Combine recursive descent (from entry) with prologue sweep
    /// to produce the broadest discoverable function set.
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

    /// Analyze a single function starting at `entry`, computing
    /// its basic-block decomposition. Returns None if `entry` is
    /// not in an executable region.
    pub fn analyze_function(&self, entry: u64) -> Option<Function> {
        let sec = self.section_for_va(entry)?;
        let sec_end_va = sec.virtual_address + sec.file_size;

        let mut block_worklist: VecDeque<u64> = VecDeque::new();
        block_worklist.push_back(entry);
        let mut blocks: BTreeMap<u64, BasicBlock> = BTreeMap::new();
        let mut callees: BTreeSet<u64> = BTreeSet::new();
        let imported_callees: BTreeSet<u64> = BTreeSet::new();

        while let Some(block_start) = block_worklist.pop_front() {
            if blocks.contains_key(&block_start) {
                continue;
            }
            if block_start < sec.virtual_address || block_start >= sec_end_va {
                continue;
            }
            let bytes = self.bytes_at_va(block_start)?;
            let mut successors: Vec<u64> = Vec::new();
            let mut kind = BlockKind::Fallthrough;
            let mut block_end = block_start;

            let mut off = 0usize;
            while off + 4 <= bytes.len() {
                let chunk = &bytes[off..off + 4];
                let ip = block_start + off as u64;
                let Ok(insn) = decode(
                    u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]),
                    ip,
                ) else {
                    // Bail on unrecognized encoding.
                    kind = BlockKind::Indirect;
                    block_end = ip + 4;
                    break;
                };
                block_end = ip + 4;
                match insn.op() {
                    Op::RET => {
                        kind = BlockKind::Return;
                        break;
                    }
                    Op::B => {
                        kind = BlockKind::Branch;
                        if let Some(t) = direct_branch_target(&insn) {
                            successors.push(t);
                            block_worklist.push_back(t);
                        }
                        break;
                    }
                    Op::BL => {
                        kind = BlockKind::Call;
                        if let Some(t) = direct_branch_target(&insn) {
                            callees.insert(t);
                        }
                        successors.push(block_end);
                        block_worklist.push_back(block_end);
                        break;
                    }
                    Op::BR | Op::BLR => {
                        kind = BlockKind::Call;
                        successors.push(block_end);
                        block_worklist.push_back(block_end);
                        break;
                    }
                    Op::CBZ | Op::CBNZ | Op::TBZ | Op::TBNZ => {
                        // Conditional compare-and-branch instructions:
                        // direct branch + fallthrough.
                        kind = BlockKind::CondBranch;
                        if let Some(t) = direct_branch_target(&insn) {
                            successors.push(t);
                            block_worklist.push_back(t);
                        }
                        successors.push(block_end);
                        block_worklist.push_back(block_end);
                        break;
                    }
                    Op::B_AL
                    | Op::B_CC
                    | Op::B_CS
                    | Op::B_EQ
                    | Op::B_GE
                    | Op::B_GT
                    | Op::B_HI
                    | Op::B_LE
                    | Op::B_LS
                    | Op::B_LT
                    | Op::B_MI
                    | Op::B_NE
                    | Op::B_NV
                    | Op::B_PL
                    | Op::B_VC
                    | Op::B_VS => {
                        kind = BlockKind::CondBranch;
                        if let Some(t) = direct_branch_target(&insn) {
                            successors.push(t);
                            block_worklist.push_back(t);
                        }
                        successors.push(block_end);
                        block_worklist.push_back(block_end);
                        break;
                    }
                    Op::ERET | Op::HVC | Op::SMC | Op::SVC | Op::BRK | Op::HLT | Op::UDF => {
                        kind = BlockKind::Indirect;
                        break;
                    }
                    _ => {
                        // Straight-line instruction; continue.
                    }
                }
                off += 4;
                // Bound block size as a runaway safety net.
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

        Some(Function {
            entry,
            blocks,
            callees,
            imported_callees,
        })
    }
}

/// Extract the direct target VA of an AArch64 control-flow
/// instruction whose first operand is an immediate label, if any.
fn direct_branch_target(insn: &bad64::Instruction) -> Option<u64> {
    let op = insn.operands().first()?;
    match op {
        Operand::Label(Imm::Unsigned(v)) => Some(*v),
        Operand::Label(Imm::Signed(v)) => Some(*v as u64),
        _ => None,
    }
}

/// Recognize canonical AArch64 function prologues in the first
/// 4-byte instruction at `code`.
///
/// We accept two common shapes:
///
/// 1. `stp x29, x30, [sp, #-imm]!` — pre-indexed frame setup. Bit
///    pattern: `1010_1001_0xxx_xxxx_xxxx_xxxx_xxxx_xxxx` with the
///    pair Rt=x29, Rt2=x30, base=sp, pre-index. The high 11 bits
///    of `stp` (pre-indexed, 64-bit, signed offset) are
///    `1010_1001_10`.
/// 2. `sub sp, sp, #imm` — frameless prologue. Bit pattern
///    `1101_0001_00xx_xxxx_xxxx_xxxx_1111_1111` (sub immediate,
///    64-bit, Rd=sp, Rn=sp).
fn matches_aarch64_prologue(code: &[u8]) -> bool {
    if code.len() < 4 {
        return false;
    }
    let w = u32::from_le_bytes([code[0], code[1], code[2], code[3]]);
    // stp x29, x30, [sp, #imm]! — class 1010_1001_10, Rt2=11110
    // (x30), Rt=11101 (x29), Rn=11111 (sp). The compact check:
    //   top 11 bits = 0xA98 (stp pre-indexed 64-bit)
    //   Rt2 (bits 10..14) = 0b11110 = 30
    //   Rn  (bits 5..9)   = 0b11111 = 31 (sp)
    //   Rt  (bits 0..4)   = 0b11101 = 29
    if (w >> 22) == 0x2A6 && ((w >> 10) & 0x1F) == 30 && ((w >> 5) & 0x1F) == 31 && (w & 0x1F) == 29
    {
        return true;
    }
    // sub sp, sp, #imm (64-bit): top 8 = 0xD1, Rd=11111, Rn=11111.
    //   (w >> 24) == 0xD1
    //   Rn (bits 5..9) == 31
    //   Rd (bits 0..4) == 31
    if (w >> 24) == 0xD1 && ((w >> 5) & 0x1F) == 31 && (w & 0x1F) == 31 {
        return true;
    }
    false
}

/// Map a bad64 register to its 64-bit canonical form (X0..X30 /
/// SP). Sub-width views (W0..W30, WSP) fold to the same X register.
pub(crate) fn full_reg(r: Reg) -> Reg {
    use Reg::*;
    match r {
        W0 | X0 => X0,
        W1 | X1 => X1,
        W2 | X2 => X2,
        W3 | X3 => X3,
        W4 | X4 => X4,
        W5 | X5 => X5,
        W6 | X6 => X6,
        W7 | X7 => X7,
        W8 | X8 => X8,
        W9 | X9 => X9,
        W10 | X10 => X10,
        W11 | X11 => X11,
        W12 | X12 => X12,
        W13 | X13 => X13,
        W14 | X14 => X14,
        W15 | X15 => X15,
        W16 | X16 => X16,
        W17 | X17 => X17,
        W18 | X18 => X18,
        W19 | X19 => X19,
        W20 | X20 => X20,
        W21 | X21 => X21,
        W22 | X22 => X22,
        W23 | X23 => X23,
        W24 | X24 => X24,
        W25 | X25 => X25,
        W26 | X26 => X26,
        W27 | X27 => X27,
        W28 | X28 => X28,
        W29 | X29 => X29,
        W30 | X30 => X30,
        WSP | SP => SP,
        other => other,
    }
}
