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
        let mut imported_callees: BTreeSet<u64> = BTreeSet::new();

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
                            // If the target is a PLT thunk, classify
                            // the call as an imported callee rather
                            // than a direct one — same treatment as
                            // the x86 path. We track the GOT VA so
                            // the heuristic + driver can match against
                            // `parsed.imports[*].iat_va`.
                            if let Some(got_va) = self.is_plt_thunk(t) {
                                imported_callees.insert(got_va);
                            } else {
                                callees.insert(t);
                            }
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

    /// If `va` looks like an AArch64 PLT-style import thunk, return
    /// the GOT entry VA the thunk dispatches through. The GOT VA is
    /// matched against `parsed.imports[*].iat_va` by the caller.
    ///
    /// Canonical AArch64 PLT thunk (12 bytes, 3 instructions):
    ///
    /// ```text
    ///   adrp x16, page_of_got      ; PC-relative page of the GOT entry
    ///   ldr  x16, [x16, #lo12_off] ; load the runtime-resolved address
    ///   br   x16                    ; tail-call into the import
    /// ```
    ///
    /// We accept any destination register so long as the same
    /// register is used across all three instructions. macOS dyld
    /// lazy stubs in `__stubs` follow the same shape, just pointing
    /// into `__la_symbol_ptr` instead of `.got.plt`.
    ///
    /// Returns `None` if the bytes don't match the shape or the
    /// resolved GOT VA isn't in our imports table.
    pub fn is_plt_thunk(&self, va: u64) -> Option<u64> {
        let bytes = self.bytes_at_va(va)?;
        if bytes.len() < 12 {
            return None;
        }
        let w0 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let w1 = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let w2 = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let i0 = bad64::decode(w0, va).ok()?;
        let i1 = bad64::decode(w1, va + 4).ok()?;
        let i2 = bad64::decode(w2, va + 8).ok()?;

        // adrp xN, page  →  xN := PC-page + (imm21 << 12)
        if i0.op() != Op::ADRP {
            return None;
        }
        let ops0 = i0.operands();
        let (adrp_dst, page) = match (ops0.first()?, ops0.get(1)?) {
            (Operand::Reg { reg, .. }, Operand::Label(imm)) => {
                let dst = full_reg(*reg);
                let p = match imm {
                    Imm::Unsigned(v) => *v,
                    Imm::Signed(v) => *v as u64,
                };
                (dst, p)
            }
            _ => return None,
        };

        // ldr xN, [xN, #imm]  (same xN)
        if i1.op() != Op::LDR {
            return None;
        }
        let ops1 = i1.operands();
        let ldr_dst = match ops1.first()? {
            Operand::Reg { reg, .. } => full_reg(*reg),
            _ => return None,
        };
        if ldr_dst != adrp_dst {
            return None;
        }
        let ldr_off: i64 = match ops1.get(1)? {
            Operand::MemReg(reg) => {
                if full_reg(*reg) != adrp_dst {
                    return None;
                }
                0
            }
            Operand::MemOffset { reg, offset, .. } => {
                if full_reg(*reg) != adrp_dst {
                    return None;
                }
                match offset {
                    Imm::Unsigned(v) => *v as i64,
                    Imm::Signed(v) => *v,
                }
            }
            _ => return None,
        };

        // br xN  (same xN)
        if i2.op() != Op::BR {
            return None;
        }
        let ops2 = i2.operands();
        let br_dst = match ops2.first()? {
            Operand::Reg { reg, .. } => full_reg(*reg),
            _ => return None,
        };
        if br_dst != adrp_dst {
            return None;
        }

        let got_va = (page as i64).wrapping_add(ldr_off) as u64;
        if self.parsed.imports.iter().any(|imp| imp.iat_va == got_va) {
            Some(got_va)
        } else {
            None
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use strix_core::InputMetadata;
    use strix_format::{Import, ParsedInput, Section};

    /// Caller at 0x1000 bl's into a PLT thunk at 0x1008. The thunk
    /// is `adrp x16, 0x2000; ldr x16, [x16, #0]; br x16` — a textbook
    /// AArch64 PLT shape. With the matching GOT VA (0x2000) registered
    /// in `parsed.imports`, the analyzer should classify the BL target
    /// as an imported callee rather than a direct one.
    #[test]
    fn analyze_function_recognizes_aarch64_plt_thunk() {
        // 0x1000  bl 0x1008                  → 0x94000002  → 02 00 00 94
        // 0x1004  ret                        → 0xD65F03C0  → C0 03 5F D6
        // 0x1008  adrp x16, page=0x2000      → 0xB0000010  → 10 00 00 B0
        // 0x100C  ldr x16, [x16, #0]         → 0xF9400210  → 10 02 40 F9
        // 0x1010  br x16                     → 0xD61F0200  → 00 02 1F D6
        let bytes: Vec<u8> = vec![
            0x02, 0x00, 0x00, 0x94, // bl 0x1008
            0xC0, 0x03, 0x5F, 0xD6, // ret
            0x10, 0x00, 0x00, 0xB0, // adrp x16, 0x2000
            0x10, 0x02, 0x40, 0xF9, // ldr  x16, [x16, #0]
            0x00, 0x02, 0x1F, 0xD6, // br   x16
        ];
        const TEXT_VA: u64 = 0x1000;
        const GOT_VA: u64 = 0x2000;

        let parsed = ParsedInput {
            metadata: InputMetadata {
                format: "sc64".into(),
                arch: Some("aarch64".into()),
                bits: Some(64),
                size: bytes.len() as u64,
                language: None,
            },
            sections: vec![Section {
                name: ".text".into(),
                file_offset: 0,
                file_size: bytes.len() as u64,
                virtual_address: TEXT_VA,
                executable: true,
                writable: false,
            }],
            entry: Some(TEXT_VA),
            warnings: Vec::new(),
            scan_window: None,
            imports: vec![Import {
                library: "libtest.so".into(),
                name: "imported_fn".into(),
                iat_va: GOT_VA,
            }],
            symbols: Default::default(),
        };

        let analyzer = AArch64Analyzer::new(&bytes, &parsed);
        let f = analyzer
            .analyze_function(TEXT_VA)
            .expect("analyze_function");
        assert!(
            f.imported_callees.contains(&GOT_VA),
            "expected imported_callees to contain {GOT_VA:#x}; got {:#x?}",
            f.imported_callees
        );
        // PLT-thunk target should NOT also appear in `callees` — it's
        // an import, not a direct callee.
        assert!(
            !f.callees.contains(&0x1008),
            "PLT thunk address should not be in direct callees; got {:#x?}",
            f.callees
        );
    }

    /// Sanity check: when imports is empty, the same call shape is
    /// classified as a direct callee (no false positives on functions
    /// that happen to start with adrp+ldr+br).
    #[test]
    fn analyze_function_without_matching_import_keeps_direct_callee() {
        let bytes: Vec<u8> = vec![
            0x02, 0x00, 0x00, 0x94, // bl 0x1008
            0xC0, 0x03, 0x5F, 0xD6, // ret
            0x10, 0x00, 0x00, 0xB0, // adrp x16, 0x2000
            0x10, 0x02, 0x40, 0xF9, // ldr  x16, [x16, #0]
            0x00, 0x02, 0x1F, 0xD6, // br   x16
        ];
        const TEXT_VA: u64 = 0x1000;

        let parsed = ParsedInput {
            metadata: InputMetadata {
                format: "sc64".into(),
                arch: Some("aarch64".into()),
                bits: Some(64),
                size: bytes.len() as u64,
                language: None,
            },
            sections: vec![Section {
                name: ".text".into(),
                file_offset: 0,
                file_size: bytes.len() as u64,
                virtual_address: TEXT_VA,
                executable: true,
                writable: false,
            }],
            entry: Some(TEXT_VA),
            warnings: Vec::new(),
            scan_window: None,
            imports: Vec::new(), // no imports → no PLT match
            symbols: Default::default(),
        };

        let analyzer = AArch64Analyzer::new(&bytes, &parsed);
        let f = analyzer
            .analyze_function(TEXT_VA)
            .expect("analyze_function");
        assert!(
            f.callees.contains(&0x1008),
            "with no imports, target should be a direct callee; got {:#x?}",
            f.callees
        );
        assert!(
            f.imported_callees.is_empty(),
            "no imports should produce no imported callees; got {:#x?}",
            f.imported_callees
        );
    }
}
