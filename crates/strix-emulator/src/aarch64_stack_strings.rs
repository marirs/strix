//! AArch64 stack-string pattern matcher.
//!
//! Mirrors [`crate::stack_strings`] for AArch64. Detects the
//! common ways AArch64 compilers stage short byte sequences onto
//! the stack:
//!
//! 1. **mov-imm + store.** `mov xN, #imm` (or `movk` follow-ups
//!    for >16-bit immediates) writes a constant into a register;
//!    a subsequent `str xN, [sp, #disp]` lays the bytes onto the
//!    stack.
//! 2. **stp pair.** `stp xN, xM, [sp, #disp]` writes two 8-byte
//!    chunks at once; common for 16-byte chunk stores.
//! 3. **`adrp` + `add` + store.** AArch64's RIP-relative pointer
//!    materialization: `adrp xN, page` then `add xN, xN, :lo12:`
//!    yields a `.rodata` pointer that the function then `ldr`s
//!    from and stores to the stack. We don't follow the load
//!    through here; that's the emulator's job.
//!
//! As with the x86 matcher we accumulate bytes per stack offset
//! per basic block, then flush printable runs.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use bad64::{Imm, Op, Operand, Reg, Shift, decode};
use strix_format::ParsedInput;

use crate::aarch64::{AArch64Analyzer, full_reg};
use crate::analyzer::Function;
use crate::stack_strings::RecoveredStackString;

/// Scan all functions in `parsed` for AArch64 stack-string
/// patterns.
pub fn extract(input: &[u8], parsed: &ParsedInput, min_len: usize) -> Vec<RecoveredStackString> {
    let analyzer = AArch64Analyzer::new(input, parsed);
    let funcs = analyzer.discover_all();
    let mut out = Vec::new();
    for (&entry, func) in &funcs {
        let loop_blocks = detect_loop_bodies(func);
        collect_in_function(&analyzer, func, entry, &loop_blocks, min_len, &mut out);
    }
    out
}

/// Same natural-loop detection used by the x86 path: a block is
/// in a loop body when some other block has a successor edge
/// targeting at or before this block's start.
fn detect_loop_bodies(func: &Function) -> BTreeSet<u64> {
    let mut loop_blocks: BTreeSet<u64> = BTreeSet::new();
    let block_starts: Vec<u64> = func.blocks.keys().copied().collect();
    for (&source_start, block) in &func.blocks {
        for &succ in &block.successors {
            if succ > source_start {
                continue;
            }
            if !func.blocks.contains_key(&succ) {
                continue;
            }
            for &b in &block_starts {
                if b >= succ && b <= source_start {
                    loop_blocks.insert(b);
                }
            }
        }
    }
    loop_blocks
}

fn collect_in_function(
    analyzer: &AArch64Analyzer<'_>,
    func: &Function,
    func_entry: u64,
    loop_blocks: &BTreeSet<u64>,
    min_len: usize,
    out: &mut Vec<RecoveredStackString>,
) {
    for block in func.blocks.values() {
        let Some(bytes_at) = analyzer.bytes_at_va(block.start) else {
            continue;
        };
        let block_size = (block.end.saturating_sub(block.start)) as usize;
        let block_size = block_size.min(bytes_at.len());
        let code = &bytes_at[..block_size];

        // Per-block state.
        let mut stack: BTreeMap<i64, u8> = BTreeMap::new();
        // Map of (canonical-reg) -> 8-byte little-endian value.
        // `bad64::Reg` is `Hash + Eq` but not `Ord`, so HashMap not BTreeMap.
        let mut reg_imms: HashMap<Reg, [u8; 8]> = HashMap::new();

        let mut off = 0usize;
        while off + 4 <= code.len() {
            let chunk = &code[off..off + 4];
            let ip = block.start + off as u64;
            let raw = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            let Ok(insn) = decode(raw, ip) else {
                off += 4;
                continue;
            };

            match insn.op() {
                Op::MOV | Op::MOVZ => {
                    if let Some((reg, imm)) = mov_imm(&insn) {
                        let mut buf = [0u8; 8];
                        buf[..8].copy_from_slice(&imm.to_le_bytes());
                        reg_imms.insert(reg, buf);
                    }
                }
                Op::MOVK => {
                    // movk Rd, #imm, lsl #shift — updates bits
                    // [shift, shift+16) of Rd while preserving the
                    // rest. We need a prior reg_imms[Rd] to mix into.
                    if let Some((reg, imm, shift)) = movk_imm(&insn) {
                        let entry = reg_imms.entry(reg).or_insert([0u8; 8]);
                        let mut value = u64::from_le_bytes(*entry);
                        let mask = !(0xFFFFu64 << shift);
                        value = (value & mask) | ((imm & 0xFFFF) << shift);
                        *entry = value.to_le_bytes();
                    }
                }
                Op::STR | Op::STUR => {
                    // str/stur Xt, [sp, #imm] — one 8-byte store
                    if let Some((src, disp)) = sp_store(&insn)
                        && let Some(bytes) = reg_imms.get(&src)
                    {
                        for (i, &b) in bytes.iter().enumerate() {
                            stack.insert(disp + i as i64, b);
                        }
                    }
                }
                Op::STP => {
                    // stp Xt, Xt2, [sp, #imm] — two 8-byte stores
                    if let Some((src1, src2, disp)) = sp_store_pair(&insn) {
                        if let Some(bytes) = reg_imms.get(&src1) {
                            for (i, &b) in bytes.iter().enumerate() {
                                stack.insert(disp + i as i64, b);
                            }
                        }
                        if let Some(bytes) = reg_imms.get(&src2) {
                            for (i, &b) in bytes.iter().enumerate() {
                                stack.insert(disp + 8 + i as i64, b);
                            }
                        }
                    }
                }
                Op::STRB | Op::STURB => {
                    // strb Wt, [sp, #imm] — one-byte store
                    if let Some((src, disp)) = sp_store(&insn)
                        && let Some(bytes) = reg_imms.get(&src)
                    {
                        stack.insert(disp, bytes[0]);
                    }
                }
                Op::STRH | Op::STURH => {
                    // strh Wt, [sp, #imm] — two-byte store
                    if let Some((src, disp)) = sp_store(&insn)
                        && let Some(bytes) = reg_imms.get(&src)
                    {
                        stack.insert(disp, bytes[0]);
                        stack.insert(disp + 1, bytes[1]);
                    }
                }
                _ => {
                    // Conservative clobber: any instruction with
                    // a register destination we didn't recognize
                    // invalidates our tracked value for that reg.
                    if let Some(dst) = first_reg_operand(&insn) {
                        reg_imms.remove(&full_reg(dst));
                    }
                }
            }
            off += 4;
        }

        let is_tight = loop_blocks.contains(&block.start);
        flush_runs(&stack, func_entry, is_tight, min_len, out);
    }
}

fn mov_imm(insn: &bad64::Instruction) -> Option<(Reg, u64)> {
    let ops = insn.operands();
    if ops.len() < 2 {
        return None;
    }
    let dst = match ops[0] {
        Operand::Reg { reg, .. } => full_reg(reg),
        _ => return None,
    };
    let imm = match ops[1] {
        Operand::Imm32 { imm, .. } | Operand::Imm64 { imm, .. } => match imm {
            Imm::Unsigned(v) => v,
            Imm::Signed(v) => v as u64,
        },
        _ => return None,
    };
    Some((dst, imm))
}

fn movk_imm(insn: &bad64::Instruction) -> Option<(Reg, u64, u32)> {
    let ops = insn.operands();
    if ops.len() < 2 {
        return None;
    }
    let dst = match ops[0] {
        Operand::Reg { reg, .. } => full_reg(reg),
        _ => return None,
    };
    // movk's second operand is the imm; third (when present) is
    // the shift specifier as a ShiftReg or an Imm. bad64 surfaces
    // it as ShiftReg or as the third operand depending on encoding.
    let imm = match ops[1] {
        Operand::Imm32 { imm, .. } | Operand::Imm64 { imm, .. } => match imm {
            Imm::Unsigned(v) => v,
            Imm::Signed(v) => v as u64,
        },
        _ => return None,
    };
    let shift = if ops.len() >= 3 {
        match ops[2] {
            Operand::ShiftReg { shift, .. } => shift_amount(shift),
            _ => 0,
        }
    } else {
        0
    };
    Some((dst, imm, shift))
}

/// Extract the shift count out of a `bad64::Shift`. `movk` only
/// ever uses LSL shifts (by 0/16/32/48), so we only handle that
/// variant explicitly and default the rest to 0.
fn shift_amount(s: Shift) -> u32 {
    if let Shift::LSL(n) = s { n } else { 0 }
}

fn sp_store(insn: &bad64::Instruction) -> Option<(Reg, i64)> {
    let ops = insn.operands();
    if ops.len() < 2 {
        return None;
    }
    let src = match ops[0] {
        Operand::Reg { reg, .. } => full_reg(reg),
        _ => return None,
    };
    let disp = mem_sp_disp(&ops[1])?;
    Some((src, disp))
}

fn sp_store_pair(insn: &bad64::Instruction) -> Option<(Reg, Reg, i64)> {
    let ops = insn.operands();
    if ops.len() < 3 {
        return None;
    }
    let src1 = match ops[0] {
        Operand::Reg { reg, .. } => full_reg(reg),
        _ => return None,
    };
    let src2 = match ops[1] {
        Operand::Reg { reg, .. } => full_reg(reg),
        _ => return None,
    };
    let disp = mem_sp_disp(&ops[2])?;
    Some((src1, src2, disp))
}

/// If the operand is `[sp, #imm]` (or `[sp]`), return the
/// displacement in bytes. Bail on register-offset and indexed-
/// addressing forms.
fn mem_sp_disp(op: &Operand) -> Option<i64> {
    match op {
        Operand::MemReg(reg) => {
            if full_reg(*reg) == Reg::SP {
                Some(0)
            } else {
                None
            }
        }
        Operand::MemOffset { reg, offset, .. } => {
            if full_reg(*reg) != Reg::SP {
                return None;
            }
            match offset {
                Imm::Unsigned(v) => Some(*v as i64),
                Imm::Signed(v) => Some(*v),
            }
        }
        Operand::MemPreIdx { reg, imm } | Operand::MemPostIdxImm { reg, imm } => {
            if full_reg(*reg) != Reg::SP {
                return None;
            }
            match imm {
                Imm::Unsigned(v) => Some(*v as i64),
                Imm::Signed(v) => Some(*v),
            }
        }
        _ => None,
    }
}

fn first_reg_operand(insn: &bad64::Instruction) -> Option<Reg> {
    insn.operands().first().and_then(|op| match op {
        Operand::Reg { reg, .. } => Some(*reg),
        _ => None,
    })
}

/// Scan the per-offset stack map for contiguous printable runs.
/// Identical semantics to the x86 path; copied here to keep both
/// extractors self-contained.
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
        let printable = (0x20..=0x7E).contains(&byte) || byte == b'\t';
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
