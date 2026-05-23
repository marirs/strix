//! Symbolic forward dataflow at AArch64 call sites.
//!
//! Mirrors [`crate::callsite`] for the AArch64 ABI. Brute-force
//! argument fuzzing covers many decoders, but two common cases need
//! the real caller arguments:
//!
//! * The decoder reads its source from a fixed pointer materialized
//!   by the caller via `adrp xN, page; add xN, xN, #lo12` — the
//!   AArch64 equivalent of `lea rcx, [rip+disp]`.
//! * The decoder's length argument is a concrete immediate the
//!   caller built up with `movz` / `movk`.
//!
//! We walk the basic block containing the BL forward from its start,
//! tracking an abstract register state through the most common
//! AArch64 idioms. By the time we reach the call we typically have
//! concrete values (or known pointers) for X0..X7, which the
//! orchestrator translates into a concrete `ArgSet` for the driver.
//!
//! What we deliberately don't do in the MVP:
//!
//! * Stack spill / reload tracking (no `str x, [sp, #off]`-to-`ldr`
//!   chain). The compiler usually keeps args in registers across the
//!   BL site so this is uncommon.
//! * PC-relative literal loads (`ldr xN, =const`). bad64 surfaces
//!   these with a resolved literal VA; we currently treat them as
//!   clobbers.
//! * Cross-block dataflow. Useful for prologue-hoisted args; we leave
//!   it for a follow-up.

use std::collections::{BTreeMap, HashMap};

use bad64::{Imm, Op, Operand, Reg, Shift, decode};

use crate::aarch64::{AArch64Analyzer, full_reg};
use crate::analyzer::Function;
use crate::callsite::{AbsValPub, CallSite};

/// Per-call-site register state for AArch64 (X0..X7 are the
/// AAPCS64 argument-passing registers).
#[derive(Debug, Default, Clone, Copy)]
pub struct ResolvedRegsAarch64 {
    /// Resolved X0 (arg 0).
    pub x0: AbsValPub,
    /// Resolved X1 (arg 1).
    pub x1: AbsValPub,
    /// Resolved X2 (arg 2).
    pub x2: AbsValPub,
    /// Resolved X3 (arg 3).
    pub x3: AbsValPub,
    /// Resolved X4 (arg 4).
    pub x4: AbsValPub,
    /// Resolved X5 (arg 5).
    pub x5: AbsValPub,
    /// Resolved X6 (arg 6).
    pub x6: AbsValPub,
    /// Resolved X7 (arg 7).
    pub x7: AbsValPub,
}

/// Find every direct BL call site targeting `target` across the
/// discovered function set. Caps per-callee output at
/// `max_per_target` to keep wall-clock bounded on highly called
/// helpers.
pub fn find_call_sites_aarch64(
    analyzer: &AArch64Analyzer<'_>,
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
            let mut off = 0usize;
            while off + 4 <= len {
                let chunk = &bytes[off..off + 4];
                let ip = block.start + off as u64;
                let raw = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                if let Ok(insn) = decode(raw, ip)
                    && insn.op() == Op::BL
                    && let Some(t) = direct_branch_target(&insn)
                    && t == target
                {
                    out.push(CallSite {
                        caller_va,
                        block_start: block.start,
                        call_ip: ip,
                        next_ip: ip + 4,
                    });
                    if out.len() >= max_per_target {
                        return out;
                    }
                }
                off += 4;
            }
        }
    }
    out
}

/// Resolve X0..X7 at `site.call_ip` by sweeping the containing block
/// forward from its start and applying the tracked instruction
/// effects.
pub fn resolve_call_site_regs_aarch64(
    analyzer: &AArch64Analyzer<'_>,
    site: CallSite,
) -> ResolvedRegsAarch64 {
    let mut state = RegState::default();
    sweep_block(analyzer, site.block_start, site.call_ip, &mut state);
    state_to_resolved(&state)
}

/// Cross-block variant: also incorporates effects from blocks that
/// fall through to the call's block. For multiple predecessors,
/// only register values that agree across all paths survive; the
/// rest collapse to Unknown — the conservative safe choice at a
/// join point.
pub fn resolve_call_site_regs_aarch64_cross_block(
    analyzer: &AArch64Analyzer<'_>,
    func: &Function,
    site: CallSite,
) -> ResolvedRegsAarch64 {
    let preds: Vec<u64> = func
        .blocks
        .values()
        .filter(|b| b.successors.contains(&site.block_start) && b.start != site.block_start)
        .map(|b| b.start)
        .collect();

    if preds.is_empty() {
        return resolve_call_site_regs_aarch64(analyzer, site);
    }

    // Run the call block on top of each predecessor's effects.
    let mut per_pred: Vec<RegState> = Vec::new();
    for pred_start in &preds {
        let Some(pred_block) = func.blocks.get(pred_start) else {
            continue;
        };
        let mut state = RegState::default();
        sweep_block(analyzer, *pred_start, pred_block.end, &mut state);
        sweep_block(analyzer, site.block_start, site.call_ip, &mut state);
        per_pred.push(state);
    }
    if per_pred.is_empty() {
        return resolve_call_site_regs_aarch64(analyzer, site);
    }

    // Intersect: a register value survives only if every predecessor
    // path yielded the *same* concrete value for it. Anything that
    // diverges (or that some predecessor didn't set at all) collapses
    // to Unknown.
    let mut merged = per_pred.remove(0);
    for other in &per_pred {
        let regs: Vec<Reg> = merged.map.keys().copied().collect();
        for reg in regs {
            let our = merged.map.get(&reg).copied().unwrap_or(AbsVal::Unknown);
            let theirs = other.map.get(&reg).copied().unwrap_or(AbsVal::Unknown);
            if our != theirs {
                merged.map.insert(reg, AbsVal::Unknown);
            }
        }
    }
    state_to_resolved(&merged)
}

// ---------- internals ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AbsVal {
    Unknown,
    Concrete(u64),
    Pointer(u64),
}

impl AbsVal {
    fn to_pub(self) -> AbsValPub {
        match self {
            AbsVal::Unknown => AbsValPub::Unknown,
            AbsVal::Concrete(v) => AbsValPub::Concrete(v),
            AbsVal::Pointer(v) => AbsValPub::Pointer(v),
        }
    }
}

#[derive(Debug, Default, Clone)]
struct RegState {
    /// Keyed by canonical (full-width) Reg. `bad64::Reg` is Hash+Eq
    /// but not Ord, so this is a HashMap rather than a BTreeMap.
    map: HashMap<Reg, AbsVal>,
}

impl RegState {
    fn get(&self, r: Reg) -> AbsVal {
        self.map
            .get(&full_reg(r))
            .copied()
            .unwrap_or(AbsVal::Unknown)
    }
    fn set(&mut self, r: Reg, v: AbsVal) {
        self.map.insert(full_reg(r), v);
    }
    fn clobber(&mut self, r: Reg) {
        self.map.insert(full_reg(r), AbsVal::Unknown);
    }
}

/// Decode and apply the per-instruction effect for every instruction
/// in `[start, end)`. Bounded by the block's byte range.
fn sweep_block(analyzer: &AArch64Analyzer<'_>, start: u64, end: u64, state: &mut RegState) {
    let Some(bytes) = analyzer.bytes_at_va(start) else {
        return;
    };
    let len = end.saturating_sub(start) as usize;
    let len = len.min(bytes.len());
    let mut off = 0usize;
    while off + 4 <= len {
        let chunk = &bytes[off..off + 4];
        let ip = start + off as u64;
        let raw = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        if let Ok(insn) = decode(raw, ip) {
            apply_effect(&insn, state);
        }
        off += 4;
    }
}

fn apply_effect(insn: &bad64::Instruction, state: &mut RegState) {
    let ops = insn.operands();
    match insn.op() {
        Op::MOV => {
            // `mov xN, xM` or `mov xN, #imm` (alias forms exist).
            let Some(Operand::Reg { reg: dst, .. }) = ops.first() else {
                return;
            };
            match ops.get(1) {
                Some(Operand::Reg { reg: src, .. }) => {
                    let v = state.get(*src);
                    state.set(*dst, v);
                }
                Some(Operand::Imm32 { imm, .. } | Operand::Imm64 { imm, .. }) => {
                    state.set(*dst, AbsVal::Concrete(imm_to_u64(*imm)));
                }
                _ => state.clobber(*dst),
            }
        }
        Op::MOVZ => {
            // MOVZ xN, #imm{, lsl #N} — zero-extend, write shifted imm.
            let Some(Operand::Reg { reg: dst, .. }) = ops.first() else {
                return;
            };
            let (imm, shift_n) = match ops.get(1) {
                Some(Operand::Imm32 { imm, shift } | Operand::Imm64 { imm, shift }) => {
                    let s = shift.as_ref().map(shift_lsl).unwrap_or(0);
                    (imm_to_u64(*imm), s)
                }
                _ => return,
            };
            state.set(*dst, AbsVal::Concrete((imm & 0xFFFF) << shift_n));
        }
        Op::MOVK => {
            // MOVK xN, #imm, lsl #N — preserve other bits, overwrite
            // 16-bit lane at LSL N. Requires a current value for xN.
            let Some(Operand::Reg { reg: dst, .. }) = ops.first() else {
                return;
            };
            let (imm, shift_n) = match ops.get(1) {
                Some(Operand::Imm32 { imm, shift } | Operand::Imm64 { imm, shift }) => {
                    let s = shift.as_ref().map(shift_lsl).unwrap_or(0);
                    (imm_to_u64(*imm), s)
                }
                _ => return,
            };
            let cur = match state.get(*dst) {
                AbsVal::Concrete(v) => v,
                AbsVal::Pointer(_) | AbsVal::Unknown => 0,
            };
            let mask = !(0xFFFFu64 << shift_n);
            let new_v = (cur & mask) | ((imm & 0xFFFF) << shift_n);
            state.set(*dst, AbsVal::Concrete(new_v));
        }
        Op::MOVN => {
            // movn xN, #imm{, lsl N} — bitwise NOT of the shifted imm.
            let Some(Operand::Reg { reg: dst, .. }) = ops.first() else {
                return;
            };
            let (imm, shift_n) = match ops.get(1) {
                Some(Operand::Imm32 { imm, shift } | Operand::Imm64 { imm, shift }) => {
                    let s = shift.as_ref().map(shift_lsl).unwrap_or(0);
                    (imm_to_u64(*imm), s)
                }
                _ => return,
            };
            state.set(*dst, AbsVal::Concrete(!((imm & 0xFFFF) << shift_n)));
        }
        Op::ADR => {
            // adr xN, label — bad64 resolves the absolute VA.
            let Some(Operand::Reg { reg: dst, .. }) = ops.first() else {
                return;
            };
            if let Some(Operand::Label(imm)) = ops.get(1) {
                state.set(*dst, AbsVal::Pointer(imm_to_u64(*imm)));
            } else {
                state.clobber(*dst);
            }
        }
        Op::ADRP => {
            // adrp xN, page — bad64 resolves the page-aligned VA.
            let Some(Operand::Reg { reg: dst, .. }) = ops.first() else {
                return;
            };
            if let Some(Operand::Label(imm)) = ops.get(1) {
                state.set(*dst, AbsVal::Pointer(imm_to_u64(*imm)));
            } else {
                state.clobber(*dst);
            }
        }
        Op::ADD => {
            // add xN, xM, #imm: if xM is a pointer, dst becomes a
            // pointer at the offset; if concrete, dst is concrete+imm.
            // Other shapes (add reg,reg,reg) downgrade to Unknown
            // unless both operands are concrete.
            let Some(Operand::Reg { reg: dst, .. }) = ops.first() else {
                return;
            };
            let src1 = match ops.get(1) {
                Some(Operand::Reg { reg, .. }) => state.get(*reg),
                _ => {
                    state.clobber(*dst);
                    return;
                }
            };
            match ops.get(2) {
                Some(Operand::Imm32 { imm, .. } | Operand::Imm64 { imm, .. }) => {
                    let off = imm_signed(*imm);
                    match src1 {
                        AbsVal::Pointer(p) => {
                            state.set(*dst, AbsVal::Pointer((p as i64 + off) as u64));
                        }
                        AbsVal::Concrete(c) => {
                            state.set(*dst, AbsVal::Concrete((c as i64 + off) as u64));
                        }
                        AbsVal::Unknown => state.clobber(*dst),
                    }
                }
                Some(Operand::Reg { reg, .. }) => {
                    let src2 = state.get(*reg);
                    match (src1, src2) {
                        (AbsVal::Concrete(a), AbsVal::Concrete(b)) => {
                            state.set(*dst, AbsVal::Concrete(a.wrapping_add(b)));
                        }
                        (AbsVal::Pointer(p), AbsVal::Concrete(o))
                        | (AbsVal::Concrete(o), AbsVal::Pointer(p)) => {
                            state.set(*dst, AbsVal::Pointer(p.wrapping_add(o)));
                        }
                        _ => state.clobber(*dst),
                    }
                }
                _ => state.clobber(*dst),
            }
        }
        Op::SUB => {
            // sub xN, xN, xN → zero. Otherwise clobber.
            if ops.len() >= 3
                && let (
                    Some(Operand::Reg { reg: dst, .. }),
                    Some(Operand::Reg { reg: s1, .. }),
                    Some(Operand::Reg { reg: s2, .. }),
                ) = (ops.first(), ops.get(1), ops.get(2))
                && full_reg(*dst) == full_reg(*s1)
                && full_reg(*s1) == full_reg(*s2)
            {
                state.set(*dst, AbsVal::Concrete(0));
                return;
            }
            if let Some(Operand::Reg { reg: dst, .. }) = ops.first() {
                state.clobber(*dst);
            }
        }
        Op::EOR => {
            // eor xN, xN, xN → zero.
            if ops.len() >= 3
                && let (
                    Some(Operand::Reg { reg: dst, .. }),
                    Some(Operand::Reg { reg: s1, .. }),
                    Some(Operand::Reg { reg: s2, .. }),
                ) = (ops.first(), ops.get(1), ops.get(2))
                && full_reg(*s1) == full_reg(*s2)
            {
                state.set(*dst, AbsVal::Concrete(0));
                return;
            }
            if let Some(Operand::Reg { reg: dst, .. }) = ops.first() {
                state.clobber(*dst);
            }
        }
        Op::ORR => {
            // ORR xN, XZR, xM is a common MOV alias — but bad64
            // usually surfaces it as Op::MOV. Conservative clobber.
            if let Some(Operand::Reg { reg: dst, .. }) = ops.first() {
                state.clobber(*dst);
            }
        }
        _ => {
            // Anything else with a register destination clobbers.
            // This is conservative — we'd rather discard a value
            // than propagate stale information past an unmodeled
            // instruction.
            if let Some(Operand::Reg { reg: dst, .. }) = ops.first() {
                state.clobber(*dst);
            }
        }
    }
}

fn state_to_resolved(state: &RegState) -> ResolvedRegsAarch64 {
    ResolvedRegsAarch64 {
        x0: state.get(Reg::X0).to_pub(),
        x1: state.get(Reg::X1).to_pub(),
        x2: state.get(Reg::X2).to_pub(),
        x3: state.get(Reg::X3).to_pub(),
        x4: state.get(Reg::X4).to_pub(),
        x5: state.get(Reg::X5).to_pub(),
        x6: state.get(Reg::X6).to_pub(),
        x7: state.get(Reg::X7).to_pub(),
    }
}

fn direct_branch_target(insn: &bad64::Instruction) -> Option<u64> {
    match insn.operands().first()? {
        Operand::Label(Imm::Unsigned(v)) => Some(*v),
        Operand::Label(Imm::Signed(v)) => Some(*v as u64),
        _ => None,
    }
}

fn imm_to_u64(imm: Imm) -> u64 {
    match imm {
        Imm::Unsigned(v) => v,
        Imm::Signed(v) => v as u64,
    }
}

fn imm_signed(imm: Imm) -> i64 {
    match imm {
        Imm::Unsigned(v) => v as i64,
        Imm::Signed(v) => v,
    }
}

fn shift_lsl(s: &Shift) -> u32 {
    match s {
        Shift::LSL(n) => *n,
        _ => 0,
    }
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
                arch: Some("aarch64".into()),
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

    /// movz x0, #0x42; bl somewhere → resolved X0 = 0x42.
    #[test]
    fn resolves_movz_into_x0() {
        // 0x1000  movz x0, #0x42        → 0xD2800840  → 40 08 80 D2
        // 0x1004  bl   0x1010           → 0x94000003  → 03 00 00 94
        let bytes: Vec<u8> = vec![0x40, 0x08, 0x80, 0xD2, 0x03, 0x00, 0x00, 0x94];
        const TEXT_VA: u64 = 0x1000;
        let parsed = parsed_for(&bytes, TEXT_VA);
        let analyzer = AArch64Analyzer::new(&bytes, &parsed);
        let site = CallSite {
            caller_va: TEXT_VA,
            block_start: TEXT_VA,
            call_ip: TEXT_VA + 4,
            next_ip: TEXT_VA + 8,
        };
        let regs = resolve_call_site_regs_aarch64(&analyzer, site);
        assert_eq!(regs.x0, AbsValPub::Concrete(0x42));
    }

    /// movz x0, #0x5678; movk x0, #0x1234, lsl #16; bl → X0 = 0x12345678.
    #[test]
    fn resolves_movz_then_movk_into_x0() {
        // 0x1000  movz x0, #0x5678         → 0xD28ACF00 → 00 CF 8A D2
        // 0x1004  movk x0, #0x1234, lsl 16 → 0xF2A24680 → 80 46 A2 F2
        // 0x1008  bl   _                   → 0x94000002 → 02 00 00 94
        let bytes: Vec<u8> = vec![
            0x00, 0xCF, 0x8A, 0xD2, // movz
            0x80, 0x46, 0xA2, 0xF2, // movk
            0x02, 0x00, 0x00, 0x94, // bl
        ];
        const TEXT_VA: u64 = 0x1000;
        let parsed = parsed_for(&bytes, TEXT_VA);
        let analyzer = AArch64Analyzer::new(&bytes, &parsed);
        let site = CallSite {
            caller_va: TEXT_VA,
            block_start: TEXT_VA,
            call_ip: TEXT_VA + 8,
            next_ip: TEXT_VA + 12,
        };
        let regs = resolve_call_site_regs_aarch64(&analyzer, site);
        assert_eq!(regs.x0, AbsValPub::Concrete(0x12345678));
    }

    /// adrp x1, 0x2000; add x1, x1, #0x10; bl → X1 = Pointer(0x2010).
    #[test]
    fn resolves_adrp_plus_add_pointer() {
        // adrp x1, 0x2000 with PC at 0x1000:
        //   imm21 = (0x2000 - 0x1000) >> 12 = 1
        //   immlo = 1, immhi = 0
        //   bits: 1 01 10000 0 ... 00001 → 0x90000001
        //
        // Actually: ADRP encoding has Rd in bits 4..0. For X1, Rd=1.
        //   With immlo=1: bits 30..29 = 01 (set bit 29 = 0x20000000)
        //   With fixed bits 28..24 = 10000 (set bit 28 = 0x10000000)
        //   bit 31 = 1 → 0x80000000 (ADRP, not ADR)
        //   Sum: 0xB0000001
        //
        // → LE: 01 00 00 B0
        //
        // add x1, x1, #0x10:
        //   ADD (immediate, 64-bit): 0x91000000 base
        //   imm12 at bits 21..10
        //   Rn at bits 9..5
        //   Rd at bits 4..0
        //   For Rd=1, Rn=1, imm12=0x10:
        //     0x91000000 | (0x10 << 10) | (1 << 5) | 1
        //   = 0x91000000 | 0x4000 | 0x20 | 1
        //   = 0x91004021
        //   → LE: 21 40 00 91
        //
        // bl _: 03 00 00 94
        let bytes: Vec<u8> = vec![
            0x01, 0x00, 0x00, 0xB0, // adrp x1, 0x2000
            0x21, 0x40, 0x00, 0x91, // add  x1, x1, #0x10
            0x03, 0x00, 0x00, 0x94, // bl
        ];
        const TEXT_VA: u64 = 0x1000;
        let parsed = parsed_for(&bytes, TEXT_VA);
        let analyzer = AArch64Analyzer::new(&bytes, &parsed);
        let site = CallSite {
            caller_va: TEXT_VA,
            block_start: TEXT_VA,
            call_ip: TEXT_VA + 8,
            next_ip: TEXT_VA + 12,
        };
        let regs = resolve_call_site_regs_aarch64(&analyzer, site);
        assert_eq!(regs.x1, AbsValPub::Pointer(0x2010));
    }

    /// eor x0, x0, x0 → X0 = 0.
    #[test]
    fn resolves_eor_self_to_zero() {
        // eor x0, x0, x0: 64-bit shifted-register form
        //   1 ca 00 00 0 R<5> 000000 R<5> R<5>  ... actually let's
        //   just encode: 0xCA000000 base for EOR (shifted reg, 64),
        //   shift=00 (LSL), N=0, Rm=0, imm6=0, Rn=0, Rd=0
        //   = 0xCA000000 | (0<<16) | (0<<10) | (0<<5) | 0 = 0xCA000000
        //   → LE: 00 00 00 CA
        //
        // bl _: 02 00 00 94
        let bytes: Vec<u8> = vec![
            0x00, 0x00, 0x00, 0xCA, // eor x0, x0, x0
            0x02, 0x00, 0x00, 0x94, // bl
        ];
        const TEXT_VA: u64 = 0x1000;
        let parsed = parsed_for(&bytes, TEXT_VA);
        let analyzer = AArch64Analyzer::new(&bytes, &parsed);
        let site = CallSite {
            caller_va: TEXT_VA,
            block_start: TEXT_VA,
            call_ip: TEXT_VA + 4,
            next_ip: TEXT_VA + 8,
        };
        let regs = resolve_call_site_regs_aarch64(&analyzer, site);
        assert_eq!(regs.x0, AbsValPub::Concrete(0));
    }
}
