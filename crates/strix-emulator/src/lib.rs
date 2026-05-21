//! Emulation-backed string extractors for strix.
//!
//! This crate owns the three string-recovery passes that require
//! running emulated x86/x86_64 code: `decoded`, `stack`, and `tight`.
//! It builds on the analyzer (basic-block discovery), the heuristics
//! layer (decoder scoring), and the driver (brute-force emulation
//! with memory diffing).
//!
//! The public entry point is [`extract_emulated`], which performs the
//! whole pipeline in one pass:
//!
//! 1. Discover all functions in the parsed binary (recursive descent
//!    from the entry point + prologue linear sweep).
//! 2. Score every function for decoder-likeness.
//! 3. Emulate the top candidates, harvesting printable bytes from the
//!    scratch buffer and emulated stack.
//! 4. Classify recovered strings as `Decoded` (from scratch) or
//!    `Stack` (from emulated stack) and return them.
//!
//! # Feature gating
//!
//! The actual emulation requires the C-based `unicorn-engine` crate,
//! which is opt-in behind the `unicorn` Cargo feature. With the
//! feature off, [`extract_emulated`] is still callable but returns an
//! empty result plus a warning telling the caller how to enable it.

#![deny(rust_2018_idioms)]
#![warn(missing_docs)]

pub mod analyzer;
pub mod callsite;
#[cfg(feature = "unicorn")]
pub mod driver;
#[cfg(feature = "unicorn")]
pub mod emulator;
pub mod heuristics;
pub mod stack_strings;

use strix_core::{DecoderCandidate, ExtractOptions, ExtractedString, Result, StringKind};
use strix_format::ParsedInput;

/// Aggregated results from a single emulation pass.
#[derive(Debug, Default)]
pub struct EmulationResults<'a> {
    /// Strings recovered from the scratch buffer (decoder outputs).
    pub decoded: Vec<ExtractedString<'a>>,
    /// Strings recovered from the emulated stack.
    pub stack: Vec<ExtractedString<'a>>,
    /// Tight strings: stack-string builds whose writing block lies
    /// inside a natural loop body (back-edge detected in the CFG).
    /// Populated by the pattern-based pass; emulated stack writes
    /// are not yet correlated to their dominating block and still
    /// land in `stack`.
    pub tight: Vec<ExtractedString<'a>>,
    /// Decoder candidates the heuristic ranked above the
    /// MIN_DECODER_SCORE threshold, in descending score order,
    /// each annotated with how many strings emulation actually
    /// produced from it.
    pub candidates: Vec<DecoderCandidate>,
    /// Non-fatal observations from the run.
    pub warnings: Vec<String>,
}

/// Minimum decoder score to bother emulating a candidate function.
/// Empirically 0.3 captures the decoders we can currently recover
/// without spending cycles on functions that aren't going to yield.
pub const MIN_DECODER_SCORE: f64 = 0.3;

/// Hard cap on the number of candidates we'll emulate per run. Real
/// binaries have hundreds of functions but the decoder is rarely
/// far down the ranked list; 200 leaves plenty of headroom while
/// keeping wall-clock bounded.
pub const MAX_CANDIDATES: usize = 200;

/// Run the emulation-based extractors over the parsed binary.
///
/// Without the `unicorn` feature, this returns an empty
/// [`EmulationResults`] plus a single warning explaining the build is
/// missing the emulator. With the feature, it runs the full pipeline.
pub fn extract_emulated<'a>(
    input: &'a [u8],
    parsed: &ParsedInput,
    options: &ExtractOptions,
) -> Result<EmulationResults<'a>> {
    use std::borrow::Cow;
    use strix_core::{Encoding, Location};

    let want = (
        options.is_enabled(StringKind::Decoded),
        options.is_enabled(StringKind::Stack),
        options.is_enabled(StringKind::Tight),
    );
    if !(want.0 || want.1 || want.2) {
        return Ok(EmulationResults::default());
    }

    let mut out = EmulationResults::default();

    // Pattern-based stack-string recovery: pure disassembly, no
    // emulation required. Runs whether or not the `unicorn` feature
    // is on, so callers always get something for the stack bucket.
    // Strings emitted from inside a loop body are classified as
    // `Tight`; straight-line builds stay `Stack`.
    if want.1 || want.2 {
        for rec in stack_strings::extract(input, parsed, options.min_length) {
            let (kind, section_tag) = if rec.is_tight {
                (StringKind::Tight, "stack-tight")
            } else {
                (StringKind::Stack, "stack")
            };
            // Honor the want flags: a Tight string only goes out if
            // tight is enabled; a Stack string only if stack is.
            let keep = match kind {
                StringKind::Tight => want.2,
                StringKind::Stack => want.1,
                _ => false,
            };
            if !keep {
                continue;
            }
            let bucket = if kind == StringKind::Tight {
                &mut out.tight
            } else {
                &mut out.stack
            };
            bucket.push(ExtractedString {
                value: Cow::Owned(rec.value),
                kind,
                encoding: Encoding::Ascii,
                location: Location {
                    offset: 0,
                    address: Some(rec.function_va),
                    section: Some(section_tag.to_string()),
                    function_va: Some(rec.function_va),
                    source_va: None,
                },
            });
        }
    }

    #[cfg(not(feature = "unicorn"))]
    {
        let _ = input;
        let _ = parsed;
        if want.0 || want.2 {
            out.warnings.push(
                "decoded/tight extractors require the `unicorn` feature; \
                 rebuild with --features unicorn"
                    .to_string(),
            );
        }
        Ok(out)
    }

    #[cfg(feature = "unicorn")]
    {
        run_emulated_pipeline(input, parsed, options, want, &mut out)?;
        Ok(out)
    }
}

/// Convert a `ResolvedRegs` from the callsite-dataflow pass into a
/// concrete `ArgSet` the emulation driver can run with.
///
/// For each register: if dataflow resolved a concrete value
/// (immediate or rdata pointer), pass it through. Otherwise fall
/// back to a pointer into scratch — this is the right default for
/// "destination buffer" arguments the decoder will write into and
/// for "I have no clue but you need *something* here" cases.
#[cfg(feature = "unicorn")]
fn resolved_to_argset(
    layout: &crate::driver::MemoryLayout,
    regs: crate::callsite::ResolvedRegs,
) -> crate::driver::ArgSet {
    use crate::callsite::AbsValPub;
    let fallback_scratch = layout.scratch_base;
    let fallback_secondary = layout.secondary_ptr();

    fn val_or(p: AbsValPub, default: u64) -> u64 {
        p.or(default)
    }

    crate::driver::ArgSet {
        rdi: val_or(regs.rdi, fallback_scratch),
        rsi: val_or(regs.rsi, fallback_secondary),
        rdx: val_or(regs.rdx, 64),
        rcx: val_or(regs.rcx, fallback_scratch),
        r8: val_or(regs.r8, fallback_secondary),
        r9: val_or(regs.r9, 64),
    }
}

#[cfg(feature = "unicorn")]
fn run_emulated_pipeline<'a>(
    input: &'a [u8],
    parsed: &ParsedInput,
    options: &ExtractOptions,
    want: (bool, bool, bool),
    out: &mut EmulationResults<'a>,
) -> Result<()> {
    use std::borrow::Cow;
    use std::collections::BTreeSet;

    use strix_core::Location;

    use crate::analyzer::CodeAnalyzer;
    use crate::callsite::{
        AbsValPub, collect_rdata_pointers, find_call_sites, make_va_reader, resolve_call_site_regs,
        resolve_call_site_regs_cross_block,
    };
    use crate::driver::{EmulationDriver, RecoveredKind};
    use crate::heuristics::{ScoreWeights, rank_candidates, score_all};

    let (want_decoded, want_stack, want_tight) = want;

    // 1. Discover functions.
    let analyzer = CodeAnalyzer::new(input, parsed);
    let funcs = analyzer.discover_all();
    if funcs.is_empty() {
        out.warnings
            .push("no functions discovered; nothing to emulate".to_string());
        return Ok(());
    }

    // 2. Score and rank.
    let scores = score_all(&analyzer, &funcs, ScoreWeights::default());
    let candidates = rank_candidates(&scores, MIN_DECODER_SCORE);
    if candidates.is_empty() {
        out.warnings.push(
            "no functions scored above the decoder-likeness threshold; \
             nothing worth emulating"
                .to_string(),
        );
        return Ok(());
    }

    // 3. Emulate the top N candidates directly with our fuzzed args.
    let mut driver = EmulationDriver::new(input, parsed)?;
    let mut driver_errors: u32 = 0;
    let mut attempts: u32 = 0;

    // Precompute the loop-body block set for every discovered
    // function so we can promote emulated stack writes to "tight"
    // when their writing IP lies inside a loop body.
    let loop_bodies_by_func: std::collections::BTreeMap<u64, std::collections::BTreeSet<u64>> =
        funcs
            .iter()
            .map(|(va, f)| (*va, stack_strings::detect_loop_bodies_public(f)))
            .collect();

    // Decide whether `ip` fell inside the loop body of *any*
    // discovered function. Writes during decoder emulation can
    // happen in the decoder itself, in callees, or in CRT helpers —
    // we don't care which function did the write, only whether the
    // writing instruction lives in a loop body somewhere.
    let ip_in_loop = |ip: u64| -> bool {
        for (func_va, func) in &funcs {
            for (start, block) in &func.blocks {
                if ip >= *start && ip < block.end {
                    return loop_bodies_by_func
                        .get(func_va)
                        .map(|l| l.contains(start))
                        .unwrap_or(false);
                }
            }
        }
        false
    };

    // Map a writing IP to the VA of the function that contains it,
    // if any. Used to tag recovered strings with their producing
    // function VA so analysts can group output by function.
    let ip_to_func = |ip: u64| -> Option<u64> {
        for (func_va, func) in &funcs {
            for (start, block) in &func.blocks {
                if ip >= *start && ip < block.end {
                    return Some(*func_va);
                }
            }
        }
        None
    };

    let push_recovered = |run: crate::driver::RunResult,
                          fallback_func_va: u64,
                          source_va: Option<u64>,
                          out: &mut EmulationResults<'a>,
                          driver_errors: &mut u32| {
        if !run.execution_ok {
            *driver_errors += 1;
        }
        for rec in run.recovered {
            if rec.value.len() < options.min_length {
                continue;
            }
            // Classify a stack-write as tight when at least one
            // writing IP lies inside a discovered loop body
            // anywhere in the binary.
            let is_tight = matches!(rec.kind, RecoveredKind::Stack)
                && rec.writing_ips.iter().any(|ip| ip_in_loop(*ip));
            // Attribute the string to whichever function contains
            // the first known writing IP; fall back to the
            // candidate we were running when we ran out of IPs.
            let function_va = rec
                .writing_ips
                .iter()
                .find_map(|ip| ip_to_func(*ip))
                .or(Some(fallback_func_va));
            let (final_kind, section_tag) = match rec.kind {
                RecoveredKind::Decoded => (StringKind::Decoded, "scratch"),
                RecoveredKind::Stack if is_tight => (StringKind::Tight, "stack-tight"),
                RecoveredKind::Stack => (StringKind::Stack, "stack"),
            };
            let extracted = ExtractedString {
                value: Cow::Owned(rec.value),
                kind: final_kind,
                encoding: rec.encoding,
                location: Location {
                    offset: 0,
                    address: Some(rec.address),
                    section: Some(section_tag.to_string()),
                    function_va,
                    source_va,
                },
            };
            match final_kind {
                StringKind::Decoded if want_decoded => out.decoded.push(extracted),
                StringKind::Stack if want_stack => out.stack.push(extracted),
                StringKind::Tight if want_tight => out.tight.push(extracted),
                _ => {}
            }
        }
    };

    let candidate_vas: Vec<u64> = candidates
        .iter()
        .take(MAX_CANDIDATES)
        .map(|(va, _)| *va)
        .collect();

    for entry in &candidate_vas {
        attempts += 1;
        match driver.run_function_fuzzed(*entry, options.max_emulation_steps) {
            Ok(r) => push_recovered(r, *entry, None, out, &mut driver_errors),
            Err(_) => driver_errors += 1,
        }
    }

    // 4. Also emulate each candidate's *callers* from their function
    //    entry. The natural code flow in the caller sets up real
    //    decoder arguments (LEA RIP-relative pointers to encoded
    //    data, real lengths, real destination buffers on the stack
    //    or heap) — so the decoder reads real bytes and writes real
    //    decoded output. Dedupe absorbs any overlap with the direct
    //    emulation pass above.
    //
    //    We cap callers per candidate to bound test wall-clock; in
    //    practice 3 is plenty since deduped runs converge quickly.
    const MAX_CALLERS_PER_CANDIDATE: usize = 3;
    let mut callers_attempted: u32 = 0;
    let mut callers_errors: u32 = 0;
    // Caller emulation has to walk the full prologue and any setup
    // calls (HeapAlloc, memcpy, etc.) before reaching the decoder.
    // Give it more headroom than the brute-force fuzzer's cap.
    let caller_step_cap = options.max_emulation_steps.saturating_mul(4).max(20_000);
    for callee in &candidate_vas {
        let callers: Vec<u64> = funcs
            .iter()
            .filter(|(caller_va, f)| *caller_va != callee && f.callees.contains(callee))
            .map(|(va, _)| *va)
            .take(MAX_CALLERS_PER_CANDIDATE)
            .collect();
        for caller in callers {
            callers_attempted += 1;
            match driver.run_function_fuzzed(caller, caller_step_cap) {
                Ok(r) => push_recovered(r, caller, None, out, &mut callers_errors),
                Err(_) => callers_errors += 1,
            }
        }
    }
    if callers_attempted > 0 && callers_errors == callers_attempted {
        out.warnings.push(format!(
            "all {callers_attempted} caller-site emulations failed; \
             call-site argument extraction yielded no additional strings"
        ));
    }

    // 5. Symbolic dataflow at the actual decoder call site. The
    //    caller-emulation pass above runs the *whole* caller from
    //    its entry, which often faults somewhere unrelated. The
    //    pass below skips ahead to each call instruction's basic
    //    block, walks the block forward tracking register values
    //    through `mov`, `lea rip-relative`, `xor reg,reg`, etc., and
    //    runs the decoder directly with the resolved argument
    //    register values. This is the only way to recover decoders
    //    whose source pointer is set by `lea rcx, [rip+disp]`
    //    pointing at .rdata — those don't appear in the brute-force
    //    fuzzer schedule (which always points args at scratch).
    const MAX_SITES_PER_CANDIDATE: usize = 6;
    let mut sites_emulated: u32 = 0;
    let mut sites_yielded: u32 = 0;
    let reader = make_va_reader(input, parsed);

    // Build an expanded candidate set: the score-ranked candidates
    // PLUS any function called from a site with concrete arg setup.
    // The latter catches small decoders (single-byte XOR, ROL/ROR
    // loops) that score below the heuristic threshold but are
    // identifiable by their *call shape*: `lea reg, [rip+rdata]`
    // immediately before the call.
    let mut expanded_candidates: BTreeSet<u64> = candidate_vas.iter().copied().collect();
    for (caller_va, func) in &funcs {
        for callee in &func.callees {
            if expanded_candidates.contains(callee) {
                continue;
            }
            // Sample a single call site to test for "concrete arg
            // setup" — if any reachable site has it, the callee is
            // worth emulating. Use cross-block dataflow so a pointer
            // set up in the function prologue (block above the
            // call) still counts.
            let sites = find_call_sites(&analyzer, &funcs, *callee, 1);
            for site in sites {
                let regs = if site.caller_va == *caller_va {
                    resolve_call_site_regs_cross_block(&analyzer, func, site, &reader)
                } else {
                    resolve_call_site_regs(&analyzer, site, &reader)
                };
                let has_pointer = matches!(regs.rcx, AbsValPub::Pointer(_))
                    || matches!(regs.rdx, AbsValPub::Pointer(_))
                    || matches!(regs.r8, AbsValPub::Pointer(_))
                    || matches!(regs.rdi, AbsValPub::Pointer(_))
                    || matches!(regs.rsi, AbsValPub::Pointer(_));
                if has_pointer {
                    expanded_candidates.insert(*callee);
                }
            }
        }
    }
    // Bound the expansion so we don't emulate every helper function
    // in a 1000-function binary.
    let expanded: Vec<u64> = expanded_candidates
        .iter()
        .copied()
        .take(MAX_CANDIDATES * 2)
        .collect();

    // Bump the step cap for callsite-dataflow runs. The brute-force
    // fuzzer uses options.max_emulation_steps as-is; here we give
    // each decoder more headroom since we expect the run to actually
    // produce output (we've staged real args).
    let callsite_step_cap = options.max_emulation_steps.saturating_mul(4).max(20_000);

    for callee in &expanded {
        let sites = find_call_sites(&analyzer, &funcs, *callee, MAX_SITES_PER_CANDIDATE);
        for site in sites {
            // Cross-block dataflow when we have the caller function:
            // arg setup commonly straddles the prologue and the
            // call's block.
            let regs = match funcs.get(&site.caller_va) {
                Some(caller_func) => {
                    resolve_call_site_regs_cross_block(&analyzer, caller_func, site, &reader)
                }
                None => resolve_call_site_regs(&analyzer, site, &reader),
            };
            // Only run if at least one argument register resolved to
            // a concrete value — otherwise we're just duplicating the
            // brute-force fuzzer's schedule.
            if !(regs.rcx.is_known()
                || regs.rdx.is_known()
                || regs.r8.is_known()
                || regs.r9.is_known()
                || regs.rdi.is_known()
                || regs.rsi.is_known())
            {
                continue;
            }
            sites_emulated += 1;
            let arg_set = resolved_to_argset(&driver.layout, regs);
            match driver.run_function_with(*callee, callsite_step_cap, &[arg_set]) {
                Ok(r) => {
                    let prev_decoded = out.decoded.len();
                    let prev_stack = out.stack.len();
                    push_recovered(r, *callee, None, out, &mut driver_errors);
                    if out.decoded.len() > prev_decoded || out.stack.len() > prev_stack {
                        sites_yielded += 1;
                    }
                }
                Err(_) => driver_errors += 1,
            }

            // Additional pass: pre-populate scratch with bytes from
            // each .rdata pointer visible near this call site, then
            // run the decoder pointing rcx at scratch. Catches the
            // common in-place pattern where the caller stages
            // encoded bytes into a local buffer (often via inline
            // mov-chains rather than a memcpy call) before invoking
            // the decoder. We try up to 4 distinct sources per call
            // site to bound wall-clock.
            const MAX_RDATA_SOURCES_PER_SITE: usize = 4;
            const PREFILL_BYTES: usize = 256;
            if let Some(caller_func) = funcs.get(&site.caller_va) {
                let sources = collect_rdata_pointers(&analyzer, caller_func, site, parsed);
                for src_va in sources.iter().take(MAX_RDATA_SOURCES_PER_SITE) {
                    let Some(prefill) = reader(*src_va, PREFILL_BYTES) else {
                        continue;
                    };
                    let mut prefill_args = arg_set;
                    // Re-point any in-rdata pointer arg at scratch
                    // since the decoder reads from there now.
                    if matches!(regs.rcx, AbsValPub::Pointer(_)) {
                        prefill_args.rcx = driver.layout.scratch_base;
                    }
                    if matches!(regs.rdx, AbsValPub::Pointer(_)) {
                        prefill_args.rdx = driver.layout.scratch_base;
                    }
                    if matches!(regs.rsi, AbsValPub::Pointer(_)) {
                        prefill_args.rsi = driver.layout.scratch_base;
                    }
                    if matches!(regs.rdi, AbsValPub::Pointer(_)) {
                        prefill_args.rdi = driver.layout.scratch_base;
                    }
                    match driver.run_function_with_prefill(
                        *callee,
                        callsite_step_cap,
                        &prefill_args,
                        &prefill,
                    ) {
                        Ok(r) => {
                            let prev_decoded = out.decoded.len();
                            let prev_stack = out.stack.len();
                            push_recovered(r, *callee, Some(*src_va), out, &mut driver_errors);
                            if out.decoded.len() > prev_decoded || out.stack.len() > prev_stack {
                                sites_yielded += 1;
                            }
                        }
                        Err(_) => driver_errors += 1,
                    }
                }
            }
        }
    }
    log::debug!(
        target: "strix::emulator",
        "callsite dataflow: emulated {sites_emulated} sites, {sites_yielded} produced new strings"
    );

    if driver_errors > 0 {
        out.warnings.push(format!(
            "{driver_errors} of {attempts} emulated candidates failed \
             (faulted on unmapped memory, hit the step cap, or both); \
             partial output may still be present"
        ));
    }

    let _ = want_tight; // tight is classified by the pattern pass above

    // Surface the ranked candidates plus per-candidate recovery
    // counts. Strings recovered through emulation are tagged with
    // their function VA via `location.address`, so we just histogram
    // by that field. Pattern-recovered stack strings also use
    // function VA, so they show up here too — which is fine: these
    // ARE the functions the heuristic flagged, regardless of which
    // recovery pass surfaced their strings.
    let mut counts_by_va: std::collections::BTreeMap<u64, u32> = std::collections::BTreeMap::new();
    for s in out
        .decoded
        .iter()
        .chain(out.stack.iter())
        .chain(out.tight.iter())
    {
        if let Some(addr) = s.location.address {
            *counts_by_va.entry(addr).or_insert(0) += 1;
        }
    }
    out.candidates = candidates
        .iter()
        .map(|(va, score)| {
            // Build capability tags from the function's resolved
            // imported callees. Look each iat_va back up in
            // parsed.imports to get the name, then run the lot
            // through the capability classifier.
            let tags = if let Some(func) = funcs.get(va) {
                let names: Vec<&str> = func
                    .imported_callees
                    .iter()
                    .filter_map(|iat| {
                        parsed
                            .imports
                            .iter()
                            .find(|imp| imp.iat_va == *iat)
                            .map(|imp| imp.name.as_str())
                    })
                    .collect();
                strix_core::tags_for_imports(names)
            } else {
                Vec::new()
            };
            DecoderCandidate {
                va: *va,
                name: parsed.symbols.get(va).cloned(),
                score: score.score,
                bitwise_density: score.components.bitwise_density,
                loop_count: score.components.loop_count,
                byte_size: score.components.byte_size,
                caller_count: score.components.caller_count,
                instruction_count: score.components.instruction_count,
                import_callee_count: score.components.import_callee_count,
                recovered_strings: counts_by_va.get(va).copied().unwrap_or(0),
                tags,
            }
        })
        .collect();

    Ok(())
}
