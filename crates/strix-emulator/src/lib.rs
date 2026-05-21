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
#[cfg(feature = "unicorn")]
pub mod driver;
#[cfg(feature = "unicorn")]
pub mod emulator;
pub mod heuristics;
pub mod stack_strings;

use strix_core::{ExtractOptions, ExtractedString, Result, StringKind};
use strix_format::ParsedInput;

/// Aggregated results from a single emulation pass.
#[derive(Debug, Default)]
pub struct EmulationResults<'a> {
    /// Strings recovered from the scratch buffer (decoder outputs).
    pub decoded: Vec<ExtractedString<'a>>,
    /// Strings recovered from the emulated stack.
    pub stack: Vec<ExtractedString<'a>>,
    /// Tight-string subset of stack strings — not yet classified
    /// separately; reserved for future loop-correlated detection.
    pub tight: Vec<ExtractedString<'a>>,
    /// Non-fatal observations from the run.
    pub warnings: Vec<String>,
}

/// Minimum decoder score to bother emulating a candidate function.
///
/// Tuned empirically against the decoder fixtures: 0.3 catches the
/// borderline decoders in `test-decode-from-heap*` and the 64-bit
/// `single-byte-xor` / `base64` / `substitution-cipher` fixtures
/// without exploding emulation time on real binaries.
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
    if want.1 {
        for rec in stack_strings::extract(input, parsed, options.min_length) {
            out.stack.push(ExtractedString {
                value: Cow::Owned(rec.value),
                kind: StringKind::Stack,
                encoding: Encoding::Ascii,
                location: Location {
                    offset: 0,
                    address: Some(rec.function_va),
                    section: Some("stack".to_string()),
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
        return Ok(out);
    }

    #[cfg(feature = "unicorn")]
    {
        run_emulated_pipeline(input, parsed, options, want, &mut out)?;
        Ok(out)
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

    use strix_core::Location;

    use crate::analyzer::CodeAnalyzer;
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

    let push_recovered =
        |run: crate::driver::RunResult, out: &mut EmulationResults<'a>, driver_errors: &mut u32| {
            if !run.execution_ok {
                *driver_errors += 1;
            }
            for rec in run.recovered {
                if rec.value.len() < options.min_length {
                    continue;
                }
                let section_tag = match rec.kind {
                    RecoveredKind::Decoded => "scratch",
                    RecoveredKind::Stack => "stack",
                };
                let extracted = ExtractedString {
                    value: Cow::Owned(rec.value),
                    kind: match rec.kind {
                        RecoveredKind::Decoded => StringKind::Decoded,
                        RecoveredKind::Stack => StringKind::Stack,
                    },
                    encoding: rec.encoding,
                    location: Location {
                        offset: 0,
                        address: Some(rec.address),
                        section: Some(section_tag.to_string()),
                    },
                };
                match rec.kind {
                    RecoveredKind::Decoded if want_decoded => out.decoded.push(extracted),
                    RecoveredKind::Stack if want_stack => out.stack.push(extracted),
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
            Ok(r) => push_recovered(r, out, &mut driver_errors),
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
    for callee in &candidate_vas {
        let callers: Vec<u64> = funcs
            .iter()
            .filter(|(caller_va, f)| *caller_va != callee && f.callees.contains(callee))
            .map(|(va, _)| *va)
            .take(MAX_CALLERS_PER_CANDIDATE)
            .collect();
        for caller in callers {
            callers_attempted += 1;
            match driver.run_function_fuzzed(caller, options.max_emulation_steps) {
                Ok(r) => push_recovered(r, out, &mut callers_errors),
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

    if driver_errors > 0 {
        out.warnings.push(format!(
            "{driver_errors} of {attempts} emulated candidates failed \
             (faulted on unmapped memory, hit the step cap, or both); \
             partial output may still be present"
        ));
    }

    if want_tight {
        // Tight strings are stack strings built inside a tight inner
        // loop. We don't yet correlate writes with their dominating
        // basic block, so we can't distinguish them from regular
        // stack strings. Flag and move on.
        out.warnings.push(
            "tight-string classification not yet implemented; tight \
             strings (if any) appear in the stack-strings list"
                .to_string(),
        );
    }

    Ok(())
}
