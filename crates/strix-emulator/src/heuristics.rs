//! Heuristics for identifying candidate decoder routines.
//!
//! Decoder identification looks at several signals per
//! function. We score each signal independently in `[0.0, 1.0]` and
//! combine them with tunable weights into a final `score`.
//!
//! Signals implemented:
//!
//! * **Bitwise/arithmetic density.** Fraction of instructions that
//!   are XOR / ADD / SUB / ROL / ROR / SHL / SHR / NOT / NEG / MUL /
//!   AND / OR. String decoders spend most of their time crunching
//!   bytes with these.
//! * **Loop count.** Number of back-edges in the function CFG. Most
//!   decoders are loop-driven; functions with zero loops are unlikely
//!   to be decoders.
//! * **Size bucket.** Decoders tend to be small-to-medium. A "Goldilocks"
//!   curve peaks around 32-512 bytes and falls off at both extremes.
//! * **Caller count.** Decoders are typically called many times (each
//!   string callsite). Functions with no callers are deprioritized.
//!
//! Default weights are an educated guess; tune against the
//! decoder-fixture corpus once we can run on real binaries.

use std::collections::BTreeMap;

use iced_x86::{Decoder, DecoderOptions, Mnemonic};

use crate::analyzer::{CodeAnalyzer, Function};

/// Weighting for each signal in the composite score. Each `w_*` is in
/// `[0.0, 1.0]` and they need not sum to 1 — the composite is just a
/// weighted average normalized by total weight.
#[derive(Debug, Clone, Copy)]
pub struct ScoreWeights {
    /// Weight for bitwise-density signal.
    pub w_bitwise: f64,
    /// Weight for loop-count signal.
    pub w_loops: f64,
    /// Weight for size-bucket signal.
    pub w_size: f64,
    /// Weight for caller-count signal.
    pub w_callers: f64,
    /// Weight for the "this function doesn't call imports" signal.
    /// Decoders are pure compute and rarely touch the IAT; functions
    /// that call several imports are almost certainly something else.
    /// Applied via [`import_purity_score`], which inverts the count.
    pub w_import_purity: f64,
    /// Weight for the "leaf-shaped" signal: functions with few or
    /// no callees of any kind (direct or via IAT) look more like
    /// decoders. A pure-leaf function gets the full signal; each
    /// additional callee drives it down. See [`leaf_score`].
    pub w_leaf: f64,
}

impl Default for ScoreWeights {
    fn default() -> Self {
        // Bitwise density and loop presence are the strongest signals
        // — a function that crunches bytes inside a loop is exactly
        // the shape we're looking for. Size and caller-count are
        // softer signals. Import-purity is a tie-breaker: it nudges
        // pure-compute functions above wrapper-style ones.
        Self {
            w_bitwise: 1.5,
            w_loops: 1.2,
            w_size: 0.3,
            w_callers: 0.3,
            w_import_purity: 0.4,
            w_leaf: 0.3,
        }
    }
}

/// Component scores that combine into a `DecoderScore`.
#[derive(Debug, Default, Clone, Copy)]
pub struct ScoreComponents {
    /// Fraction of instructions classified as bitwise/arithmetic.
    pub bitwise_density: f64,
    /// Number of back-edges (loops) detected.
    pub loop_count: u32,
    /// Function size in bytes.
    pub byte_size: u64,
    /// Number of distinct callers in the analyzed call graph.
    pub caller_count: u32,
    /// Total number of decoded instructions.
    pub instruction_count: u32,
    /// Number of distinct imported callees (`call [iat_entry]`
    /// instructions whose target resolved to a known import).
    pub import_callee_count: u32,
    /// Number of distinct direct-call callees. Used together with
    /// `import_callee_count` to compute the leaf-shape signal.
    pub callee_count: u32,
}

/// A function's likelihood of being a string decoder.
#[derive(Debug, Clone, Copy)]
pub struct DecoderScore {
    /// Composite score in `[0.0, 1.0]`. Higher = more likely.
    pub score: f64,
    /// The component metrics that produced the composite.
    pub components: ScoreComponents,
}

/// Score a single function in isolation. Caller count is not knowable
/// from one function alone; for that, use [`score_all`].
pub fn score_function(
    analyzer: &CodeAnalyzer<'_>,
    func: &Function,
    caller_count: u32,
    weights: ScoreWeights,
) -> DecoderScore {
    let components = compute_components(analyzer, func, caller_count);
    let score = combine(&components, weights);
    DecoderScore { score, components }
}

/// Score every function in a discovered set, computing caller counts
/// from the global call graph.
pub fn score_all(
    analyzer: &CodeAnalyzer<'_>,
    funcs: &BTreeMap<u64, Function>,
    weights: ScoreWeights,
) -> BTreeMap<u64, DecoderScore> {
    // Build caller-count map: for each function, how many distinct
    // other functions list it as a callee?
    let mut caller_counts: BTreeMap<u64, u32> = BTreeMap::new();
    for func in funcs.values() {
        for &callee in &func.callees {
            *caller_counts.entry(callee).or_insert(0) += 1;
        }
    }
    funcs
        .iter()
        .map(|(&va, func)| {
            let cc = caller_counts.get(&va).copied().unwrap_or(0);
            (va, score_function(analyzer, func, cc, weights))
        })
        .collect()
}

/// Return the function entry points sorted by descending decoder score.
pub fn rank_candidates(
    scores: &BTreeMap<u64, DecoderScore>,
    min_score: f64,
) -> Vec<(u64, DecoderScore)> {
    let mut v: Vec<(u64, DecoderScore)> = scores
        .iter()
        .filter(|(_, s)| s.score >= min_score)
        .map(|(&k, &v)| (k, v))
        .collect();
    v.sort_by(|a, b| {
        b.1.score
            .partial_cmp(&a.1.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    v
}

// ---------- internals ----------

fn compute_components(
    analyzer: &CodeAnalyzer<'_>,
    func: &Function,
    caller_count: u32,
) -> ScoreComponents {
    let mut bitwise_ops: u32 = 0;
    let mut total_ops: u32 = 0;

    // Walk every block's bytes, decode, and tally mnemonics.
    for block in func.blocks.values() {
        let Some(bytes) = analyzer.bytes_at_va(block.start) else {
            continue;
        };
        // Bound the decode to the block's byte range.
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
            total_ops += 1;
            if is_bitwise_or_arith(insn.mnemonic()) {
                bitwise_ops += 1;
            }
        }
    }

    let bitwise_density = if total_ops == 0 {
        0.0
    } else {
        bitwise_ops as f64 / total_ops as f64
    };
    let loop_count = count_back_edges(func);
    let byte_size = func.byte_size();

    ScoreComponents {
        bitwise_density,
        loop_count,
        byte_size,
        caller_count,
        instruction_count: total_ops,
        import_callee_count: func.imported_callees.len() as u32,
        callee_count: func.callees.len() as u32,
    }
}

/// Count back-edges in the function CFG.
///
/// A back-edge is a successor whose address is strictly less than the
/// source block's end address (i.e. the jump targets an earlier point
/// in the function). This is a reasonable proxy for loops without
/// requiring full dominator analysis.
fn count_back_edges(func: &Function) -> u32 {
    let mut count = 0;
    for block in func.blocks.values() {
        for &succ in &block.successors {
            if succ < block.end && func.blocks.contains_key(&succ) {
                count += 1;
            }
        }
    }
    count
}

/// Mnemonics counted as bitwise-or-arithmetic for decoder scoring.
///
/// INC and DEC are included because decoders routinely use them for
/// counter management inside the inner loop.
fn is_bitwise_or_arith(m: Mnemonic) -> bool {
    matches!(
        m,
        Mnemonic::Xor
            | Mnemonic::And
            | Mnemonic::Or
            | Mnemonic::Not
            | Mnemonic::Neg
            | Mnemonic::Add
            | Mnemonic::Sub
            | Mnemonic::Adc
            | Mnemonic::Sbb
            | Mnemonic::Inc
            | Mnemonic::Dec
            | Mnemonic::Mul
            | Mnemonic::Imul
            | Mnemonic::Div
            | Mnemonic::Idiv
            | Mnemonic::Shl
            | Mnemonic::Shr
            | Mnemonic::Sar
            | Mnemonic::Rol
            | Mnemonic::Ror
            | Mnemonic::Rcl
            | Mnemonic::Rcr
    )
}

/// Normalize a component score to `[0, 1]` and combine with weights.
fn combine(c: &ScoreComponents, w: ScoreWeights) -> f64 {
    let s_bitwise = c.bitwise_density.clamp(0.0, 1.0);
    let s_loops = loop_score(c.loop_count);
    let s_size = size_score(c.byte_size);
    let s_callers = caller_score(c.caller_count);
    let s_import_purity = import_purity_score(c.import_callee_count);
    // Combine direct + import callees for the leaf signal — a
    // function that calls two helpers is just as un-leaf-like as
    // one that calls two imports.
    let s_leaf = leaf_score(c.callee_count + c.import_callee_count);

    let total_w = w.w_bitwise + w.w_loops + w.w_size + w.w_callers + w.w_import_purity + w.w_leaf;
    if total_w == 0.0 {
        return 0.0;
    }
    (w.w_bitwise * s_bitwise
        + w.w_loops * s_loops
        + w.w_size * s_size
        + w.w_callers * s_callers
        + w.w_import_purity * s_import_purity
        + w.w_leaf * s_leaf)
        / total_w
}

/// Leaf-shape score: a function that calls nothing else looks the
/// most decoder-like. Each callee drops the score; by the time a
/// function calls four or more other things, it's almost
/// certainly orchestrator logic rather than the decoder itself.
pub fn leaf_score(total_callees: u32) -> f64 {
    match total_callees {
        0 => 1.0,
        1 => 0.7,
        2 => 0.4,
        3 => 0.2,
        _ => 0.0,
    }
}

/// "Doesn't call imports" score — saturates quickly. A function that
/// touches zero imports gets the full signal; one or two might be
/// memcpy/strlen-ish helpers a decoder *could* legitimately call, so
/// the falloff is gentle; above that we drop off fast.
pub fn import_purity_score(n: u32) -> f64 {
    match n {
        0 => 1.0,
        1 => 0.7,
        2 => 0.4,
        3 => 0.15,
        _ => 0.0,
    }
}

/// Saturating loop score: 0 loops -> 0, 1 -> 0.75, 2 -> 0.9, >=3 -> 1.
///
/// A single loop is already a strong signal — most decoders are
/// single-loop. Additional loops are diminishing-returns informative.
fn loop_score(n: u32) -> f64 {
    match n {
        0 => 0.0,
        1 => 0.75,
        2 => 0.9,
        _ => 1.0,
    }
}

/// Goldilocks curve for function size: peaks around 256 bytes,
/// falls off at both extremes. Tight inner-loop decoders (~12 bytes
/// — a 1-byte-XOR / ROL / ADD loop) score competitively because
/// they're a real decoder shape; huge functions (> 8KB) go to zero
/// because real decoders are rarely that large.
///
/// The curve was lifted at the small end after observing real
/// fixtures (single-byte-XOR variants, tight base64 inner loops)
/// scoring just below the candidate threshold under the previous
/// `b/16 * 0.5` ramp that capped tiny functions at 0.5.
fn size_score(bytes: u64) -> f64 {
    let b = bytes as f64;
    if b < 8.0 {
        // Sub-three-instruction. Not a function we care about.
        return 0.0;
    }
    if b < 16.0 {
        // 8..16 bytes ramps from 0.4 to 0.6 — small decoders get
        // a credible base score rather than being capped at 0.5.
        return 0.4 + (b - 8.0) / 8.0 * 0.2;
    }
    if b < 256.0 {
        // 16..256 bytes ramps from 0.6 to 1.0.
        return 0.6 + 0.4 * ((b - 16.0) / (256.0 - 16.0));
    }
    if b < 2048.0 {
        return 1.0 - 0.5 * ((b - 256.0) / (2048.0 - 256.0));
    }
    if b < 8192.0 {
        return 0.5 * (1.0 - (b - 2048.0) / (8192.0 - 2048.0));
    }
    0.0
}

/// Caller-count score: saturates quickly — even a couple of callers
/// is a meaningful signal.
fn caller_score(n: u32) -> f64 {
    match n {
        0 => 0.0,
        1 => 0.4,
        2 => 0.7,
        _ => 1.0,
    }
}

#[cfg(test)]
mod purity_tests {
    use super::*;

    #[test]
    fn import_purity_falls_off_quickly() {
        assert_eq!(import_purity_score(0), 1.0);
        assert!(import_purity_score(1) > 0.5);
        assert!(import_purity_score(3) < 0.3);
        assert_eq!(import_purity_score(10), 0.0);
    }

    #[test]
    fn leaf_score_rewards_pure_leaves() {
        assert_eq!(leaf_score(0), 1.0);
        assert!(leaf_score(1) > 0.5);
        assert!(leaf_score(2) < 0.5);
        assert!(leaf_score(3) < 0.3);
        assert_eq!(leaf_score(8), 0.0);
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

    /// A trivial "no-op" function should score low.
    #[test]
    fn trivial_function_scores_low() {
        // mov rax, 0 ; ret
        let code = vec![0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00, 0xC3];
        let parsed = parsed_for(&code, 0x1000);
        let analyzer = CodeAnalyzer::new(&code, &parsed);
        let funcs = analyzer.discover_from_entry(0x1000);
        let scores = score_all(&analyzer, &funcs, ScoreWeights::default());
        let s = scores[&0x1000];
        assert!(s.score < 0.4, "score too high: {:?}", s);
        assert_eq!(s.components.loop_count, 0);
    }

    /// A function with a tight XOR-decode loop should score high.
    #[test]
    fn xor_loop_scores_high() {
        // Hand-coded XOR loop:
        //   xor ecx, ecx                  (2 bytes: 31 c9)            @ 0x2000
        // loop_top:
        //   xor byte [rdi+rcx], 0x42      (4 bytes: 80 34 0f 42)      @ 0x2002
        //   add rcx, 1                    (4 bytes: 48 83 c1 01)      @ 0x2006
        //   cmp rcx, rsi                  (3 bytes: 48 39 f1)         @ 0x200A
        //   jb loop_top                   (2 bytes: 72 f3)            @ 0x200D
        //                                 ; next_ip = 0x200F, target = 0x2002, disp = -13 = 0xf3
        //   ret                           (1 byte:  c3)               @ 0x200F
        let code: Vec<u8> = vec![
            0x31, 0xC9, // xor ecx, ecx
            0x80, 0x34, 0x0F, 0x42, // xor byte [rdi+rcx], 0x42
            0x48, 0x83, 0xC1, 0x01, // add rcx, 1
            0x48, 0x39, 0xF1, // cmp rcx, rsi
            0x72, 0xF3, // jb -13 (back to 0x2002)
            0xC3, // ret
        ];
        let parsed = parsed_for(&code, 0x2000);
        let analyzer = CodeAnalyzer::new(&code, &parsed);
        let funcs = analyzer.discover_from_entry(0x2000);
        let scores = score_all(&analyzer, &funcs, ScoreWeights::default());
        let s = scores[&0x2000];
        assert!(s.score > 0.5, "score too low: {:?}", s);
        assert!(
            s.components.bitwise_density > 0.3,
            "density too low: {:?}",
            s.components
        );
        assert!(
            s.components.loop_count >= 1,
            "no loop detected: {:?}",
            s.components
        );
    }

    /// Caller count should add a multiplicative-ish boost.
    #[test]
    fn caller_count_raises_score() {
        // Same XOR loop as above; manually score with cc=0 vs cc=5.
        let code: Vec<u8> = vec![
            0x31, 0xC9, 0x80, 0x34, 0x0F, 0x42, 0x48, 0x83, 0xC1, 0x01, 0x48, 0x39, 0xF1, 0x72,
            0xF3, 0xC3,
        ];
        let parsed = parsed_for(&code, 0x3000);
        let analyzer = CodeAnalyzer::new(&code, &parsed);
        let func = analyzer.analyze_function(0x3000).unwrap();
        let s_alone = score_function(&analyzer, &func, 0, ScoreWeights::default()).score;
        let s_popular = score_function(&analyzer, &func, 10, ScoreWeights::default()).score;
        assert!(
            s_popular > s_alone,
            "popular {} should beat alone {}",
            s_popular,
            s_alone
        );
    }

    #[test]
    fn ranking_filters_by_min_score() {
        let mut scores: BTreeMap<u64, DecoderScore> = BTreeMap::new();
        for (va, s) in [(0x100u64, 0.1), (0x200, 0.9), (0x300, 0.5)] {
            scores.insert(
                va,
                DecoderScore {
                    score: s,
                    components: ScoreComponents::default(),
                },
            );
        }
        let ranked = rank_candidates(&scores, 0.4);
        assert_eq!(ranked.len(), 2);
        assert_eq!(ranked[0].0, 0x200); // sorted descending
        assert_eq!(ranked[1].0, 0x300);
    }

    #[test]
    fn size_score_peaks_in_middle() {
        assert_eq!(size_score(0), 0.0);
        let s_small = size_score(64);
        let s_medium = size_score(256);
        let s_large = size_score(4096);
        let s_huge = size_score(100_000);
        assert!(s_medium > s_small);
        assert!(s_medium > s_large);
        assert!(s_large > s_huge);
        assert_eq!(s_huge, 0.0);
    }
}
