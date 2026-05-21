//! Per-string quality scoring.
//!
//! Raw printable-byte scans always pick up some amount of noise:
//! repeated-character runs (`AAAAAAAA`), single-symbol filler
//! (`////////`, `++++++++`), low-entropy pattern bytes
//! (`\x20\x20\x20\x20`), and similar. These pass `is_printable`
//! but carry no useful information for an analyst.
//!
//! [`string_quality`] returns a score in `[0.0, 1.0]` that combines
//! a handful of simple, predictable signals:
//!
//! * **Character diversity** — how many distinct characters the
//!   string contains, normalized against its length.
//! * **Longest single-character run** — penalizes strings that are
//!   mostly one character repeated.
//! * **Alphanumeric content** — the fraction of bytes that are
//!   `[A-Za-z0-9]`, the strongest single signal that a string
//!   carries human-readable content.
//! * **Length bonus** — very short strings get a small score
//!   floor so legitimate 4-6 character literals aren't penalized
//!   into the dirt.
//!
//! The function is deliberately allocation-free: it does a single
//! O(n) pass over the string's bytes.

/// Score `s` in `[0.0, 1.0]`. Higher = more likely meaningful text.
///
/// The empty string scores `0.0`. A typical English-language string
/// scores in the `0.7..1.0` range. Single-character or near-single-
/// character runs (`AAAAAA`, `//////`) score below `0.3`.
pub fn string_quality(s: &str) -> f64 {
    let bytes = s.as_bytes();
    let n = bytes.len();
    if n == 0 {
        return 0.0;
    }

    // O(n) sweep: count alphanumeric, track distinct bytes (256-bit
    // bitset on the stack), find the longest single-character run.
    let mut seen = [false; 256];
    let mut distinct: u32 = 0;
    let mut alnum: u32 = 0;
    let mut prev: u8 = 0;
    let mut run: u32 = 1;
    let mut max_run: u32 = 1;
    for (i, &b) in bytes.iter().enumerate() {
        if !seen[b as usize] {
            seen[b as usize] = true;
            distinct += 1;
        }
        if b.is_ascii_alphanumeric() {
            alnum += 1;
        }
        if i > 0 {
            if b == prev {
                run += 1;
                if run > max_run {
                    max_run = run;
                }
            } else {
                run = 1;
            }
        }
        prev = b;
    }

    let n_f = n as f64;
    // Component scores, each in [0, 1].
    let diversity = (distinct as f64 / n_f).clamp(0.0, 1.0);
    let alnum_ratio = (alnum as f64 / n_f).clamp(0.0, 1.0);
    // Longer single-character runs are worse. 1 == no repeats at
    // all, n == the whole string is one character.
    let run_penalty = 1.0 - ((max_run as f64 - 1.0) / n_f).clamp(0.0, 1.0);
    // Combine alnum_ratio with diversity multiplicatively so that
    // a single repeated alphanumeric character (e.g. `AAAAAAAA`)
    // doesn't get a high score on the alnum signal alone — it
    // needs *both* good alphanumeric content and a non-trivial
    // distinct-character count to score well.
    let effective_alnum = alnum_ratio * diversity;
    // Very short strings: give a small floor so they aren't
    // punished out of existence by the diversity term (which can't
    // exceed `n / n = 1.0` but for `n=4` and 3 distinct chars is
    // already only 0.75).
    let length_floor = if n <= 6 { 0.2 } else { 0.0 };

    // Weighted combination. effective_alnum carries the bulk of
    // the signal; the run penalty is a secondary check that hits
    // pure single-character runs hard.
    let composite = 0.6 * effective_alnum + 0.4 * run_penalty;
    (composite + length_floor).clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_string_is_zero() {
        assert_eq!(string_quality(""), 0.0);
    }

    #[test]
    fn high_quality_strings_score_high() {
        assert!(string_quality("Hello, world!") > 0.65);
        assert!(string_quality("kernel32.dll") > 0.65);
        assert!(string_quality("InitializeCriticalSection") > 0.7);
    }

    #[test]
    fn single_character_runs_score_low() {
        assert!(string_quality("AAAAAAAA") < 0.35);
        assert!(string_quality("////////") < 0.35);
        assert!(string_quality("++++++++++") < 0.35);
    }

    #[test]
    fn assembly_byte_runs_are_not_classified_as_noise() {
        // `AWAVAUATSH` is the byte encoding of `push r15; push r14;
        // push r13; push r12; push rbx; push rax` — it looks like
        // text but is actually executable code. Content-based
        // quality scoring can't distinguish it from real text
        // (well-mixed uppercase letters), so it passes the noise
        // filter; the dedicated `skip_code_sections` option is what
        // suppresses these. Asserting the score is non-trivial
        // documents this limitation explicitly.
        let q = string_quality("AWAVAUATSH");
        assert!(q > 0.5, "assembly run scores {q}, expected > 0.5");
    }

    #[test]
    fn short_strings_get_a_floor() {
        // 4-character strings shouldn't be punished into the dirt.
        let q = string_quality("HTTP");
        assert!(q > 0.45, "short alphanumeric should clear 0.45, got {q}");
    }
}
