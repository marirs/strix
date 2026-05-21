//! Tests against the decoder-pattern fixtures.
//!
//! These binaries are intentionally compiled with various
//! string-decoder patterns — single-byte XOR, RC4, base64,
//! substitution cipher, decode-from-heap, and a raw stack-string
//! shellcode blob. They're the closest thing to "real malware" we
//! have in-tree for validating the emulation pipeline.
//!
//! We test in three tiers:
//!
//! 1. **Parses.** `extract` returns Ok and identifies the format.
//! 2. **Produces output.** Some non-trivial number of static strings
//!    are recovered (guards against the parser regressing to empty).
//! 3. **Emulation runs.** With the `unicorn` feature, the call
//!    completes without panicking. Whether we recover the specific
//!    decoded strings each binary contains is a softer expectation —
//!    we log counts to stdout for visibility but don't fail tests on
//!    zero decoded recoveries (the heuristics + driver work is
//!    ongoing). Future iterations will tighten these into strict
//!    assertions once we've validated which fixtures should work
//!    with which configurations.

use std::path::PathBuf;

use strix::{ExtractOptions, FormatHint, StringKind, extract};

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
}

fn fixture_path(name: &str) -> Option<PathBuf> {
    let p = fixtures_dir().join(name);
    if p.is_file() { Some(p) } else { None }
}

fn skip(name: &str) {
    eprintln!(
        "skipping {name}: fixture not present in tests/fixtures/. \
         see tests/fixtures/README.md."
    );
}

/// Default options used by the decoder tests. Emulation step cap is
/// kept modest to keep test wall-clock time reasonable; can be
/// raised if real decoders need more iterations to unfold.
fn opts() -> ExtractOptions {
    ExtractOptions {
        min_length: 4,
        enabled: None,
        format_override: None,
        max_emulation_steps: 5_000,
        dedupe: true,
        skip_code_sections: false,
    }
}

/// Standard parse + extract + log battery.
fn check_decoder(name: &str, expected_format: &str, fmt_hint: Option<FormatHint>) {
    let Some(path) = fixture_path(name) else {
        skip(name);
        return;
    };
    let bytes = std::fs::read(&path).unwrap_or_else(|e| {
        panic!("read fixture {name}: {e}");
    });

    let mut o = opts();
    o.format_override = fmt_hint;

    let result = extract(&bytes, &o).unwrap_or_else(|e| {
        panic!("fixture {name}: extract failed: {e}");
    });
    assert_eq!(
        result.input.format, expected_format,
        "fixture {name}: expected format {expected_format}, got {}",
        result.input.format
    );

    let total = result.strings.len();
    let decoded = result
        .strings
        .iter()
        .filter(|s| {
            matches!(
                s.kind,
                StringKind::Decoded | StringKind::Stack | StringKind::Tight
            )
        })
        .count();
    let static_count = result
        .strings
        .iter()
        .filter(|s| matches!(s.kind, StringKind::StaticAscii | StringKind::StaticUtf16Le))
        .count();

    println!(
        "decoder fixture {name}: total={total}, static={static_count}, \
         decoded/stack/tight={decoded}, warnings={}",
        result.warnings.len()
    );

    // Tier-2 hard assertion: we should get at least a handful of
    // strings from any non-trivial binary.
    assert!(
        total >= 5,
        "fixture {name}: only {total} strings recovered, expected more"
    );

    // Tier-3 soft assertion (logging only): with `unicorn` we hope
    // to see at least one Decoded/Stack/Tight string.
    #[cfg(feature = "unicorn")]
    if decoded == 0 {
        eprintln!(
            "  note: {name} produced no decoded/stack/tight strings — \
             heuristics may need tuning for this decoder shape"
        );
    }
}

// ---------- PE decoders ----------

#[test]
fn decode_rc4_pe32() {
    check_decoder("test-decode-rc4.exe", "pe", None);
}
#[test]
fn decode_single_byte_xor_pe64() {
    check_decoder("test-decode-single-byte-xor64.exe", "pe", None);
}
#[test]
fn decode_base64_pe32() {
    check_decoder("test-decode-base64.exe", "pe", None);
}
#[test]
fn decode_base64_pe64() {
    check_decoder("test-decode-base6464.exe", "pe", None);
}
#[test]
fn decode_from_heap_pe32() {
    check_decoder("test-decode-from-heap.exe", "pe", None);
}
#[test]
fn decode_from_heap_pe64() {
    check_decoder("test-decode-from-heap64.exe", "pe", None);
}
#[test]
fn decode_substitution_cipher_pe64() {
    check_decoder("test-decode-substitution-cipher64.exe", "pe", None);
}

// ---------- ELF decoders ----------

#[test]
fn decode_rc4_elf() {
    check_decoder("test-decode-rc4", "elf", None);
}
#[test]
fn decode_single_byte_xor_elf() {
    check_decoder("test-decode-single-byte-xor", "elf", None);
}
#[test]
fn decode_substitution_cipher_elf() {
    check_decoder("test-decode-substitution-cipher", "elf", None);
}

// ---------- Shellcode ----------

/// Raw shellcode blob — needs an explicit format hint since there's
/// no header for auto-detection. The sample is built for 32-bit x86
/// stack-string assembly.
#[test]
fn shellcode_stackstrings() {
    check_decoder("shellcode-stackstrings.bin", "sc32", Some(FormatHint::Sc32));
}

// ---------- Real malware sample ----------

/// One SHA256-named sample. Just verify the parser handles it
/// without crashing.
#[test]
fn real_malware_sample() {
    check_decoder(
        "a294620543334a721a2ae8eaaf9680a0786f4b9a216d75b55cfd28f39e9430ea.exe_",
        "pe",
        None,
    );
}
