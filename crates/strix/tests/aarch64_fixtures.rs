//! End-to-end AArch64 fixtures.
//!
//! These exercise the public [`strix::extract`] API on hand-crafted
//! AArch64 shellcode blobs. The blobs are intentionally tiny — just
//! enough to validate each phase of the pipeline:
//!
//! * Function discovery (the analyzer must recognize the prologue).
//! * Stack-string pattern matcher (`movz wN, #c; strb wN, [sp, #off]`).
//! * Brute-force decoder emulation (writes to the X0 dst pointer
//!   land in `scratch` and surface as `Decoded` strings).
//!
//! Tests that require the emulator (decoded-string recovery) are
//! gated behind the `unicorn` feature flag; the stack-string tests
//! run with or without it.
//!
//! All shellcode is assembled by hand with the AArch64 encodings
//! documented inline. The format hint is `Sc64Arm64` so strix parses
//! the bytes as raw AArch64 instructions with arch metadata set
//! accordingly.

use strix::{ExtractOptions, FormatHint, StringKind, extract};

/// Default-ish options for AArch64 emulation runs: enable all string
/// kinds, generous step cap.
fn opts() -> ExtractOptions {
    ExtractOptions {
        min_length: 4,
        enabled: None,
        format_override: Some(FormatHint::Sc64Arm64),
        max_emulation_steps: 20_000,
        dedupe: true,
        skip_code_sections: false,
        skip_library_strings: false,
        min_quality: 0.0,
    }
}

/// A leaf function that builds "STACK" on the stack via the
/// `movz wN, #c; strb wN, [sp, #off]` idiom, then unwinds and
/// returns. The AArch64 stack-string pattern matcher should pick
/// every byte up and flush them as a contiguous printable run.
///
/// Disassembly:
///
/// ```text
/// 0x00  sub  sp, sp, #16              ; prologue (recognized by analyzer)
/// 0x04  movz w1, #'S'                 ; 0x53
/// 0x08  strb w1, [sp, #0]
/// 0x0C  movz w1, #'T'                 ; 0x54
/// 0x10  strb w1, [sp, #1]
/// 0x14  movz w1, #'A'                 ; 0x41
/// 0x18  strb w1, [sp, #2]
/// 0x1C  movz w1, #'C'                 ; 0x43
/// 0x20  strb w1, [sp, #3]
/// 0x24  movz w1, #'K'                 ; 0x4B
/// 0x28  strb w1, [sp, #4]
/// 0x2C  add  sp, sp, #16              ; epilogue
/// 0x30  ret
/// ```
#[test]
fn aarch64_stack_string_pattern_matcher_recovers_stack_bytes() {
    let code: Vec<u8> = vec![
        // sub sp, sp, #16             → 0xD10043FF → FF 43 00 D1
        0xFF, 0x43, 0x00, 0xD1, // movz w1, #'S' (0x53)         → 0x52800A61 → 61 0A 80 52
        0x61, 0x0A, 0x80, 0x52, // strb w1, [sp, #0]            → 0x390003E1 → E1 03 00 39
        0xE1, 0x03, 0x00, 0x39, // movz w1, #'T' (0x54)         → 0x52800A81 → 81 0A 80 52
        0x81, 0x0A, 0x80, 0x52, // strb w1, [sp, #1]            → 0x390007E1 → E1 07 00 39
        0xE1, 0x07, 0x00, 0x39, // movz w1, #'A' (0x41)         → 0x52800821 → 21 08 80 52
        0x21, 0x08, 0x80, 0x52, // strb w1, [sp, #2]            → 0x39000BE1 → E1 0B 00 39
        0xE1, 0x0B, 0x00, 0x39, // movz w1, #'C' (0x43)         → 0x52800861 → 61 08 80 52
        0x61, 0x08, 0x80, 0x52, // strb w1, [sp, #3]            → 0x39000FE1 → E1 0F 00 39
        0xE1, 0x0F, 0x00, 0x39, // movz w1, #'K' (0x4B)         → 0x52800961 → 61 09 80 52
        0x61, 0x09, 0x80, 0x52, // strb w1, [sp, #4]            → 0x390013E1 → E1 13 00 39
        0xE1, 0x13, 0x00, 0x39, // add sp, sp, #16              → 0x910043FF → FF 43 00 91
        0xFF, 0x43, 0x00, 0x91, // ret                          → 0xD65F03C0 → C0 03 5F D6
        0xC0, 0x03, 0x5F, 0xD6,
    ];

    let result = extract(&code, &opts()).expect("extract");
    let stack_values: Vec<&str> = result
        .strings
        .iter()
        .filter(|s| s.kind == StringKind::Stack || s.kind == StringKind::Tight)
        .map(|s| s.value.as_ref())
        .collect();
    assert!(
        stack_values.contains(&"STACK"),
        "expected STACK in stack/tight bucket, got {:?}",
        result.strings
    );
}

/// End-to-end emulation pipeline. The function writes "DECODED"
/// bytewise to the pointer in X0 (the first AAPCS64 argument), then
/// returns. The driver's brute-force fuzzer points X0 at the
/// pre-mapped `scratch` region; after emulation, the scan picks
/// the printable run up and surfaces it as a `Decoded` string.
///
/// This validates Phases A (emulator backend), B (driver), and E
/// (lib wiring) all at once.
///
/// Disassembly:
///
/// ```text
/// 0x00  movz w1, #'D'; strb w1, [x0, #0]
/// 0x08  movz w1, #'E'; strb w1, [x0, #1]
/// 0x10  movz w1, #'C'; strb w1, [x0, #2]
/// 0x18  movz w1, #'O'; strb w1, [x0, #3]
/// 0x20  movz w1, #'D'; strb w1, [x0, #4]
/// 0x28  movz w1, #'E'; strb w1, [x0, #5]
/// 0x30  movz w1, #'D'; strb w1, [x0, #6]
/// 0x38  ret
/// ```
#[cfg(feature = "unicorn")]
#[test]
fn aarch64_decoded_string_via_brute_force_fuzz() {
    // STRB w1, [x0, #imm] base = 0x39000001 | (imm12 << 10) | (Rn=0)<<5 | Rt=1
    //   = 0x39000001 | (imm12 << 10)
    // Encoded LE for imm=0..6:
    //   0  → 0x39000001 → 01 00 00 39
    //   1  → 0x39000401 → 01 04 00 39
    //   2  → 0x39000801 → 01 08 00 39
    //   3  → 0x39000C01 → 01 0C 00 39
    //   4  → 0x39001001 → 01 10 00 39
    //   5  → 0x39001401 → 01 14 00 39
    //   6  → 0x39001801 → 01 18 00 39
    //
    // movz w1, #c  = 0x52800000 | (c << 5) | 1
    //   'D' (0x44) → 0x52800881 → 81 08 80 52
    //   'E' (0x45) → 0x528008A1 → A1 08 80 52
    //   'C' (0x43) → 0x52800861 → 61 08 80 52
    //   'O' (0x4F) → 0x528009E1 → E1 09 80 52
    let code: Vec<u8> = vec![
        // movz w1, #'D'
        0x81, 0x08, 0x80, 0x52, // strb w1, [x0, #0]
        0x01, 0x00, 0x00, 0x39, // movz w1, #'E'
        0xA1, 0x08, 0x80, 0x52, // strb w1, [x0, #1]
        0x01, 0x04, 0x00, 0x39, // movz w1, #'C'
        0x61, 0x08, 0x80, 0x52, // strb w1, [x0, #2]
        0x01, 0x08, 0x00, 0x39, // movz w1, #'O'
        0xE1, 0x09, 0x80, 0x52, // strb w1, [x0, #3]
        0x01, 0x0C, 0x00, 0x39, // movz w1, #'D'
        0x81, 0x08, 0x80, 0x52, // strb w1, [x0, #4]
        0x01, 0x10, 0x00, 0x39, // movz w1, #'E'
        0xA1, 0x08, 0x80, 0x52, // strb w1, [x0, #5]
        0x01, 0x14, 0x00, 0x39, // movz w1, #'D'
        0x81, 0x08, 0x80, 0x52, // strb w1, [x0, #6]
        0x01, 0x18, 0x00, 0x39, // ret
        0xC0, 0x03, 0x5F, 0xD6,
    ];

    let result = extract(&code, &opts()).expect("extract");
    let decoded: Vec<&str> = result
        .strings
        .iter()
        .filter(|s| s.kind == StringKind::Decoded)
        .map(|s| s.value.as_ref())
        .collect();
    assert!(
        decoded.contains(&"DECODED"),
        "expected DECODED in decoded bucket, got {:?}",
        result.strings
    );
}

/// The pipeline must also report sensible metadata on the result.
/// At minimum, the parsed format should be `sc64` (we share the
/// shellcode format string between the x86_64 and AArch64 variants
/// since the wire format is identical — just the arch differs) and
/// the arch should be `aarch64`.
#[test]
fn aarch64_shellcode_metadata_is_recorded() {
    // Minimal 4-byte function: just `ret`.
    let code: Vec<u8> = vec![0xC0, 0x03, 0x5F, 0xD6];
    let result = extract(&code, &opts()).expect("extract");
    assert_eq!(
        result.input.arch.as_deref(),
        Some("aarch64"),
        "expected arch=aarch64 in result metadata"
    );
    assert_eq!(result.input.bits, Some(64));
}
