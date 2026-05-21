//! End-to-end integration tests for the umbrella crate.
//!
//! These exercise the public API (`strix::extract`) over synthetic
//! byte buffers so they don't require checking malware samples into
//! the repo.

use std::borrow::Cow;

use strix::{ExtractOptions, FormatHint, StringKind, extract};

#[test]
fn extracts_ascii_strings_from_raw_bytes() {
    // Three printable runs separated by NULs.
    let buf = b"\x00hello world\x00ab\x00greetings\x00x";
    let opts = ExtractOptions {
        min_length: 4,
        enabled: Some(vec![StringKind::StaticAscii]),
        format_override: Some(FormatHint::Sc64),
        max_emulation_steps: 0,
        dedupe: false,
        skip_code_sections: false,
        skip_library_strings: false,
    };
    let result = extract(buf, &opts).expect("extract");
    let values: Vec<&str> = result.strings.iter().map(|s| s.value.as_ref()).collect();
    assert!(values.contains(&"hello world"));
    assert!(values.contains(&"greetings"));
    // "ab" is below min_length and must not appear.
    assert!(!values.contains(&"ab"));
}

#[test]
fn ascii_strings_borrow_from_input() {
    let buf = b"\x00abcdef\x00";
    let opts = ExtractOptions {
        min_length: 4,
        enabled: Some(vec![StringKind::StaticAscii]),
        format_override: Some(FormatHint::Sc64),
        max_emulation_steps: 0,
        dedupe: false,
        skip_code_sections: false,
        skip_library_strings: false,
    };
    let result = extract(buf, &opts).expect("extract");
    assert_eq!(result.strings.len(), 1);
    match &result.strings[0].value {
        Cow::Borrowed(_) => {} // good — zero-copy path used
        Cow::Owned(_) => panic!("expected borrowed slice, got owned String"),
    }
}

#[test]
fn json_round_trip_is_lossless() {
    let buf = b"\x00hello\x00world\x00";
    let opts = ExtractOptions {
        min_length: 4,
        enabled: Some(vec![StringKind::StaticAscii]),
        format_override: Some(FormatHint::Sc64),
        max_emulation_steps: 0,
        dedupe: false,
        skip_code_sections: false,
        skip_library_strings: false,
    };
    let result = extract(buf, &opts).expect("extract");
    let json = serde_json::to_string(&result).expect("to_string");
    assert!(json.contains("\"hello\""));
    assert!(json.contains("\"world\""));
    assert!(json.contains("\"static_ascii\""));
}

#[test]
fn emulation_extractors_do_not_fail() {
    // Enabling decoded/stack/tight should never return Err, regardless
    // of whether the `unicorn` feature is compiled in. Without the
    // feature we expect a warning; with it we expect emulation to run
    // (and likely find nothing in a 9-byte garbage buffer).
    let buf = b"\x00hello\x00";
    let opts = ExtractOptions {
        min_length: 4,
        enabled: Some(vec![
            StringKind::Decoded,
            StringKind::Stack,
            StringKind::Tight,
        ]),
        format_override: Some(FormatHint::Sc64),
        max_emulation_steps: 1_000,
        dedupe: false,
        skip_code_sections: false,
        skip_library_strings: false,
    };
    let _result = extract(buf, &opts).expect("emulation extractors must not error");
}

#[test]
fn unknown_format_falls_back_to_raw_with_warning() {
    let buf = b"\x00hello world\x00";
    let opts = ExtractOptions {
        min_length: 4,
        enabled: Some(vec![StringKind::StaticAscii]),
        format_override: None,
        max_emulation_steps: 0,
        dedupe: false,
        skip_code_sections: false,
        skip_library_strings: false,
    };
    let result = extract(buf, &opts).expect("extract");
    assert_eq!(result.input.format, "unknown");
    assert!(!result.warnings.is_empty());
    let values: Vec<&str> = result.strings.iter().map(|s| s.value.as_ref()).collect();
    assert!(values.contains(&"hello world"));
}

#[test]
fn utf16le_strings_are_extracted() {
    // "Mozilla" in UTF-16LE
    let mut buf = vec![0u8; 2];
    for c in b"Mozilla" {
        buf.push(*c);
        buf.push(0x00);
    }
    buf.extend_from_slice(b"\x00\x00");
    let opts = ExtractOptions {
        min_length: 4,
        enabled: Some(vec![StringKind::StaticUtf16Le]),
        format_override: Some(FormatHint::Sc64),
        max_emulation_steps: 0,
        dedupe: false,
        skip_code_sections: false,
        skip_library_strings: false,
    };
    let result = extract(&buf, &opts).expect("extract");
    let values: Vec<&str> = result.strings.iter().map(|s| s.value.as_ref()).collect();
    assert!(values.contains(&"Mozilla"));
}

/// With `dedupe: true`, repeated occurrences of the same string in
/// the same kind/encoding collapse into one. Without it, every
/// occurrence is preserved.
#[test]
fn dedupe_drops_repeats() {
    let buf = b"\x00hello\x00\x00hello\x00\x00world\x00\x00hello\x00";
    let opts_keep = ExtractOptions {
        min_length: 4,
        enabled: Some(vec![StringKind::StaticAscii]),
        format_override: Some(FormatHint::Sc64),
        max_emulation_steps: 0,
        dedupe: false,
        skip_code_sections: false,
        skip_library_strings: false,
    };
    let opts_drop = ExtractOptions {
        dedupe: true,
        ..opts_keep.clone()
    };

    let kept = extract(buf, &opts_keep).expect("extract");
    let deduped = extract(buf, &opts_drop).expect("extract");

    let kept_values: Vec<&str> = kept.strings.iter().map(|s| s.value.as_ref()).collect();
    let dd_values: Vec<&str> = deduped.strings.iter().map(|s| s.value.as_ref()).collect();

    // The raw scan sees three "hello"s and one "world".
    assert_eq!(kept_values.iter().filter(|s| **s == "hello").count(), 3);
    assert_eq!(kept_values.iter().filter(|s| **s == "world").count(), 1);

    // After dedupe, each string appears exactly once.
    assert_eq!(dd_values.iter().filter(|s| **s == "hello").count(), 1);
    assert_eq!(dd_values.iter().filter(|s| **s == "world").count(), 1);
    assert_eq!(dd_values.len(), 2);
}

/// `skip_code_sections` drops strings whose section is marked
/// executable. We use `FormatHint::Sc64` because its single synthetic
/// section is executable, so any static string falls in it.
#[test]
fn skip_code_sections_filters_executable_section_strings() {
    let buf = b"\x00hello world\x00";

    let opts_keep = ExtractOptions {
        min_length: 4,
        enabled: Some(vec![StringKind::StaticAscii]),
        format_override: Some(FormatHint::Sc64),
        max_emulation_steps: 0,
        dedupe: false,
        skip_code_sections: false,
        skip_library_strings: false,
    };
    let opts_drop = ExtractOptions {
        skip_code_sections: true,
        skip_library_strings: false,
        ..opts_keep.clone()
    };

    let kept = extract(buf, &opts_keep).expect("extract");
    let dropped = extract(buf, &opts_drop).expect("extract");

    assert!(kept.strings.iter().any(|s| s.value == "hello world"));
    assert!(
        dropped.strings.iter().all(|s| s.value != "hello world"),
        "skip_code_sections should drop strings in executable sections, got {:?}",
        dropped.strings
    );
}

/// `skip_library_strings` drops static strings matching the
/// curated CRT / libc / Windows-API list. Verify a known library
/// name is dropped while a non-library string is preserved.
#[test]
fn skip_library_strings_filters_curated_set() {
    // "kernel32.dll" is in the library list; "myprogram.exe" is not.
    let buf = b"\x00kernel32.dll\x00myprogram.exe\x00";

    let opts_keep = ExtractOptions {
        min_length: 4,
        enabled: Some(vec![StringKind::StaticAscii]),
        format_override: Some(FormatHint::Sc64),
        max_emulation_steps: 0,
        dedupe: false,
        skip_code_sections: false,
        skip_library_strings: false,
    };
    let opts_drop = ExtractOptions {
        skip_library_strings: true,
        ..opts_keep.clone()
    };

    let kept = extract(buf, &opts_keep).expect("extract");
    let dropped = extract(buf, &opts_drop).expect("extract");

    assert!(kept.strings.iter().any(|s| s.value == "kernel32.dll"));
    assert!(kept.strings.iter().any(|s| s.value == "myprogram.exe"));
    assert!(
        dropped.strings.iter().all(|s| s.value != "kernel32.dll"),
        "skip_library_strings should drop kernel32.dll, got {:?}",
        dropped.strings
    );
    assert!(
        dropped.strings.iter().any(|s| s.value == "myprogram.exe"),
        "non-library string should survive, got {:?}",
        dropped.strings
    );
}

#[test]
fn empty_input_returns_empty_result() {
    let opts = ExtractOptions {
        min_length: 4,
        enabled: None,
        format_override: Some(FormatHint::Sc64),
        max_emulation_steps: 0,
        dedupe: false,
        skip_code_sections: false,
        skip_library_strings: false,
    };
    let result = extract(b"", &opts).expect("extract");
    assert!(result.strings.is_empty());
}

/// End-to-end test of the full decoded-string pipeline through the
/// public API.
///
/// The shellcode below is a tiny XOR decoder — it XOR-decodes a 5-byte
/// table into its first argument. We use a real decoder shape (not
/// just literal stores) because the heuristics layer filters out
/// non-decoder functions before emulation; that's the whole point of
/// the scoring pass. With `unicorn` on, the recovered string must
/// surface as a Decoded entry. Without the feature, the emulator
/// emits a warning and produces no Decoded strings.
///
/// Layout:
/// ```text
/// 0x1000  48 8D 35 14 00 00 00   lea  rsi, [rip + 0x14]   ; rsi -> table
/// 0x1007  31 C9                  xor  ecx, ecx
/// 0x1009  8A 04 0E               mov  al, [rsi + rcx]     ; loop top
/// 0x100C  34 42                  xor  al, 0x42
/// 0x100E  88 04 0F               mov  [rdi + rcx], al
/// 0x1011  48 FF C1               inc  rcx
/// 0x1014  48 83 F9 05            cmp  rcx, 5
/// 0x1018  72 EF                  jb   0x1009              ; back-edge
/// 0x101A  C3                     ret
/// 0x101B  0A 07 0E 0E 0D         encoded "HELLO" ^ 0x42
/// ```
#[test]
fn end_to_end_decoded_extraction_via_public_api() {
    let code: Vec<u8> = vec![
        0x48, 0x8D, 0x35, 0x14, 0x00, 0x00, 0x00, // lea rsi, [rip + 0x14]
        0x31, 0xC9, // xor ecx, ecx
        0x8A, 0x04, 0x0E, // mov al, [rsi+rcx]
        0x34, 0x42, // xor al, 0x42
        0x88, 0x04, 0x0F, // mov [rdi+rcx], al
        0x48, 0xFF, 0xC1, // inc rcx
        0x48, 0x83, 0xF9, 0x05, // cmp rcx, 5
        0x72, 0xEF, // jb -17 (back to 0x1009)
        0xC3, // ret
        0x0A, 0x07, 0x0E, 0x0E, 0x0D, // encoded "HELLO" ^ 0x42
    ];
    let opts = ExtractOptions {
        min_length: 4,
        enabled: Some(vec![StringKind::Decoded]),
        format_override: Some(FormatHint::Sc64),
        max_emulation_steps: 10_000,
        dedupe: false,
        skip_code_sections: false,
        skip_library_strings: false,
    };
    let result = extract(&code, &opts).expect("extract must not error");

    #[cfg(feature = "unicorn")]
    {
        let decoded: Vec<&str> = result
            .strings
            .iter()
            .filter(|s| s.kind == StringKind::Decoded)
            .map(|s| s.value.as_ref())
            .collect();
        assert!(
            decoded.contains(&"HELLO"),
            "expected HELLO in decoded strings, got {:?} (warnings: {:?})",
            decoded,
            result.warnings
        );
    }
    #[cfg(not(feature = "unicorn"))]
    {
        // Without unicorn, the emulator emits a warning and produces
        // no Decoded strings.
        assert!(result.strings.iter().all(|s| s.kind != StringKind::Decoded));
        assert!(result.warnings.iter().any(|w| w.contains("unicorn")));
    }
}
