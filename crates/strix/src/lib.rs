//! # strix
//!
//! Extract obfuscated strings from binaries, exposed as a library.
//! Given a buffer of bytes from an executable (PE / ELF / Mach-O / raw
//! shellcode), it returns the strings it can extract, with a JSON
//! schema that's stable and machine-readable for downstream tooling.
//!
//! ```no_run
//! use strix::{extract, ExtractOptions};
//!
//! let bytes = std::fs::read("malware.exe")?;
//! let result = extract(&bytes, &ExtractOptions::default())?;
//! println!("{}", serde_json::to_string_pretty(&result)?);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Zero-copy
//!
//! Strings recovered from the input directly (static, Go, Rust) are
//! returned as `Cow::Borrowed(&str)` slices into the input buffer.
//! Strings synthesized via CPU emulation (decoded/stack/tight) own
//! their bytes — those bytes don't exist in the file until emulation
//! produces them, so zero-copy is not possible there. If you need
//! `'static` outputs (e.g. to send across thread boundaries), call
//! [`ExtractionResult::into_owned`].
//!
//! ## Extractor availability
//!
//! | Extractor | Available |
//! |---|---|
//! | static (ASCII + UTF-16LE) | always |
//! | Go / Rust language strings | always |
//! | decoded / stack / tight | with `unicorn` feature, port in progress |

#![deny(rust_2018_idioms)]
#![warn(missing_docs)]

pub use strix_core::{
    Encoding, Error, ExtractOptions, ExtractedString, ExtractionResult, FormatHint, InputMetadata,
    Location, Result, StringKind,
};
pub use strix_format::{ParsedInput, Section};

/// Run all enabled extractors over `input` and return a combined result.
///
/// This is the main library entry point. The returned
/// [`ExtractionResult`] borrows from `input`; bind `input` to a name
/// that lives at least as long as the result, or call
/// [`ExtractionResult::into_owned`].
pub fn extract<'a>(input: &'a [u8], options: &ExtractOptions) -> Result<ExtractionResult<'a>> {
    // 1. Parse the input file (or treat as shellcode).
    let parsed_result = strix_format::parse(input, options.format_override);
    let (parsed, parse_warning) = match parsed_result {
        Ok(p) => (Some(p), None),
        Err(Error::UnknownFormat) => {
            // Fall back to scanning the raw bytes for static strings
            // only — best effort when the file isn't a recognized
            // executable container.
            let meta = InputMetadata {
                format: "unknown".to_string(),
                arch: None,
                bits: None,
                size: input.len() as u64,
                language: None,
            };
            (
                Some(ParsedInput {
                    metadata: meta,
                    sections: vec![Section {
                        name: "raw".to_string(),
                        file_offset: 0,
                        file_size: input.len() as u64,
                        virtual_address: 0,
                        executable: false,
                        writable: false,
                    }],
                    entry: None,
                    warnings: Vec::new(),
                    scan_window: None,
                    imports: Vec::new(),
                    symbols: Default::default(),
                }),
                Some("input not recognized as PE/ELF/Mach-O; running over raw bytes".to_string()),
            )
        }
        Err(e) => return Err(e),
    };
    let parsed = parsed.expect("set above");

    let mut result = ExtractionResult::new(parsed.metadata.clone());
    if let Some(w) = parse_warning {
        result.warnings.push(w);
    }
    // Surface any non-fatal observations from the format parser
    // (e.g. "fat Mach-O has multiple architectures").
    for w in &parsed.warnings {
        result.warnings.push(w.clone());
    }

    // 2. Static strings (always-on, zero-copy).
    if options.is_enabled(StringKind::StaticAscii) || options.is_enabled(StringKind::StaticUtf16Le)
    {
        // Restrict the scan to the active byte window if the parser
        // set one. Fat Mach-O sets this to the selected arch's slice
        // so we don't dredge duplicate strings out of the other
        // arch's load commands.
        let (scan_start, scan_view) = match parsed.scan_window {
            Some((start, end)) => {
                let s = (start as usize).min(input.len());
                let e = (end as usize).min(input.len()).max(s);
                (s, &input[s..e])
            }
            None => (0usize, input),
        };
        let strings = strix_static::extract(scan_view, options)?;
        // Annotate locations with section info from the parsed input.
        // If skip_code_sections is set, drop strings landing in an
        // executable section (typically `AWAVAUATSH`-style assembly
        // bytes that look like text but aren't meaningful).
        for mut s in strings {
            // Shift offsets from scan_view-local back to absolute.
            s.location.offset += scan_start as u64;
            let in_code = parsed
                .section_at(s.location.offset)
                .map(|sec| sec.executable)
                .unwrap_or(false);
            if options.skip_code_sections && in_code {
                continue;
            }
            if options.skip_library_strings && strix_core::is_library_string(&s.value) {
                continue;
            }
            if let Some(sec) = parsed.section_at(s.location.offset) {
                s.location.address = sec.offset_to_va(s.location.offset);
                s.location.section = Some(sec.name.clone());
            }
            result.strings.push(s);
        }
    }

    // 3. Language-specific strings (Go / Rust).
    let lang_kinds_on = options.is_enabled(StringKind::Go) || options.is_enabled(StringKind::Rust);
    if lang_kinds_on {
        let lang_strings = strix_lang::extract_with_context(input, &parsed, options)?;
        // Tag detected toolchain in input metadata.
        if !lang_strings.is_empty() {
            let tc = strix_lang::detect_toolchain(input, &parsed);
            result.input.language = match tc {
                strix_lang::Toolchain::Go => Some("go".to_string()),
                strix_lang::Toolchain::Rust => Some("rust".to_string()),
                strix_lang::Toolchain::Unknown => None,
            };
        }
        result.strings.extend(lang_strings);
    }

    // 4. Emulation-backed extractors (decoded, stack, tight). One
    //    pipeline does discovery + scoring + emulation, then we fan
    //    the results out into the result-strings list by kind. With
    //    the `unicorn` feature disabled, this returns a warning-only
    //    result rather than failing.
    let emul = strix_emulator::extract_emulated(input, &parsed, options)?;
    result.strings.extend(emul.decoded);
    result.strings.extend(emul.stack);
    result.strings.extend(emul.tight);
    result.candidates = emul.candidates;
    for w in emul.warnings {
        result.warnings.push(w);
    }

    // Optional quality filter: drop strings whose content-based
    // score falls below the user's threshold. Applied uniformly
    // across all extractors since quality is purely a function of
    // the string's contents.
    if options.min_quality > 0.0 {
        let threshold = options.min_quality;
        result
            .strings
            .retain(|s| strix_core::string_quality(&s.value) >= threshold);
    }

    // Sort by (offset, kind) for stable JSON output.
    result.strings.sort_by(|a, b| {
        a.location
            .offset
            .cmp(&b.location.offset)
            .then_with(|| format!("{:?}", a.kind).cmp(&format!("{:?}", b.kind)))
    });

    // Optional deduplication. We dedupe by (value, kind, encoding) so
    // that "the same string in ASCII and UTF-16LE" or "the same string
    // recovered as both Decoded and Stack" remain distinct entries.
    if options.dedupe {
        use std::collections::HashSet;
        let mut seen: HashSet<(String, StringKind, Encoding)> = HashSet::new();
        result
            .strings
            .retain(|s| seen.insert((s.value.to_string(), s.kind, s.encoding)));
    }

    Ok(result)
}
