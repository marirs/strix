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

#[cfg(feature = "unicorn")]
pub use strix_emulator::{DumpedString, dump_decoder_at};

/// Dump-decoder convenience wrapper: parses `input`, then runs
/// the emulation driver against the function at `va` and returns
/// each recovered string annotated with the writing instruction's
/// disassembly. Only available when built with the `unicorn`
/// feature.
#[cfg(feature = "unicorn")]
pub fn dump_decoder(input: &[u8], options: &ExtractOptions, va: u64) -> Result<Vec<DumpedString>> {
    let parsed = strix_format::parse(input, options.format_override)?;
    dump_decoder_at(input, &parsed, options, va)
}

/// Run all enabled extractors over `input` and return a combined result.
///
/// This is the main library entry point. The returned
/// [`ExtractionResult`] borrows from `input`; bind `input` to a name
/// that lives at least as long as the result, or call
/// [`ExtractionResult::into_owned`].
pub fn extract<'a>(input: &'a [u8], options: &ExtractOptions) -> Result<ExtractionResult<'a>> {
    // 1. Parse the input file (or treat as shellcode). For fat
    //    Mach-O `parse_all` returns one ParsedInput per arch so we
    //    can run the extraction pipeline against each slice.
    let parsed_list = match strix_format::parse_all(input, options.format_override) {
        Ok(v) => v,
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
            let mut p = ParsedInput {
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
            };
            p.warnings
                .push("input not recognized as PE/ELF/Mach-O; running over raw bytes".to_string());
            vec![p]
        }
        Err(e) => return Err(e),
    };

    // Use the first arch's metadata for the result header. For
    // fat binaries we tag each per-arch section name with the
    // arch so analysts can tell strings apart by source slice.
    let mut result = ExtractionResult::new(parsed_list[0].metadata.clone());
    let is_fat = parsed_list.len() > 1;
    if is_fat {
        result.warnings.push(format!(
            "fat Mach-O: analyzing all {} architectures",
            parsed_list.len()
        ));
    }
    // Surface any non-fatal observations from the format parser
    // (carries through warnings the parser emitted per arch).
    for parsed in &parsed_list {
        for w in &parsed.warnings {
            result.warnings.push(w.clone());
        }
    }

    // Run the per-arch extraction loop. For non-fat binaries this
    // executes once; for fat Mach-O it executes per arch and the
    // results all merge into `result`.
    for parsed in &parsed_list {
        extract_one(input, options, parsed, is_fat, &mut result)?;
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

/// Run the static / language / emulation / xref passes against a
/// single parsed arch and append everything into `result`. Pulled
/// out of `extract` so we can run it once per arch for fat Mach-O.
fn extract_one<'a>(
    input: &'a [u8],
    options: &ExtractOptions,
    parsed: &ParsedInput,
    is_fat: bool,
    result: &mut ExtractionResult<'a>,
) -> Result<()> {
    // Helper to tag section names with the arch when running over
    // a fat binary, so analysts can tell same-name sections apart
    // across slices (e.g., __TEXT,__cstring from x86_64 vs arm64).
    let arch_tag = if is_fat {
        parsed.metadata.arch.clone()
    } else {
        None
    };
    let tag_section = |name: &str| -> String {
        if let Some(arch) = &arch_tag {
            format!("[{arch}] {name}")
        } else {
            name.to_string()
        }
    };

    // 2. Static strings (always-on, zero-copy).
    if options.is_enabled(StringKind::StaticAscii) || options.is_enabled(StringKind::StaticUtf16Le)
    {
        let (scan_start, scan_view) = match parsed.scan_window {
            Some((start, end)) => {
                let s = (start as usize).min(input.len());
                let e = (end as usize).min(input.len()).max(s);
                (s, &input[s..e])
            }
            None => (0usize, input),
        };
        let strings = strix_static::extract(scan_view, options)?;
        for mut s in strings {
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
                s.location.section = Some(tag_section(&sec.name));
            }
            result.strings.push(s);
        }
    }

    // 3. Language-specific strings (Go / Rust).
    let lang_kinds_on = options.is_enabled(StringKind::Go) || options.is_enabled(StringKind::Rust);
    if lang_kinds_on {
        let lang_strings = strix_lang::extract_with_context(input, parsed, options)?;
        if !lang_strings.is_empty() {
            let tc = strix_lang::detect_toolchain(input, parsed);
            // First-arch toolchain wins for the result-level
            // language field; subsequent arches can't disagree
            // in practice (universal binaries are built from one
            // source).
            if result.input.language.is_none() {
                result.input.language = match tc {
                    strix_lang::Toolchain::Go => Some("go".to_string()),
                    strix_lang::Toolchain::Rust => Some("rust".to_string()),
                    strix_lang::Toolchain::Unknown => None,
                };
            }
        }
        for mut s in lang_strings {
            if let Some(sec_name) = s.location.section.take() {
                s.location.section = Some(tag_section(&sec_name));
            }
            result.strings.push(s);
        }
    }

    // 4. Emulation-backed extractors.
    let emul = strix_emulator::extract_emulated(input, parsed, options)?;
    result.strings.extend(emul.decoded);
    result.strings.extend(emul.stack);
    result.strings.extend(emul.tight);
    // For fat binaries, candidates from later arches accumulate;
    // we de-dup by VA (the same arch's candidates don't overlap)
    // by appending and letting analysts see all of them.
    for c in emul.candidates {
        result.candidates.push(c);
    }
    for w in emul.warnings {
        result.warnings.push(w);
    }

    // 5. Xref counts on static strings for this arch.
    {
        use std::collections::HashSet;
        let mut targets: HashSet<u64> = HashSet::new();
        for s in &result.strings {
            if matches!(s.kind, StringKind::StaticAscii | StringKind::StaticUtf16Le)
                && let Some(va) = s.location.address
            {
                targets.insert(va);
            }
        }
        if !targets.is_empty() {
            let analyzer = strix_emulator::analyzer::CodeAnalyzer::new(input, parsed);
            let counts = analyzer.count_rip_xrefs(&targets);
            for s in &mut result.strings {
                if !matches!(s.kind, StringKind::StaticAscii | StringKind::StaticUtf16Le) {
                    continue;
                }
                if let Some(va) = s.location.address
                    && let Some(count) = counts.get(&va)
                {
                    // Accumulate counts across arches — a string
                    // referenced from both x86_64 and arm64 gets
                    // both refs counted.
                    s.location.xrefs = s.location.xrefs.saturating_add(*count);
                }
            }
        }
    }

    Ok(())
}
