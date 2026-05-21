//! Language-specific string extraction (Go, Rust).
//!
//! Go and Rust binaries store strings differently from C: their
//! runtime string representations are not NUL-terminated, so classic
//! `strings`-style scanning produces large undifferentiated blobs.
//!
//! * **Go**: `struct String { ptr: *u8, len: int }`. Strings live in a
//!   single contiguous blob and are referenced by pointer + length.
//! * **Rust**: UTF-8 string literals packed into `.rodata`, sliced by
//!   `(ptr, len)` references from code.
//!
//! A full implementation (analyzing instances of the String struct,
//! finding the monotonically-increasing length sequence to locate the
//! blob, splitting by cross-references) requires code analysis on top
//! of file parsing. This initial implementation detects the language
//! and does a UTF-8 run extraction from the read-only sections, which
//! catches the common case. Xref-driven splitting is a follow-up —
//! the trait surface is wired up so that upgrade is a localized change.

#![deny(rust_2018_idioms)]
#![warn(missing_docs)]

use std::borrow::Cow;

use strix_core::{
    Encoding, ExtractOptions, ExtractedString, Extractor, Location, Result, StringKind,
};
use strix_format::{ParsedInput, Section};

pub mod go;
pub mod rust;

/// Combined Go + Rust language extractor.
#[derive(Debug, Default, Clone, Copy)]
pub struct LangExtractor;

impl Extractor for LangExtractor {
    fn name(&self) -> &'static str {
        "lang"
    }

    fn extract<'a>(
        &self,
        _input: &'a [u8],
        _options: &ExtractOptions,
    ) -> Result<Vec<ExtractedString<'a>>> {
        // The free-function form below requires parsed-input context to
        // know which sections are read-only data. This trait method
        // exists for API symmetry but always returns empty when called
        // without context; the umbrella crate calls
        // `extract_with_context` instead.
        Ok(Vec::new())
    }
}

/// Detect which language toolchain (if any) produced this binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Toolchain {
    /// Go (`runtime.go`, `.gopclntab`, etc.).
    Go,
    /// Rust (panic strings, `.rustc` section, etc.).
    Rust,
    /// Could not be classified.
    Unknown,
}

/// Heuristically detect the toolchain by scanning for distinctive
/// section names and signature bytes.
pub fn detect_toolchain(input: &[u8], parsed: &ParsedInput) -> Toolchain {
    // Go: presence of `.gopclntab` / `.go.buildinfo` is conclusive.
    for s in &parsed.sections {
        let n = s.name.as_str();
        if n.ends_with("gopclntab") || n.contains("go.buildinfo") || n == "__gopclntab" {
            return Toolchain::Go;
        }
    }
    // Go magic: \xfb\xff\xff\xff or \xfa\xff\xff\xff at start of gopclntab.
    // Fall back to scanning for the buildinfo magic.
    if input.windows(14).any(|w| w == b"\xff Go buildinf:") {
        return Toolchain::Go;
    }

    // Rust: look for the panic info marker and rustc strings that the
    // compiler emits into .rodata for nearly every binary.
    let rust_markers: &[&[u8]] = &[
        b"rustc",
        b"library/std/src/panicking.rs",
        b"library/core/src/panicking.rs",
        b"called `Result::unwrap()`",
        b"called `Option::unwrap()`",
    ];
    if rust_markers
        .iter()
        .any(|m| input.windows(m.len()).any(|w| w == *m))
    {
        return Toolchain::Rust;
    }
    Toolchain::Unknown
}

/// Run language-specific extraction with parsed binary context.
pub fn extract_with_context<'a>(
    input: &'a [u8],
    parsed: &ParsedInput,
    options: &ExtractOptions,
) -> Result<Vec<ExtractedString<'a>>> {
    let mut out = Vec::new();
    let tc = detect_toolchain(input, parsed);
    match tc {
        Toolchain::Go if options.is_enabled(StringKind::Go) => {
            go::extract(input, parsed, options, &mut out)?;
        }
        Toolchain::Rust if options.is_enabled(StringKind::Rust) => {
            rust::extract(input, parsed, options, &mut out)?;
        }
        _ => {}
    }
    Ok(out)
}

/// Extract printable UTF-8 runs from a section's bytes.
///
/// Used as the building block for both Go and Rust extractors. The
/// returned strings borrow from `input`.
pub(crate) fn extract_utf8_runs<'a>(
    input: &'a [u8],
    section: &Section,
    min_len: usize,
    kind: StringKind,
    out: &mut Vec<ExtractedString<'a>>,
) {
    let start = section.file_offset as usize;
    let end = (section.file_offset + section.file_size) as usize;
    if start >= input.len() || end > input.len() || start >= end {
        return;
    }
    let bytes = &input[start..end];

    let mut i = 0;
    while i < bytes.len() {
        // Find the next valid UTF-8 printable run.
        let run_start = i;
        let mut run_end = i;
        while run_end < bytes.len() {
            let b = bytes[run_end];
            if b == 0 {
                break;
            }
            // Look at this byte as the start of a UTF-8 sequence.
            let width = utf8_char_width(b);
            if width == 0 || run_end + width > bytes.len() {
                break;
            }
            // Validate the sequence and check it's printable enough.
            let candidate = &bytes[run_end..run_end + width];
            match std::str::from_utf8(candidate) {
                Ok(s) => {
                    if s.chars().all(is_printable_char) {
                        run_end += width;
                    } else {
                        break;
                    }
                }
                Err(_) => break,
            }
        }

        let len = run_end - run_start;
        if len >= min_len {
            // SAFETY: every byte in `bytes[run_start..run_end]` was
            // confirmed to be part of a valid UTF-8 printable
            // sequence above.
            let s: &'a str = unsafe {
                std::str::from_utf8_unchecked(&input[start + run_start..start + run_end])
            };
            let offset = (start + run_start) as u64;
            out.push(ExtractedString {
                value: Cow::Borrowed(s),
                kind,
                encoding: Encoding::Utf8,
                location: Location {
                    offset,
                    address: section.offset_to_va(offset),
                    section: Some(section.name.clone()),
                    function_va: None,
                    source_va: None,
                },
            });
            i = run_end;
        } else {
            i = run_start + 1;
        }
    }
}

/// Returns the expected byte-width of a UTF-8 sequence starting with `b`,
/// or 0 if `b` isn't a valid leading byte.
#[inline]
fn utf8_char_width(b: u8) -> usize {
    match b {
        0x00..=0x7F => 1,
        0xC2..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF4 => 4,
        _ => 0,
    }
}

/// Is `c` a "printable" character for language-string purposes?
///
/// We accept ASCII printable, tab, and any non-control non-surrogate
/// Unicode scalar value. This looser definition is appropriate for
/// Go/Rust where strings legitimately contain non-ASCII text.
#[inline]
fn is_printable_char(c: char) -> bool {
    if c == '\t' {
        return true;
    }
    if (c as u32) < 0x20 {
        return false;
    }
    if c == '\u{007F}' {
        return false;
    }
    !c.is_control()
}
