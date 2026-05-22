//! Rust string and symbol extraction.
//!
//! Rust binaries don't have a single tidy function-name table like
//! Go's pclntab — they rely on the dynamic / debug symbol tables
//! the linker emits. We extract Rust-flavored content from three
//! sources:
//!
//! 1. **UTF-8 runs in `.rodata` / `__rodata`.** Catches string
//!    literals, panic strings, `#[derive(Debug)]` output, format
//!    strings.
//! 2. **The `.rustc` section's compressed-bytecode header.**
//!    Older Rust releases used `RUST_CRATE` magic bytes followed
//!    by a snappy-compressed crate metadata blob; modern releases
//!    write an LLVM `__LLVM_BITCODE` style `RUSTC` magic. We surface
//!    the magic + version string as a Rust-kind output entry so
//!    analysts can confirm the toolchain version.
//! 3. **Rust-mangled symbols.** Both legacy (`_ZN`) and v0
//!    (`_R`) Rust mangling produce path-like names that survive
//!    in the binary's symbol table (populated by strix-format).
//!    We emit each that looks Rust-mangled as a `Rust`-kind string
//!    so the analyst sees `core::option::Option::unwrap` etc.

use std::borrow::Cow;

use strix_core::{Encoding, ExtractOptions, ExtractedString, Location, Result, StringKind};
use strix_format::ParsedInput;

const RUST_RODATA_SECTIONS: &[&str] = &[
    ".rodata",
    ".rdata",
    "__rodata",
    "__TEXT,__const",
    "__TEXT,__rodata",
    "__TEXT,__cstring",
];

const RUST_METADATA_SECTIONS: &[&str] = &[".rustc", "__rustc", "__DATA_CONST,__rustc"];

pub(crate) fn extract<'a>(
    input: &'a [u8],
    parsed: &ParsedInput,
    options: &ExtractOptions,
    out: &mut Vec<ExtractedString<'a>>,
) -> Result<()> {
    // Rodata UTF-8 sweep.
    for section in &parsed.sections {
        if RUST_RODATA_SECTIONS
            .iter()
            .any(|s| section.name.contains(s))
        {
            super::extract_utf8_runs(input, section, options.min_length, StringKind::Rust, out);
        }
    }

    // .rustc metadata header — surface the rustc version string if
    // we can find one. The metadata blob is compressed, so we don't
    // try to decode the whole thing here.
    for section in &parsed.sections {
        if RUST_METADATA_SECTIONS
            .iter()
            .any(|s| section.name.contains(s))
        {
            extract_rustc_metadata(input, section, options, out);
            extract_rustc_crate_names(input, section, options, out);
        }
    }

    // Rust-mangled symbol names. The symbol table was populated by
    // strix-format's PE/ELF/Mach-O parsers — we just filter.
    for (&va, name) in &parsed.symbols {
        if is_rust_mangled(name) && name.len() >= options.min_length {
            out.push(ExtractedString {
                value: Cow::Owned(name.clone()),
                kind: StringKind::Rust,
                encoding: Encoding::Utf8,
                location: Location {
                    offset: 0,
                    address: Some(va),
                    section: None,
                    function_va: Some(va),
                    source_va: None,
                    xrefs: 0,
                },
            });
        }
    }

    Ok(())
}

/// Pull the rustc-version stamp out of a `.rustc` section header.
/// The .rustc section starts with an 8-byte magic plus a 4-byte
/// version, then a length-prefixed UTF-8 rustc identifier like
/// `rustc 1.78.0 (9b00956e5 2024-04-29)`.
fn extract_rustc_metadata<'a>(
    input: &'a [u8],
    section: &strix_format::Section,
    options: &ExtractOptions,
    out: &mut Vec<ExtractedString<'a>>,
) {
    let start = section.file_offset as usize;
    let end = (section.file_offset + section.file_size) as usize;
    if start >= input.len() || end > input.len() {
        return;
    }
    let bytes = &input[start..end];
    // The header layout is "rustc xxx" buried after a short magic
    // prefix. Rather than tracking the exact layout (which has
    // changed over time), scan the first 256 bytes for a "rustc "
    // prefix and emit the run that starts there.
    let look = &bytes[..bytes.len().min(256)];
    if let Some(pos) = find_subsequence(look, b"rustc ") {
        let run_start = pos;
        let mut run_end = pos;
        while run_end < look.len() && look[run_end] >= 0x20 && look[run_end] < 0x7f {
            run_end += 1;
        }
        if run_end - run_start >= options.min_length
            && let Ok(s) = std::str::from_utf8(&look[run_start..run_end])
        {
            let abs = start + run_start;
            let borrowed: &'a str =
                unsafe { std::str::from_utf8_unchecked(&input[abs..abs + s.len()]) };
            out.push(ExtractedString {
                value: Cow::Borrowed(borrowed),
                kind: StringKind::Rust,
                encoding: Encoding::Utf8,
                location: Location {
                    offset: abs as u64,
                    address: section.offset_to_va(abs as u64),
                    section: Some(section.name.clone()),
                    function_va: None,
                    source_va: None,
                    xrefs: 0,
                },
            });
        }
    }
}

/// Recognize the two Rust symbol-mangling schemes:
///   * Legacy (Itanium-ABI-style): `_ZN...E` — name decomposes into
///     length-prefixed path components.
///   * v0 (RFC 2603): `_R...` — leading `_R` with a base64-ish
///     payload.
///
/// We accept either as Rust-flavored when the rest of the symbol
/// looks well-formed enough to not be a C++ name. The legacy scheme
/// is shared with C++ (Itanium ABI), so we additionally require the
/// presence of a Rust-specific path token like `core::`, `std::`,
/// `alloc::`, or `..` to keep the false-positive rate down.
fn is_rust_mangled(name: &str) -> bool {
    if name.starts_with("_R") {
        // v0 mangling is Rust-only.
        return name.len() > 4
            && name
                .bytes()
                .skip(2)
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'$');
    }
    if name.starts_with("_ZN") && name.ends_with('E') {
        // Legacy scheme. Require a Rust-typical path token to
        // distinguish from C++.
        return name.contains("$LT$")
            || name.contains("4core")
            || name.contains("3std")
            || name.contains("5alloc")
            || name.contains("11collections")
            || name.contains("17h"); // legacy disambiguator suffix
    }
    false
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Heuristic extraction of plaintext crate identifiers from the
/// `.rustc` section. Rust's metadata blob is compressed, but
/// crate-name strings often appear in a plaintext header / index
/// region near the start. Scan the first 8 KB for runs that match
/// the Rust crate-identifier shape: `[a-z_][a-z0-9_]*` of length
/// 4..=32. Emit each unique match as a Rust-kind string.
fn extract_rustc_crate_names<'a>(
    input: &'a [u8],
    section: &strix_format::Section,
    options: &ExtractOptions,
    out: &mut Vec<ExtractedString<'a>>,
) {
    let start = section.file_offset as usize;
    let end = (section.file_offset + section.file_size) as usize;
    if start >= input.len() || end > input.len() {
        return;
    }
    let scan_end = end.min(start + 8192);
    let bytes = &input[start..scan_end];

    let mut emitted: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        // Crate names start with [a-z_].
        if !(b.is_ascii_lowercase() || b == b'_') {
            i += 1;
            continue;
        }
        let run_start = i;
        let mut run_end = i;
        while run_end < bytes.len() {
            let c = bytes[run_end];
            if c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' {
                run_end += 1;
            } else {
                break;
            }
        }
        let len = run_end - run_start;
        if (4..=32).contains(&len) && len >= options.min_length {
            // SAFETY: every byte was ASCII alnum/underscore.
            let s: &'a str = unsafe {
                std::str::from_utf8_unchecked(&input[start + run_start..start + run_end])
            };
            if emitted.insert(s) {
                let abs_offset = start + run_start;
                out.push(ExtractedString {
                    value: Cow::Borrowed(s),
                    kind: StringKind::Rust,
                    encoding: Encoding::Utf8,
                    location: Location {
                        offset: abs_offset as u64,
                        address: section.offset_to_va(abs_offset as u64),
                        section: Some(section.name.clone()),
                        function_va: None,
                        source_va: None,
                        xrefs: 0,
                    },
                });
            }
        }
        i = run_end.max(i + 1);
    }
}
