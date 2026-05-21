//! Rust string extraction.
//!
//! Like Go, Rust strings are not NUL-terminated. We extract UTF-8
//! runs from read-only data sections and uses code-reference analysis
//! to split adjacent strings.
//!
//! This initial implementation does the UTF-8 run extraction without
//! the xref-driven splitting; it will be replaced once the analyzer
//! in `strix-emulator` is online.

use strix_core::{ExtractOptions, ExtractedString, Result, StringKind};
use strix_format::ParsedInput;

const RUST_RODATA_SECTIONS: &[&str] = &[
    ".rodata",
    ".rdata",
    "__rodata",
    "__TEXT,__const",
    "__TEXT,__rodata",
    "__TEXT,__cstring",
];

pub(crate) fn extract<'a>(
    input: &'a [u8],
    parsed: &ParsedInput,
    options: &ExtractOptions,
    out: &mut Vec<ExtractedString<'a>>,
) -> Result<()> {
    for section in &parsed.sections {
        if RUST_RODATA_SECTIONS
            .iter()
            .any(|s| section.name.contains(s))
        {
            super::extract_utf8_runs(input, section, options.min_length, StringKind::Rust, out);
        }
    }
    Ok(())
}
