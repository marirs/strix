//! Go string extraction.
//!
//! Initial implementation. A faithful Go string-table algorithm:
//!   1. Locate the Go string blob via the monotonically-increasing
//!      length sequence of String structs.
//!   2. Use `00 00 00 00` as a delimiter for blob boundaries.
//!   3. Split the blob by cross-references to identify individual
//!      strings.
//!
//! Steps 1 and 3 require code analysis (disassembly + xref discovery).
//! That work belongs in `strix-emulator`; once it lands, this module
//! will consume those xrefs to do faithful splitting. In the meantime
//! we extract UTF-8 runs from the read-only sections most likely to
//! contain the blob, which catches the common case of Go binaries
//! where strings happen to be NUL-delimited by neighboring data.

use strix_core::{ExtractOptions, ExtractedString, Result, StringKind};
use strix_format::ParsedInput;

/// Section names where Go strings are most commonly found.
const GO_RODATA_SECTIONS: &[&str] = &[
    ".rodata",
    ".rdata",
    "__rodata",
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
        if GO_RODATA_SECTIONS.iter().any(|s| section.name.contains(s)) {
            super::extract_utf8_runs(input, section, options.min_length, StringKind::Go, out);
        }
    }
    Ok(())
}
