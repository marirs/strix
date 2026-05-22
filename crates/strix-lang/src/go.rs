//! Go string and function-name extraction.
//!
//! This module has two paths:
//!
//! 1. **`.gopclntab` parsing.** Go binaries ship a runtime PCLN
//!    table that includes a contiguous function-name table
//!    (`funcnametab`). Parsing it gives us every Go function and
//!    package name — `runtime.main`, `github.com/user/pkg.Func`,
//!    etc. — which is the highest-signal metadata a Go binary
//!    carries. We support the modern Go 1.18+ header layout
//!    (`0xfffffff0` / `0xfffffff1` magic).
//! 2. **UTF-8 sweep over .rodata.** Fallback that catches whatever
//!    NUL-delimited string literals the linker happens to lay
//!    down. Catches the common case of Go binaries where strings
//!    are NUL-separated by neighboring data.

use std::borrow::Cow;

use strix_core::{Encoding, ExtractOptions, ExtractedString, Location, Result, StringKind};
use strix_format::{ParsedInput, Section};

/// Section names where Go strings are most commonly found.
const GO_RODATA_SECTIONS: &[&str] = &[
    ".rodata",
    ".rdata",
    "__rodata",
    "__TEXT,__rodata",
    "__TEXT,__cstring",
];

/// Section names that carry the Go PCLN table.
const GO_PCLNTAB_SECTIONS: &[&str] = &[".gopclntab", "__gopclntab", "runtime.pclntab"];

pub(crate) fn extract<'a>(
    input: &'a [u8],
    parsed: &ParsedInput,
    options: &ExtractOptions,
    out: &mut Vec<ExtractedString<'a>>,
) -> Result<()> {
    // Function-name table from the PCLN section.
    for section in &parsed.sections {
        if GO_PCLNTAB_SECTIONS
            .iter()
            .any(|s| section.name.contains(s) || section.name.ends_with(s))
        {
            extract_pclntab_names(input, section, options, out);
            // Only parse the first hit; some Mach-O fat binaries
            // expose the section multiple times but we want each
            // name once.
            break;
        }
    }

    // UTF-8 sweep over the read-only sections most likely to hold
    // string literals.
    for section in &parsed.sections {
        if GO_RODATA_SECTIONS.iter().any(|s| section.name.contains(s)) {
            super::extract_utf8_runs(input, section, options.min_length, StringKind::Go, out);
        }
    }
    Ok(())
}

/// Walk `.gopclntab` for Go 1.18+ and emit every entry in its
/// `funcnametab` as a Go-kind string. Each entry is a NUL-
/// terminated UTF-8 function name like `runtime.main` or
/// `github.com/user/pkg.Type.Method`.
fn extract_pclntab_names<'a>(
    input: &'a [u8],
    section: &Section,
    options: &ExtractOptions,
    out: &mut Vec<ExtractedString<'a>>,
) {
    let sec_off = section.file_offset as usize;
    let sec_size = section.file_size as usize;
    if sec_off >= input.len() {
        return;
    }
    let sec_end = sec_off
        .checked_add(sec_size)
        .map(|e| e.min(input.len()))
        .unwrap_or(input.len());
    let bytes = &input[sec_off..sec_end];
    if bytes.len() < 8 {
        return;
    }
    // Magic + 2 pad + minLC + ptrSize header.
    let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let pad1 = bytes[4];
    let pad2 = bytes[5];
    let _min_lc = bytes[6];
    let ptr_size = bytes[7] as usize;
    if pad1 != 0 || pad2 != 0 {
        return;
    }
    if ptr_size != 4 && ptr_size != 8 {
        return;
    }

    // Header layout — the offset of funcnameOffset depends on
    // version:
    //   Go 1.16-1.17 (magic = 0xfffffffa): no textStart field;
    //     funcname is the 3rd uintptr after the 8-byte preamble
    //     (skipping nfunc, nfiles).
    //   Go 1.18+ (magic = 0xfffffff0 / 0xfffffff1): textStart sits
    //     between nfiles and funcnameOffset; funcname is the 4th
    //     uintptr.
    //   Go 1.20+ added the same layout; we treat both 0xfffffff0
    //     and 0xfffffff1 the same.
    let funcname_field_index: usize = match magic {
        0xffff_fffa => 2,
        0xffff_fff0 | 0xffff_fff1 => 3,
        _ => return,
    };
    let funcname_off_pos = 8 + funcname_field_index * ptr_size;
    if funcname_off_pos + ptr_size > bytes.len() {
        return;
    }
    let funcname_offset = read_uint(&bytes[funcname_off_pos..funcname_off_pos + ptr_size]);
    let funcname_offset = funcname_offset as usize;
    if funcname_offset >= bytes.len() {
        return;
    }
    let nametab = &bytes[funcname_offset..];

    // Walk NUL-terminated entries. Bound by some sanity limits so
    // a corrupt tab doesn't pin us in a long loop.
    const MAX_NAME_LEN: usize = 1024;
    const MAX_NAMES: usize = 200_000;
    let mut i = 0usize;
    let mut emitted: usize = 0;
    while i < nametab.len() && emitted < MAX_NAMES {
        // Skip stray NULs.
        if nametab[i] == 0 {
            i += 1;
            continue;
        }
        let start = i;
        let mut end = i;
        while end < nametab.len() && nametab[end] != 0 && end - start < MAX_NAME_LEN {
            end += 1;
        }
        let raw = &nametab[start..end];
        if raw.len() >= options.min_length {
            // Names are conventionally ASCII printable plus dots /
            // slashes / generic-type punctuation. Validate UTF-8
            // and require at least one '.' or '/' so we don't
            // accidentally emit chunks of unrelated data when the
            // header parse went wrong.
            if let Ok(name) = std::str::from_utf8(raw)
                && name.chars().any(|c| c == '.' || c == '/')
                && name
                    .chars()
                    .all(|c| !c.is_control() && (c.is_ascii() || c.is_alphanumeric()))
            {
                let abs_offset = sec_off + funcname_offset + start;
                let s: &'a str = unsafe {
                    std::str::from_utf8_unchecked(&input[abs_offset..abs_offset + raw.len()])
                };
                out.push(ExtractedString {
                    value: Cow::Borrowed(s),
                    kind: StringKind::Go,
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
                emitted += 1;
            }
        }
        i = end + 1;
    }
}

/// Read a 4- or 8-byte little-endian unsigned integer.
fn read_uint(bytes: &[u8]) -> u64 {
    match bytes.len() {
        4 => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64,
        8 => u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]),
        _ => 0,
    }
}
