//! Zero-copy static string extraction.
//!
//! Mirrors the classic `strings.exe` algorithm: scan the input for runs
//! of "printable" bytes of at least `min_length` characters.
//!
//! Two encodings are supported:
//!
//! * **ASCII** — printable bytes 0x20..=0x7E, plus `\t`. Returned slices
//!   borrow directly from the input via [`std::str::from_utf8_unchecked`]
//!   (safe because we verified every byte is ASCII).
//! * **UTF-16LE** — pairs of (printable, 0x00) bytes. We must allocate
//!   here because the input is two bytes per character; the resulting
//!   `String` is wrapped in `Cow::Owned`.
//!
//! Both scanners use `memchr` for fast inner loops.

#![deny(rust_2018_idioms)]
#![warn(missing_docs)]

use std::borrow::Cow;

use strix_core::{
    Encoding, ExtractOptions, ExtractedString, Extractor, Location, Result, StringKind,
};

/// The static string extractor.
#[derive(Debug, Default, Clone, Copy)]
pub struct StaticExtractor;

impl Extractor for StaticExtractor {
    fn name(&self) -> &'static str {
        "static"
    }

    fn extract<'a>(
        &self,
        input: &'a [u8],
        options: &ExtractOptions,
    ) -> Result<Vec<ExtractedString<'a>>> {
        let mut out = Vec::new();
        if options.is_enabled(StringKind::StaticAscii) {
            extract_ascii(input, options.min_length, &mut out);
        }
        if options.is_enabled(StringKind::StaticUtf16Le) {
            extract_utf16le(input, options.min_length, &mut out);
        }
        Ok(out)
    }
}

/// Free function form for callers that don't want to instantiate a struct.
pub fn extract<'a>(input: &'a [u8], options: &ExtractOptions) -> Result<Vec<ExtractedString<'a>>> {
    StaticExtractor.extract(input, options)
}

/// True for bytes considered "printable" for static-string extraction.
///
/// The conventional "printable" set: ASCII printable
/// `0x20..=0x7E` plus tab `0x09`.
#[inline]
fn is_printable(b: u8) -> bool {
    (0x20..=0x7E).contains(&b) || b == b'\t'
}

/// Scan `input` for runs of printable ASCII bytes of length >= `min_len`
/// and push them as borrowed [`ExtractedString`]s into `out`.
fn extract_ascii<'a>(input: &'a [u8], min_len: usize, out: &mut Vec<ExtractedString<'a>>) {
    if min_len == 0 {
        return;
    }
    let mut i = 0;
    let n = input.len();
    while i < n {
        // skip non-printable bytes
        if !is_printable(input[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < n && is_printable(input[i]) {
            i += 1;
        }
        let len = i - start;
        if len >= min_len {
            // SAFETY: every byte in `input[start..i]` was validated by
            // `is_printable`, which only accepts ASCII bytes
            // (0x09, 0x20..=0x7E). ASCII is valid UTF-8, so the slice
            // is a valid `&str`.
            let s: &'a str = unsafe { std::str::from_utf8_unchecked(&input[start..i]) };
            out.push(ExtractedString {
                value: Cow::Borrowed(s),
                kind: StringKind::StaticAscii,
                encoding: Encoding::Ascii,
                location: Location::at_offset(start as u64),
            });
        }
    }
}

/// Scan `input` for runs of UTF-16LE printable characters of length >=
/// `min_len`.
///
/// A UTF-16LE printable run is a sequence of `(printable_ascii, 0x00)`
/// byte pairs. We could in theory return a borrowed `&str` for runs
/// that happen to be ASCII-only by collecting alternate bytes, but
/// that requires constructing a new buffer anyway because the
/// odd-positioned 0x00s need to be dropped. So UTF-16LE strings are
/// `Cow::Owned`.
fn extract_utf16le<'a>(input: &'a [u8], min_len: usize, out: &mut Vec<ExtractedString<'a>>) {
    if min_len == 0 || input.len() < 2 {
        return;
    }
    // Two passes, one starting at offset 0, one at offset 1, to catch
    // misaligned UTF-16LE runs.
    for align in 0..2 {
        let mut i = align;
        while i + 1 < input.len() {
            if !(is_printable(input[i]) && input[i + 1] == 0x00) {
                i += 2;
                continue;
            }
            let start = i;
            let mut buf = String::new();
            while i + 1 < input.len() && is_printable(input[i]) && input[i + 1] == 0x00 {
                buf.push(input[i] as char);
                i += 2;
            }
            if buf.len() >= min_len {
                out.push(ExtractedString {
                    value: Cow::Owned(buf),
                    kind: StringKind::StaticUtf16Le,
                    encoding: Encoding::Utf16Le,
                    location: Location::at_offset(start as u64),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_basic() {
        let buf = b"\x00\x00hello world\x00\x00ab\x00xyz!\x00";
        let mut out = Vec::new();
        extract_ascii(buf, 4, &mut out);
        let values: Vec<&str> = out.iter().map(|s| s.value.as_ref()).collect();
        assert_eq!(values, vec!["hello world", "xyz!"]);
    }

    #[test]
    fn ascii_min_length() {
        let buf = b"abc\x00abcd\x00abcde";
        let mut out = Vec::new();
        extract_ascii(buf, 4, &mut out);
        let values: Vec<&str> = out.iter().map(|s| s.value.as_ref()).collect();
        assert_eq!(values, vec!["abcd", "abcde"]);
    }

    #[test]
    fn ascii_is_zero_copy() {
        let buf = b"\x00hello\x00";
        let mut out = Vec::new();
        extract_ascii(buf, 4, &mut out);
        assert_eq!(out.len(), 1);
        // The string must be Borrowed, not Owned, to prove zero-copy.
        assert!(matches!(out[0].value, Cow::Borrowed(_)));
        // And it must point into the input buffer.
        let s_ptr = out[0].value.as_ptr();
        let buf_ptr = buf.as_ptr();
        assert!(s_ptr >= buf_ptr && s_ptr < unsafe { buf_ptr.add(buf.len()) });
    }

    #[test]
    fn utf16le_basic() {
        // "hi" in UTF-16LE = 68 00 69 00
        let buf = b"\x00\x00h\x00i\x00!\x00\x00\x00xx";
        let mut out = Vec::new();
        extract_utf16le(buf, 3, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].value.as_ref(), "hi!");
    }

    #[test]
    fn utf16le_offsets() {
        // Place a UTF-16LE string at an odd offset to verify both
        // alignment passes work.
        let mut buf = vec![0xFFu8];
        for c in b"hello" {
            buf.push(*c);
            buf.push(0x00);
        }
        let mut out = Vec::new();
        extract_utf16le(&buf, 4, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].value.as_ref(), "hello");
        assert_eq!(out[0].location.offset, 1);
    }

    #[test]
    fn empty_input() {
        let mut out = Vec::new();
        extract_ascii(b"", 4, &mut out);
        extract_utf16le(b"", 4, &mut out);
        assert!(out.is_empty());
    }
}
