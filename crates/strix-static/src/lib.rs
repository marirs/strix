//! Zero-copy static string extraction.
//!
//! Mirrors the classic `strings.exe` algorithm: scan the input for runs
//! of "printable" bytes of at least `min_length` characters.
//!
//! ASCII and general UTF-8 borrow input slices. UTF-16LE/BE are decoded
//! into owned strings, including surrogate pairs.
//!
//! UTF-16 scans both byte alignments. Explicit encoding selection is useful
//! for raw data with multiple plausible Unicode interpretations. Scoring and
//! annotation never run implicitly in this low-level scanner.

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
        if options.is_enabled(StringKind::StaticUtf8) {
            extract_utf8(
                input,
                options.min_length,
                !options.is_enabled(StringKind::StaticAscii),
                &mut out,
            );
        }
        if options.is_enabled(StringKind::StaticUtf16Le) {
            extract_utf16(input, options.min_length, false, &mut out);
        }
        if options.is_enabled(StringKind::StaticUtf16Be) {
            extract_utf16(input, options.min_length, true, &mut out);
        }
        // Suppress the one-byte-shifted, truncated ASCII interpretation when
        // the opposite endian scan recovered the complete containing string.
        let spans: std::collections::HashSet<_> = out
            .iter()
            .filter(|s| {
                matches!(s.encoding, Encoding::Utf16Le | Encoding::Utf16Be) && s.value.is_ascii()
            })
            .map(|s| (s.location.offset, s.value.len() * 2, s.encoding))
            .collect();
        out.retain(|s| {
            let opposite = match s.encoding {
                Encoding::Utf16Le => Encoding::Utf16Be,
                Encoding::Utf16Be => Encoding::Utf16Le,
                _ => return true,
            };
            !(s.value.is_ascii()
                && s.location.offset > 0
                && spans.contains(&(s.location.offset - 1, s.value.len() * 2 + 2, opposite)))
        });
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
                analysis: Default::default(),
                value: Cow::Borrowed(s),
                kind: StringKind::StaticAscii,
                encoding: Encoding::Ascii,
                location: Location::at_offset(start as u64),
            });
        }
    }
}

/// Printable Unicode, excluding control codes, replacement characters and BOMs.
fn printable(ch: char) -> bool {
    let point = ch as u32;
    (!ch.is_control() || ch == '\t')
        && ch != '\u{fffd}'
        && ch != '\u{feff}'
        && !(0xfdd0..=0xfdef).contains(&point)
        && point & 0xffff < 0xfffe
}

fn extract_utf8<'a>(
    input: &'a [u8],
    min_len: usize,
    include_ascii: bool,
    out: &mut Vec<ExtractedString<'a>>,
) {
    if min_len == 0 {
        return;
    }
    let mut offset = 0;
    while offset < input.len() {
        let (valid, skip) = match std::str::from_utf8(&input[offset..]) {
            Ok(text) => (text, 0),
            Err(error) => {
                let end = offset + error.valid_up_to();
                // SAFETY: valid_up_to is the UTF-8 validator's verified prefix.
                (
                    unsafe { std::str::from_utf8_unchecked(&input[offset..end]) },
                    error.error_len().unwrap_or(input.len() - end),
                )
            }
        };
        let mut start = 0;
        for (i, ch) in valid.char_indices() {
            if !printable(ch) {
                push_utf8(
                    &valid[start..i],
                    offset + start,
                    min_len,
                    include_ascii,
                    out,
                );
                start = i + ch.len_utf8();
            }
        }
        push_utf8(&valid[start..], offset + start, min_len, include_ascii, out);
        offset += valid.len() + skip;
    }
}

fn push_utf8<'a>(
    text: &'a str,
    offset: usize,
    min_len: usize,
    include_ascii: bool,
    out: &mut Vec<ExtractedString<'a>>,
) {
    // Pure ASCII already has a borrowed result from the ASCII scanner.
    if (include_ascii || !text.is_ascii()) && text.chars().count() >= min_len {
        out.push(ExtractedString::borrowed(
            text,
            StringKind::StaticUtf8,
            Encoding::Utf8,
            offset as u64,
        ));
    }
}

fn extract_utf16<'a>(
    input: &'a [u8],
    min_len: usize,
    big: bool,
    out: &mut Vec<ExtractedString<'a>>,
) {
    if min_len == 0 {
        return;
    }
    let unit = |i: usize| {
        if big {
            u16::from_be_bytes([input[i], input[i + 1]])
        } else {
            u16::from_le_bytes([input[i], input[i + 1]])
        }
    };
    for align in 0..2 {
        let mut i = align;
        while i + 1 < input.len() {
            let start = i;
            let mut chars = 0;
            let mut text = String::new();
            while i + 1 < input.len() {
                let first = unit(i);
                let (value, width) = if (0xd800..=0xdbff).contains(&first)
                    && i + 3 < input.len()
                    && (0xdc00..=0xdfff).contains(&unit(i + 2))
                {
                    (
                        0x10000 + ((first as u32 - 0xd800) << 10) + (unit(i + 2) as u32 - 0xdc00),
                        4,
                    )
                } else {
                    (first as u32, 2)
                };
                let Some(ch) = char::from_u32(value).filter(|c| printable(*c)) else {
                    break;
                };
                text.push(ch);
                chars += 1;
                i += width;
            }
            if chars >= min_len {
                out.push(ExtractedString {
                    value: Cow::Owned(text),
                    kind: if big {
                        StringKind::StaticUtf16Be
                    } else {
                        StringKind::StaticUtf16Le
                    },
                    encoding: if big {
                        Encoding::Utf16Be
                    } else {
                        Encoding::Utf16Le
                    },
                    location: Location::at_offset(start as u64),
                    analysis: Default::default(),
                });
            }
            // Invalid code unit / separator is consumed, not silently replaced.
            if i == start || i + 1 < input.len() {
                i += 2;
            }
        }
    }
}

#[cfg(test)]
fn extract_utf16le<'a>(input: &'a [u8], min_len: usize, out: &mut Vec<ExtractedString<'a>>) {
    extract_utf16(input, min_len, false, out);
}

mod base64;
pub use base64::extract_base64;

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
        // The opposite alignment can now also form printable Unicode.
        assert!(out.iter().any(|s| s.value == "hi!"));
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
        let found = out.iter().find(|s| s.value == "hello").unwrap();
        assert_eq!(found.location.offset, 1);
    }

    #[test]
    fn empty_input() {
        let mut out = Vec::new();
        extract_ascii(b"", 4, &mut out);
        extract_utf16le(b"", 4, &mut out);
        assert!(out.is_empty());
    }
    #[test]
    fn unicode_utf8_borrows_input_across_invalid_sequences() {
        let text = "Привет 世界 😀";
        let mut data = vec![0xff, 0xfe];
        data.extend_from_slice(text.as_bytes());
        data.extend_from_slice(&[0, 0xf0, 0x9f]);
        let result = extract(
            &data,
            &ExtractOptions {
                enabled: Some(vec![StringKind::StaticUtf8]),
                ..Default::default()
            },
        )
        .unwrap();
        let found = result.iter().find(|s| s.value == text).unwrap();
        assert!(matches!(found.value, Cow::Borrowed(_)));
        assert_eq!(found.value.as_ptr(), data[2..].as_ptr());
        assert_eq!(found.location.offset, 2);
    }
    #[test]
    fn utf8_only_also_keeps_ascii_and_counts_characters() {
        let options = ExtractOptions {
            enabled: Some(vec![StringKind::StaticUtf8]),
            ..Default::default()
        };
        assert_eq!(extract(b"hello", &options).unwrap()[0].value, "hello");
        assert!(extract("你好".as_bytes(), &options).unwrap().is_empty());
    }
    #[test]
    fn utf16_endian_surrogates_and_odd_offsets() {
        let text = "Привет 世界 😀";
        for (big, kind, encoding) in [
            (false, StringKind::StaticUtf16Le, Encoding::Utf16Le),
            (true, StringKind::StaticUtf16Be, Encoding::Utf16Be),
        ] {
            let mut data = vec![0xff];
            for u in text.encode_utf16() {
                data.extend_from_slice(&if big {
                    u.to_be_bytes()
                } else {
                    u.to_le_bytes()
                });
            }
            data.extend_from_slice(&[0, 0]);
            let result = extract(
                &data,
                &ExtractOptions {
                    enabled: Some(vec![kind]),
                    ..Default::default()
                },
            )
            .unwrap();
            let found = result.iter().find(|s| s.value == text).unwrap();
            assert!(matches!(found.value, Cow::Owned(_)));
            assert_eq!(found.location.offset, 1);
            assert_eq!(found.encoding, encoding);
        }
    }
    #[test]
    fn full_be_string_supersedes_truncated_shifted_le() {
        let data: Vec<_> = "hello world"
            .encode_utf16()
            .flat_map(u16::to_be_bytes)
            .collect();
        let result = extract(&data, &Default::default()).unwrap();
        assert!(
            result
                .iter()
                .any(|s| s.value == "hello world" && s.encoding == Encoding::Utf16Be)
        );
        assert!(!result.iter().any(|s| s.value == "hello worl"));
    }
    #[test]
    fn invalid_surrogate_is_a_separator_not_a_replacement() {
        let mut data = Vec::new();
        for unit in [0xd800u16, 0x0068, 0x0065, 0x006c, 0x006c, 0x006f, 0xdc00] {
            data.extend_from_slice(&unit.to_le_bytes());
        }
        let result = extract(
            &data,
            &ExtractOptions {
                enabled: Some(vec![StringKind::StaticUtf16Le]),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(
            result
                .iter()
                .any(|s| s.value == "hello" && s.location.offset == 2)
        );
        assert!(result.iter().all(|s| !s.value.contains('\u{fffd}')));
    }
    #[test]
    fn base64_outputs_own_text_and_keep_source_provenance() {
        let input = b"\0aGVsbG8gd29ybGQ=\0";
        let result = extract_base64(input, &ExtractOptions::default());
        let found = result.iter().find(|s| s.value == "hello world").unwrap();
        assert!(matches!(found.value, Cow::Owned(_)));
        assert_eq!(found.kind, StringKind::Base64);
        assert_eq!(found.location.offset, 1);
        assert_eq!(found.analysis.decoded_offset, Some(0));
        assert_eq!(found.analysis.source_length, Some(16));
        assert!(extract_base64(b"!!!====!!!", &Default::default()).is_empty());
    }
    #[test]
    fn base64_url_safe_unpadded_single_layer_and_limits() {
        let options = ExtractOptions {
            enabled: Some(vec![StringKind::StaticAscii]),
            ..Default::default()
        };
        assert!(
            extract_base64(b"aGVsbG8_", &options)
                .iter()
                .any(|s| s.value == "hello?")
        );
        let nested = extract_base64(b"YUdWc2JHOD0=", &options);
        assert!(nested.iter().any(|s| s.value == "aGVsbG8="));
        assert!(!nested.iter().any(|s| s.value == "hello"));
        assert!(extract_base64(&vec![b'A'; 1024 * 1024 + 1], &options).is_empty());
    }
    #[test]
    fn malformed_buffers_do_not_panic_and_borrows_stay_in_bounds() {
        let mut state = 0x1234u64;
        for length in 0..256 {
            let bytes: Vec<_> = (0..length)
                .map(|_| {
                    state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                    (state >> 32) as u8
                })
                .collect();
            for min_length in [0, 1, 4, usize::MAX] {
                let result = extract(
                    &bytes,
                    &ExtractOptions {
                        min_length,
                        ..Default::default()
                    },
                )
                .unwrap();
                for found in result {
                    assert!(found.location.offset < bytes.len() as u64);
                    if let Cow::Borrowed(text) = found.value {
                        assert!(text.as_ptr() >= bytes.as_ptr());
                        assert!(
                            text.as_ptr() as usize + text.len()
                                <= bytes.as_ptr() as usize + bytes.len()
                        );
                    }
                }
            }
        }
    }
    #[test]
    fn unicode_noncharacters_split_runs() {
        for point in [0xfffe, 0xffff, 0xfdd0, 0xfdef, 0x1fffe, 0x10ffff] {
            let separator = char::from_u32(point).unwrap();
            let text = format!("{separator}hello");
            let result = extract(
                text.as_bytes(),
                &ExtractOptions {
                    enabled: Some(vec![StringKind::StaticUtf8]),
                    ..Default::default()
                },
            )
            .unwrap();
            assert_eq!(result.len(), 1);
            assert_eq!(result[0].value, "hello");
            assert_eq!(result[0].location.offset, separator.len_utf8() as u64);
        }
    }
}
