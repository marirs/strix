//! Ownership, source provenance and opt-in analysis are public contracts.
use std::{borrow::Cow, sync::Arc};
use strix::{ExtractOptions, FormatHint, StringKind, StringTag, TrigramModel, extract};

#[test]
fn annotation_tag_filter_and_dedupe_leave_payload_borrowed() {
    let input = b"https://example.com\0https://example.com\0";
    let options = ExtractOptions {
        enabled: Some(vec![StringKind::StaticAscii]),
        annotate: true,
        dedupe: true,
        required_tags: vec![StringTag::Url],
        ..Default::default()
    };
    let result = extract(input, &options).unwrap();
    assert_eq!(result.strings.len(), 1);
    let s = &result.strings[0];
    assert!(matches!(s.value, Cow::Borrowed(_)));
    assert_eq!(s.value.as_ptr(), input.as_ptr());
    assert!(s.analysis.tags.contains(&StringTag::Url));
    let owned = result.into_owned();
    assert!(owned.strings[0].analysis.tags.contains(&StringTag::Url));
    let json = serde_json::to_string(&owned).unwrap();
    assert!(json.contains("\"tags\":[\"url\"]"));
}
#[test]
fn duplicate_tag_is_opt_in_and_non_destructive() {
    let input = b"hello world\0hello world\0";
    let options = ExtractOptions {
        enabled: Some(vec![StringKind::StaticAscii]),
        required_tags: vec![StringTag::Duplicate],
        ..Default::default()
    };
    let result = extract(input, &options).unwrap();
    assert_eq!(result.strings.len(), 1);
    assert_eq!(result.strings[0].location.offset, 12);
    assert!(matches!(result.strings[0].value, Cow::Borrowed(_)));
}
#[test]
fn binary_code_context_is_preserved_in_json_instead_of_hidden() {
    let input = b"https://example.com\0";
    let options = ExtractOptions {
        format_override: Some(FormatHint::Sc64),
        enabled: Some(vec![StringKind::StaticAscii]),
        annotate: true,
        ..Default::default()
    };
    let result = extract(input, &options).unwrap();
    assert!(result.strings[0].analysis.tags.contains(&StringTag::Code));
    assert!(result.strings[0].analysis.tags.contains(&StringTag::Url));
}
#[test]
fn score_is_optional_never_transliterates_unicode_or_copies_ascii() {
    let model=Arc::new(TrigramModel::from_sng("# Model Type: lowercase\n[^]\th\te\t10\nh\te\tl\t10\ne\tl\tl\t10\nl\tl\to\t10\nl\to\t[$]\t10").unwrap());
    let input = "hello\0你好世界".as_bytes();
    let options = ExtractOptions {
        enabled: Some(vec![StringKind::StaticAscii, StringKind::StaticUtf8]),
        trigram_model: Some(model),
        min_trigram_score: Some(0.0),
        ..Default::default()
    };
    let result = extract(input, &options).unwrap();
    assert_eq!(result.strings.len(), 1);
    assert_eq!(result.strings[0].value, "你好世界");
    assert!(matches!(result.strings[0].value, Cow::Borrowed(_)));
    assert_eq!(result.strings[0].value.as_ptr(), input[6..].as_ptr());
    assert_eq!(result.strings[0].analysis.trigram_score, None);
    let invalid = ExtractOptions {
        min_trigram_score: Some(-5.0),
        ..Default::default()
    };
    assert!(extract(input, &invalid).is_err());
    let invalid = ExtractOptions {
        min_quality: f64::NAN,
        ..Default::default()
    };
    assert!(extract(input, &invalid).is_err());
}
#[test]
fn base64_is_opt_in_and_json_has_encoded_and_decoded_offsets() {
    let input = b"\0aGVsbG8gd29ybGQ=\0";
    let base = ExtractOptions {
        enabled: Some(vec![StringKind::StaticAscii, StringKind::Base64]),
        ..Default::default()
    };
    assert!(
        !extract(input, &base)
            .unwrap()
            .strings
            .iter()
            .any(|s| s.kind == StringKind::Base64)
    );
    let options = ExtractOptions {
        decode_base64: true,
        ..base
    };
    let result = extract(input, &options).unwrap();
    assert!(
        result
            .strings
            .iter()
            .any(|s| s.value == "aGVsbG8gd29ybGQ=" && matches!(s.value, Cow::Borrowed(_)))
    );
    let decoded = result
        .strings
        .iter()
        .find(|s| s.value == "hello world")
        .unwrap();
    assert_eq!(decoded.kind, StringKind::Base64);
    assert!(matches!(decoded.value, Cow::Owned(_)));
    assert_eq!(decoded.location.offset, 1);
    assert_eq!(decoded.analysis.decoded_offset, Some(0));
    assert_eq!(decoded.analysis.source_length, Some(16));
}
