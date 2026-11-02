//! Bounded, single-layer Base64 recovery. Never changes direct static results.
use base64::{
    Engine, alphabet,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
};
use strix_core::{ExtractOptions, ExtractedString, StringKind};

/// Extract text from standard / URL-safe, padded / unpadded Base64 tokens.
/// Limits: 1 MiB encoded token, 16 MiB total decoded bytes, one decoding layer.
/// Original offset points to the encoded token; analysis records decoded offset.
pub fn extract_base64<'a>(input: &'a [u8], options: &ExtractOptions) -> Vec<ExtractedString<'a>> {
    const MAX_TOKEN: usize = 1024 * 1024;
    const BUDGET: usize = 16 * 1024 * 1024;
    let config =
        GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent);
    let standard = GeneralPurpose::new(&alphabet::STANDARD, config);
    let url = GeneralPurpose::new(&alphabet::URL_SAFE, config);
    let candidate =
        |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'-' | b'_' | b'=');
    let mut out = Vec::new();
    let mut i = 0;
    let mut used = 0;
    let mut inner = options.clone();
    // Base64-only requests must still select the decoded text encodings.
    inner.enabled = options.enabled.as_ref().and_then(|kinds| {
        let selected: Vec<_> = kinds
            .iter()
            .copied()
            .filter(|kind| kind.is_static())
            .collect();
        if selected.is_empty() {
            None
        } else {
            Some(selected)
        }
    });
    inner.decode_base64 = false;
    while i < input.len() {
        if !candidate(input[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < input.len() && candidate(input[i]) {
            i += 1;
        }
        let token = &input[start..i];
        if token.len() < 8 || token.len() > MAX_TOKEN {
            continue;
        }
        let Ok(decoded) = standard.decode(token).or_else(|_| url.decode(token)) else {
            continue;
        };
        if used + decoded.len() > BUDGET {
            break;
        }
        used += decoded.len();
        if let Ok(strings) = super::extract(&decoded, &inner) {
            for string in strings {
                let mut owned = string.into_owned();
                owned.kind = StringKind::Base64;
                owned.analysis.decoded_offset = Some(owned.location.offset);
                owned.analysis.source_length = Some(token.len() as u64);
                owned.location.offset = start as u64;
                out.push(owned);
            }
        }
    }
    out
}
