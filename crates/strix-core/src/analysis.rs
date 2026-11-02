//! Non-destructive, FLOSS-inspired context tags. Tags are indicators, not verdicts.
use crate::{ExtractedString, StringKind};
use serde::{Deserialize, Serialize};

/// Semantic or binary-layout context for a string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StringTag {
    /// HTTP(S) or FTP URL prefix.
    Url,
    /// Standalone IP address (v4 or v6).
    IpAddress,
    /// Simple email-shaped candidate.
    Email,
    /// Absolute Unix/Windows or UNC path.
    Path,
    /// Windows registry root.
    Registry,
    /// Known runtime/library boilerplate.
    Library,
    /// String is located in an executable section.
    Code,
    /// Same text was already found elsewhere in this result.
    Duplicate,
    /// String recovered from an embedded Base64 block.
    Base64,
}
impl StringTag {
    /// Stable CLI/JSON spelling.
    pub fn name(self) -> &'static str {
        match self {
            Self::Url => "url",
            Self::IpAddress => "ip_address",
            Self::Email => "email",
            Self::Path => "path",
            Self::Registry => "registry",
            Self::Library => "library",
            Self::Code => "code",
            Self::Duplicate => "duplicate",
            Self::Base64 => "base64",
        }
    }
    /// Parse a stable spelling, accepting an optional leading #.
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.strip_prefix('#').unwrap_or(text);
        [
            Self::Url,
            Self::IpAddress,
            Self::Email,
            Self::Path,
            Self::Registry,
            Self::Library,
            Self::Code,
            Self::Duplicate,
            Self::Base64,
        ]
        .into_iter()
        .find(|tag| tag.name().eq_ignore_ascii_case(text))
    }
}
/// Optional annotations. The extracted text itself is never rewritten.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StringAnalysis {
    /// Deterministic semantic/context tags.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<StringTag>,
    /// Average model log10 probability; Unicode/short inputs may be unscored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trigram_score: Option<f64>,
    /// For Base64 results, byte offset inside the decoded body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decoded_offset: Option<u64>,
    /// For Base64 results, encoded source length in the original file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_length: Option<u64>,
}
impl StringAnalysis {
    /// Whether there is nothing to serialize.
    pub fn is_empty(&self) -> bool {
        self.tags.is_empty()
            && self.trigram_score.is_none()
            && self.decoded_offset.is_none()
            && self.source_length.is_none()
    }
}
/// Inspect borrowed text without allocating or normalizing a copy of it.
pub fn tags_for(string: &ExtractedString<'_>) -> Vec<StringTag> {
    let value = string.value.as_ref();
    let mut tags = Vec::new();
    if ["http://", "https://", "ftp://"].iter().any(|prefix| {
        value
            .get(..prefix.len())
            .is_some_and(|v| v.eq_ignore_ascii_case(prefix))
    }) {
        tags.push(StringTag::Url);
    }
    if value.parse::<std::net::IpAddr>().is_ok() {
        tags.push(StringTag::IpAddress);
    }
    if !value.contains(char::is_whitespace)
        && let Some((local, domain)) = value.split_once('@')
        && !local.is_empty()
        && domain.contains('.')
        && !domain.contains('@')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
    {
        tags.push(StringTag::Email);
    }
    let b = value.as_bytes();
    if value.starts_with('/')
        || value.starts_with("\\\\")
        || (b.len() > 2
            && b[0].is_ascii_alphabetic()
            && b[1] == b':'
            && matches!(b[2], b'/' | b'\\'))
    {
        tags.push(StringTag::Path);
    }
    if ["HKEY_", "HKLM\\", "HKCU\\", "HKCR\\", "HKU\\"]
        .iter()
        .any(|prefix| {
            value
                .get(..prefix.len())
                .is_some_and(|v| v.eq_ignore_ascii_case(prefix))
        })
    {
        tags.push(StringTag::Registry);
    }
    if crate::is_library_string(value) {
        tags.push(StringTag::Library);
    }
    if string.kind == StringKind::Base64 {
        tags.push(StringTag::Base64);
    }
    tags
}
