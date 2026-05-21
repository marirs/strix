//! Core types and JSON schema for the strix string-extraction library.
//!
//! Lifetimes here are deliberate: every string-bearing struct carries
//! a `'a` so that extractors that scan the input file directly
//! (static, language) can borrow `&str` slices into the input bytes
//! without allocating. Extractors that synthesize new bytes (decoded,
//! stack, tight via emulation) own their strings via `Cow::Owned`.

#![deny(rust_2018_idioms)]
#![warn(missing_docs)]

use std::borrow::Cow;

use serde::{Deserialize, Serialize};

pub mod capability;
pub mod error;
pub mod library;
pub mod quality;
pub mod traits;

pub use capability::tags_for_imports;
pub use error::{Error, Result};
pub use library::is_library_string;
pub use quality::string_quality;
pub use traits::Extractor;

/// The kind of string that was extracted.
///
/// String categories cover both raw printable runs (static / language)
/// and bytes produced at runtime by decoders (stack / tight / decoded).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StringKind {
    /// Classic ASCII printable run.
    StaticAscii,
    /// UTF-16 little-endian printable run.
    StaticUtf16Le,
    /// String pulled from a Go runtime string table.
    Go,
    /// String pulled from a Rust binary's `.rodata`.
    Rust,
    /// String built up on the stack at runtime (recovered by emulation).
    Stack,
    /// "Tight" stack string — decoded inside a tight loop.
    Tight,
    /// String produced by an in-memory decoder routine (recovered by emulation).
    Decoded,
}

impl StringKind {
    /// The short tag used in CLI flags (`--only static lang stack ...`).
    pub fn cli_tag(self) -> &'static str {
        match self {
            StringKind::StaticAscii | StringKind::StaticUtf16Le => "static",
            StringKind::Go | StringKind::Rust => "lang",
            StringKind::Stack => "stack",
            StringKind::Tight => "tight",
            StringKind::Decoded => "decoded",
        }
    }
}

/// Encoding of a static string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Encoding {
    /// ASCII (7-bit printable).
    Ascii,
    /// UTF-16 little-endian.
    Utf16Le,
    /// UTF-8 (used for Go/Rust strings).
    Utf8,
}

/// Where a string was located in the input.
///
/// Offsets are byte offsets into the input file. `address` is the
/// runtime virtual address if the binary has been mapped (PE/ELF/Mach-O);
/// `None` for raw shellcode or when the offset doesn't fall in a mapped
/// section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    /// Byte offset into the input file.
    pub offset: u64,
    /// Virtual address, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<u64>,
    /// Section name, if known (e.g., `.rdata`, `.text`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub section: Option<String>,
    /// Virtual address of the function that produced this string,
    /// when known. Set for emulation-recovered strings (decoded /
    /// stack / tight) — pattern-based stack strings carry the
    /// function they were built in, and emulated writes get
    /// attributed to whichever function contains the writing
    /// instruction. `None` for static / language strings since
    /// those don't have a producing function.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_va: Option<u64>,
    /// Virtual address of the encoded source bytes that fed a
    /// prefill-driven decoder run. Only set on decoded strings
    /// that were recovered from the rdata-prefill path; lets
    /// analysts trace each decoded string back to the exact
    /// `.rdata` blob it came from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_va: Option<u64>,
}

impl Location {
    /// Construct a location with just a file offset.
    pub fn at_offset(offset: u64) -> Self {
        Self {
            offset,
            address: None,
            section: None,
            function_va: None,
            source_va: None,
        }
    }
}

/// One extracted string.
///
/// `'a` is the lifetime of the input bytes. Borrowing extractors return
/// `Cow::Borrowed(&'a str)` which costs zero allocations. Emulation
/// extractors return `Cow::Owned(String)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedString<'a> {
    /// The string contents.
    #[serde(borrow)]
    pub value: Cow<'a, str>,
    /// What kind of string this is.
    pub kind: StringKind,
    /// Original encoding.
    pub encoding: Encoding,
    /// Where the string came from.
    pub location: Location,
}

impl<'a> ExtractedString<'a> {
    /// Convenience constructor for a borrowed string at a file offset.
    pub fn borrowed(value: &'a str, kind: StringKind, encoding: Encoding, offset: u64) -> Self {
        Self {
            value: Cow::Borrowed(value),
            kind,
            encoding,
            location: Location::at_offset(offset),
        }
    }

    /// Take ownership of the inner string, breaking the borrow.
    pub fn into_owned(self) -> ExtractedString<'static> {
        ExtractedString {
            value: Cow::Owned(self.value.into_owned()),
            kind: self.kind,
            encoding: self.encoding,
            location: self.location,
        }
    }
}

/// Options controlling extraction.
#[derive(Debug, Clone)]
pub struct ExtractOptions {
    /// Minimum string length (in characters) for static strings.
    /// Default is 4, matching the convention of classic `strings(1)`.
    pub min_length: usize,
    /// Which extractors to run. If `None`, run all available.
    pub enabled: Option<Vec<StringKind>>,
    /// Override file format detection. `None` = auto-detect.
    pub format_override: Option<FormatHint>,
    /// Hard upper bound on emulation work (per-function steps); applied
    /// only by the emulation extractors. Reasonable default ~20_000.
    pub max_emulation_steps: u64,
    /// If true, drop duplicate strings from the result (matching on
    /// value + kind + encoding). The first occurrence is kept with its
    /// location; later occurrences are discarded. Default `false` so
    /// library callers see every occurrence.
    pub dedupe: bool,
    /// If true, drop static strings whose location falls inside an
    /// executable section. Useful for filtering assembly-byte runs
    /// like `AWAVAUATSH` (which is `push r15; push r14; push r13;
    /// push r12; push rbx; push rax` encoded) that scanners always
    /// pick up in `.text` / `__TEXT,__text`. Default `false`.
    pub skip_code_sections: bool,
    /// If true, drop static strings that match a curated list of
    /// well-known CRT / libc / Windows-API boilerplate (see
    /// [`crate::library::LIBRARY_STRINGS`]). Useful for triage
    /// workflows where the analyst wants to see program strings, not
    /// the noise from statically-linked runtime libraries. Default
    /// `false`.
    pub skip_library_strings: bool,
    /// Minimum quality score in `[0.0, 1.0]`. Strings whose
    /// [`crate::quality::string_quality`] score falls below this
    /// threshold are dropped from the result. Default `0.0` (no
    /// filtering). Typical useful values are `0.35`–`0.5`, which
    /// cuts single-character runs (`AAAAAA`, `//////`) and other
    /// low-entropy noise without losing real text.
    pub min_quality: f64,
}

impl Default for ExtractOptions {
    fn default() -> Self {
        Self {
            min_length: 4,
            enabled: None,
            format_override: None,
            max_emulation_steps: 20_000,
            dedupe: false,
            skip_code_sections: false,
            skip_library_strings: false,
            min_quality: 0.0,
        }
    }
}

impl ExtractOptions {
    /// Is the given string kind enabled for this run?
    pub fn is_enabled(&self, kind: StringKind) -> bool {
        match &self.enabled {
            None => true,
            Some(list) => list.contains(&kind),
        }
    }
}

/// A hint about how to interpret the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FormatHint {
    /// Auto-detect from magic bytes.
    Auto,
    /// PE (Windows).
    Pe,
    /// ELF (Linux / BSD).
    Elf,
    /// Mach-O (macOS).
    MachO,
    /// Raw 32-bit shellcode.
    Sc32,
    /// Raw 64-bit shellcode.
    Sc64,
}

/// Metadata about the analyzed input file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InputMetadata {
    /// Detected or specified format.
    pub format: String,
    /// Architecture if known ("x86", "x86_64", "arm", "aarch64", ...).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    /// Bitness (32 / 64) if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bits: Option<u8>,
    /// Total input size in bytes.
    pub size: u64,
    /// Identified language toolchain, if any ("go", "rust").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
}

/// One decoder candidate considered by the emulation pipeline.
///
/// Surfaced in [`ExtractionResult::candidates`] so analysts can see
/// which functions the heuristic ranked as decoder-shaped, what
/// signals went into the score, and how many strings each one
/// actually produced — useful for tuning thresholds, validating
/// recoveries against expected behavior, and spotting candidates
/// that were ranked highly but produced nothing (interesting!).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecoderCandidate {
    /// Virtual address of the function entry.
    pub va: u64,
    /// Symbol name for the function, when the binary still carries
    /// a symbol table. `None` for stripped binaries. Lets analysts
    /// see `decode_rc4 at 0x4015a0` instead of a bare VA.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Composite decoder-likeness score in `[0, 1]`.
    pub score: f64,
    /// Fraction of instructions that were bitwise / arithmetic.
    pub bitwise_density: f64,
    /// Number of back-edges (loop count proxy).
    pub loop_count: u32,
    /// Function size in bytes.
    pub byte_size: u64,
    /// Number of distinct callers in the analyzed call graph.
    pub caller_count: u32,
    /// Total decoded instruction count.
    pub instruction_count: u32,
    /// Number of distinct imports the function calls (via IAT
    /// indirect calls). High values flag wrapper functions and
    /// drive down the composite score.
    pub import_callee_count: u32,
    /// Number of strings emulation actually recovered from this
    /// function. Strings are attributed by their `location.address`,
    /// which the emulator sets to the function VA.
    pub recovered_strings: u32,
    /// Capability tags derived from the function's imported
    /// callees. Each tag is a coarse category — `calls_alloc`,
    /// `calls_memcpy`, `calls_network`, `calls_filesystem`,
    /// `calls_registry`, `calls_process`, `calls_crypto`,
    /// `calls_loader`, `calls_debug` — so analysts can spot
    /// allocator-using decoders or wrapper-style functions at a
    /// glance. Omitted from JSON when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

/// Top-level result of an extraction.
///
/// JSON shape is roughly:
/// ```json
/// {
///   "version": "0.1.0",
///   "input": { "format": "pe", "arch": "x86_64", "bits": 64, "size": 12345 },
///   "strings": [
///     { "value": "...", "kind": "static_ascii", "encoding": "ascii",
///       "location": { "offset": 4096, "address": 4198400, "section": ".rdata" } },
///     ...
///   ],
///   "warnings": ["..."]
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionResult<'a> {
    /// strix version that produced this result.
    pub version: String,
    /// Information about the analyzed input.
    pub input: InputMetadata,
    /// All extracted strings.
    #[serde(borrow)]
    pub strings: Vec<ExtractedString<'a>>,
    /// Decoder-candidate metadata, ordered by descending score.
    /// Populated by the emulation pipeline; empty for runs that
    /// didn't enable any emulation-backed kind. Omitted from JSON
    /// when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<DecoderCandidate>,
    /// Non-fatal warnings encountered during extraction.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl<'a> ExtractionResult<'a> {
    /// Construct an empty result with the given input metadata.
    pub fn new(input: InputMetadata) -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            input,
            strings: Vec::new(),
            candidates: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Detach all borrowed strings, producing a `'static` result safe to
    /// move across thread or task boundaries.
    pub fn into_owned(self) -> ExtractionResult<'static> {
        ExtractionResult {
            version: self.version,
            input: self.input,
            strings: self.strings.into_iter().map(|s| s.into_owned()).collect(),
            candidates: self.candidates,
            warnings: self.warnings,
        }
    }
}
