//! Shared traits that the individual extractor crates implement.

use crate::{ExtractOptions, ExtractedString, Result};

/// An extractor pulls strings of a particular kind out of a byte buffer.
///
/// The `'a` lifetime is the lifetime of the input bytes; implementers
/// are free to return [`ExtractedString`]s that borrow from `input`.
pub trait Extractor {
    /// Extract strings from `input` according to `options`.
    fn extract<'a>(
        &self,
        input: &'a [u8],
        options: &ExtractOptions,
    ) -> Result<Vec<ExtractedString<'a>>>;

    /// A short human-readable name for this extractor, used in logs.
    fn name(&self) -> &'static str;
}
