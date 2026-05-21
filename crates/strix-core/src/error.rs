//! Error types for the strix library.

use thiserror::Error;

/// Convenience result alias used throughout the strix crates.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// All errors strix can produce.
#[derive(Debug, Error)]
pub enum Error {
    /// The input bytes were not in a recognizable file format and no
    /// override was provided.
    #[error("unrecognized file format (try passing a format hint)")]
    UnknownFormat,

    /// The input was syntactically a known format but malformed.
    #[error("malformed {format}: {msg}")]
    MalformedFile {
        /// Which format we thought it was.
        format: &'static str,
        /// What was wrong.
        msg: String,
    },

    /// An extractor that requires emulation was invoked but the emulator
    /// feature isn't compiled in (or isn't implemented yet).
    #[error("extractor `{0}` is not yet implemented in this build")]
    NotImplemented(&'static str),

    /// I/O error reading the input file at the CLI layer.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization failure (should be unreachable for our schema).
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// Anything else.
    #[error("{0}")]
    Other(String),
}

impl Error {
    /// Construct a `MalformedFile` error.
    pub fn malformed(format: &'static str, msg: impl Into<String>) -> Self {
        Error::MalformedFile {
            format,
            msg: msg.into(),
        }
    }
}
