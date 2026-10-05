//! Errors raised while recording run provenance.

use thiserror::Error;

/// Error raised while writing or reading run provenance.
#[derive(Debug, Error)]
pub enum RunLogError {
    /// A file or directory could not be read or written.
    #[error("I/O error at {path}: {source}")]
    Io {
        /// Path involved.
        path: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// The run log could not be encoded or decoded as JSON.
    #[error("run log JSON error: {0}")]
    Json(String),
}

impl RunLogError {
    /// Wraps an I/O error with the path it concerns.
    pub fn io(path: &std::path::Path, source: std::io::Error) -> Self {
        RunLogError::Io {
            path: path.display().to_string(),
            source,
        }
    }
}
