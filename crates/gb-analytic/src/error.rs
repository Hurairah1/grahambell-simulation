//! Errors raised by the analytical computations.

use thiserror::Error;

/// Error raised when an analysis receives inputs outside its domain.
#[derive(Debug, Error, PartialEq)]
pub enum AnalyticError {
    /// An input value is outside the range the formula accepts.
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

/// Result type of this crate.
pub type Result<T> = std::result::Result<T, AnalyticError>;

/// Returns an [`AnalyticError::InvalidInput`] with `message` unless `condition` holds.
pub(crate) fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(AnalyticError::InvalidInput(message.to_string()))
    }
}
