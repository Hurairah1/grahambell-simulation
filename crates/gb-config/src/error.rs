//! Errors raised while loading or validating a configuration.

use thiserror::Error;

/// Error raised while loading or validating a [`crate::Config`].
#[derive(Debug, Error)]
pub enum ConfigError {
    /// The configuration file could not be read.
    #[error("cannot read configuration file {path}: {source}")]
    Read {
        /// Path that was being read.
        path: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// The TOML text could not be parsed.
    #[error("invalid TOML: {0}")]
    Parse(String),
    /// The merged configuration does not match the expected structure, for example because
    /// of an unknown key.
    #[error("configuration does not match the expected structure: {0}")]
    Structure(String),
    /// The default configuration could not be serialized (an internal error).
    #[error("cannot serialize the default configuration: {0}")]
    Serialize(String),
    /// A configuration file tried to change a SPEC status tag.
    #[error(
        "parameter `{path}` has SPEC status {expected} and cannot be changed to {found} in a configuration file"
    )]
    StatusOverride {
        /// Dotted key of the parameter.
        path: String,
        /// Status defined by the SPEC.
        expected: String,
        /// Status found in the configuration file.
        found: String,
    },
    /// One or more values are out of their valid range.
    #[error("invalid configuration: {}", .0.join("; "))]
    Invalid(Vec<String>),
}
