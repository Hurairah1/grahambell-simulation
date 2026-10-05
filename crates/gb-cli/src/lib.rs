//! Library behind the `gb` command-line tool.
//!
//! The binary in `main.rs` only parses arguments; everything it does is implemented here so
//! integration tests can drive the same code paths.

pub mod params;

use anyhow::Context;
use gb_config::Config;
use std::path::Path;

/// Loads the configuration from `path`, or the built-in defaults when `path` is `None`.
pub fn load_config(path: Option<&Path>) -> anyhow::Result<Config> {
    match path {
        Some(path) => Config::from_file(path)
            .with_context(|| format!("loading configuration {}", path.display())),
        None => Ok(Config::default()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_path_loads_the_defaults() {
        assert_eq!(load_config(None).unwrap(), Config::default());
    }

    #[test]
    fn missing_file_reports_the_path() {
        let error = load_config(Some(Path::new("/nonexistent/gb.toml"))).unwrap_err();
        assert!(format!("{error:#}").contains("/nonexistent/gb.toml"));
    }
}
