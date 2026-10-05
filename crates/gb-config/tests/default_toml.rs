//! Checks that `configs/default.toml` mirrors `Config::default()` exactly.

use gb_config::Config;
use std::path::PathBuf;

fn default_toml_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../configs/default.toml")
}

#[test]
fn default_toml_file_equals_built_in_defaults() {
    let from_file = Config::from_file(&default_toml_path()).unwrap();
    assert_eq!(from_file, Config::default());
}

#[test]
fn default_toml_file_restates_every_parameter_without_relying_on_the_merge() {
    // Parsing the file directly (no merge over defaults) proves it is a complete mirror.
    let text = std::fs::read_to_string(default_toml_path()).unwrap();
    let parsed: Config = toml::from_str(&text).unwrap();
    assert_eq!(parsed, Config::default());
}
