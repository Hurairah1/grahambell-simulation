//! SHA-256 manifest of the files a run wrote, so anyone can check a rerun is bit-identical.

use crate::error::RunLogError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// One output file in a run directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputFile {
    /// Path relative to the run directory, with `/` separators.
    pub path: String,
    /// Lower-case hex SHA-256 of the file contents.
    pub sha256: String,
    /// File size in bytes.
    pub bytes: u64,
}

/// Lower-case hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Lists every file under `root` with its hash, sorted by path, skipping names in `exclude`.
pub fn build_manifest(root: &Path, exclude: &[&str]) -> Result<Vec<OutputFile>, RunLogError> {
    let mut files = Vec::new();
    collect_files(root, root, exclude, &mut files)?;
    files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(files)
}

fn collect_files(
    root: &Path,
    dir: &Path,
    exclude: &[&str],
    files: &mut Vec<OutputFile>,
) -> Result<(), RunLogError> {
    let entries = std::fs::read_dir(dir).map_err(|e| RunLogError::io(dir, e))?;
    let mut paths: Vec<PathBuf> = Vec::new();
    for entry in entries {
        paths.push(entry.map_err(|e| RunLogError::io(dir, e))?.path());
    }
    for path in paths {
        let relative = relative_path(root, &path);
        if exclude.contains(&relative.as_str()) {
            continue;
        }
        if path.is_dir() {
            collect_files(root, &path, exclude, files)?;
        } else {
            let bytes = std::fs::read(&path).map_err(|e| RunLogError::io(&path, e))?;
            files.push(OutputFile {
                path: relative,
                sha256: sha256_hex(&bytes),
                bytes: bytes.len() as u64,
            });
        }
    }
    Ok(())
}

fn relative_path(root: &Path, path: &Path) -> String {
    let relative = path.strip_prefix(root).unwrap_or(path);
    relative
        .components()
        .map(|part| part.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_of_abc_matches_the_standard_test_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn manifest_lists_nested_files_sorted_and_skips_excluded_names() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("charts")).unwrap();
        std::fs::write(dir.path().join("b.csv"), "b").unwrap();
        std::fs::write(dir.path().join("a.csv"), "a").unwrap();
        std::fs::write(dir.path().join("charts/c.png"), "c").unwrap();
        std::fs::write(dir.path().join("run.json"), "{}").unwrap();
        let manifest = build_manifest(dir.path(), &["run.json"]).unwrap();
        let paths: Vec<&str> = manifest.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, vec!["a.csv", "b.csv", "charts/c.png"]);
        assert_eq!(manifest[0].bytes, 1);
        assert_eq!(manifest[0].sha256, sha256_hex(b"a"));
    }

    #[test]
    fn missing_directory_is_an_error() {
        assert!(build_manifest(Path::new("/nonexistent/run"), &[]).is_err());
    }
}
