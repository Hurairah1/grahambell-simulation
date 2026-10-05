//! Git provenance: the commit a run was produced from, and whether the tree was clean.

use std::path::Path;
use std::process::Command;

/// Git state of the working tree at run time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitInfo {
    /// Full commit hash, or `None` when the directory is not a git repository or git is
    /// unavailable.
    pub commit: Option<String>,
    /// True when tracked files differ from the commit or untracked files are present.
    pub dirty: bool,
}

impl GitInfo {
    /// Reads the git state of the repository containing `dir`.
    ///
    /// Never fails: a missing repository or git binary yields `commit: None`.
    pub fn read(dir: &Path) -> GitInfo {
        let commit = run_git(dir, &["rev-parse", "HEAD"])
            .map(|text| text.trim().to_string())
            .filter(|hash| is_commit_hash(hash));
        let dirty = match &commit {
            Some(_) => run_git(dir, &["status", "--porcelain"])
                .map(|text| porcelain_reports_changes(&text))
                .unwrap_or(true),
            None => false,
        };
        GitInfo { commit, dirty }
    }

    /// True when results can be attributed to an exact commit.
    pub fn is_clean_commit(&self) -> bool {
        self.commit.is_some() && !self.dirty
    }

    /// First seven characters of the commit, `-dirty` appended when the tree was dirty, or
    /// `nogit` when there is no commit.
    pub fn short_label(&self) -> String {
        match &self.commit {
            Some(hash) => {
                let short: String = hash.chars().take(7).collect();
                if self.dirty {
                    format!("{short}-dirty")
                } else {
                    short
                }
            }
            None => "nogit".to_string(),
        }
    }
}

/// True when `git status --porcelain` output lists any change.
pub fn porcelain_reports_changes(output: &str) -> bool {
    output.lines().any(|line| !line.trim().is_empty())
}

fn is_commit_hash(text: &str) -> bool {
    text.len() >= 40 && text.chars().all(|c| c.is_ascii_hexdigit())
}

fn run_git(dir: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_porcelain_output_means_clean() {
        assert!(!porcelain_reports_changes(""));
        assert!(!porcelain_reports_changes("\n"));
    }

    #[test]
    fn modified_or_untracked_files_mean_dirty() {
        assert!(porcelain_reports_changes(" M src/lib.rs\n"));
        assert!(porcelain_reports_changes("?? new_file.rs\n"));
    }

    #[test]
    fn short_label_marks_dirty_trees() {
        let hash = "0123456789abcdef0123456789abcdef01234567".to_string();
        let clean = GitInfo {
            commit: Some(hash.clone()),
            dirty: false,
        };
        let dirty = GitInfo {
            commit: Some(hash),
            dirty: true,
        };
        assert_eq!(clean.short_label(), "0123456");
        assert_eq!(dirty.short_label(), "0123456-dirty");
        assert!(clean.is_clean_commit());
        assert!(!dirty.is_clean_commit());
    }

    #[test]
    fn directory_outside_any_repository_has_no_commit() {
        let dir = tempfile::tempdir().unwrap();
        let info = GitInfo::read(dir.path());
        assert_eq!(info.commit, None);
        assert_eq!(info.short_label(), "nogit");
        assert!(!info.is_clean_commit());
    }

    #[test]
    fn fresh_repository_with_a_commit_is_read_as_clean() {
        let dir = tempfile::tempdir().unwrap();
        let git = |args: &[&str]| {
            Command::new("git")
                .arg("-C")
                .arg(dir.path())
                .args(args)
                .output()
                .map(|out| out.status.success())
                .unwrap_or(false)
        };
        if !git(&["init", "-q"]) {
            return; // git is not installed; nothing to check.
        }
        std::fs::write(dir.path().join("a.txt"), "a").unwrap();
        assert!(git(&["add", "a.txt"]));
        assert!(git(&[
            "-c",
            "user.name=test",
            "-c",
            "user.email=test@example.com",
            "commit",
            "-q",
            "-m",
            "init"
        ]));
        let info = GitInfo::read(dir.path());
        assert!(info.is_clean_commit(), "{info:?}");
        std::fs::write(dir.path().join("b.txt"), "b").unwrap();
        assert!(GitInfo::read(dir.path()).dirty);
    }
}
