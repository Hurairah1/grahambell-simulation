//! The run log: everything needed to identify, reproduce and verify one run.

use crate::error::RunLogError;
use crate::git::GitInfo;
use crate::manifest::{OutputFile, build_manifest, sha256_hex};
use crate::time::UtcTimestamp;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// File name of the run log inside a run directory.
pub const RUN_LOG_FILE: &str = "run.json";

/// File name of the resolved configuration inside a run directory.
pub const RESOLVED_CONFIG_FILE: &str = "config.resolved.toml";

/// Compiler that built this binary, captured at build time.
pub const RUSTC_VERSION: &str = env!("GB_RUSTC_VERSION");

/// Provenance of one run, written as `run.json` next to its outputs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunLog {
    /// Run identifier, also the run directory name.
    pub run_id: String,
    /// UTC start time in RFC 3339 form.
    pub created_utc: String,
    /// Analysis that was run, for example `analytic`.
    pub analysis: String,
    /// Full command line.
    pub command_line: Vec<String>,
    /// Master seed.
    pub seed: u64,
    /// Git commit the code was run from, if known.
    pub git_commit: Option<String>,
    /// True when the working tree differed from the commit.
    pub git_dirty: bool,
    /// Configuration file given on the command line, if any.
    pub config_path: Option<String>,
    /// SHA-256 of the resolved configuration written next to the outputs.
    pub config_sha256: String,
    /// Version of the crate that produced the run.
    pub crate_version: String,
    /// Compiler version.
    pub rustc_version: String,
    /// Operating system the run executed on.
    pub target_os: String,
    /// CPU architecture the run executed on.
    pub target_arch: String,
    /// Every output file with its SHA-256, excluding this log.
    pub outputs: Vec<OutputFile>,
}

/// Inputs that identify a run before its outputs exist.
#[derive(Debug, Clone, PartialEq)]
pub struct RunIdentity {
    /// Analysis name, for example `analytic`.
    pub analysis: String,
    /// Start time.
    pub started: UtcTimestamp,
    /// Git state.
    pub git: GitInfo,
    /// Master seed.
    pub seed: u64,
}

impl RunIdentity {
    /// Run identifier `YYYYMMDDTHHMMSSZ_<commit7>[-dirty]_s<seed>`.
    pub fn run_id(&self) -> String {
        format!(
            "{}_{}_s{}",
            self.started.compact(),
            self.git.short_label(),
            self.seed
        )
    }
}

/// Writes the resolved configuration into `run_dir` and returns its SHA-256.
pub fn write_resolved_config(run_dir: &Path, toml_text: &str) -> Result<String, RunLogError> {
    let path = run_dir.join(RESOLVED_CONFIG_FILE);
    std::fs::write(&path, toml_text).map_err(|e| RunLogError::io(&path, e))?;
    Ok(sha256_hex(toml_text.as_bytes()))
}

/// Details recorded alongside the identity when a run finishes.
#[derive(Debug, Clone, PartialEq)]
pub struct RunDetails {
    /// Full command line.
    pub command_line: Vec<String>,
    /// Configuration file given on the command line, if any.
    pub config_path: Option<String>,
    /// SHA-256 of the resolved configuration.
    pub config_sha256: String,
    /// Version of the crate that produced the run.
    pub crate_version: String,
}

/// Hashes every file in `run_dir` and writes `run.json`. Returns the path written.
pub fn finish_run(
    run_dir: &Path,
    identity: &RunIdentity,
    details: &RunDetails,
) -> Result<PathBuf, RunLogError> {
    let outputs = build_manifest(run_dir, &[RUN_LOG_FILE])?;
    let log = RunLog {
        run_id: identity.run_id(),
        created_utc: identity.started.rfc3339(),
        analysis: identity.analysis.clone(),
        command_line: details.command_line.clone(),
        seed: identity.seed,
        git_commit: identity.git.commit.clone(),
        git_dirty: identity.git.dirty,
        config_path: details.config_path.clone(),
        config_sha256: details.config_sha256.clone(),
        crate_version: details.crate_version.clone(),
        rustc_version: RUSTC_VERSION.to_string(),
        target_os: std::env::consts::OS.to_string(),
        target_arch: std::env::consts::ARCH.to_string(),
        outputs,
    };
    let text = serde_json::to_string_pretty(&log).map_err(|e| RunLogError::Json(e.to_string()))?;
    let path = run_dir.join(RUN_LOG_FILE);
    std::fs::write(&path, text + "\n").map_err(|e| RunLogError::io(&path, e))?;
    Ok(path)
}

/// Reads a `run.json` file.
pub fn read_run_log(path: &Path) -> Result<RunLog, RunLogError> {
    let text = std::fs::read_to_string(path).map_err(|e| RunLogError::io(path, e))?;
    serde_json::from_str(&text).map_err(|e| RunLogError::Json(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> RunIdentity {
        RunIdentity {
            analysis: "analytic".to_string(),
            started: UtcTimestamp::from_unix_seconds(1_791_207_120),
            git: GitInfo {
                commit: Some("abcdef0123456789abcdef0123456789abcdef01".to_string()),
                dirty: false,
            },
            seed: 42,
        }
    }

    #[test]
    fn run_id_combines_time_commit_and_seed() {
        assert_eq!(identity().run_id(), "20261005T133200Z_abcdef0_s42");
    }

    #[test]
    fn finished_run_log_records_outputs_and_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("table.csv"), "x\n1\n").unwrap();
        let config_hash = write_resolved_config(dir.path(), "[run]\nseed = 42\n").unwrap();
        let details = RunDetails {
            command_line: vec!["gb".into(), "analytic".into()],
            config_path: None,
            config_sha256: config_hash.clone(),
            crate_version: "0.1.0".into(),
        };
        let path = finish_run(dir.path(), &identity(), &details).unwrap();
        let log = read_run_log(&path).unwrap();
        assert_eq!(log.run_id, "20261005T133200Z_abcdef0_s42");
        assert_eq!(log.config_sha256, config_hash);
        let names: Vec<&str> = log.outputs.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(names, vec![RESOLVED_CONFIG_FILE, "table.csv"]);
        assert!(!log.rustc_version.is_empty());
    }

    #[test]
    fn reading_a_missing_run_log_is_an_error() {
        assert!(read_run_log(Path::new("/nonexistent/run.json")).is_err());
    }
}
