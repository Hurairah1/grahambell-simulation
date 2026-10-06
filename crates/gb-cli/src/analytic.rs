//! `gb analytic`: runs the M1 analytical baseline and writes every output with its provenance.

use crate::brief::{BRIEF_FILE, render_brief};
use crate::charts::draw_all;
use crate::load_config;
use crate::summary::{Provenance, render};
use crate::tables::write_tables;
use anyhow::{Context, bail, ensure};
use gb_analytic::M1Results;
use gb_config::Config;
use gb_runlog::{
    GitInfo, RunDetails, RunIdentity, UtcTimestamp, finish_run, write_resolved_config,
};
use std::path::{Path, PathBuf};

/// File name of the summary inside a run directory (and its copy next to the run directories).
pub const SUMMARY_FILE: &str = "SUMMARY.md";

/// Options of `gb analytic`.
#[derive(Debug, Clone, PartialEq)]
pub struct AnalyticOptions {
    /// Configuration file merged over the defaults.
    pub config_path: Option<PathBuf>,
    /// Seed overriding the configuration's.
    pub seed: Option<u64>,
    /// Directory that receives one sub-directory per run.
    pub out_root: PathBuf,
    /// Allow running from a working tree with uncommitted changes.
    pub allow_dirty: bool,
    /// Directory whose git state is recorded.
    pub repo_dir: PathBuf,
    /// Full command line, recorded in `run.json`.
    pub command_line: Vec<String>,
}

/// What a finished run produced.
#[derive(Debug, Clone, PartialEq)]
pub struct AnalyticOutcome {
    /// Directory holding the run's outputs.
    pub run_dir: PathBuf,
    /// Number of cross-checks run.
    pub checks: usize,
    /// Identifiers of failed cross-checks.
    pub failed: Vec<String>,
}

/// Computes every table and writes all outputs except `run.json` into `dir`: the resolved
/// configuration, the CSV tables, the charts, `SUMMARY.md` and the public brief. Returns the
/// results and the provenance written into the summary.
pub fn produce(
    dir: &Path,
    config: &Config,
    git: &GitInfo,
) -> anyhow::Result<(M1Results, Provenance)> {
    let results = gb_analytic::run(config)?;
    let config_sha256 = write_resolved_config(dir, &config.to_toml_string()?)?;
    let provenance = Provenance {
        commit: git.commit.clone(),
        dirty: git.dirty,
        seed: config.run.seed,
        config_sha256,
    };
    write_tables(dir, config, &results)?;
    draw_all(&dir.join("charts"), &results)?;
    let summary = render(config, &results, &provenance);
    let path = dir.join(SUMMARY_FILE);
    std::fs::write(&path, summary).with_context(|| format!("writing {}", path.display()))?;
    let brief_path = dir.join(BRIEF_FILE);
    std::fs::write(&brief_path, render_brief(config, &results))
        .with_context(|| format!("writing {}", brief_path.display()))?;
    Ok((results, provenance))
}

/// Runs the M1 analysis: checks provenance, writes a new run directory, records `run.json`,
/// and copies the summary next to the run directories.
pub fn run_analytic(options: &AnalyticOptions) -> anyhow::Result<AnalyticOutcome> {
    let mut config = load_config(options.config_path.as_deref())?;
    if let Some(seed) = options.seed {
        config.run.seed = seed;
    }
    let git = GitInfo::read(&options.repo_dir);
    if !git.is_clean_commit() && !options.allow_dirty {
        bail!(
            "the working tree is not a clean git commit ({}); commit your changes so results can be attributed, or pass --allow-dirty (recorded in run.json)",
            git.short_label()
        );
    }
    let identity = RunIdentity {
        analysis: "analytic".to_string(),
        started: UtcTimestamp::now(),
        git,
        seed: config.run.seed,
    };
    let run_dir = options.out_root.join(identity.run_id());
    ensure!(
        !run_dir.exists(),
        "run directory {} already exists",
        run_dir.display()
    );
    std::fs::create_dir_all(&run_dir).with_context(|| format!("creating {}", run_dir.display()))?;
    let (results, provenance) = produce(&run_dir, &config, &identity.git)?;
    let details = RunDetails {
        command_line: options.command_line.clone(),
        config_path: options
            .config_path
            .as_ref()
            .map(|p| p.display().to_string()),
        config_sha256: provenance.config_sha256,
        crate_version: env!("CARGO_PKG_VERSION").to_string(),
    };
    finish_run(&run_dir, &identity, &details)?;
    std::fs::copy(
        run_dir.join(SUMMARY_FILE),
        options.out_root.join(SUMMARY_FILE),
    )
    .context("copying SUMMARY.md next to the run directories")?;
    Ok(AnalyticOutcome {
        run_dir,
        checks: results.checks.len(),
        failed: results
            .checks
            .iter()
            .filter(|c| !c.passed)
            .map(|c| c.check.clone())
            .collect(),
    })
}
