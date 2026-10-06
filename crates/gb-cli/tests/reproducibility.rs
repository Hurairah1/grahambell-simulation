//! End-to-end checks of `gb analytic`: identical inputs give byte-identical outputs, every
//! expected file is written, every cross-check passes, the committed public brief matches a
//! fresh run, and a run refuses to start from a working tree that is not a clean commit.

use gb_cli::analytic::{AnalyticOptions, SUMMARY_FILE, produce, run_analytic};
use gb_cli::brief::BRIEF_FILE;
use gb_cli::charts::CHART_FILES;
use gb_cli::tables::TABLE_FILES;
use gb_config::Config;
use gb_runlog::{GitInfo, RESOLVED_CONFIG_FILE, build_manifest};
use std::path::PathBuf;

/// Default configuration with smaller Monte Carlo samples, so the test runs quickly.
fn test_config() -> Config {
    let mut config = Config::default();
    let mc = &mut config.run.monte_carlo;
    mc.issuance_replicates = 60;
    mc.partition_replicates = 300;
    mc.committee_refreshes = 400_000;
    mc.restart_successes = 2_000;
    mc.per_round_trials = 2_000;
    mc.hopping_replicates = 600;
    mc.tie_rounds = 20_000;
    config
}

fn clean_git() -> GitInfo {
    GitInfo {
        commit: Some("0123456789abcdef0123456789abcdef01234567".to_string()),
        dirty: false,
    }
}

#[test]
fn identical_inputs_produce_byte_identical_outputs_and_all_checks_pass() {
    let config = test_config();
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let (results, _) = produce(first.path(), &config, &clean_git()).unwrap();
    produce(second.path(), &config, &clean_git()).unwrap();

    // Reference: the SHA-256 manifest of the first run; tolerance: every byte identical.
    let manifest_first = build_manifest(first.path(), &[]).unwrap();
    let manifest_second = build_manifest(second.path(), &[]).unwrap();
    assert_eq!(manifest_first, manifest_second);

    let written: Vec<String> = manifest_first.iter().map(|f| f.path.clone()).collect();
    for table in TABLE_FILES {
        assert!(written.contains(&table.to_string()), "missing {table}");
    }
    for chart in CHART_FILES {
        assert!(
            written.contains(&format!("charts/{chart}")),
            "missing {chart}"
        );
    }
    assert!(written.contains(&SUMMARY_FILE.to_string()));
    assert!(written.contains(&BRIEF_FILE.to_string()));
    assert!(written.contains(&RESOLVED_CONFIG_FILE.to_string()));

    let failed: Vec<_> = results.checks.iter().filter(|c| !c.passed).collect();
    assert!(failed.is_empty(), "failed checks: {failed:#?}");

    // The brief uses exact tables only, so the reduced Monte Carlo sample sizes of this test
    // cannot change it: the committed copy must equal the freshly generated one.
    let committed = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/M1_PUBLIC_BRIEF.md");
    let generated = std::fs::read_to_string(first.path().join(BRIEF_FILE)).unwrap();
    let on_disk = std::fs::read_to_string(&committed).unwrap_or_default();
    assert!(
        on_disk == generated,
        "docs/M1_PUBLIC_BRIEF.md differs from the generated brief; copy {BRIEF_FILE} from a run directory"
    );
}

#[test]
fn a_run_outside_a_clean_commit_is_refused_without_allow_dirty() {
    let not_a_repository = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();
    let options = AnalyticOptions {
        config_path: None,
        seed: None,
        out_root: out.path().to_path_buf(),
        allow_dirty: false,
        repo_dir: not_a_repository.path().to_path_buf(),
        command_line: vec!["gb".to_string(), "analytic".to_string()],
    };
    let error = run_analytic(&options).unwrap_err();
    assert!(format!("{error}").contains("--allow-dirty"), "{error}");
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
}
