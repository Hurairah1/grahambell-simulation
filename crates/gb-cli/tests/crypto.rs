//! End-to-end checks of `gb crypto`: identical inputs give byte-identical reproducible outputs
//! (everything outside `bench/`), every table is written and every cross-check passes.

use gb_cli::crypto::{BENCH_DIR, CRYPTO_TABLES, produce};
use gb_config::Config;
use gb_runlog::{GitInfo, build_manifest};

/// Default configuration with small samples, so the test runs quickly.
fn small_config() -> Config {
    let mut config = Config::default();
    let c = &mut config.crypto_tests;
    c.grinding_trials = 40;
    c.grinding_budgets = vec![1, 4];
    c.batches = 10;
    c.equivocation_trials = 20;
    c.sorted_hex_trials = 200;
    c.beacon_trials = 4_000;
    c.beacon_population = 1_000;
    c.placement_trials = 4_000;
    c.bench_signer_counts = vec![3];
    c.bench_min_seconds = 0.01;
    c.testnet_miners = vec![100];
    c.dkg_member_counts = vec![6];
    c.equivalence_trials = 300;
    config
}

#[test]
fn reproducible_outputs_are_byte_identical_and_all_checks_pass() {
    let config = small_config();
    let git = GitInfo {
        commit: Some("0123456789abcdef0123456789abcdef01234567".to_string()),
        dirty: false,
    };
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let results = produce(first.path(), &config, &git).unwrap();
    produce(second.path(), &config, &git).unwrap();
    let reproducible = |dir: &std::path::Path| {
        build_manifest(dir, &[])
            .unwrap()
            .into_iter()
            .filter(|f| !f.path.starts_with(&format!("{BENCH_DIR}/")))
            .collect::<Vec<_>>()
    };
    assert_eq!(reproducible(first.path()), reproducible(second.path()));
    let written: Vec<String> = build_manifest(first.path(), &[])
        .unwrap()
        .into_iter()
        .map(|f| f.path)
        .collect();
    for table in CRYPTO_TABLES {
        assert!(written.contains(&table.to_string()), "missing {table}");
    }
    assert!(written.contains(&"SUMMARY.md".to_string()));
    assert!(written.contains(&format!("{BENCH_DIR}/BENCH.md")));
    let failed: Vec<_> = results.checks.iter().filter(|c| !c.passed).collect();
    assert!(failed.is_empty(), "failed checks: {failed:#?}");
}
