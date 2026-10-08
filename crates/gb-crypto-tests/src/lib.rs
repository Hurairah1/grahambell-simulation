//! M2 measurements with real SHA-256 and BLS12-381 (SPEC §8 S11, S14; ARCHITECTURE §8.6;
//! SPEC §12 \[P\] threshold BLS).
//!
//! | Part | Module | Output |
//! |---|---|---|
//! | C1 grinding and equivocation | [`grinding`] | K1 |
//! | C2 sorted-hex rule | [`sorted_hex`] | K2 |
//! | C3 beacon withholding and placement grinding | [`beacon`] | K3 |
//! | C4 timings and the §13 server estimate | [`bench`](mod@bench) | `bench/` |
//! | C5 threshold-BLS prototype (benchmark only, not audited) | [`threshold`] | K5, `bench/` |
//! | C6 equivalence of the simulator's entropy stand-in | [`equivalence`] | K6 |
//!
//! [`run`] produces everything that is reproducible from the seed; [`timings`] produces the
//! machine-dependent measurements.

pub mod beacon;
pub mod bench;
pub mod common;
pub mod equivalence;
pub mod grinding;
pub mod sorted_hex;
pub mod stats;
pub mod threshold;

use gb_analytic::mc::Estimate;
use gb_analytic::validation::Check;
use gb_config::Config;

/// Every reproducible M2 table and its cross-checks.
#[derive(Debug, Clone, PartialEq)]
pub struct CryptoResults {
    /// K1 grinding.
    pub grinding: Vec<grinding::GrindingRow>,
    /// K1(d) equivocation.
    pub equivocation: Vec<grinding::EquivocationRow>,
    /// K2 sorted-hex collisions.
    pub sorted_hex: Vec<sorted_hex::SortedHexRow>,
    /// K2: field assignments sharing one sorted-hex hash with a sample header.
    pub equivalent_headers: usize,
    /// K3 beacon withholding.
    pub beacon: Vec<beacon::BeaconRow>,
    /// K3 placement grinding.
    pub placement: Vec<beacon::PlacementRow>,
    /// K5 threshold-BLS sizes and correctness.
    pub threshold: Vec<threshold::ThresholdRow>,
    /// K6 equivalence tests.
    pub equivalence: Vec<equivalence::EquivalenceRow>,
    /// Cross-checks.
    pub checks: Vec<Check>,
}

/// Machine-dependent measurements.
#[derive(Debug, Clone, PartialEq)]
pub struct Timings {
    /// C4 operation timings.
    pub operations: Vec<bench::TimingRow>,
    /// C4 §13 witness-server CPU estimate.
    pub server_cpu: Vec<bench::ServerCpuRow>,
    /// C5 threshold-BLS timings.
    pub threshold: Vec<threshold::ThresholdTimingRow>,
}

/// Runs every reproducible measurement.
pub fn run(config: &Config) -> CryptoResults {
    let seed = config.run.seed;
    let c = &config.crypto_tests;
    let grinding = grinding::grinding(seed, c);
    let equivocation = grinding::equivocation(seed, c);
    let sorted_hex = sorted_hex::sorted_hex(seed, c.sorted_hex_trials);
    let mut rng = gb_runlog::rng_stream(seed, "K2-equivalent");
    let sample = common::header_for(&mut rng, [7; 48], common::target_for(64));
    let equivalent_headers = sorted_hex::equivalent_headers(&sample);
    let beacon = beacon::beacon_withholding(seed, c);
    let placement = beacon::placement(seed, c);
    let (threshold, _) = threshold::threshold(seed, c);
    let equivalence = equivalence::equivalence(seed, c);
    let mut results = CryptoResults {
        grinding,
        equivocation,
        sorted_hex,
        equivalent_headers,
        beacon,
        placement,
        threshold,
        equivalence,
        checks: Vec::new(),
    };
    results.checks = checks(config, &results);
    results
}

/// Runs the machine-dependent measurements.
pub fn timings(config: &Config) -> Timings {
    let seed = config.run.seed;
    let c = &config.crypto_tests;
    let operations = bench::timings(seed, c);
    let server_cpu = bench::server_cpu(c, &operations);
    let (_, threshold) = threshold::threshold(seed, c);
    Timings {
        operations,
        server_cpu,
        threshold,
    }
}

fn checks(config: &Config, r: &CryptoResults) -> Vec<Check> {
    let k = config.run.monte_carlo.tolerance_standard_errors;
    let mut checks = Vec::new();
    for row in r.grinding.iter().filter(|g| g.experiment != "c′") {
        let se = (row.ci_high - row.ci_low) / (2.0 * 1.96);
        checks.push(Check::monte_carlo(
            "K",
            &format!("K1-{}-G{}", row.experiment, row.budget),
            &format!(
                "C1({}) G = {}: simulated advantage vs the independent-tries formula ({})",
                row.experiment, row.budget, row.description
            ),
            row.independent_tries_advantage,
            Estimate {
                value: row.advantage,
                standard_error: se,
                samples: row.trials,
            },
            k,
            0.0,
        ));
    }
    let e_rows: Vec<_> = r.grinding.iter().filter(|g| g.experiment == "e").collect();
    checks.push(Check::all_rows(
        "K",
        "K1-e-unique",
        "C1(e) current flow: re-signing produces one distinct entropy at every budget",
        e_rows
            .iter()
            .filter(|g| g.distinct_entropies != 1.0)
            .count() as u64,
        e_rows.len() as u64,
    ));
    checks.push(Check::all_rows(
        "K",
        "K1-d-equivocation",
        "C1(d): every equivocating pair flagged, no false positives in the three control cases",
        r.equivocation
            .iter()
            .filter(|e| e.flagged != e.expected)
            .count() as u64,
        r.equivocation.len() as u64,
    ));
    let swaps = &r.sorted_hex[..r.sorted_hex.len().saturating_sub(1)];
    checks.push(Check::all_rows(
        "K",
        "K2-sorted-hex",
        "C2: every field swap collides under the sorted-hex rule and none under fixed order; random headers never collide",
        swaps
            .iter()
            .filter(|s| s.sorted_hex_collisions != s.pairs || s.fixed_order_collisions != 0)
            .count() as u64
            + r.sorted_hex
                .last()
                .map_or(1, |s| u64::from(s.sorted_hex_collisions + s.fixed_order_collisions != 0)),
        r.sorted_hex.len() as u64,
    ));
    for row in &r.beacon {
        checks.push(Check::monte_carlo(
            "K",
            &format!(
                "K3-{}-s{}-{}",
                if row.k.is_some() { "lottery" } else { "allocation" },
                row.attacker_block_share,
                row.k.map_or(format!("q{}", row.favourable_share), |k| format!("k{k}"))
            ),
            &format!(
                "C3 {}: simulated probability of a favourable outcome with withholding vs q/(1 − s(1 − q))",
                row.beacon
            ),
            row.p_with_withholding_formula,
            Estimate {
                value: row.p_with_withholding,
                standard_error: row.standard_error,
                samples: row.trials,
            },
            k,
            0.0,
        ));
    }
    for row in &r.placement {
        checks.push(Check::monte_carlo(
            "K",
            &format!(
                "K3-placement-{}",
                if row.ids.starts_with("all") {
                    "all"
                } else {
                    "kept"
                }
            ),
            &format!(
                "C3 placement grinding ({}): share in the target seats vs the target share",
                row.ids
            ),
            row.target_share,
            Estimate {
                value: row.p_target,
                standard_error: row.standard_error,
                samples: row.trials,
            },
            k,
            0.0,
        ));
    }
    checks.push(Check::all_rows(
        "K",
        "K5-threshold-verifies",
        "C5: at every size, all share checks pass and the combined threshold signature verifies under blst",
        r.threshold.iter().filter(|t| !t.combined_signature_verifies).count() as u64,
        r.threshold.len() as u64,
    ));
    checks.push(Check::all_rows(
        "K",
        "K6-equivalence",
        "C6: real entropy and the uniform stand-in pass every test at the configured minimum p-value",
        r.equivalence.iter().filter(|e| !e.passes).count() as u64,
        r.equivalence.len() as u64,
    ));
    checks
}
