//! Settings of the M2 measurements in `gb-crypto-tests` (`gb crypto`).
//!
//! These are sample sizes and grids for measurements, not protocol parameters.

use crate::protocol::Fraction;
use serde::{Deserialize, Serialize};

/// M2 measurement settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoTestsConfig {
    /// Batches for batch-means confidence intervals.
    pub batches: u64,
    /// C1: trials per grinding experiment.
    pub grinding_trials: u64,
    /// C1: grinding budgets G (attempts an attacker can try per round).
    pub grinding_budgets: Vec<u64>,
    /// C1 and C6: expected attempts to win, `E[N + 1]`; sets the small test difficulty.
    pub expected_winning_attempts: u64,
    /// C1: members of the witness group in the grinding experiments.
    pub grinding_members: u64,
    /// C1(b): quorum a subset must meet in the subset-selection experiment.
    pub subset_quorum: u64,
    /// C1(d): header pairs tested for equivocation detection.
    pub equivocation_trials: u64,
    /// C2: random headers and chain inputs tested under the sorted-hex rule.
    pub sorted_hex_trials: u64,
    /// C3: trials per beacon-withholding case.
    pub beacon_trials: u64,
    /// C3: committee lottery beacon offsets k.
    pub beacon_offsets_k: Vec<u64>,
    /// C3: attacker share of blocks and of active IDs.
    pub beacon_attacker_shares: Vec<f64>,
    /// C3: share of seats the attacker wants its new ID in (allocation beacon).
    pub beacon_target_fractions: Vec<f64>,
    /// C3: active IDs in the lottery and filled seats in the allocation experiment.
    pub beacon_population: u64,
    /// C3: trials of the placement-grinding experiment.
    pub placement_trials: u64,
    /// C4: signer counts benchmarked.
    pub bench_signer_counts: Vec<u64>,
    /// C4: minimum seconds per timing measurement in `gb crypto`.
    pub bench_min_seconds: f64,
    /// C4: miners per §13 testnet witness server.
    pub testnet_miners: Vec<u64>,
    /// C4: witness nodes per §13 server (one WC).
    pub testnet_witnesses_per_server: u64,
    /// C4: seconds per round (fresh entropy every round).
    pub testnet_round_s: f64,
    /// C5: KWC sizes n for the threshold-BLS prototype.
    pub dkg_member_counts: Vec<u64>,
    /// C5: threshold t = ⌈fraction × n⌉.
    pub dkg_threshold: Fraction,
    /// C6: trials of the real-versus-stand-in entropy comparison.
    pub equivalence_trials: u64,
    /// C6: members signing the entropy in the comparison.
    pub equivalence_members: u64,
    /// C6: smallest p-value that passes.
    pub equivalence_min_p_value: f64,
}

impl Default for CryptoTestsConfig {
    fn default() -> Self {
        CryptoTestsConfig {
            batches: 50,
            grinding_trials: 1_000,
            grinding_budgets: vec![1, 4, 16, 64],
            expected_winning_attempts: 64,
            grinding_members: 10,
            subset_quorum: 7,
            equivocation_trials: 500,
            sorted_hex_trials: 10_000,
            beacon_trials: 100_000,
            beacon_offsets_k: vec![1, 3, 6, 12],
            beacon_attacker_shares: vec![0.1, 0.25],
            beacon_target_fractions: vec![0.01, 0.1],
            beacon_population: 100_000,
            placement_trials: 100_000,
            bench_signer_counts: vec![3, 10, 27, 40, 60, 100],
            bench_min_seconds: 0.5,
            testnet_miners: vec![5_000, 10_000, 30_000],
            testnet_witnesses_per_server: 3,
            testnet_round_s: 30.0,
            dkg_member_counts: vec![30, 40, 60, 100],
            dkg_threshold: Fraction::new(2, 3),
            equivalence_trials: 4_000,
            equivalence_members: 3,
            equivalence_min_p_value: 0.001,
        }
    }
}

impl CryptoTestsConfig {
    /// Problems with the settings, as messages.
    pub fn problems(&self) -> Vec<String> {
        let mut p = Vec::new();
        let positive = [
            ("batches", self.batches),
            ("grinding_trials", self.grinding_trials),
            ("expected_winning_attempts", self.expected_winning_attempts),
            ("equivocation_trials", self.equivocation_trials),
            ("sorted_hex_trials", self.sorted_hex_trials),
            ("beacon_trials", self.beacon_trials),
            ("beacon_population", self.beacon_population),
            ("placement_trials", self.placement_trials),
            (
                "testnet_witnesses_per_server",
                self.testnet_witnesses_per_server,
            ),
            ("equivalence_trials", self.equivalence_trials),
            ("equivalence_members", self.equivalence_members),
        ];
        for (name, value) in positive {
            if value == 0 {
                p.push(format!("crypto_tests.{name} must be positive"));
            }
        }
        if self.grinding_budgets.is_empty() || self.grinding_budgets.contains(&0) {
            p.push("crypto_tests.grinding_budgets must be non-empty and positive".to_string());
        }
        if self.subset_quorum == 0 || self.subset_quorum > self.grinding_members {
            p.push("crypto_tests.subset_quorum must lie in 1..=grinding_members".to_string());
        }
        let shares = self
            .beacon_attacker_shares
            .iter()
            .chain(&self.beacon_target_fractions);
        if shares.clone().any(|s| !(*s > 0.0 && *s < 1.0)) {
            p.push(
                "crypto_tests beacon shares and target fractions must lie in (0, 1)".to_string(),
            );
        }
        if self.dkg_member_counts.iter().any(|n| *n < 2) {
            p.push("crypto_tests.dkg_member_counts must be at least 2".to_string());
        }
        if !self.dkg_threshold.is_proper() || self.dkg_threshold.numerator == 0 {
            p.push("crypto_tests.dkg_threshold must lie in (0, 1]".to_string());
        }
        if !(self.bench_min_seconds > 0.0 && self.testnet_round_s > 0.0) {
            p.push("crypto_tests timing values must be positive".to_string());
        }
        if !(self.equivalence_min_p_value > 0.0 && self.equivalence_min_p_value < 1.0) {
            p.push("crypto_tests.equivalence_min_p_value must lie in (0, 1)".to_string());
        }
        p
    }
}
