//! C3 — the open risks of ARCHITECTURE §8.6, measured with real SHA-256.
//!
//! **Beacon withholding.** The miner of a beacon block sees its hash before publishing it. If
//! the outcome is unfavourable it can withhold the block, giving up that block, and the next
//! block at that height becomes the beacon. The attacker mines each candidate block with
//! probability `s`; when an honest miner wins, the outcome stands. With a favourable outcome of
//! probability `q`, the attacker gets it with probability `q / (1 − s(1 − q))` and gives up
//! `s(1 − q) / (1 − s(1 − q))` blocks per beacon on average.
//!
//! - Allocation beacon (SPEC §4.2): favourable = the attacker's new ID lands in a target share
//!   `q` of seats.
//! - Committee lottery beacon at offset k (SPEC §4.3): favourable = the drawn ID is the
//!   attacker's; `q` = its share of active IDs, and its share of blocks is the same.
//!
//! **Placement grinding.** An ID is the hash of its winning block, fixed before its allocation
//! beacon (6 blocks later) exists, so no rule applied when minting can steer its seat.

use crate::common::random_hash;
use gb_analytic::mc::{RunningStats, shuffle, uniform};
use gb_config::CryptoTestsConfig;
use gb_protocol::allocation::insertion_position;
use gb_protocol::committee::lottery_position;
use gb_runlog::rng_stream;
use serde::Serialize;

/// One row of table K3.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BeaconRow {
    /// Which beacon.
    pub beacon: &'static str,
    /// Committee lottery offset k (empty for the allocation beacon).
    pub k: Option<u64>,
    /// Attacker share of blocks, s.
    pub attacker_block_share: f64,
    /// Probability of a favourable outcome from one beacon, q.
    pub favourable_share: f64,
    /// Trials.
    pub trials: u64,
    /// Simulated probability without withholding.
    pub p_without_withholding: f64,
    /// Simulated probability with withholding.
    pub p_with_withholding: f64,
    /// Standard error of the latter.
    pub standard_error: f64,
    /// Formula `q / (1 − s(1 − q))`.
    pub p_with_withholding_formula: f64,
    /// Gain = with ÷ without (formula).
    pub gain_formula: f64,
    /// Simulated blocks given up per beacon.
    pub blocks_forgone: f64,
    /// Formula `s(1 − q) / (1 − s(1 − q))`.
    pub blocks_forgone_formula: f64,
}

/// One row of table K3 (placement grinding).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PlacementRow {
    /// Which IDs.
    pub ids: &'static str,
    /// IDs placed.
    pub trials: u64,
    /// Share landing in the target share of seats.
    pub p_target: f64,
    /// Standard error.
    pub standard_error: f64,
    /// Target share q.
    pub target_share: f64,
}

/// Plays one beacon: returns (favourable without withholding, favourable with, blocks forgone).
fn play(
    rng: &mut rand_chacha::ChaCha20Rng,
    s: f64,
    favourable: &dyn Fn(&[u8; 32]) -> bool,
) -> (bool, bool, f64) {
    let first = random_hash(rng);
    let honest_outcome = favourable(&first);
    let mut candidate = first;
    let mut forgone = 0.0;
    for _ in 0..10_000 {
        let attacker_mined = uniform(rng) < s;
        let good = favourable(&candidate);
        if !attacker_mined || good {
            return (honest_outcome, good, forgone);
        }
        forgone += 1.0;
        candidate = random_hash(rng);
    }
    (honest_outcome, favourable(&candidate), forgone)
}

fn row(
    beacon: &'static str,
    k: Option<u64>,
    s: f64,
    q: f64,
    outcomes: &[(bool, bool, f64)],
) -> BeaconRow {
    let (mut without, mut with, mut forgone) = (
        RunningStats::default(),
        RunningStats::default(),
        RunningStats::default(),
    );
    for (a, b, f) in outcomes {
        without.push(f64::from(u8::from(*a)));
        with.push(f64::from(u8::from(*b)));
        forgone.push(*f);
    }
    let formula = q / (1.0 - s * (1.0 - q));
    BeaconRow {
        beacon,
        k,
        attacker_block_share: s,
        favourable_share: q,
        trials: outcomes.len() as u64,
        p_without_withholding: without.mean(),
        p_with_withholding: with.mean(),
        standard_error: with.standard_error(),
        p_with_withholding_formula: formula,
        gain_formula: formula / q,
        blocks_forgone: forgone.mean(),
        blocks_forgone_formula: s * (1.0 - q) / (1.0 - s * (1.0 - q)),
    }
}

/// Runs C3 beacon withholding.
pub fn beacon_withholding(seed: u64, config: &CryptoTestsConfig) -> Vec<BeaconRow> {
    let n = config.beacon_population;
    let mut rows = Vec::new();
    for &s in &config.beacon_attacker_shares {
        for &q in &config.beacon_target_fractions {
            let mut rng = rng_stream(seed, &format!("K3-allocation-s{s}-q{q}"));
            let cutoff = (q * (n + 1) as f64).round() as u64;
            let outcomes: Vec<_> = (0..config.beacon_trials)
                .map(|_| {
                    let id = random_hash(&mut rng);
                    play(&mut rng, s, &|b| insertion_position(&id, b, n) < cutoff)
                })
                .collect();
            rows.push(row(
                "allocation (§4.2)",
                None,
                s,
                cutoff as f64 / (n + 1) as f64,
                &outcomes,
            ));
        }
        for &k in &config.beacon_offsets_k {
            let mut rng = rng_stream(seed, &format!("K3-lottery-s{s}-k{k}"));
            let attackers = (s * n as f64).round() as usize;
            let mut is_attacker: Vec<bool> = (0..n as usize).map(|i| i < attackers).collect();
            shuffle(&mut rng, &mut is_attacker);
            let outcomes: Vec<_> = (0..config.beacon_trials)
                .map(|_| {
                    play(&mut rng, s, &|b| {
                        is_attacker[lottery_position(b, 0, n) as usize]
                    })
                })
                .collect();
            rows.push(row(
                "committee lottery (§4.3)",
                Some(k),
                s,
                attackers as f64 / n as f64,
                &outcomes,
            ));
        }
    }
    rows
}

/// Runs C3 placement grinding: IDs kept by a rule applied at minting land in the target share
/// of seats no more often than all IDs.
pub fn placement(seed: u64, config: &CryptoTestsConfig) -> Vec<PlacementRow> {
    let n = config.beacon_population;
    let q = config
        .beacon_target_fractions
        .iter()
        .copied()
        .fold(1.0, f64::min);
    let cutoff = (q * (n + 1) as f64).round() as u64;
    let mut rng = rng_stream(seed, "K3-placement");
    let (mut all, mut kept) = (RunningStats::default(), RunningStats::default());
    for _ in 0..config.placement_trials {
        let id = random_hash(&mut rng);
        let beacon = random_hash(&mut rng);
        let hit = f64::from(u8::from(insertion_position(&id, &beacon, n) < cutoff));
        all.push(hit);
        // A minting-time rule: keep only IDs whose hash starts below 0x40.
        if id[0] < 0x40 {
            kept.push(hit);
        }
    }
    let share = cutoff as f64 / (n + 1) as f64;
    vec![
        PlacementRow {
            ids: "all minted IDs",
            trials: all.count(),
            p_target: all.mean(),
            standard_error: all.standard_error(),
            target_share: share,
        },
        PlacementRow {
            ids: "IDs kept by a minting-time rule (hash starts below 0x40)",
            trials: kept.count(),
            p_target: kept.mean(),
            standard_error: kept.standard_error(),
            target_share: share,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small() -> CryptoTestsConfig {
        CryptoTestsConfig {
            beacon_trials: 20_000,
            beacon_population: 1_000,
            placement_trials: 20_000,
            ..CryptoTestsConfig::default()
        }
    }

    #[test]
    fn withholding_matches_the_formula() {
        for r in beacon_withholding(5, &small()) {
            assert!(
                (r.p_with_withholding - r.p_with_withholding_formula).abs()
                    < 5.0 * r.standard_error + 1e-3,
                "{r:?}"
            );
            assert!(
                (r.p_without_withholding - r.favourable_share).abs() < 0.01,
                "{r:?}"
            );
        }
    }

    #[test]
    fn minting_time_rules_do_not_steer_placement() {
        for r in placement(6, &small()) {
            assert!(
                (r.p_target - r.target_share).abs() < 5.0 * r.standard_error,
                "{r:?}"
            );
        }
    }
}
