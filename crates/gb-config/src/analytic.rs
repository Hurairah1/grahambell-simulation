//! Grids for the M1 analytical baseline, and run-level settings.
//!
//! These are analysis inputs, not protocol parameters, so they carry no SPEC status tag.
//! The defaults are the value lists given in the M1 brief and the architect's amendments of
//! 2026-10-05 and 2026-10-06.

use crate::protocol::Fraction;
use serde::{Deserialize, Serialize};

/// Modelling constants that are not protocol parameters.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelConstants {
    /// Seconds in a modelled year. 365 days gives R = 1,051,200 IDs per year at 30 s.
    pub seconds_per_year: u64,
}

impl Default for ModelConstants {
    fn default() -> Self {
        ModelConstants {
            seconds_per_year: 31_536_000,
        }
    }
}

/// Section A grid: time for an attacker to reach a share of active IDs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeToThresholdGrid {
    /// Historical active base sizes G.
    pub genesis_ids: Vec<u64>,
    /// Attacker's sustained share s of new issuance.
    pub attacker_shares: Vec<f64>,
    /// Target shares T of active IDs.
    pub thresholds: Vec<f64>,
    /// Honest online fractions f.
    pub online_fractions: Vec<f64>,
    /// Honest active-base growth g, as multiples of the issuance rate R.
    pub honest_growth_multiples_of_r: Vec<f64>,
    /// Attack-time floors T_min, in years.
    pub t_min_years: Vec<f64>,
    /// Adaptive-cap checkpoint intervals, as fractions of T_min.
    pub checkpoint_fractions_of_t_min: Vec<f64>,
    /// Threshold that defines the time floor (majority).
    pub floor_threshold: f64,
    /// Horizon of the share-trajectory table, in years.
    pub trajectory_horizon_years: f64,
    /// Step of the share-trajectory table, in years.
    pub trajectory_step_years: f64,
}

impl Default for TimeToThresholdGrid {
    fn default() -> Self {
        TimeToThresholdGrid {
            genesis_ids: vec![1_000_000, 2_100_000, 2_900_000, 5_000_000, 10_000_000],
            attacker_shares: vec![
                0.05, 0.10, 0.20, 0.25, 0.30, 0.34, 0.40, 0.52, 0.55, 0.60, 0.75, 1.0,
            ],
            thresholds: vec![0.33, 0.51, 0.67],
            online_fractions: vec![0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
            honest_growth_multiples_of_r: vec![0.0, 0.5, 1.0, 2.0],
            t_min_years: vec![1.0, 2.0, 5.0, 10.0],
            checkpoint_fractions_of_t_min: vec![0.25, 0.5, 1.0],
            floor_threshold: 0.51,
            trajectory_horizon_years: 50.0,
            trajectory_step_years: 0.5,
        }
    }
}

/// Section B grid: witness capture and stall probabilities.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessGrid {
    /// Attacker's fraction p of registered IDs.
    pub attacker_fractions: Vec<f64>,
    /// Network sizes, in KWCs (equal to WCs).
    pub kwc_counts: Vec<u64>,
    /// Horizon of the KWC-composition count (SPEC §10 H6), in years.
    pub composition_horizon_years: f64,
    /// Starting KWC counts for the composition count.
    pub composition_initial_kwc_counts: Vec<u64>,
    /// Ban rates, as fractions of registered IDs per year (sensitivity; 0 is the base case).
    pub ban_rates_per_year: Vec<f64>,
    /// Deactivation cycles (deactivation, then re-activation) per registered ID per year. An
    /// illustrative sensitivity until M3 provides household downtime profiles.
    pub deactivation_cycles_per_id_per_year: Vec<f64>,
}

impl Default for WitnessGrid {
    fn default() -> Self {
        WitnessGrid {
            attacker_fractions: vec![0.05, 0.10, 0.15, 0.20, 0.25, 0.30, 0.33, 0.40],
            kwc_counts: vec![10_000, 100_000, 1_000_000],
            composition_horizon_years: 10.0,
            composition_initial_kwc_counts: vec![10_000, 100_000, 290_000, 1_000_000],
            ban_rates_per_year: vec![0.0, 0.01, 0.05],
            deactivation_cycles_per_id_per_year: vec![0.0, 1.0, 4.0],
        }
    }
}

/// Section C grid: Chain Allocation Committee.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacGrid {
    /// Committee sizes n.
    pub committee_sizes: Vec<u64>,
    /// Attacker's fraction p of active IDs.
    pub attacker_fractions: Vec<f64>,
    /// Active IDs: the canonical active list the lottery draws from.
    pub active_population: u64,
    /// Fractions of honest IDs that mine, for the v0.2 comparison rule (attacker IDs always
    /// mine).
    pub honest_mining_fractions: Vec<f64>,
}

impl Default for CacGrid {
    fn default() -> Self {
        CacGrid {
            committee_sizes: vec![30, 100, 600, 1000],
            attacker_fractions: vec![0.1, 0.2, 0.25, 0.3, 0.33, 0.4],
            active_population: 2_900_000,
            honest_mining_fractions: vec![0.5, 0.7, 1.0],
        }
    }
}

/// Section D grid: restart attack.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestartGrid {
    /// Competing unregistered miners N.
    pub competing_miners: Vec<u64>,
    /// Restart cost C, in seconds.
    pub restart_costs_s: Vec<f64>,
    /// Keep windows W, in seconds.
    pub keep_windows_s: Vec<u64>,
}

impl Default for RestartGrid {
    fn default() -> Self {
        RestartGrid {
            competing_miners: vec![1_000_000, 5_000_000],
            restart_costs_s: vec![60.0, 300.0, 600.0],
            keep_windows_s: vec![3_600, 86_400, 259_200],
        }
    }
}

/// Section E grid: difficulty hopping.
///
/// The retarget window and clamp of the Variant A comparison are protocol parameters
/// (`issuance.retarget_window_blocks`, `issuance.retarget_clamp_factor`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HoppingGrid {
    /// Attacker miners added for one window, as multiples m of the honest miners.
    pub attacker_ratios: Vec<f64>,
}

impl Default for HoppingGrid {
    fn default() -> Self {
        HoppingGrid {
            attacker_ratios: vec![0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 4.0],
        }
    }
}

/// Section F grid: same-step ties between PoW-ID blocks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TiesGrid {
    /// Competing unregistered miners N.
    pub competing_miners: Vec<u64>,
    /// PoW-ID target intervals I, in seconds.
    pub intervals_s: Vec<f64>,
    /// Largest tie size reported in the tie-size distribution.
    pub max_tie_size: u32,
}

impl Default for TiesGrid {
    fn default() -> Self {
        TiesGrid {
            competing_miners: vec![1_000_000, 5_000_000],
            intervals_s: vec![10.0, 30.0, 60.0],
            max_tie_size: 4,
        }
    }
}

/// Section G grid: the quorum trade-off.
///
/// The CAC part uses the committee size `cac.size` and the active population of the section C
/// grid; the 10-year counts use the horizon of the section B grid.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuorumTradeoffGrid {
    /// Quorum fractions q applied to the 40-member pool and to each group of the registered
    /// layout (G1).
    pub quorum_fractions: Vec<Fraction>,
    /// PoWit-only quorum fractions for the split rule (G2).
    pub powit_quorum_fractions: Vec<Fraction>,
    /// Quorum for decisions that global validation cannot re-check (G2).
    pub decision_quorum: Fraction,
    /// Committee quorum fractions (G3).
    pub cac_quorum_fractions: Vec<Fraction>,
    /// Attacker's fraction p of registered (or active) IDs.
    pub attacker_fractions: Vec<f64>,
    /// Network sizes, in KWCs.
    pub kwc_counts: Vec<u64>,
}

impl Default for QuorumTradeoffGrid {
    fn default() -> Self {
        QuorumTradeoffGrid {
            quorum_fractions: vec![
                Fraction::new(51, 100),
                Fraction::new(55, 100),
                Fraction::new(60, 100),
                Fraction::new(2, 3),
                Fraction::new(75, 100),
            ],
            powit_quorum_fractions: vec![
                Fraction::new(51, 100),
                Fraction::new(55, 100),
                Fraction::new(60, 100),
            ],
            decision_quorum: Fraction::new(2, 3),
            cac_quorum_fractions: vec![Fraction::new(51, 100), Fraction::new(2, 3)],
            attacker_fractions: vec![0.05, 0.10, 0.20, 0.25, 0.30, 0.33, 0.40, 0.45, 0.49],
            kwc_counts: vec![100_000, 1_000_000],
        }
    }
}

/// All M1 grids.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnalyticConfig {
    /// Section A.
    pub time_to_threshold: TimeToThresholdGrid,
    /// Section B.
    pub witness: WitnessGrid,
    /// Section C.
    pub cac: CacGrid,
    /// Section D.
    pub restart: RestartGrid,
    /// Section E.
    pub hopping: HoppingGrid,
    /// Section F.
    pub ties: TiesGrid,
    /// Section G.
    pub quorum_tradeoff: QuorumTradeoffGrid,
}

/// Sample sizes for the seeded Monte Carlo cross-checks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MonteCarloConfig {
    /// Replicates of the per-block issuance simulation (section A).
    pub issuance_replicates: u64,
    /// Genesis size used by the per-block issuance simulation (section A).
    pub issuance_genesis_ids: u64,
    /// Replicates of the random-partition simulation (section B).
    pub partition_replicates: u64,
    /// WCs in the random-partition simulation (section B).
    pub partition_wcs: u64,
    /// Committee refreshes in each sliding-committee simulation (section C).
    pub committee_refreshes: u64,
    /// Mining IDs in the simulation of the v0.2 comparison rule (section C).
    pub committee_population: u64,
    /// Length of the canonical active list in the lottery simulation (section C).
    pub lottery_population: u64,
    /// Successful IDs per restart-attack simulation (section D).
    pub restart_successes: u64,
    /// Trials of the per-round-entropy restart simulation (section D).
    pub per_round_trials: u64,
    /// Replicates of the difficulty-hopping simulation (section E).
    pub hopping_replicates: u64,
    /// Rounds in the tie simulation (section F).
    pub tie_rounds: u64,
    /// Miners in the tie simulation (section F).
    pub tie_miners: u64,
    /// Agreement tolerance, in standard errors.
    pub tolerance_standard_errors: f64,
}

impl Default for MonteCarloConfig {
    fn default() -> Self {
        MonteCarloConfig {
            issuance_replicates: 400,
            issuance_genesis_ids: 10_000,
            partition_replicates: 2_000,
            partition_wcs: 1_000,
            committee_refreshes: 4_000_000,
            committee_population: 10_000,
            lottery_population: 100_000,
            restart_successes: 20_000,
            per_round_trials: 20_000,
            hopping_replicates: 4_000,
            tie_rounds: 200_000,
            tie_miners: 200,
            tolerance_standard_errors: 5.0,
        }
    }
}

/// Run-level settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunConfig {
    /// Master seed for every random stream.
    pub seed: u64,
    /// Monte Carlo sample sizes.
    pub monte_carlo: MonteCarloConfig,
}

impl Default for RunConfig {
    fn default() -> Self {
        RunConfig {
            seed: 20_261_005,
            monte_carlo: MonteCarloConfig::default(),
        }
    }
}
