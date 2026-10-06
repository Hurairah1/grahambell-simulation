//! Section E — difficulty hopping (SPEC §3.8, §8 S6, §10 H5).
//!
//! SPEC v0.3 makes Variant B (count-based) the default and keeps Variant A as the
//! comparison, with window `K = 144` PoW-ID blocks and a 4× clamp per retarget. Both values
//! are protocol parameters (`issuance.retarget_window_blocks`,
//! `issuance.retarget_clamp_factor`). The table also shows Variant A without a clamp, as a
//! sensitivity.
//!
//! # Variant A (comparison): Bitcoin-style retargeting
//!
//! Difficulty is retargeted every `K` blocks so that the last window would have lasted
//! `K·I`. Honest miners `H` are constant, and difficulty is calibrated to them. An attacker
//! adds `M = m·H` miners for exactly one window and then leaves.
//!
//! **First-order estimate** (window durations equal their expectations, no clamp):
//!
//! - **Attack window.** Blocks arrive `(1 + m)` times too fast, so the window lasts
//!   `K·I/(1 + m)`. The attacker wins `m/(1 + m)` of its `K` blocks: `K·m/(1 + m)` IDs.
//! - **Recovery window.** The retarget raises difficulty by `(1 + m)`, so the honest-only next
//!   window lasts `K·I·(1 + m)`. With a retarget clamp `c`, it lasts `K·I·min(1 + m, c)`.
//! - **Variant B (default).** Count-based difficulty follows the admitted count exactly, so
//!   blocks keep arriving every `I`. The same participation time, `K·I/(1 + m)`, then earns
//!   `K·m/(1 + m)²` IDs.
//! - **Gain.** IDs per attacker miner-second, Variant A over Variant B, is `1 + m`. The clamp
//!   does not change it for a one-window hop, because the gain is earned before any retarget.
//! - **Cycle issuance.** Over the two windows, issuance runs at
//!   `2 / (1/(1 + m) + min(1 + m, c))` of the target rate.
//!
//! The Monte Carlo cross-check simulates exponential block arrivals and real retargeting. The
//! recovery window's mean carries a known `K/(K − 1)` factor, because the retarget uses
//! `1/D` of a random window duration `D`.

use crate::error::{Result, ensure};
use crate::mc::{Estimate, RunningStats, bernoulli, exponential, ratio_of_sums};
use crate::validation::Check;
use gb_config::Config;
use gb_runlog::rng_stream;
use serde::Serialize;

/// First-order results for one hop.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HopFirstOrder {
    /// Attacker IDs during the hop window under Variant A, `K·m/(1 + m)`.
    pub attacker_ids_variant_a: f64,
    /// Attacker IDs for the same participation time under Variant B, `K·m/(1 + m)²`.
    pub attacker_ids_variant_b: f64,
    /// IDs per attacker miner-second, Variant A over Variant B, `1 + m`.
    pub gain_factor: f64,
    /// Duration of the hop window, seconds.
    pub attack_window_s: f64,
    /// Duration of the honest-only recovery window, seconds.
    pub recovery_window_s: f64,
    /// Issuance over both windows relative to target.
    pub cycle_issuance_ratio: f64,
}

/// First-order hop results for window `K`, attacker ratio `m`, target interval `I` and an
/// optional retarget clamp `c`.
pub fn first_order(
    window_blocks: u64,
    ratio: f64,
    interval_s: f64,
    clamp: Option<f64>,
) -> Result<HopFirstOrder> {
    ensure(
        window_blocks > 0 && ratio > 0.0 && interval_s > 0.0,
        "window, ratio and interval must be positive",
    )?;
    let k = window_blocks as f64;
    let speedup = 1.0 + ratio;
    let slowdown = clamp.map_or(speedup, |c| speedup.min(c));
    let attack_window_s = k * interval_s / speedup;
    let recovery_window_s = k * interval_s * slowdown;
    Ok(HopFirstOrder {
        attacker_ids_variant_a: k * ratio / speedup,
        attacker_ids_variant_b: k * ratio / (speedup * speedup),
        gain_factor: speedup,
        attack_window_s,
        recovery_window_s,
        cycle_issuance_ratio: 2.0 * k * interval_s / (attack_window_s + recovery_window_s),
    })
}

/// E1 row.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HopRow {
    /// Retarget window K, blocks.
    pub window_blocks: u64,
    /// Attacker miners as a multiple m of honest miners.
    pub attacker_ratio: f64,
    /// "none" or "4x".
    pub clamp: String,
    /// Attacker IDs during the hop window (Variant A).
    pub attacker_ids_variant_a: f64,
    /// Attacker IDs for the same participation time (Variant B).
    pub attacker_ids_variant_b: f64,
    /// Gain factor in IDs per attacker miner-second, A over B.
    pub gain_factor: f64,
    /// Gain in percent, `100·m`.
    pub gain_percent: f64,
    /// Hop window duration, hours.
    pub attack_window_hours: f64,
    /// Recovery window duration, hours.
    pub recovery_window_hours: f64,
    /// Issuance over both windows relative to target.
    pub cycle_issuance_ratio: f64,
}

/// Variant A comparison settings from the configuration: window K and clamp factor.
fn variant_a(config: &Config) -> (u64, f64) {
    (
        u64::from(config.issuance.retarget_window_blocks.value),
        config.issuance.retarget_clamp_factor.value,
    )
}

/// Builds the E1 table from the configuration.
pub fn section_e(config: &Config) -> Result<Vec<HopRow>> {
    let grid = &config.analytic.hopping;
    let interval = config.issuance.pow_id_target_interval_s.value;
    let (window, clamp_factor) = variant_a(config);
    let mut rows = Vec::new();
    for &ratio in &grid.attacker_ratios {
        for clamp in [None, Some(clamp_factor)] {
            let hop = first_order(window, ratio, interval, clamp)?;
            rows.push(HopRow {
                window_blocks: window,
                attacker_ratio: ratio,
                clamp: clamp.map_or("none".to_string(), |c| format!("{c}x")),
                attacker_ids_variant_a: hop.attacker_ids_variant_a,
                attacker_ids_variant_b: hop.attacker_ids_variant_b,
                gain_factor: hop.gain_factor,
                gain_percent: 100.0 * (hop.gain_factor - 1.0),
                attack_window_hours: hop.attack_window_s / 3_600.0,
                recovery_window_hours: hop.recovery_window_s / 3_600.0,
                cycle_issuance_ratio: hop.cycle_issuance_ratio,
            });
        }
    }
    Ok(rows)
}

/// Monte Carlo results for one hop configuration.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HopSimulation {
    /// Gain in IDs per attacker miner-second relative to the fair count-based rate.
    pub gain: Estimate,
    /// Mean recovery-window duration, seconds.
    pub recovery_window_s: Estimate,
}

/// Simulates one hop many times under Variant A (`count_based = false`) or Variant B
/// (`count_based = true`, where difficulty always matches the miner count).
pub fn simulate_hop(
    seed: u64,
    window_blocks: u64,
    ratio: f64,
    interval_s: f64,
    clamp: Option<f64>,
    count_based: bool,
    replicates: u64,
) -> HopSimulation {
    let label = format!("E-hop-{window_blocks}-{ratio}-{clamp:?}-{count_based}");
    let mut rng = rng_stream(seed, &label);
    let attacker_win = ratio / (1.0 + ratio);
    let attack_rate = if count_based { 1.0 } else { 1.0 + ratio } / interval_s;
    let target = window_blocks as f64 * interval_s;
    let (mut wins, mut durations) = (Vec::new(), Vec::new());
    let mut recovery = RunningStats::default();
    for _ in 0..replicates {
        let (mut attack_time, mut attacker_ids) = (0.0, 0.0);
        for _ in 0..window_blocks {
            attack_time += exponential(&mut rng, attack_rate);
            attacker_ids += f64::from(u8::from(bernoulli(&mut rng, attacker_win)));
        }
        // Success probability per hash scales by actual/target duration, within the clamp.
        let factor = clamp.map_or(attack_time / target, |c| {
            (attack_time / target).clamp(1.0 / c, c)
        });
        let recovery_rate = factor / interval_s;
        let recovery_time: f64 = (0..window_blocks)
            .map(|_| exponential(&mut rng, recovery_rate))
            .sum();
        recovery.push(recovery_time);
        wins.push(attacker_ids);
        durations.push(attack_time);
    }
    let per_second = ratio_of_sums(&wins, &durations, 50);
    let scale = (1.0 + ratio) * interval_s / ratio;
    HopSimulation {
        gain: Estimate {
            value: per_second.value * scale,
            standard_error: per_second.standard_error * scale,
            samples: per_second.samples,
        },
        recovery_window_s: recovery.estimate(),
    }
}

/// Section E cross-checks.
pub fn checks(config: &Config) -> Result<Vec<Check>> {
    let mc = &config.run.monte_carlo;
    let k = mc.tolerance_standard_errors;
    let interval = config.issuance.pow_id_target_interval_s.value;
    let (window, clamp_factor) = variant_a(config);
    let mut checks = Vec::new();
    for ratio in [0.5, 1.0, 4.0] {
        for clamp in [None, Some(clamp_factor)] {
            let hop = first_order(window, ratio, interval, clamp)?;
            let sim = simulate_hop(
                config.run.seed,
                window,
                ratio,
                interval,
                clamp,
                false,
                mc.hopping_replicates,
            );
            let tag = clamp.map_or("noclamp".to_string(), |c| format!("clamp{c}"));
            checks.push(Check::monte_carlo(
                "E",
                &format!("E-mc-gain-A-K{window}-m{ratio}-{tag}"),
                &format!(
                    "Variant A, K={window}, m={ratio}, {tag}: simulated gain vs first-order 1 + m"
                ),
                hop.gain_factor,
                sim.gain,
                k,
                0.0,
            ));
            let clamped = clamp.is_some_and(|c| 1.0 + ratio > c);
            let jensen = if clamped {
                1.0
            } else {
                window as f64 / (window as f64 - 1.0)
            };
            checks.push(Check::monte_carlo(
                "E",
                &format!("E-mc-recovery-A-K{window}-m{ratio}-{tag}"),
                &format!(
                    "Variant A, K={window}, m={ratio}, {tag}: simulated recovery window vs first-order value × {jensen:.5} (K/(K-1) when unclamped)"
                ),
                hop.recovery_window_s * jensen,
                sim.recovery_window_s,
                k,
                0.0,
            ));
        }
        let b = simulate_hop(
            config.run.seed,
            window,
            ratio,
            interval,
            None,
            true,
            mc.hopping_replicates,
        );
        checks.push(Check::monte_carlo(
            "E",
            &format!("E-mc-gain-B-K{window}-m{ratio}"),
            &format!("Variant B (exact count), K={window}, m={ratio}: simulated gain vs 1 (no hopping gain)"),
            1.0,
            b.gain,
            k,
            0.0,
        ));
    }
    Ok(checks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doubling_the_miners_for_one_window_doubles_ids_per_miner_second() {
        let hop = first_order(2016, 1.0, 30.0, None).unwrap();
        assert_eq!(hop.gain_factor, 2.0);
        assert_eq!(hop.attacker_ids_variant_a, 1008.0);
        assert_eq!(hop.attacker_ids_variant_b, 504.0);
        assert_eq!(hop.attack_window_s, 2016.0 * 15.0);
        assert_eq!(hop.recovery_window_s, 2016.0 * 60.0);
    }

    #[test]
    fn clamp_only_shortens_the_recovery_window() {
        let free = first_order(144, 4.0, 30.0, None).unwrap();
        let clamped = first_order(144, 4.0, 30.0, Some(4.0)).unwrap();
        assert_eq!(free.gain_factor, clamped.gain_factor);
        assert_eq!(clamped.recovery_window_s, 144.0 * 30.0 * 4.0);
        assert!(clamped.cycle_issuance_ratio > free.cycle_issuance_ratio);
    }

    #[test]
    fn cycle_issuance_is_below_target_after_a_hop() {
        let hop = first_order(2016, 1.0, 30.0, None).unwrap();
        assert!((hop.cycle_issuance_ratio - 2.0 / (0.5 + 2.0)).abs() < 1e-12);
    }

    #[test]
    fn invalid_inputs_are_rejected() {
        assert!(first_order(0, 1.0, 30.0, None).is_err());
        assert!(first_order(10, 0.0, 30.0, None).is_err());
    }

    #[test]
    fn section_e_table_has_both_clamp_variants_at_the_spec_window() {
        let config = Config::default();
        let rows = section_e(&config).unwrap();
        assert_eq!(
            rows.len(),
            config.analytic.hopping.attacker_ratios.len() * 2
        );
        assert!(rows.iter().any(|r| r.clamp == "4x"));
        assert!(rows.iter().all(|r| r.window_blocks == 144));
    }

    #[test]
    fn all_section_e_checks_pass() {
        let mut config = Config::default();
        config.run.monte_carlo.hopping_replicates = 1_500;
        for check in checks(&config).unwrap() {
            assert!(check.passed, "{check:?}");
        }
    }
}
