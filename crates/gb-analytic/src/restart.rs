//! Section D — the restart attack (SPEC §3.3–§3.4, §8 S5, §10 H4).
//!
//! # Old design: entropy fixed for the whole connection
//!
//! If a miner's entropy stays fixed while it is connected, its whole future hash sequence is
//! known at connection time, and the miner can compute it instantly. It can then reconnect
//! until it draws a sequence with a winning step soon.
//!
//! - **Model.** With `N` competing miners and a target interval `I`, each one-second step wins
//!   with probability `q = 1/(N·I)`. The first winning step `X` is geometric:
//!   `P(X = k) = (1 − q)^k q`.
//! - **Honest miner.** Pays one admission `C`, then waits: `E[T_h] = C + (1 − q)/q`.
//! - **Restarting miner.** Pays `C` per connection and keeps a connection only if `X ≤ W`,
//!   which happens with probability `π = 1 − (1 − q)^{W+1}`. Then
//!   `E[T_r] = C/π + E[X | X ≤ W]`.
//! - **Advantage** is `E[T_h] / E[T_r]`, approximately `W / (C + qW²/2)`. It is largest near
//!   `W* = √(2C/q)`.
//!
//! # Current design: entropy refreshed every round
//!
//! Each round's entropy is fresh and unpredictable, and does not depend on anything the miner
//! did before. The header names the previous PoW-ID block, and the entropy aggregates every
//! online member's signature. A miner gets one header per round, and abandoning it means
//! waiting for the next block. So in every round a connected miner wins with the same
//! probability, `1/N`, whatever it did before. A disconnected miner cannot win at all.
//! Restarting can only remove rounds, never improve them. The fastest policy is never to
//! restart, and the advantage of any restart policy is at most **1**.

use crate::error::{Result, ensure};
use crate::mc::{RunningStats, bernoulli, geometric_failures};
use crate::validation::Check;
use gb_config::Config;
use gb_runlog::rng_stream;
use serde::Serialize;

/// Advantage factor of the best restart policy under per-round entropy (see module docs).
pub const PER_ROUND_ENTROPY_ADVANTAGE: f64 = 1.0;

/// Per-step win probability `q = 1/(N·I)`.
pub fn per_step_win_probability(miners: u64, interval_s: f64) -> Result<f64> {
    ensure(
        miners > 0 && interval_s > 0.0,
        "miners and interval must be positive",
    )?;
    Ok(1.0 / (miners as f64 * interval_s))
}

/// Expected time to an ID for a miner that stays connected, `C + (1 − q)/q` seconds.
pub fn honest_expected_time_s(q: f64, restart_cost_s: f64) -> f64 {
    restart_cost_s + (1.0 - q) / q
}

/// Probability that the first winning step is within the keep window, `1 − (1 − q)^{W+1}`.
pub fn keep_probability(q: f64, window: u64) -> f64 {
    -libm::expm1((window as f64 + 1.0) * libm::log1p(-q))
}

/// `E[X | X ≤ W]` by direct summation with Neumaier compensation.
///
/// Stable for very small `q`, where the closed form cancels catastrophically.
pub fn truncated_mean_steps(q: f64, window: u64) -> f64 {
    let ln_miss = libm::log1p(-q);
    let (mut weights, mut weights_c) = (0.0, 0.0);
    let (mut moments, mut moments_c) = (0.0, 0.0);
    for k in 0..=window {
        let weight = libm::exp(k as f64 * ln_miss);
        neumaier_add(&mut weights, &mut weights_c, weight);
        neumaier_add(&mut moments, &mut moments_c, k as f64 * weight);
    }
    (moments + moments_c) / (weights + weights_c)
}

fn neumaier_add(sum: &mut f64, compensation: &mut f64, value: f64) {
    let total = *sum + value;
    if sum.abs() >= value.abs() {
        *compensation += (*sum - total) + value;
    } else {
        *compensation += (value - total) + *sum;
    }
    *sum = total;
}

/// `E[X | X ≤ W]` from the closed form `1/(e^λ − 1) − (W + 1)/(e^{λ(W+1)} − 1)`, with
/// `λ = −ln(1 − q)`. Accurate only when `q·W` is not tiny; used as a cross-check.
pub fn truncated_mean_steps_closed_form(q: f64, window: u64) -> f64 {
    let lambda = -libm::log1p(-q);
    1.0 / libm::expm1(lambda) - (window as f64 + 1.0) / libm::expm1(lambda * (window as f64 + 1.0))
}

/// Expected time to an ID for the restarting miner, `C/π + E[X | X ≤ W]` seconds.
pub fn restart_expected_time_s(q: f64, restart_cost_s: f64, window: u64) -> f64 {
    restart_cost_s / keep_probability(q, window) + truncated_mean_steps(q, window)
}

/// Advantage of the restart strategy under the old design, `E[T_h] / E[T_r]`.
pub fn advantage_old_design(q: f64, restart_cost_s: f64, window: u64) -> f64 {
    honest_expected_time_s(q, restart_cost_s) / restart_expected_time_s(q, restart_cost_s, window)
}

/// First-order approximation of the advantage, `W / (C + qW²/2)`.
pub fn advantage_approximation(q: f64, restart_cost_s: f64, window: u64) -> f64 {
    let w = window as f64;
    w / (restart_cost_s + q * w * w / 2.0)
}

/// Keep window that minimises the restarting miner's expected time, and the advantage it
/// gives. Found by golden-section search on the closed form, then refined with the stable
/// summation over neighbouring integers.
pub fn optimal_window(q: f64, restart_cost_s: f64) -> (u64, f64) {
    let objective = |w: f64| {
        let window = w.max(1.0) as u64;
        restart_cost_s / keep_probability(q, window) + truncated_mean_steps_closed_form(q, window)
    };
    let guess = (2.0 * restart_cost_s / q).sqrt();
    let (mut low, mut high) = (1.0, 10.0 * guess);
    let ratio = 0.5 * (5.0_f64.sqrt() - 1.0);
    for _ in 0..200 {
        let a = high - ratio * (high - low);
        let b = low + ratio * (high - low);
        if objective(a) < objective(b) {
            high = b;
        } else {
            low = a;
        }
    }
    let centre = (0.5 * (low + high)) as u64;
    let best = (centre.saturating_sub(2)..=centre + 2)
        .filter(|w| *w >= 1)
        .map(|w| (w, restart_expected_time_s(q, restart_cost_s, w)))
        .fold(
            (centre, f64::INFINITY),
            |acc, c| if c.1 < acc.1 { c } else { acc },
        );
    (best.0, honest_expected_time_s(q, restart_cost_s) / best.1)
}

/// D1 row.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RestartRow {
    /// Competing unregistered miners N.
    pub competing_miners: u64,
    /// Restart cost C, seconds.
    pub restart_cost_s: f64,
    /// Keep window W, seconds.
    pub keep_window_s: u64,
    /// Per-step win probability q.
    pub per_step_win_probability: f64,
    /// Honest expected time to an ID, days.
    pub honest_expected_days: f64,
    /// Restarting miner's expected time to an ID, days (old design).
    pub restart_expected_days: f64,
    /// Advantage factor, old design.
    pub advantage_old_design: f64,
    /// First-order approximation W/(C + qW²/2).
    pub advantage_approximation: f64,
    /// Keep window that maximises the advantage, seconds.
    pub optimal_keep_window_s: u64,
    /// Advantage at the optimal window.
    pub maximum_advantage_old_design: f64,
    /// Advantage of the best restart policy under per-round entropy (exactly 1).
    pub advantage_per_round_entropy: f64,
}

/// Builds the D1 table from the configuration.
pub fn section_d(config: &Config) -> Result<Vec<RestartRow>> {
    let grid = &config.analytic.restart;
    let interval = config.issuance.pow_id_target_interval_s.value;
    let mut rows = Vec::new();
    for &miners in &grid.competing_miners {
        let q = per_step_win_probability(miners, interval)?;
        for &cost in &grid.restart_costs_s {
            let (optimal, maximum) = optimal_window(q, cost);
            for &window in &grid.keep_windows_s {
                rows.push(RestartRow {
                    competing_miners: miners,
                    restart_cost_s: cost,
                    keep_window_s: window,
                    per_step_win_probability: q,
                    honest_expected_days: honest_expected_time_s(q, cost) / 86_400.0,
                    restart_expected_days: restart_expected_time_s(q, cost, window) / 86_400.0,
                    advantage_old_design: advantage_old_design(q, cost, window),
                    advantage_approximation: advantage_approximation(q, cost, window),
                    optimal_keep_window_s: optimal,
                    maximum_advantage_old_design: maximum,
                    advantage_per_round_entropy: PER_ROUND_ENTROPY_ADVANTAGE,
                });
            }
        }
    }
    Ok(rows)
}

/// D2 row: the old-design advantage across keep windows, for the chart.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CurveRow {
    /// Competing unregistered miners N.
    pub competing_miners: u64,
    /// Restart cost C, seconds.
    pub restart_cost_s: f64,
    /// Keep window W, seconds.
    pub keep_window_s: u64,
    /// Advantage factor, old design.
    pub advantage_old_design: f64,
}

/// Keep windows for the advantage curve: 31 log-spaced points from one minute to 30 days.
pub fn curve_windows() -> Vec<u64> {
    (0..=30)
        .map(|i| (60.0 * libm::pow(43_200.0, f64::from(i) / 30.0)).round() as u64)
        .collect()
}

/// Builds the D2 curve from the configuration.
pub fn advantage_curve(config: &Config) -> Result<Vec<CurveRow>> {
    let grid = &config.analytic.restart;
    let interval = config.issuance.pow_id_target_interval_s.value;
    let mut rows = Vec::new();
    for &miners in &grid.competing_miners {
        let q = per_step_win_probability(miners, interval)?;
        for &cost in &grid.restart_costs_s {
            for window in curve_windows() {
                rows.push(CurveRow {
                    competing_miners: miners,
                    restart_cost_s: cost,
                    keep_window_s: window,
                    advantage_old_design: advantage_old_design(q, cost, window),
                });
            }
        }
    }
    Ok(rows)
}

/// Simulates the old-design restart policy connection by connection; returns the time to an
/// ID per trial, in seconds.
fn simulate_restart(
    seed: u64,
    label: &str,
    q: f64,
    cost: f64,
    window: u64,
    trials: u64,
) -> RunningStats {
    let mut rng = rng_stream(seed, label);
    let mut stats = RunningStats::default();
    for _ in 0..trials {
        let mut time = 0.0;
        loop {
            time += cost;
            let first_win = geometric_failures(&mut rng, q);
            if first_win <= window {
                time += first_win as f64;
                break;
            }
        }
        stats.push(time);
    }
    stats
}

/// Simulates rounds under per-round entropy. Each round a connected miner wins with
/// probability `1/miners` and learns the outcome when the round starts. With `restart_on_loss`
/// it disconnects after every losing draw and misses `lost_rounds` rounds while it re-admits.
/// Returns rounds to the first ID per trial.
fn simulate_per_round(
    seed: u64,
    label: &str,
    miners: u64,
    lost_rounds: u64,
    restart_on_loss: bool,
    trials: u64,
) -> RunningStats {
    let mut rng = rng_stream(seed, label);
    let win = 1.0 / miners as f64;
    let mut stats = RunningStats::default();
    for _ in 0..trials {
        let mut rounds = 0u64;
        loop {
            rounds += 1;
            if bernoulli(&mut rng, win) {
                break;
            }
            if restart_on_loss {
                rounds += lost_rounds;
            }
        }
        stats.push(rounds as f64);
    }
    stats
}

/// Section D cross-checks.
pub fn checks(config: &Config) -> Result<Vec<Check>> {
    let mc = &config.run.monte_carlo;
    let k = mc.tolerance_standard_errors;
    let seed = config.run.seed;
    let mut checks = vec![sanity_check()?];
    let interval = config.issuance.pow_id_target_interval_s.value;
    let cases = [
        (10_000_u64, 60.0, 3_600_u64, "D-mc-restart-small"),
        (5_000_000, 600.0, 86_400, "D-mc-restart-5m-600s-1day"),
    ];
    for (miners, cost, window, id) in cases {
        let q = per_step_win_probability(miners, interval)?;
        let trials = if miners > 1_000_000 {
            mc.restart_successes / 4
        } else {
            mc.restart_successes
        };
        let stats = simulate_restart(seed, id, q, cost, window, trials);
        checks.push(Check::monte_carlo(
            "D",
            id,
            &format!(
                "old design, N={miners}, C={cost} s, W={window} s: simulated mean time to an ID vs C/π + E[X | X ≤ W]"
            ),
            restart_expected_time_s(q, cost, window),
            stats.estimate(),
            k,
            0.0,
        ));
    }
    let q_moderate = per_step_win_probability(1_000, interval)?;
    checks.push(Check::relative(
        "D",
        "D-truncated-mean-closed-form",
        "E[X | X ≤ W] by stable summation vs closed form (q = 1/30,000, W = 86,400)",
        truncated_mean_steps_closed_form(q_moderate, 86_400),
        truncated_mean_steps(q_moderate, 86_400),
        1e-9,
    ));
    let miners = 100;
    let lost_rounds = 10;
    let stay = simulate_per_round(
        seed,
        "D-per-round-stay",
        miners,
        lost_rounds,
        false,
        mc.per_round_trials,
    );
    let restart = simulate_per_round(
        seed,
        "D-per-round-restart",
        miners,
        lost_rounds,
        true,
        mc.per_round_trials,
    );
    let advantage = stay.mean() / restart.mean();
    let relative_se =
        (stay.standard_error() / stay.mean()).hypot(restart.standard_error() / restart.mean());
    checks.push(Check::at_most(
        "D",
        "D-per-round-entropy",
        "per-round entropy: restart-on-loss advantage (stay mean / restart mean) does not exceed 1 (N=100, 10 rounds lost per restart)",
        PER_ROUND_ENTROPY_ADVANTAGE,
        advantage,
        k * relative_se * advantage,
        mc.per_round_trials,
    ));
    Ok(checks)
}

fn sanity_check() -> Result<Check> {
    let q = per_step_win_probability(5_000_000, 30.0)?;
    let advantage = advantage_old_design(q, 600.0, 86_400);
    let approximation = advantage_approximation(q, 600.0, 86_400);
    let mut check = Check::relative(
        "D",
        "D-sanity-5m-600s-1day",
        "N=5M, C=600 s, W=1 day: advantage is of order 100 (in [100, 200]) and matches W/(C + qW²/2) within 0.1%",
        approximation,
        advantage,
        1e-3,
    );
    check.passed = check.passed && (100.0..=200.0).contains(&advantage);
    Ok(check)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanity_five_million_miners_600_second_restart_one_day_window_gives_about_138x() {
        let q = per_step_win_probability(5_000_000, 30.0).unwrap();
        let advantage = advantage_old_design(q, 600.0, 86_400);
        assert!((100.0..=200.0).contains(&advantage), "{advantage}");
        assert!(
            (advantage - 138.230_227_593_406).abs() < 1e-6,
            "{advantage}"
        );
    }

    #[test]
    fn honest_expected_time_is_n_times_the_interval_plus_admission() {
        let q = per_step_win_probability(1_000_000, 30.0).unwrap();
        assert!((honest_expected_time_s(q, 60.0) - (60.0 + 30_000_000.0 - 1.0)).abs() < 1e-6);
    }

    #[test]
    fn truncated_mean_is_about_half_the_window_when_wins_are_rare() {
        let q = 1e-9;
        let mean = truncated_mean_steps(q, 3_600);
        assert!((mean - 1_800.0).abs() < 1e-2, "{mean}");
    }

    #[test]
    fn summation_and_closed_form_agree_at_moderate_q() {
        let q = 1.0 / 30_000.0;
        let a = truncated_mean_steps(q, 50_000);
        let b = truncated_mean_steps_closed_form(q, 50_000);
        assert!((a - b).abs() / b < 1e-10);
    }

    #[test]
    fn optimal_window_is_near_square_root_of_two_c_over_q() {
        let q = per_step_win_probability(5_000_000, 30.0).unwrap();
        let (window, maximum) = optimal_window(q, 600.0);
        let guess = (2.0 * 600.0 / q).sqrt();
        assert!(
            (window as f64 / guess - 1.0).abs() < 0.02,
            "{window} vs {guess}"
        );
        assert!(maximum > advantage_old_design(q, 600.0, 86_400));
        assert!(maximum >= advantage_old_design(q, 600.0, window + 1_000));
    }

    #[test]
    fn curve_spans_one_minute_to_thirty_days() {
        let windows = curve_windows();
        assert_eq!(windows.first(), Some(&60));
        assert_eq!(windows.last(), Some(&2_592_000));
        assert!(windows.windows(2).all(|w| w[1] > w[0]));
    }

    #[test]
    fn invalid_inputs_are_rejected() {
        assert!(per_step_win_probability(0, 30.0).is_err());
        assert!(per_step_win_probability(10, 0.0).is_err());
    }

    #[test]
    fn section_d_table_covers_the_grid() {
        let config = Config::default();
        let rows = section_d(&config).unwrap();
        let g = &config.analytic.restart;
        assert_eq!(
            rows.len(),
            g.competing_miners.len() * g.restart_costs_s.len() * g.keep_windows_s.len()
        );
        assert!(rows.iter().all(|r| r.advantage_per_round_entropy == 1.0));
    }

    #[test]
    fn all_section_d_checks_pass() {
        let mut config = Config::default();
        config.run.monte_carlo.restart_successes = 8_000;
        config.run.monte_carlo.per_round_trials = 8_000;
        for check in checks(&config).unwrap() {
            assert!(check.passed, "{check:?}");
        }
    }
}
