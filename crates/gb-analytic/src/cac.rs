//! Section C — Chain Allocation Committee stalling and capture (SPEC §4.3, §8 S21).
//!
//! The committee has `n` members, first in, first out; the miner of every 10th PoW-Tx block
//! joins. An Allocation Committee Block needs `a = ⌈2n/3⌉` approvals. The attacker can
//! **stall** the committee when it holds `n − a + 1` seats, and **capture** it (approve
//! without honest members) when it holds `a` seats.
//!
//! # Seat model
//!
//! Under the \[P\] seat rule, one ID holds at most one seat. A member's 10th-block win passes to
//! the next 10th-block miner who is not a member, so each new member is uniform over the
//! `N − n` non-members. This FIFO chain is doubly stochastic, so its stationary distribution
//! is uniform over ordered sets of `n` distinct IDs. The attacker's seat count is therefore
//! **hypergeometric** over the `N` mining IDs, with `K` of them the attacker's. With
//! duplicates allowed, it is binomial with `p = K/N`.
//!
//! # Events per year
//!
//! - **Brief's approximation:** one independent composition per `n` refreshes, so events per
//!   year ≈ (refreshes per year / n) × P(state).
//! - **Exact onset rate**, under the same model: the committee enters a state at a refresh when
//!   the remaining `n − 1` members hold `t − 1` attacker seats, the departing (oldest) member
//!   is honest, and the new member is the attacker's. In stationarity this is
//!   `P(X = t − 1) · (n − t + 1)/n · (K − t + 1)/(N − n)`. With duplicates allowed it becomes
//!   `P(X = t − 1) · (n − t + 1)/n · p`, which equals `p(1 − p)·P(Bin(n − 1, p) = t − 1)`.

use crate::dist::{ExactDistribution, SeatModel};
use crate::error::{AnalyticError, Result, ensure};
use crate::exact::{Q, decimal, integer, log10, ratio, scientific, to_f64};
use crate::mc::{RunningStats, uniform_below};
use crate::validation::Check;
use crate::witness::attacker_ids;
use gb_config::Config;
use gb_config::protocol::ApprovalThreshold;
use gb_runlog::rng_stream;
use num_traits::{One, Zero};
use serde::Serialize;
use std::collections::VecDeque;

/// Committee seat model.
#[derive(Debug, Clone, PartialEq)]
pub enum CommitteeModel {
    /// \[P\] One seat per ID: seats are distinct IDs drawn from `population` mining IDs.
    DistinctMembers {
        /// Mining IDs the committee is drawn from.
        population: u64,
        /// Attacker IDs among them.
        attackers: u64,
    },
    /// Comparison: duplicates allowed; each seat is the attacker's with probability `p`.
    WithReplacement(Q),
}

impl CommitteeModel {
    /// Label used in tables.
    pub fn label(&self) -> &'static str {
        match self {
            CommitteeModel::DistinctMembers { .. } => "one seat per ID (hypergeometric)",
            CommitteeModel::WithReplacement(_) => "duplicates allowed (binomial)",
        }
    }

    fn seat_model(&self) -> SeatModel {
        match self {
            CommitteeModel::DistinctMembers {
                population,
                attackers,
            } => SeatModel::Hypergeometric {
                population: *population,
                attackers: *attackers,
            },
            CommitteeModel::WithReplacement(p) => SeatModel::Binomial(p.clone()),
        }
    }

    /// Probability that a newly joining member is the attacker's, given `seats` attacker
    /// members before the refresh.
    fn joiner_is_attacker(&self, members: u64, seats: u64) -> Q {
        match self {
            CommitteeModel::DistinctMembers {
                population,
                attackers,
            } => ratio(attackers.saturating_sub(seats), population - members),
            CommitteeModel::WithReplacement(p) => p.clone(),
        }
    }
}

/// Approvals needed out of `members` under the threshold rule.
pub fn approvals_needed(members: u64, threshold: &ApprovalThreshold) -> Result<u64> {
    threshold.approvals_needed(members).ok_or_else(|| {
        AnalyticError::InvalidInput("approval threshold has a zero denominator".to_string())
    })
}

/// Attacker seats that deny approval: `n − a + 1`.
pub fn stall_seats(members: u64, approvals: u64) -> u64 {
    members - approvals + 1
}

/// Mining population and attacker IDs when the attacker holds `attacker_fraction` of
/// `total_ids` (all mining) and only `honest_mining_fraction` of honest IDs mine.
pub fn mining_population(
    total_ids: u64,
    attacker_fraction: &Q,
    honest_mining_fraction: &Q,
) -> (u64, u64) {
    let attackers = attacker_ids(attacker_fraction, total_ids);
    let honest_mining = attacker_ids(honest_mining_fraction, total_ids - attackers);
    (attackers + honest_mining, attackers)
}

/// Exact distribution of the attacker's committee seats.
pub fn seat_distribution(members: u64, model: &CommitteeModel) -> Result<ExactDistribution> {
    ExactDistribution::new(members, &model.seat_model())
}

/// Committee refreshes per year: 10th-block miners per year, times the share that are not
/// already members under the seat rule.
pub fn refreshes_per_year(
    seconds_per_year: u64,
    tx_interval_s: &Q,
    join_every: u64,
    members: u64,
    model: &CommitteeModel,
) -> Q {
    let tenth_blocks = integer(seconds_per_year) / tx_interval_s / integer(join_every);
    match model {
        CommitteeModel::DistinctMembers { population, .. } => {
            tenth_blocks * integer(population - members) / integer(*population)
        }
        CommitteeModel::WithReplacement(_) => tenth_blocks,
    }
}

/// Exact probability, per refresh in stationarity, that the committee enters the state
/// "attacker holds at least `threshold_seats` seats".
pub fn onset_probability_per_refresh(
    members: u64,
    threshold_seats: u64,
    model: &CommitteeModel,
) -> Result<Q> {
    ensure(
        threshold_seats >= 1 && threshold_seats <= members,
        "threshold seats must lie between 1 and the committee size",
    )?;
    let distribution = seat_distribution(members, model)?;
    let before = distribution.pmf(threshold_seats - 1);
    let oldest_honest = ratio(members - threshold_seats + 1, members);
    Ok(before * oldest_honest * model.joiner_is_attacker(members, threshold_seats - 1))
}

// ----------------------------------------------------------------------------- tables

/// C1: probability of stalling and capture.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct OddsRow {
    /// Committee size n.
    pub committee_size: u64,
    /// Approvals needed, ⌈2n/3⌉.
    pub approvals_needed: u64,
    /// Attacker seats that stall the committee, n − a + 1.
    pub stall_seats: u64,
    /// Attacker fraction p of active IDs.
    pub attacker_fraction: f64,
    /// Fraction of honest IDs that mine (attacker IDs always mine).
    pub honest_mining_fraction: f64,
    /// Seat model.
    pub model: &'static str,
    /// Mining IDs the committee draws from (one-seat-per-ID model).
    pub mining_population: Option<u64>,
    /// Attacker share of mining IDs, `p / (p + μ(1 − p))`.
    pub attacker_mining_share: f64,
    /// P(attacker can stall).
    pub p_stall: String,
    /// log10 P(stall).
    pub log10_p_stall: f64,
    /// P(attacker holds ⌈2n/3⌉ seats).
    pub p_capture: String,
    /// log10 P(capture).
    pub log10_p_capture: f64,
}

/// C2: events per year.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EventsRow {
    /// Committee size n.
    pub committee_size: u64,
    /// Attacker fraction p.
    pub attacker_fraction: f64,
    /// Fraction of honest IDs that mine.
    pub honest_mining_fraction: f64,
    /// Seat model.
    pub model: &'static str,
    /// "stall" or "capture".
    pub state: &'static str,
    /// Attacker seats that define the state.
    pub threshold_seats: u64,
    /// Committee refreshes per year.
    pub refreshes_per_year: f64,
    /// Independent compositions per year assumed by the brief, refreshes / n.
    pub independent_compositions_per_year: f64,
    /// Brief's estimate: compositions per year × P(state).
    pub events_per_year_independence_approximation: String,
    /// Exact expected entries into the state per year (same seat model).
    pub onsets_per_year_exact: String,
    /// Exact onsets ÷ approximation.
    pub ratio_exact_to_approximation: f64,
    /// Long-run fraction of time in the state, P(state).
    pub time_fraction: String,
    /// Mean length of one episode, in refreshes.
    pub mean_episode_refreshes: f64,
}

/// All section C tables.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SectionC {
    /// C1.
    pub odds: Vec<OddsRow>,
    /// C2.
    pub events: Vec<EventsRow>,
}

/// Builds every section C table from the configuration.
pub fn section_c(config: &Config) -> Result<SectionC> {
    let grid = &config.analytic.cac;
    let threshold = config.cac.approval_threshold.value;
    let tx_interval = decimal(config.transactions.pow_tx_interval_s.value)?;
    let join_every = u64::from(config.cac.join_every_n_tx_blocks.value);
    let mut tables = SectionC::default();
    for &members in &grid.committee_sizes {
        let approvals = approvals_needed(members, &threshold)?;
        let stall = stall_seats(members, approvals);
        for p_f in &grid.attacker_fractions {
            let p = decimal(*p_f)?;
            for mu_f in &grid.honest_mining_fractions {
                let mu = decimal(*mu_f)?;
                let (population, attackers) = mining_population(grid.mining_population, &p, &mu);
                let share = ratio(attackers, population);
                let models = [
                    CommitteeModel::DistinctMembers {
                        population,
                        attackers,
                    },
                    CommitteeModel::WithReplacement(share.clone()),
                ];
                for model in models {
                    let distribution = seat_distribution(members, &model)?;
                    let (p_stall, p_capture) = (
                        distribution.at_least(stall),
                        distribution.at_least(approvals),
                    );
                    tables.odds.push(OddsRow {
                        committee_size: members,
                        approvals_needed: approvals,
                        stall_seats: stall,
                        attacker_fraction: *p_f,
                        honest_mining_fraction: *mu_f,
                        model: model.label(),
                        mining_population: matches!(model, CommitteeModel::DistinctMembers { .. })
                            .then_some(population),
                        attacker_mining_share: to_f64(&share),
                        p_stall: scientific(&p_stall, 6),
                        log10_p_stall: log10(&p_stall).unwrap_or(f64::NEG_INFINITY),
                        p_capture: scientific(&p_capture, 6),
                        log10_p_capture: log10(&p_capture).unwrap_or(f64::NEG_INFINITY),
                    });
                    let refreshes = refreshes_per_year(
                        config.model.seconds_per_year,
                        &tx_interval,
                        join_every,
                        members,
                        &model,
                    );
                    for (state, seats, probability) in [
                        ("stall", stall, &p_stall),
                        ("capture", approvals, &p_capture),
                    ] {
                        let onset = onset_probability_per_refresh(members, seats, &model)?;
                        tables.events.push(events_row(
                            members,
                            *p_f,
                            *mu_f,
                            &model,
                            state,
                            seats,
                            &refreshes,
                            probability,
                            &onset,
                        ));
                    }
                }
            }
        }
    }
    Ok(tables)
}

#[allow(clippy::too_many_arguments)]
fn events_row(
    members: u64,
    p: f64,
    mu: f64,
    model: &CommitteeModel,
    state: &'static str,
    seats: u64,
    refreshes: &Q,
    probability: &Q,
    onset: &Q,
) -> EventsRow {
    let compositions = refreshes / integer(members);
    let approximation = &compositions * probability;
    let exact = refreshes * onset;
    let ratio = if approximation.is_zero() {
        0.0
    } else {
        to_f64(&(&exact / &approximation))
    };
    let episode = if onset.is_zero() {
        0.0
    } else {
        to_f64(&(probability / onset))
    };
    EventsRow {
        committee_size: members,
        attacker_fraction: p,
        honest_mining_fraction: mu,
        model: model.label(),
        state,
        threshold_seats: seats,
        refreshes_per_year: to_f64(refreshes),
        independent_compositions_per_year: to_f64(&compositions),
        events_per_year_independence_approximation: scientific(&approximation, 6),
        onsets_per_year_exact: scientific(&exact, 6),
        ratio_exact_to_approximation: ratio,
        time_fraction: scientific(probability, 6),
        mean_episode_refreshes: episode,
    }
}

// ----------------------------------------------------------------------------- checks

/// Results of simulating a FIFO committee with the one-seat-per-ID rule.
#[derive(Debug, Clone, Default)]
struct CommitteeSimulation {
    stall_time: Vec<f64>,
    capture_time: Vec<f64>,
    stall_onsets: Vec<f64>,
    capture_onsets: Vec<f64>,
    skips: Vec<f64>,
    draws: Vec<f64>,
}

fn simulate_committee(
    seed: u64,
    population: u64,
    attackers: u64,
    members: u64,
    approvals: u64,
    refreshes: u64,
) -> CommitteeSimulation {
    const BATCHES: u64 = 50;
    let mut rng = rng_stream(
        seed,
        &format!("C-committee-{members}-{attackers}-{population}"),
    );
    let mut is_member = vec![false; population as usize];
    let mut queue = VecDeque::with_capacity(members as usize);
    while (queue.len() as u64) < members {
        let id = uniform_below(&mut rng, population);
        if !is_member[id as usize] {
            is_member[id as usize] = true;
            queue.push_back(id);
        }
    }
    let mut seats = queue.iter().filter(|id| **id < attackers).count() as u64;
    let stall = stall_seats(members, approvals);
    let mut sim = CommitteeSimulation::default();
    let batch_size = refreshes / BATCHES;
    let burn_in = 20 * members;
    let mut batch = [0.0f64; 6];
    for step in 0..burn_in + batch_size * BATCHES {
        let before = seats;
        let mut draws = 0.0;
        let joiner = loop {
            draws += 1.0;
            let id = uniform_below(&mut rng, population);
            if !is_member[id as usize] {
                break id;
            }
        };
        is_member[joiner as usize] = true;
        queue.push_back(joiner);
        seats += u64::from(joiner < attackers);
        if let Some(oldest) = queue.pop_front() {
            is_member[oldest as usize] = false;
            seats -= u64::from(oldest < attackers);
        }
        if step < burn_in {
            continue;
        }
        let counters = [
            f64::from(u8::from(seats >= stall)),
            f64::from(u8::from(seats >= approvals)),
            f64::from(u8::from(before < stall && seats >= stall)),
            f64::from(u8::from(before < approvals && seats >= approvals)),
            draws - 1.0,
            draws,
        ];
        for (total, value) in batch.iter_mut().zip(counters) {
            *total += value;
        }
        if (step - burn_in + 1) % batch_size == 0 {
            let n = batch_size as f64;
            sim.stall_time.push(batch[0] / n);
            sim.capture_time.push(batch[1] / n);
            sim.stall_onsets.push(batch[2] / n);
            sim.capture_onsets.push(batch[3] / n);
            sim.skips.push(batch[4]);
            sim.draws.push(batch[5]);
            batch = [0.0; 6];
        }
    }
    sim
}

fn batch_estimate(values: &[f64]) -> RunningStats {
    let mut stats = RunningStats::default();
    for v in values {
        stats.push(*v);
    }
    stats
}

/// Section C cross-checks.
pub fn checks(config: &Config) -> Result<Vec<Check>> {
    let mut checks = vec![binomial_onset_identity_check()?];
    checks.extend(committee_monte_carlo_checks(config)?);
    Ok(checks)
}

fn binomial_onset_identity_check() -> Result<Check> {
    let mut failures = 0;
    let mut rows = 0;
    for (members, p) in [
        (30, decimal(0.4)?),
        (100, decimal(0.33)?),
        (600, decimal(0.3)?),
    ] {
        let model = CommitteeModel::WithReplacement(p.clone());
        let smaller = ExactDistribution::new(members - 1, &SeatModel::Binomial(p.clone()))?;
        for seats in [members / 3, members * 2 / 3] {
            rows += 1;
            let formula = onset_probability_per_refresh(members, seats, &model)?;
            let identity = &p * (Q::one() - &p) * smaller.pmf(seats - 1);
            failures += u64::from(formula != identity);
        }
    }
    Ok(Check::all_rows(
        "C",
        "C-binomial-onset-identity",
        "with duplicates allowed, the onset formula equals p(1-p)·P(Bin(n-1,p) = t-1) exactly",
        failures,
        rows,
    ))
}

fn committee_monte_carlo_checks(config: &Config) -> Result<Vec<Check>> {
    let mc = &config.run.monte_carlo;
    let k = mc.tolerance_standard_errors;
    let threshold = config.cac.approval_threshold.value;
    let population = mc.committee_population;
    let mut checks = Vec::new();
    for members in [30_u64, 100] {
        let approvals = approvals_needed(members, &threshold)?;
        for p_f in [0.3, 0.4] {
            let attackers = attacker_ids(&decimal(p_f)?, population);
            let model = CommitteeModel::DistinctMembers {
                population,
                attackers,
            };
            let sim = simulate_committee(
                config.run.seed,
                population,
                attackers,
                members,
                approvals,
                mc.committee_refreshes,
            );
            let distribution = seat_distribution(members, &model)?;
            let stall = stall_seats(members, approvals);
            let cases = [
                (
                    "stall-time",
                    to_f64(&distribution.at_least(stall)),
                    &sim.stall_time,
                ),
                (
                    "capture-time",
                    to_f64(&distribution.at_least(approvals)),
                    &sim.capture_time,
                ),
                (
                    "stall-onsets",
                    to_f64(&onset_probability_per_refresh(members, stall, &model)?),
                    &sim.stall_onsets,
                ),
                (
                    "capture-onsets",
                    to_f64(&onset_probability_per_refresh(members, approvals, &model)?),
                    &sim.capture_onsets,
                ),
            ];
            for (name, exact, values) in cases {
                if exact * mc.committee_refreshes as f64 / (members as f64) < 30.0 {
                    continue; // too rare for this sample size
                }
                checks.push(Check::monte_carlo(
                    "C",
                    &format!("C-mc-{name}-n{members}-p{p_f}"),
                    &format!(
                        "FIFO committee with one seat per ID (N={population}, n={members}, p={p_f}): simulated {name} per refresh vs exact formula"
                    ),
                    exact,
                    batch_estimate(values).estimate(),
                    k,
                    0.0,
                ));
            }
            let skips: f64 = sim.skips.iter().sum();
            let draws: f64 = sim.draws.iter().sum();
            checks.push(Check::relative(
                "C",
                &format!("C-mc-skip-rate-n{members}-p{p_f}"),
                &format!("share of 10th-block wins that go to existing members (N={population}, n={members}) vs n/N"),
                members as f64 / population as f64,
                skips / draws,
                0.05,
            ));
        }
    }
    Ok(checks)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn two_thirds() -> ApprovalThreshold {
        ApprovalThreshold {
            numerator: 2,
            denominator: 3,
        }
    }

    #[test]
    fn two_thirds_rule_gives_the_planned_thresholds() {
        for (members, approvals, stall) in [
            (30, 20, 11),
            (100, 67, 34),
            (600, 400, 201),
            (1000, 667, 334),
        ] {
            let a = approvals_needed(members, &two_thirds()).unwrap();
            assert_eq!((a, stall_seats(members, a)), (approvals, stall));
        }
    }

    #[test]
    fn stall_probability_at_600_members_and_33_percent_is_about_41_percent() {
        let model = CommitteeModel::WithReplacement(ratio(33, 100));
        let p = seat_distribution(600, &model).unwrap().at_least(201);
        assert!((to_f64(&p) - 0.412_268_244_173_590_9).abs() < 1e-12);
    }

    #[test]
    fn honest_non_mining_raises_the_attacker_share() {
        let (population, attackers) = mining_population(2_100_000, &ratio(1, 4), &ratio(1, 2));
        assert_eq!(attackers, 525_000);
        assert_eq!(population, 525_000 + 787_500);
        let share = attackers as f64 / population as f64;
        assert!((share - 0.25 / (0.25 + 0.5 * 0.75)).abs() < 1e-12);
    }

    #[test]
    fn refresh_rate_accounts_for_skipped_members() {
        let model = CommitteeModel::DistinctMembers {
            population: 2_100_000,
            attackers: 0,
        };
        let refreshes = refreshes_per_year(31_536_000, &integer(10), 10, 600, &model);
        assert_eq!(
            refreshes,
            integer(315_360) * integer(2_099_400) / integer(2_100_000)
        );
        let plain = refreshes_per_year(
            31_536_000,
            &integer(10),
            10,
            600,
            &CommitteeModel::WithReplacement(ratio(1, 4)),
        );
        assert_eq!(plain, integer(315_360));
    }

    #[test]
    fn onset_rate_exceeds_the_independent_composition_estimate() {
        let model = CommitteeModel::WithReplacement(ratio(4, 10));
        let onset = onset_probability_per_refresh(30, 20, &model).unwrap();
        let hold = seat_distribution(30, &model).unwrap().at_least(20);
        let ratio = to_f64(&(onset * integer(30) / hold));
        assert!(ratio > 5.0, "{ratio}");
    }

    #[test]
    fn onset_threshold_outside_the_committee_is_rejected() {
        let model = CommitteeModel::WithReplacement(ratio(1, 4));
        assert!(onset_probability_per_refresh(30, 0, &model).is_err());
        assert!(onset_probability_per_refresh(30, 31, &model).is_err());
    }

    #[test]
    fn section_c_tables_cover_every_combination() {
        let config = Config::default();
        let c = section_c(&config).unwrap();
        let g = &config.analytic.cac;
        let combos = g.committee_sizes.len()
            * g.attacker_fractions.len()
            * g.honest_mining_fractions.len()
            * 2;
        assert_eq!(c.odds.len(), combos);
        assert_eq!(c.events.len(), 2 * combos);
    }

    #[test]
    fn all_section_c_checks_pass() {
        let mut config = Config::default();
        config.run.monte_carlo.committee_refreshes = 1_000_000;
        for check in checks(&config).unwrap() {
            assert!(check.passed, "{check:?}");
        }
    }
}
