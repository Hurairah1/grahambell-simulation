//! Section C — Chain Allocation Committee stalling and capture (SPEC §4.3, §8 S21).
//!
//! The committee has `n` members, first in, first out; one new member joins for every 10th
//! PoW-Tx block. An Allocation Committee Block needs `a = ⌈2n/3⌉` approvals. The attacker can
//! **stall** the committee when it holds `n − a + 1` seats, and **capture** it (approve
//! without honest members) when it holds `a` seats.
//!
//! Since SPEC v0.4 (§4.2–§4.3) placement takes effect at each ID's beacon block without the
//! committee; the Allocation Committee Block is a record and attestation only. A stall
//! therefore delays the record, never a placement, and a captured committee cannot choose
//! one: every node recomputes placement and rejects a mismatch.
//!
//! # Seat rules
//!
//! - **Lottery (SPEC v0.3, primary).** The new member is the ID at a hash-derived position of
//!   the canonical active list (SPEC §3.11); a draw that lands on a member moves to the next
//!   position. The draw happens before the oldest member leaves. Where the attacker's IDs sit
//!   in the list matters slightly:
//!   - **spread through the list** (the primary model): a draw that lands on a member passes
//!     to a neighbour of random type, so the new member is close to uniform over the `N − n`
//!     non-members. The attacker's seat count is then **hypergeometric** over the `N` active
//!     IDs, `K` of them the attacker's.
//!   - **in one block of the list** (sensitivity): a draw that lands on a member almost
//!     always passes to a neighbour of the same type, so each new member is the attacker's
//!     with probability `K/N` whatever the committee holds. The seat count is then
//!     **binomial** with `p = K/N`.
//!
//!   The two differ by `O(n/N)` per draw; Monte Carlo runs of the real next-position rule
//!   check both. Either way the attacker's expected committee share equals its share of
//!   active IDs, and mining power plays no part. Every 10th PoW-Tx block refreshes the
//!   committee.
//! - **10th-block miner (the v0.2 rule, comparison).** The miner of every 10th PoW-Tx block
//!   joins; a member's win passes to the next 10th-block miner who is not a member. New
//!   members are uniform over the non-members among the `N_m` mining IDs, so the seat count
//!   is hypergeometric over mining IDs. If only a fraction μ of honest IDs mines, the
//!   attacker's share of mining IDs is `p / (p + μ(1 − p))`. Member wins delay refreshes.
//!
//! For the uniform rules the FIFO chain is doubly stochastic, so the committee's stationary
//! distribution is uniform over ordered `n`-sets of distinct IDs; that is where the
//! hypergeometric count comes from.
//!
//! # Events per year and episode lengths
//!
//! - **Exact entries (primary).** The committee enters "at least `t` attacker seats" at a
//!   refresh when it holds `t − 1`, the new member is the attacker's and the departing
//!   (oldest) member is honest. In stationarity that is
//!   `P(X = t − 1) · (n − t + 1)/n · P(new member is the attacker's | t − 1 seats)`, with the
//!   last factor `(K − t + 1)/(N − n)` (hypergeometric) or `K/N` (binomial).
//! - **Share of time** in the state is `P(X ≥ t)`.
//! - **Mean episode length** is the share of time divided by the entry rate, in refreshes,
//!   and in hours using the seconds per refresh.
//! - **The M1 brief's estimate (comparison only):** one independent composition per `n`
//!   refreshes, so events per year ≈ (refreshes per year / `n`) × `P(state)`.
//!
//! # Departures (SPEC v0.4, table C3)
//!
//! A banned or deactivated member leaves at once, and an extra lottery draw fills its seat at
//! the next 10th PoW-Tx block. Attacker IDs never go offline, while an honest member
//! deactivates during a refresh interval with probability `δ = 1 − e^(−c/R)` for absences
//! starting at rate `c` per ID per year and `R` refreshes per year. An honest member's mean
//! tenure is then `r = (1 − (1 − δ)^n)/(nδ)` times the full tenure of `n` refreshes. New
//! members arrive in proportion `p : (1 − p)` (the lottery draws from active IDs, so `p` is the
//! attacker's share of active IDs, as in C1), and by Little's law the attacker's seat share is
//! `p / (p + (1 − p)·r)`. C3 evaluates the C1 stall and capture probabilities at that share.
//! This is an approximation: it ignores the seats left empty until the next 10th block and the
//! small shortening of every tenure by departures ahead in the queue. M4 simulates the
//! committee itself.

use crate::dist::{ExactDistribution, SeatModel};
use crate::error::{AnalyticError, Result, ensure};
use crate::exact::{Q, decimal, integer, log10, ratio, scientific, to_f64};
use crate::mc::{RunningStats, bernoulli, geometric_failures, shuffle, uniform_below};
use crate::validation::Check;
use crate::witness::attacker_ids;
use gb_config::Config;
use gb_config::protocol::Fraction;
use gb_runlog::rng_stream;
use num_traits::{One, Zero};
use serde::Serialize;
use std::collections::VecDeque;

/// Committee seat model: the seat rule together with the population it draws from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitteeModel {
    /// Lottery (primary), attacker IDs spread through the canonical list: each new member is
    /// uniform over the non-members (hypergeometric seat count).
    LotterySpread {
        /// Active IDs in the canonical list, `N`.
        population: u64,
        /// Attacker IDs among them, `K`.
        attackers: u64,
    },
    /// Lottery, attacker IDs in one block of the canonical list: each new member is the
    /// attacker's with probability `K/N` (binomial seat count).
    LotteryBlock {
        /// Active IDs in the canonical list, `N`.
        population: u64,
        /// Attacker IDs among them, `K`.
        attackers: u64,
    },
    /// The v0.2 rule (comparison): the miner of every 10th PoW-Tx block joins, skipping
    /// existing members.
    TenthBlockMiner {
        /// Mining IDs, `N_m`.
        population: u64,
        /// Attacker IDs among them.
        attackers: u64,
    },
}

impl CommitteeModel {
    /// Seat rule, as used in tables.
    pub fn rule(&self) -> &'static str {
        match self {
            CommitteeModel::LotterySpread { .. } | CommitteeModel::LotteryBlock { .. } => "lottery",
            CommitteeModel::TenthBlockMiner { .. } => "10th-block miner (v0.2 comparison)",
        }
    }

    /// Seat model, as used in tables.
    pub fn label(&self) -> &'static str {
        match self {
            CommitteeModel::LotterySpread { .. } => {
                "attacker IDs spread through the list (hypergeometric)"
            }
            CommitteeModel::LotteryBlock { .. } => {
                "attacker IDs in one block of the list (binomial)"
            }
            CommitteeModel::TenthBlockMiner { .. } => "hypergeometric over mining IDs",
        }
    }

    /// IDs the committee is drawn from and the attacker's IDs among them.
    pub fn population_and_attackers(&self) -> (u64, u64) {
        match self {
            CommitteeModel::LotterySpread {
                population,
                attackers,
            }
            | CommitteeModel::LotteryBlock {
                population,
                attackers,
            }
            | CommitteeModel::TenthBlockMiner {
                population,
                attackers,
            } => (*population, *attackers),
        }
    }

    fn seat_model(&self) -> SeatModel {
        let (population, attackers) = self.population_and_attackers();
        match self {
            CommitteeModel::LotteryBlock { .. } => {
                SeatModel::Binomial(ratio(attackers, population))
            }
            _ => SeatModel::Hypergeometric {
                population,
                attackers,
            },
        }
    }

    /// Probability that a newly joining member is the attacker's, given `seats` attacker
    /// members among the `members` before the refresh.
    fn joiner_is_attacker(&self, members: u64, seats: u64) -> Q {
        let (population, attackers) = self.population_and_attackers();
        match self {
            CommitteeModel::LotteryBlock { .. } => ratio(attackers, population),
            _ => ratio(attackers.saturating_sub(seats), population - members),
        }
    }

    /// Probability that a newly joining member is honest, given `seats` attacker members.
    fn joiner_is_honest(&self, members: u64, seats: u64) -> Q {
        let (population, attackers) = self.population_and_attackers();
        match self {
            CommitteeModel::LotteryBlock { .. } => ratio(population - attackers, population),
            _ => ratio(
                (population - attackers).saturating_sub(members - seats),
                population - members,
            ),
        }
    }
}

/// Approvals needed out of `members` under the threshold rule.
pub fn approvals_needed(members: u64, threshold: &Fraction) -> Result<u64> {
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

/// 10th PoW-Tx blocks per year: `seconds_per_year / tx_interval / join_every`.
pub fn tenth_blocks_per_year(seconds_per_year: u64, tx_interval_s: &Q, join_every: u64) -> Q {
    integer(seconds_per_year) / tx_interval_s / integer(join_every)
}

/// Committee refreshes per year. Every 10th PoW-Tx block refreshes a lottery committee; under
/// the v0.2 rule only the share of 10th-block wins that go to non-members does.
pub fn refreshes_per_year(
    seconds_per_year: u64,
    tx_interval_s: &Q,
    join_every: u64,
    members: u64,
    model: &CommitteeModel,
) -> Q {
    let tenth_blocks = tenth_blocks_per_year(seconds_per_year, tx_interval_s, join_every);
    match model {
        CommitteeModel::TenthBlockMiner { population, .. } => {
            tenth_blocks * integer(population - members) / integer(*population)
        }
        _ => tenth_blocks,
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

/// Exact probability, per refresh in stationarity, that the committee leaves the state
/// "attacker holds at least `threshold_seats` seats": it holds exactly that many, the oldest
/// member is the attacker's and the new member is honest.
pub fn exit_probability_per_refresh(
    members: u64,
    threshold_seats: u64,
    model: &CommitteeModel,
) -> Result<Q> {
    ensure(
        threshold_seats >= 1 && threshold_seats <= members,
        "threshold seats must lie between 1 and the committee size",
    )?;
    let distribution = seat_distribution(members, model)?;
    let at = distribution.pmf(threshold_seats);
    let oldest_attacker = ratio(threshold_seats, members);
    Ok(at * oldest_attacker * model.joiner_is_honest(members, threshold_seats))
}

/// Mean length of one episode in a state, in refreshes: share of time ÷ entries per refresh.
/// `None` when the state is never entered.
pub fn mean_episode_refreshes(time_fraction: &Q, onset: &Q) -> Option<f64> {
    (!onset.is_zero()).then(|| to_f64(&(time_fraction / onset)))
}

/// Probability that an honest member deactivates during one refresh interval, for absences
/// starting as a Poisson process at `absences_per_year`: `1 − e^(−c/R)`.
pub fn departure_probability_per_refresh(absences_per_year: f64, refreshes_per_year: f64) -> f64 {
    -libm::expm1(-absences_per_year / refreshes_per_year)
}

/// An honest member's mean tenure relative to the full tenure of `members` refreshes, when it
/// leaves early with probability `delta` per refresh: `(1 − (1 − δ)^n)/(n·δ)`.
pub fn honest_tenure_ratio(members: u64, delta: f64) -> f64 {
    if delta <= 0.0 {
        return 1.0;
    }
    let n = members as f64;
    -libm::expm1(n * libm::log1p(-delta)) / (n * delta)
}

/// Attacker's committee seat share by Little's law, with arrivals in proportion `p : (1 − p)`
/// and tenures in proportion `1 : ratio`.
pub fn effective_share(p: f64, ratio: f64) -> f64 {
    p / (p + (1.0 - p) * ratio)
}

// ----------------------------------------------------------------------------- tables

/// C1: probability of stalling and capture, with mean episode lengths.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct OddsRow {
    /// Seat rule: "lottery" or the v0.2 comparison.
    pub rule: &'static str,
    /// Seat model within the rule.
    pub model: &'static str,
    /// Committee size n.
    pub committee_size: u64,
    /// Approvals needed, ⌈2n/3⌉.
    pub approvals_needed: u64,
    /// Attacker seats that stall the committee, n − a + 1.
    pub stall_seats: u64,
    /// Attacker fraction p of active IDs.
    pub attacker_fraction: f64,
    /// Fraction of honest IDs that mine (v0.2 comparison only; attacker IDs always mine).
    pub honest_mining_fraction: Option<f64>,
    /// IDs the committee draws from: active IDs (lottery) or mining IDs (comparison).
    pub population: u64,
    /// Attacker IDs among them.
    pub attacker_ids: u64,
    /// Attacker share of the IDs drawn from.
    pub attacker_share_of_population: f64,
    /// P(attacker can stall) = share of time stalled.
    pub p_stall: String,
    /// log10 P(stall).
    pub log10_p_stall: f64,
    /// Mean length of one stall episode, hours (empty when never entered).
    pub mean_stall_hours: Option<f64>,
    /// P(attacker holds ⌈2n/3⌉ seats).
    pub p_capture: String,
    /// log10 P(capture).
    pub log10_p_capture: f64,
    /// Mean length of one capture episode, hours (empty when never entered).
    pub mean_capture_hours: Option<f64>,
}

/// C2: entries per year and episode lengths; the brief's estimate last, as a comparison.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EventsRow {
    /// Seat rule.
    pub rule: &'static str,
    /// Seat model within the rule.
    pub model: &'static str,
    /// Committee size n.
    pub committee_size: u64,
    /// Attacker fraction p of active IDs.
    pub attacker_fraction: f64,
    /// Fraction of honest IDs that mine (v0.2 comparison only).
    pub honest_mining_fraction: Option<f64>,
    /// "stall" or "capture".
    pub state: &'static str,
    /// Attacker seats that define the state.
    pub threshold_seats: u64,
    /// Exact expected entries into the state per year.
    pub entries_per_year_exact: String,
    /// Long-run share of time in the state, P(state).
    pub share_of_time: String,
    /// Mean length of one episode, in refreshes.
    pub mean_episode_refreshes: Option<f64>,
    /// Mean length of one episode, in hours.
    pub mean_episode_hours: Option<f64>,
    /// Committee refreshes per year.
    pub refreshes_per_year: f64,
    /// Mean seconds between refreshes.
    pub seconds_per_refresh: f64,
    /// Comparison: independent compositions per year assumed by the M1 brief, refreshes / n.
    pub brief_independent_compositions_per_year: f64,
    /// Comparison: the M1 brief's estimate, compositions per year × P(state).
    pub brief_estimate_events_per_year: String,
    /// Exact entries ÷ the brief's estimate.
    pub ratio_exact_to_brief_estimate: f64,
}

/// C3: the committee when honest members deactivate while serving (SPEC v0.4 §4.3).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DepartureRow {
    /// Committee size n (the SPEC default).
    pub committee_size: u64,
    /// Attacker fraction p of active IDs.
    pub attacker_fraction: f64,
    /// Absences (deactivations) per honest ID per year; attacker IDs never go offline.
    pub absences_per_id_per_year: f64,
    /// Committee refreshes per year.
    pub refreshes_per_year: f64,
    /// Full tenure, n refreshes, in hours.
    pub tenure_hours: f64,
    /// Probability that an honest member deactivates during a full tenure.
    pub honest_departure_probability: f64,
    /// An honest member's mean tenure ÷ the full tenure, r.
    pub honest_tenure_ratio: f64,
    /// The attacker's seat share, p / (p + (1 − p)·r).
    pub effective_attacker_share: f64,
    /// P(stall) at p (hypergeometric over active IDs, as C1).
    pub p_stall_at_p: String,
    /// P(stall) at the effective share.
    pub p_stall_at_effective_share: String,
    /// P(capture) at p.
    pub p_capture_at_p: String,
    /// P(capture) at the effective share.
    pub p_capture_at_effective_share: String,
    /// How the share is modelled.
    pub model: &'static str,
}

/// Label of the C3 model.
pub const DEPARTURE_MODEL: &str = "Little's law approximation (M4 simulates)";

/// All section C tables.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SectionC {
    /// C1.
    pub odds: Vec<OddsRow>,
    /// C2.
    pub events: Vec<EventsRow>,
    /// C3.
    pub departures: Vec<DepartureRow>,
}

/// Committee models for one committee size and attacker fraction: the two lottery layouts,
/// then the v0.2 comparison for every honest mining fraction.
fn models(config: &Config, p: &Q) -> Result<Vec<(CommitteeModel, Option<f64>)>> {
    let grid = &config.analytic.cac;
    let population = grid.active_population;
    let attackers = attacker_ids(p, population);
    let mut models = vec![
        (
            CommitteeModel::LotterySpread {
                population,
                attackers,
            },
            None,
        ),
        (
            CommitteeModel::LotteryBlock {
                population,
                attackers,
            },
            None,
        ),
    ];
    for mu_f in &grid.honest_mining_fractions {
        let (mining, mining_attackers) = mining_population(population, p, &decimal(*mu_f)?);
        models.push((
            CommitteeModel::TenthBlockMiner {
                population: mining,
                attackers: mining_attackers,
            },
            Some(*mu_f),
        ));
    }
    Ok(models)
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
            for (model, mu) in models(config, &p)? {
                let distribution = seat_distribution(members, &model)?;
                let refreshes = refreshes_per_year(
                    config.model.seconds_per_year,
                    &tx_interval,
                    join_every,
                    members,
                    &model,
                );
                let seconds_per_refresh = integer(config.model.seconds_per_year) / &refreshes;
                let hours = |episode: Option<f64>| {
                    episode.map(|e| e * to_f64(&seconds_per_refresh) / 3_600.0)
                };
                let mut episodes = Vec::new();
                for (state, seats) in [("stall", stall), ("capture", approvals)] {
                    let time = distribution.at_least(seats);
                    let onset = onset_probability_per_refresh(members, seats, &model)?;
                    let episode = mean_episode_refreshes(&time, &onset);
                    episodes.push(hours(episode));
                    let compositions = &refreshes / integer(members);
                    let estimate = &compositions * &time;
                    let exact = &refreshes * &onset;
                    tables.events.push(EventsRow {
                        rule: model.rule(),
                        model: model.label(),
                        committee_size: members,
                        attacker_fraction: *p_f,
                        honest_mining_fraction: mu,
                        state,
                        threshold_seats: seats,
                        entries_per_year_exact: scientific(&exact, 6),
                        share_of_time: scientific(&time, 6),
                        mean_episode_refreshes: episode,
                        mean_episode_hours: hours(episode),
                        refreshes_per_year: to_f64(&refreshes),
                        seconds_per_refresh: to_f64(&seconds_per_refresh),
                        brief_independent_compositions_per_year: to_f64(&compositions),
                        brief_estimate_events_per_year: scientific(&estimate, 6),
                        ratio_exact_to_brief_estimate: if estimate.is_zero() {
                            0.0
                        } else {
                            to_f64(&(&exact / &estimate))
                        },
                    });
                }
                let (p_stall, p_capture) = (
                    distribution.at_least(stall),
                    distribution.at_least(approvals),
                );
                let (population, attackers) = model.population_and_attackers();
                tables.odds.push(OddsRow {
                    rule: model.rule(),
                    model: model.label(),
                    committee_size: members,
                    approvals_needed: approvals,
                    stall_seats: stall,
                    attacker_fraction: *p_f,
                    honest_mining_fraction: mu,
                    population,
                    attacker_ids: attackers,
                    attacker_share_of_population: attackers as f64 / population as f64,
                    p_stall: scientific(&p_stall, 6),
                    log10_p_stall: log10(&p_stall).unwrap_or(f64::NEG_INFINITY),
                    mean_stall_hours: episodes[0],
                    p_capture: scientific(&p_capture, 6),
                    log10_p_capture: log10(&p_capture).unwrap_or(f64::NEG_INFINITY),
                    mean_capture_hours: episodes[1],
                });
            }
        }
    }
    tables.departures = departure_rows(config)?;
    Ok(tables)
}

fn departure_rows(config: &Config) -> Result<Vec<DepartureRow>> {
    let grid = &config.analytic.cac;
    let members = u64::from(config.cac.size.value);
    let approvals = approvals_needed(members, &config.cac.approval_threshold.value)?;
    let stall = stall_seats(members, approvals);
    let tx_interval = decimal(config.transactions.pow_tx_interval_s.value)?;
    let join_every = u64::from(config.cac.join_every_n_tx_blocks.value);
    let refreshes = to_f64(&tenth_blocks_per_year(
        config.model.seconds_per_year,
        &tx_interval,
        join_every,
    ));
    let population = grid.active_population;
    let tenure_hours = members as f64 * config.model.seconds_per_year as f64 / refreshes / 3_600.0;
    let mut rows = Vec::new();
    for p_f in &grid.attacker_fractions {
        let at_p = seat_distribution(
            members,
            &CommitteeModel::LotterySpread {
                population,
                attackers: attacker_ids(&decimal(*p_f)?, population),
            },
        )?;
        for &c in &config.analytic.absence.absences_per_id_per_year {
            let delta = departure_probability_per_refresh(c, refreshes);
            let ratio = honest_tenure_ratio(members, delta);
            let share = effective_share(*p_f, ratio);
            let at_share = seat_distribution(
                members,
                &CommitteeModel::LotterySpread {
                    population,
                    attackers: attacker_ids(&decimal(share)?, population),
                },
            )?;
            rows.push(DepartureRow {
                committee_size: members,
                attacker_fraction: *p_f,
                absences_per_id_per_year: c,
                refreshes_per_year: refreshes,
                tenure_hours,
                honest_departure_probability: -libm::expm1(members as f64 * libm::log1p(-delta)),
                honest_tenure_ratio: ratio,
                effective_attacker_share: share,
                p_stall_at_p: scientific(&at_p.at_least(stall), 6),
                p_stall_at_effective_share: scientific(&at_share.at_least(stall), 6),
                p_capture_at_p: scientific(&at_p.at_least(approvals), 6),
                p_capture_at_effective_share: scientific(&at_share.at_least(approvals), 6),
                model: DEPARTURE_MODEL,
            });
        }
    }
    Ok(rows)
}

// ----------------------------------------------------------------------------- checks

/// Results of simulating a FIFO committee.
#[derive(Debug, Clone, Default)]
struct CommitteeSimulation {
    stall_time: Vec<f64>,
    capture_time: Vec<f64>,
    stall_onsets: Vec<f64>,
    capture_onsets: Vec<f64>,
    skips: Vec<f64>,
    draws: Vec<f64>,
}

/// How a simulated committee picks its new member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Draw {
    /// The lottery's next-position rule over the canonical list.
    NextPosition,
    /// The v0.2 rule: redraw until a non-member wins a 10th block.
    Redraw,
}

/// Draws a new member who is not yet one; returns its position and the number of draws used.
fn pick_member<R: rand_core::Rng + ?Sized>(
    rng: &mut R,
    is_member: &[bool],
    draw: Draw,
) -> (usize, f64) {
    let population = is_member.len() as u64;
    let mut draws = 1.0;
    let mut position = uniform_below(rng, population) as usize;
    while is_member[position] {
        match draw {
            Draw::NextPosition => position = (position + 1) % is_member.len(),
            Draw::Redraw => {
                draws += 1.0;
                position = uniform_below(rng, population) as usize;
            }
        }
    }
    (position, draws)
}

/// Simulates a FIFO committee over a list of `is_attacker.len()` IDs. The new member is drawn
/// before the oldest leaves, as SPEC §4.3 requires.
fn simulate_committee(
    seed: u64,
    label: &str,
    is_attacker: &[bool],
    members: u64,
    approvals: u64,
    refreshes: u64,
    draw: Draw,
) -> CommitteeSimulation {
    const BATCHES: u64 = 50;
    let mut rng = rng_stream(seed, label);
    let mut is_member = vec![false; is_attacker.len()];
    let mut queue = VecDeque::with_capacity(members as usize);
    while (queue.len() as u64) < members {
        let (id, _) = pick_member(&mut rng, &is_member, draw);
        is_member[id] = true;
        queue.push_back(id);
    }
    let mut seats = queue.iter().filter(|id| is_attacker[**id]).count() as u64;
    let stall = stall_seats(members, approvals);
    let mut sim = CommitteeSimulation::default();
    let batch_size = refreshes / BATCHES;
    let burn_in = 20 * members;
    let mut batch = [0.0f64; 6];
    for step in 0..burn_in + batch_size * BATCHES {
        let before = seats;
        let (joiner, draws) = pick_member(&mut rng, &is_member, draw);
        is_member[joiner] = true;
        queue.push_back(joiner);
        seats += u64::from(is_attacker[joiner]);
        if let Some(oldest) = queue.pop_front() {
            is_member[oldest] = false;
            seats -= u64::from(is_attacker[oldest]);
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
    let mut checks = vec![binomial_onset_identity_check()?, flow_balance_check()?];
    checks.extend(lottery_monte_carlo_checks(config)?);
    checks.extend(tenth_block_monte_carlo_checks(config)?);
    checks.extend(departure_monte_carlo_checks(config));
    Ok(checks)
}

/// A new committee member: the attacker's with probability `p`; an honest one also gets the
/// refresh at which it would leave early. It leaves during the `k`-th interval after joining
/// (`k ≥ 1`) with probability `(1 − δ)^(k−1)·δ`, so before the record at `step + k`.
fn departing_joiner<R: rand_core::Rng + ?Sized>(
    rng: &mut R,
    step: u64,
    p: f64,
    delta: f64,
) -> (bool, u64) {
    if bernoulli(rng, p) {
        (true, u64::MAX)
    } else {
        (false, step + 1 + geometric_failures(rng, delta))
    }
}

/// Simulates a FIFO committee of `members` whose honest members leave early with probability
/// `delta` per refresh interval. At each refresh the regular draw joins, the oldest leaves and
/// one extra draw fills each seat vacated since the last refresh. Returns batch means of the
/// attacker's seat share after each refresh.
fn simulate_departures(
    seed: u64,
    label: &str,
    members: u64,
    p: f64,
    delta: f64,
    refreshes: u64,
) -> RunningStats {
    const BATCHES: u64 = 50;
    let mut rng = rng_stream(seed, label);
    let mut queue: VecDeque<(bool, u64)> = (0..members)
        .map(|_| departing_joiner(&mut rng, 0, p, delta))
        .collect();
    let burn_in = 20 * members;
    let batch_size = refreshes / BATCHES;
    let mut stats = RunningStats::default();
    let mut batch = 0.0;
    for step in 1..=burn_in + batch_size * BATCHES {
        let before = queue.len();
        queue.retain(|(_, leave)| *leave != step);
        let departed = before - queue.len();
        queue.push_back(departing_joiner(&mut rng, step, p, delta));
        queue.pop_front();
        for _ in 0..departed {
            queue.push_back(departing_joiner(&mut rng, step, p, delta));
        }
        if step <= burn_in {
            continue;
        }
        batch += queue.iter().filter(|(attacker, _)| *attacker).count() as f64 / members as f64;
        if (step - burn_in) % batch_size == 0 {
            stats.push(batch / batch_size as f64);
            batch = 0.0;
        }
    }
    stats
}

/// The departure cases simulated: committee size, attacker share and per-refresh departure
/// probability. The departure probabilities are far above the C3 values (about 1e-5) so that
/// the effect is many standard errors wide.
const DEPARTURE_CASES: [(u64, f64, f64); 2] = [(30, 0.3, 0.004), (30, 0.25, 0.004)];

fn departure_monte_carlo_checks(config: &Config) -> Vec<Check> {
    let mc = &config.run.monte_carlo;
    DEPARTURE_CASES
        .iter()
        .map(|&(members, p, delta)| {
            let id = format!("C-mc-departures-n{members}-p{p}");
            let stats = simulate_departures(
                config.run.seed,
                &id,
                members,
                p,
                delta,
                mc.committee_refreshes,
            );
            Check::monte_carlo(
                "C",
                &id,
                &format!(
                    "committee with honest departures (n={members}, p={p}, departure probability {delta} per refresh, extra draws at the next refresh): simulated attacker seat share vs p/(p + (1-p)r)"
                ),
                effective_share(p, honest_tenure_ratio(members, delta)),
                stats.estimate(),
                mc.tolerance_standard_errors,
                0.0,
            )
        })
        .collect()
}

fn binomial_onset_identity_check() -> Result<Check> {
    let mut failures = 0;
    let mut rows = 0;
    for (members, population, attackers) in [
        (30, 10_000, 4_000),
        (100, 100_000, 33_000),
        (600, 2_900_000, 870_000),
    ] {
        let model = CommitteeModel::LotteryBlock {
            population,
            attackers,
        };
        let p = ratio(attackers, population);
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
        "lottery with attacker IDs in one block (binomial): the onset formula equals p(1-p)·P(Bin(n-1,p) = t-1) exactly",
        failures,
        rows,
    ))
}

fn flow_balance_check() -> Result<Check> {
    // In stationarity every state is entered as often as it is left. Entries and exits are
    // computed by separate formulas, so equality checks both and the stationary distribution.
    let mut failures = 0;
    let mut rows = 0;
    for (members, population, attackers) in [
        (30_u64, 1_000_u64, 330_u64),
        (100, 100_000, 25_000),
        (600, 2_900_000, 957_000),
    ] {
        let spread = CommitteeModel::LotterySpread {
            population,
            attackers,
        };
        let block = CommitteeModel::LotteryBlock {
            population,
            attackers,
        };
        let tenth = CommitteeModel::TenthBlockMiner {
            population,
            attackers,
        };
        for model in [spread, block, tenth] {
            for seats in [1, members / 3, members / 2, members * 2 / 3, members] {
                rows += 1;
                let entries = onset_probability_per_refresh(members, seats, &model)?;
                let exits = exit_probability_per_refresh(members, seats, &model)?;
                failures += u64::from(entries != exits);
            }
        }
    }
    Ok(Check::all_rows(
        "C",
        "C-flow-balance",
        "stationary FIFO committee: exact entries into each state equal exact exits from it, for every seat model",
        failures,
        rows,
    ))
}

/// The cases simulated by the Monte Carlo checks.
const MC_CASES: [(u64, f64); 4] = [(30, 0.3), (30, 0.4), (100, 0.3), (100, 0.4)];

#[allow(clippy::too_many_arguments)]
fn committee_checks(
    checks: &mut Vec<Check>,
    sim: &CommitteeSimulation,
    model: &CommitteeModel,
    members: u64,
    approvals: u64,
    refreshes: u64,
    k: f64,
    id: &str,
    what: &str,
) -> Result<()> {
    let distribution = seat_distribution(members, model)?;
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
            to_f64(&onset_probability_per_refresh(members, stall, model)?),
            &sim.stall_onsets,
        ),
        (
            "capture-onsets",
            to_f64(&onset_probability_per_refresh(members, approvals, model)?),
            &sim.capture_onsets,
        ),
    ];
    for (name, exact, values) in cases {
        if exact * refreshes as f64 / (members as f64) < 30.0 {
            continue; // too rare for this sample size
        }
        checks.push(Check::monte_carlo(
            "C",
            &format!("{id}-{name}"),
            &format!("{what}: simulated {name} per refresh vs exact formula"),
            exact,
            batch_estimate(values).estimate(),
            k,
            0.0,
        ));
    }
    Ok(())
}

fn lottery_monte_carlo_checks(config: &Config) -> Result<Vec<Check>> {
    let mc = &config.run.monte_carlo;
    let threshold = config.cac.approval_threshold.value;
    let population = mc.lottery_population;
    let mut checks = Vec::new();
    for (members, p_f) in MC_CASES {
        let approvals = approvals_needed(members, &threshold)?;
        let attackers = attacker_ids(&decimal(p_f)?, population);
        let block: Vec<bool> = (0..population).map(|i| i < attackers).collect();
        let mut spread = block.clone();
        let mut layout_rng = rng_stream(
            config.run.seed,
            &format!("C-lottery-layout-{members}-{p_f}"),
        );
        shuffle(&mut layout_rng, &mut spread);
        let layouts = [
            (
                "spread",
                spread,
                CommitteeModel::LotterySpread {
                    population,
                    attackers,
                },
            ),
            (
                "block",
                block,
                CommitteeModel::LotteryBlock {
                    population,
                    attackers,
                },
            ),
        ];
        for (layout, is_attacker, model) in layouts {
            let id = format!("C-mc-lottery-{layout}-n{members}-p{p_f}");
            let sim = simulate_committee(
                config.run.seed,
                &id,
                &is_attacker,
                members,
                approvals,
                mc.committee_refreshes,
                Draw::NextPosition,
            );
            committee_checks(
                &mut checks,
                &sim,
                &model,
                members,
                approvals,
                mc.committee_refreshes,
                mc.tolerance_standard_errors,
                &id,
                &format!(
                    "lottery with the next-position rule, attacker IDs {} (N={population}, n={members}, p={p_f})",
                    if layout == "spread" {
                        "spread through the list, vs hypergeometric"
                    } else {
                        "in one block of the list, vs binomial"
                    }
                ),
            )?;
        }
    }
    Ok(checks)
}

fn tenth_block_monte_carlo_checks(config: &Config) -> Result<Vec<Check>> {
    let mc = &config.run.monte_carlo;
    let threshold = config.cac.approval_threshold.value;
    let population = mc.committee_population;
    let mut checks = Vec::new();
    for (members, p_f) in MC_CASES {
        let approvals = approvals_needed(members, &threshold)?;
        let attackers = attacker_ids(&decimal(p_f)?, population);
        let is_attacker: Vec<bool> = (0..population).map(|i| i < attackers).collect();
        let model = CommitteeModel::TenthBlockMiner {
            population,
            attackers,
        };
        let id = format!("C-mc-tenth-block-n{members}-p{p_f}");
        let sim = simulate_committee(
            config.run.seed,
            &id,
            &is_attacker,
            members,
            approvals,
            mc.committee_refreshes,
            Draw::Redraw,
        );
        committee_checks(
            &mut checks,
            &sim,
            &model,
            members,
            approvals,
            mc.committee_refreshes,
            mc.tolerance_standard_errors,
            &id,
            &format!(
                "v0.2 comparison rule, members' wins passed on (N={population}, n={members}, p={p_f}), vs hypergeometric"
            ),
        )?;
        let skips: f64 = sim.skips.iter().sum();
        let draws: f64 = sim.draws.iter().sum();
        checks.push(Check::relative(
            "C",
            &format!("C-mc-skip-rate-n{members}-p{p_f}"),
            &format!(
                "v0.2 comparison rule: share of 10th-block wins that go to existing members (N={population}, n={members}) vs n/N"
            ),
            members as f64 / population as f64,
            skips / draws,
            0.05,
        ));
    }
    Ok(checks)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spread(population: u64, attackers: u64) -> CommitteeModel {
        CommitteeModel::LotterySpread {
            population,
            attackers,
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
            let a = approvals_needed(members, &Fraction::new(2, 3)).unwrap();
            assert_eq!((a, stall_seats(members, a)), (approvals, stall));
        }
    }

    #[test]
    fn block_layout_stall_probability_at_600_members_and_33_percent_is_about_41_percent() {
        // Binomial reference value carried over from M1 (duplicates allowed, p = 0.33).
        let model = CommitteeModel::LotteryBlock {
            population: 100,
            attackers: 33,
        };
        let p = seat_distribution(600, &model).unwrap().at_least(201);
        assert!((to_f64(&p) - 0.412_268_244_173_590_9).abs() < 1e-12);
    }

    #[test]
    fn lottery_seat_share_equals_active_share_in_expectation() {
        // E[X] = n·K/N for both lottery layouts.
        for model in [
            spread(2_900_000, 870_000),
            CommitteeModel::LotteryBlock {
                population: 2_900_000,
                attackers: 870_000,
            },
        ] {
            let d = seat_distribution(600, &model).unwrap();
            let mean = (0..=600u64).fold(Q::zero(), |acc, x| acc + d.pmf(x) * integer(x));
            assert_eq!(mean, integer(180));
        }
    }

    #[test]
    fn honest_non_mining_raises_the_attacker_share_under_the_v02_rule() {
        let (population, attackers) = mining_population(2_900_000, &ratio(1, 4), &ratio(1, 2));
        assert_eq!(attackers, 725_000);
        assert_eq!(population, 725_000 + 1_087_500);
        let share = attackers as f64 / population as f64;
        assert!((share - 0.25 / (0.25 + 0.5 * 0.75)).abs() < 1e-12);
    }

    #[test]
    fn lottery_refreshes_every_tenth_block_and_the_v02_rule_skips_members() {
        let lottery = refreshes_per_year(31_536_000, &integer(10), 10, 600, &spread(2_900_000, 0));
        assert_eq!(lottery, integer(315_360));
        let tenth = CommitteeModel::TenthBlockMiner {
            population: 2_900_000,
            attackers: 0,
        };
        let refreshes = refreshes_per_year(31_536_000, &integer(10), 10, 600, &tenth);
        assert_eq!(
            refreshes,
            integer(315_360) * integer(2_899_400) / integer(2_900_000)
        );
    }

    #[test]
    fn entries_equal_exits_in_stationarity() {
        let model = spread(1_000, 330);
        for seats in [1, 10, 20, 30] {
            assert_eq!(
                onset_probability_per_refresh(30, seats, &model).unwrap(),
                exit_probability_per_refresh(30, seats, &model).unwrap()
            );
        }
    }

    #[test]
    fn onset_rate_exceeds_the_independent_composition_estimate_for_rare_states() {
        let model = CommitteeModel::LotteryBlock {
            population: 10,
            attackers: 4,
        };
        let onset = onset_probability_per_refresh(30, 20, &model).unwrap();
        let hold = seat_distribution(30, &model).unwrap().at_least(20);
        let ratio = to_f64(&(onset * integer(30) / hold));
        assert!(ratio > 5.0, "{ratio}");
    }

    #[test]
    fn mean_episode_is_time_share_over_entry_rate() {
        assert_eq!(
            mean_episode_refreshes(&ratio(1, 10), &ratio(1, 1_000)),
            Some(100.0)
        );
        assert_eq!(mean_episode_refreshes(&ratio(1, 10), &Q::zero()), None);
    }

    #[test]
    fn onset_threshold_outside_the_committee_is_rejected() {
        let model = spread(1_000, 250);
        assert!(onset_probability_per_refresh(30, 0, &model).is_err());
        assert!(onset_probability_per_refresh(30, 31, &model).is_err());
        assert!(exit_probability_per_refresh(30, 31, &model).is_err());
    }

    #[test]
    fn section_c_tables_cover_every_combination() {
        let config = Config::default();
        let c = section_c(&config).unwrap();
        let g = &config.analytic.cac;
        let combos = g.committee_sizes.len()
            * g.attacker_fractions.len()
            * (2 + g.honest_mining_fractions.len());
        assert_eq!(c.odds.len(), combos);
        assert_eq!(c.events.len(), 2 * combos);
        let lottery_rows = c.odds.iter().filter(|r| r.rule == "lottery").count();
        assert_eq!(
            lottery_rows,
            2 * g.committee_sizes.len() * g.attacker_fractions.len()
        );
    }

    #[test]
    fn stall_episode_at_600_members_and_30_percent_lasts_about_40_minutes() {
        let config = Config::default();
        let c = section_c(&config).unwrap();
        let primary = spread(1, 0).label();
        let row = c
            .odds
            .iter()
            .find(|r| r.model == primary && r.committee_size == 600 && r.attacker_fraction == 0.3)
            .unwrap();
        // Reference: P(X ≥ 201) / onset rate × 100 s, from Python's exact integer arithmetic
        // (23.94 refreshes).
        let hours = row.mean_stall_hours.unwrap();
        assert!((hours - 0.664_900_352_341_196_8).abs() < 1e-9, "{hours}");
    }

    #[test]
    fn departures_raise_the_attacker_share_by_little_more_than_a_tenth_of_a_point() {
        // Plan preview: 4 absences per ID per year at R = 315,360 refreshes (10 s PoW-Tx
        // blocks, every 10th) and n = 600 give r ≈ 1 − nδ/2 and a share of about 25.07% at
        // p = 25%.
        let delta = departure_probability_per_refresh(4.0, 315_360.0);
        assert!((delta - 4.0 / 315_360.0).abs() < 1e-9);
        let r = honest_tenure_ratio(600, delta);
        assert!((r - (1.0 - 600.0 * delta / 2.0)).abs() < 1e-4);
        let share = effective_share(0.25, r);
        assert!((share - 0.2507).abs() < 0.0001, "{share}");
        assert_eq!(honest_tenure_ratio(600, 0.0), 1.0);
        assert_eq!(effective_share(0.25, 1.0), 0.25);
    }

    #[test]
    fn departure_rows_cover_every_share_and_absence_rate() {
        let config = Config::default();
        let rows = departure_rows(&config).unwrap();
        assert_eq!(
            rows.len(),
            config.analytic.cac.attacker_fractions.len()
                * config.analytic.absence.absences_per_id_per_year.len()
        );
        let row = rows
            .iter()
            .find(|r| r.attacker_fraction == 0.25 && r.absences_per_id_per_year == 4.0)
            .unwrap();
        // 600 refreshes of 100 s.
        assert!((row.tenure_hours - 600.0 * 100.0 / 3_600.0).abs() < 1e-9);
        assert!(row.effective_attacker_share > 0.25);
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
