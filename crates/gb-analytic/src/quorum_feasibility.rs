//! Section H — quorum feasibility under honest downtime (SPEC §2 quorums, §3.2, §4.5–§4.7).
//!
//! A KWC approves only when enough members sign. Honest members are sometimes offline, and an
//! attacker's members may withhold their signatures. This section asks how often a KWC cannot
//! meet its quorum at all, for each quorum layout, and how much honest uptime keeps that rare.
//!
//! # Model
//!
//! Each seat is the attacker's with probability `p`, and attacker members never sign. Each
//! honest member is online, and signs, with probability `f`, independently. A seat therefore
//! signs with probability `s = (1 − p)·f` (binomial thinning), and a KWC fails exactly when
//! the non-signing seats could stall it in the sense of section G. The layouts:
//!
//! - **unregistered PoWit**: any 27 of 40 (SPEC §2);
//! - **registered PoWit, SPEC**: 7 of the leader WC's 10 **and** 21 of the 30 subordinates;
//! - **registered PoWit, single quorum (comparison)**: any 27 of 40, the validity rule of the
//!   \[P\] proposal to separate validity from payment (SPEC §12). Its numbers equal the
//!   unregistered row; it is listed so the cost of the leader requirement shows directly.
//!
//! A KWC that fails quorum is a **local** liveness problem: its miners move to another KWC
//! after the grace epoch plus admission (SPEC §3.2), and the rest of the network continues.
//! Miners are spread evenly over KWCs, so the share of miners affected at any moment equals
//! the failure probability.
//!
//! The withholding rows assume withholding costs the attacker nothing. Under SPEC §4.5–§4.6 an
//! online member that refuses to sign after One Chance is banned; M4 models that.
//!
//! # Tables
//!
//! - **H1**: P(fail) per layout, `p` and `f`: exact under the binomial seat model, and at a
//!   network of `W` KWCs with hypergeometric attacker seats. For the SPEC registered layout it
//!   also gives each group's own probability of falling below its quorum; the groups are
//!   independent under the binomial model, so P(fail) = 1 − (1 − P_leader)(1 − P_subordinates).
//! - **H2**: the minimum `f` for fewer than each target share of KWCs failing, by exact
//!   bisection on a 10⁻⁴ grid; "not reachable" when even `f = 1` misses the target. P(fail)
//!   at `f = 1` is section B's block probability.
//! - **H3**: absent IDs keep their seats under SPEC v0.4 (§4.7) until a ban or an absence
//!   longer than L. By Little's law, honest seat-holders are absent a share
//!   `(c·E[min(D, L)] + a·L)/365` of the time, for `c` absences and `a` permanent departures
//!   per ID per year (realised rates), absence durations `D` and L in days. The ordinary
//!   uptime needed among present members is then `s*/((1 − p)(1 − share))`, where `s*` is the
//!   signing probability at which P(fail) equals the target.

use crate::allocation::{AbsenceDurations, absence_models, days_in_blocks, long_absence_days};
use crate::dist::{ExactDistribution, JointDistribution, SeatModel};
use crate::error::{Result, ensure};
use crate::exact::{Q, decimal, integer, log10, ratio, scientific, to_f64};
use crate::logspace;
use crate::mc::{RunningStats, bernoulli};
use crate::quorum_tradeoff::{Harm, QuorumLayout};
use crate::validation::Check;
use crate::witness::{KwcSpec, KwcState, MinerKind, attacker_ids, state_probability};
use gb_config::Config;
use gb_runlog::rng_stream;
use num_traits::{One, Zero};
use serde::Serialize;

/// Layout label: the unregistered PoWit quorum.
pub const UNREGISTERED: &str = "unregistered PoWit";
/// Layout label: the SPEC registered quorum.
pub const REGISTERED: &str = "registered PoWit, SPEC (leader WC and subordinates)";
/// Layout label: the registered comparison under one quorum over all members.
pub const REGISTERED_SINGLE: &str =
    "registered PoWit, single quorum ([P] validity rule, comparison)";

/// Grid step for minimum uptimes: 10⁻⁴.
const GRID: u64 = 10_000;

/// A quorum layout as reported in section H.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeasibilityLayout {
    /// Label used in tables.
    pub label: &'static str,
    /// The quorum rule.
    pub layout: QuorumLayout,
    /// Miner kind whose section B block state equals failure at full uptime.
    pub kind: MinerKind,
}

/// The three layouts of section H, from the SPEC quorums.
pub fn layouts(config: &Config) -> Vec<FeasibilityLayout> {
    let spec = KwcSpec::forty_node(config);
    let (n1, n2) = (spec.leader_seats(), spec.subordinate_seats());
    let pool = QuorumLayout::Pool {
        seats: n1 + n2,
        quorum: spec.unregistered_min,
    };
    vec![
        FeasibilityLayout {
            label: UNREGISTERED,
            layout: pool,
            kind: MinerKind::Unregistered,
        },
        FeasibilityLayout {
            label: REGISTERED,
            layout: QuorumLayout::TwoGroup {
                leader_seats: n1,
                leader_quorum: spec.leader_min,
                subordinate_seats: n2,
                subordinate_quorum: spec.subordinate_min,
            },
            kind: MinerKind::Registered,
        },
        FeasibilityLayout {
            label: REGISTERED_SINGLE,
            layout: pool,
            kind: MinerKind::Unregistered,
        },
    ]
}

/// P(at least `quorum` of `seats` sign) when each signs independently with probability `s`.
fn signs(seats: u64, quorum: u64, s: &Q) -> Result<Q> {
    Ok(ExactDistribution::new(seats, &SeatModel::Binomial(s.clone()))?.at_least(quorum))
}

/// Exact P(fail) when every seat signs independently with probability `s`.
pub fn fail_probability(layout: &QuorumLayout, s: &Q) -> Result<Q> {
    Ok(match *layout {
        QuorumLayout::Pool { seats, quorum } => Q::one() - signs(seats, quorum, s)?,
        QuorumLayout::TwoGroup {
            leader_seats,
            leader_quorum,
            subordinate_seats,
            subordinate_quorum,
        } => {
            Q::one()
                - signs(leader_seats, leader_quorum, s)?
                    * signs(subordinate_seats, subordinate_quorum, s)?
        }
    })
}

/// For a two-group layout, P(leader group below its quorum) and P(subordinates below
/// theirs) when every seat signs with probability `s`.
pub fn group_fail_probabilities(layout: &QuorumLayout, s: &Q) -> Result<Option<(Q, Q)>> {
    Ok(match *layout {
        QuorumLayout::Pool { .. } => None,
        QuorumLayout::TwoGroup {
            leader_seats,
            leader_quorum,
            subordinate_seats,
            subordinate_quorum,
        } => Some((
            Q::one() - signs(leader_seats, leader_quorum, s)?,
            Q::one() - signs(subordinate_seats, subordinate_quorum, s)?,
        )),
    })
}

/// Exact P(fail) by summing over the attacker's seats under `attacker`, with each honest
/// member online with probability `f`. With binomial attacker seats this equals
/// [`fail_probability`] at `s = (1 − p)·f` (the thinning identity, checked); with
/// hypergeometric seats it is the finite-network value.
pub fn fail_probability_mixture(layout: &QuorumLayout, attacker: &SeatModel, f: &Q) -> Result<Q> {
    let honest_tails = |seats: u64, quorum: u64| -> Result<Vec<Q>> {
        (0..=seats)
            .map(|a| {
                if quorum > seats - a {
                    Ok(Q::zero())
                } else {
                    signs(seats - a, quorum, f)
                }
            })
            .collect()
    };
    Ok(match *layout {
        QuorumLayout::Pool { seats, quorum } => {
            let d = ExactDistribution::new(seats, attacker)?;
            let tails = honest_tails(seats, quorum)?;
            let mut total = Q::zero();
            for (a, tail) in tails.iter().enumerate() {
                total += d.pmf(a as u64) * (Q::one() - tail);
            }
            total
        }
        QuorumLayout::TwoGroup {
            leader_seats,
            leader_quorum,
            subordinate_seats,
            subordinate_quorum,
        } => {
            let j = JointDistribution::new(leader_seats, subordinate_seats, attacker)?;
            let leader = honest_tails(leader_seats, leader_quorum)?;
            let subordinate = honest_tails(subordinate_seats, subordinate_quorum)?;
            let mut total = Q::zero();
            for (x, lx) in leader.iter().enumerate() {
                for (y, sy) in subordinate.iter().enumerate() {
                    total += j.pmf(x as u64, y as u64) * (Q::one() - lx * sy);
                }
            }
            total
        }
    })
}

/// Independent log-space computation of `log10 P(fail)` at signing probability `s`.
pub fn log10_fail_probability_logspace(layout: &QuorumLayout, s: f64) -> f64 {
    // ln P(fewer than `quorum` of `seats` sign).
    let ln_below = |seats: u64, quorum: u64| -> f64 {
        let terms: Vec<f64> = (0..quorum)
            .map(|j| logspace::ln_binomial_pmf(seats, j, s))
            .collect();
        logspace::log10_sum_exp(&terms) * std::f64::consts::LN_10
    };
    match *layout {
        QuorumLayout::Pool { seats, quorum } => ln_below(seats, quorum) / std::f64::consts::LN_10,
        QuorumLayout::TwoGroup {
            leader_seats,
            leader_quorum,
            subordinate_seats,
            subordinate_quorum,
        } => {
            let leader = libm::exp(ln_below(leader_seats, leader_quorum));
            let subordinate = libm::exp(ln_below(subordinate_seats, subordinate_quorum));
            libm::log10(leader + subordinate * (1.0 - leader))
        }
    }
}

/// Smallest `f = k/10⁴` with P(fail) below `target` when seats are the attacker's with
/// probability `p`, by exact bisection; `None` when `f = 1` misses the target.
pub fn minimum_online_fraction(layout: &QuorumLayout, p: &Q, target: &Q) -> Result<Option<u64>> {
    let fails =
        |k: u64| -> Result<Q> { fail_probability(layout, &((Q::one() - p) * ratio(k, GRID))) };
    if fails(GRID)? >= *target {
        return Ok(None);
    }
    // Invariant: P(fail) ≥ target at `low` (or low = 0), P(fail) < target at `high`.
    let (mut low, mut high) = (0u64, GRID);
    while high - low > 1 {
        let middle = (low + high) / 2;
        if fails(middle)? < *target {
            high = middle;
        } else {
            low = middle;
        }
    }
    Ok(Some(high))
}

/// Signing probability `s*` at which P(fail) crosses `target`, as the upper end of an exact
/// bisection bracket of width 2⁻⁵⁰ (so P(fail) < target at the returned value).
pub fn critical_signing_probability(layout: &QuorumLayout, target: &Q) -> Result<f64> {
    const STEPS: u32 = 50;
    let scale: u64 = 1 << STEPS;
    let fails = |m: u64| fail_probability(layout, &ratio(m, scale));
    ensure(
        fails(scale)? < *target,
        "the target must be reachable when every seat signs",
    )?;
    let (mut low, mut high) = (0u64, scale);
    while high - low > 1 {
        let middle = low + (high - low) / 2;
        if fails(middle)? < *target {
            high = middle;
        } else {
            low = middle;
        }
    }
    Ok(high as f64 / scale as f64)
}

/// Share of honest seats held by absent IDs: `(c·E[min(D, L)] + a·L)/365`.
pub fn absent_seat_share(
    durations: &AbsenceDurations,
    absences_per_year: f64,
    departures_per_year: f64,
    long_absence_days: f64,
) -> f64 {
    (absences_per_year * durations.capped_mean(long_absence_days)
        + departures_per_year * long_absence_days)
        / 365.0
}

// ----------------------------------------------------------------------------- tables

/// H1: probability that a KWC cannot meet its quorum.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FeasibilityRow {
    /// Layout label.
    pub layout: &'static str,
    /// Signatures needed.
    pub approvals: String,
    /// Attacker fraction p of seats (its members withhold).
    pub attacker_fraction: f64,
    /// Probability f that an honest member is online.
    pub online_fraction: f64,
    /// Probability that a seat signs, (1 − p)·f.
    pub signing_probability: f64,
    /// P(fail), exact under the binomial seat model.
    pub p_fail: String,
    /// log10 P(fail).
    pub log10_p_fail: f64,
    /// SPEC registered layout: P(the leader WC falls below its quorum).
    pub p_leader_below_quorum: Option<String>,
    /// SPEC registered layout: P(the subordinates fall below theirs).
    pub p_subordinates_below_quorum: Option<String>,
    /// Network size of the comparison, KWCs.
    pub kwcs: u64,
    /// P(fail) at that network (hypergeometric attacker seats).
    pub p_fail_hypergeometric: String,
    /// Share of miners affected at any moment (miners spread evenly over KWCs): P(fail).
    pub share_of_miners_affected: f64,
    /// Expected failing KWCs at the comparison network, W × P(fail, hypergeometric).
    pub expected_failing_kwcs: f64,
}

/// H2: minimum honest uptime for fewer than a target share of KWCs failing.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MinimumUptimeRow {
    /// Layout label.
    pub layout: &'static str,
    /// Signatures needed.
    pub approvals: String,
    /// Attacker fraction p.
    pub attacker_fraction: f64,
    /// Target share of failing KWCs.
    pub failure_target: f64,
    /// Smallest f on a 10⁻⁴ grid with P(fail) below the target (empty when not reachable).
    pub minimum_online_fraction: Option<f64>,
    /// "reachable" or "not reachable".
    pub status: &'static str,
    /// P(fail) at the minimum, below the target.
    pub p_fail_at_minimum: Option<String>,
    /// P(fail) one grid step lower, at or above the target.
    pub p_fail_one_step_below: Option<String>,
    /// P(fail) at f = 1, which is section B's block probability.
    pub p_fail_at_full_uptime: String,
}

/// H3: ordinary uptime needed when absent IDs keep their seats (SPEC v0.4 §4.7).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AbsentSeatRow {
    /// Layout label.
    pub layout: &'static str,
    /// Signatures needed.
    pub approvals: String,
    /// Attacker fraction p.
    pub attacker_fraction: f64,
    /// Target share of failing KWCs.
    pub failure_target: f64,
    /// Absence-duration model.
    pub duration_model: &'static str,
    /// Absences per ID per year.
    pub absences_per_id_per_year: f64,
    /// Permanent departures per ID per year.
    pub departures_per_id_per_year: f64,
    /// Long-absence threshold L, days.
    pub long_absence_days: f64,
    /// L in PoW-ID blocks at the target interval.
    pub long_absence_blocks: f64,
    /// E[min(D, L)], days.
    pub capped_mean_absence_days: f64,
    /// Share of honest seats held by absent IDs.
    pub absent_seat_share: f64,
    /// Uptime needed among present honest members (empty when not reachable).
    pub required_ordinary_uptime: Option<f64>,
    /// "reachable" or "not reachable".
    pub status: &'static str,
}

/// All section H tables.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SectionH {
    /// H1.
    pub feasibility: Vec<FeasibilityRow>,
    /// H2.
    pub minimum_uptime: Vec<MinimumUptimeRow>,
    /// H3.
    pub absent_seats: Vec<AbsentSeatRow>,
}

/// Label for a reachable or unreachable target.
pub fn status(reachable: bool) -> &'static str {
    if reachable {
        "reachable"
    } else {
        "not reachable"
    }
}

/// Builds every section H table from the configuration.
pub fn section_h(config: &Config) -> Result<SectionH> {
    let grid = &config.analytic.quorum_feasibility;
    let layouts = layouts(config);
    let spec = KwcSpec::forty_node(config);
    let kwcs = grid.comparison_kwcs;
    let population = spec.wc_size * kwcs;
    let mut tables = SectionH::default();
    for layout in &layouts {
        for p_f in &grid.attacker_fractions {
            let p = decimal(*p_f)?;
            let hypergeometric = SeatModel::Hypergeometric {
                population,
                attackers: attacker_ids(&p, population),
            };
            for f_f in &grid.online_fractions {
                let f = decimal(*f_f)?;
                let s = (Q::one() - &p) * &f;
                let fail = fail_probability(&layout.layout, &s)?;
                let groups = group_fail_probabilities(&layout.layout, &s)?;
                let hyper = fail_probability_mixture(&layout.layout, &hypergeometric, &f)?;
                tables.feasibility.push(FeasibilityRow {
                    layout: layout.label,
                    approvals: layout.layout.approvals_label(),
                    attacker_fraction: *p_f,
                    online_fraction: *f_f,
                    signing_probability: to_f64(&s),
                    p_fail: scientific(&fail, 6),
                    log10_p_fail: log10(&fail).unwrap_or(f64::NEG_INFINITY),
                    p_leader_below_quorum: groups.as_ref().map(|(l, _)| scientific(l, 6)),
                    p_subordinates_below_quorum: groups.as_ref().map(|(_, g)| scientific(g, 6)),
                    kwcs,
                    p_fail_hypergeometric: scientific(&hyper, 6),
                    share_of_miners_affected: to_f64(&fail),
                    expected_failing_kwcs: to_f64(&(hyper * integer(kwcs))),
                });
            }
            for target_f in &grid.failure_targets {
                let target = decimal(*target_f)?;
                let minimum = minimum_online_fraction(&layout.layout, &p, &target)?;
                let at = |k: u64| -> Result<String> {
                    let s = (Q::one() - &p) * ratio(k, GRID);
                    Ok(scientific(&fail_probability(&layout.layout, &s)?, 6))
                };
                let full = fail_probability(&layout.layout, &(Q::one() - &p))?;
                tables.minimum_uptime.push(MinimumUptimeRow {
                    layout: layout.label,
                    approvals: layout.layout.approvals_label(),
                    attacker_fraction: *p_f,
                    failure_target: *target_f,
                    minimum_online_fraction: minimum.map(|k| k as f64 / GRID as f64),
                    status: status(minimum.is_some()),
                    p_fail_at_minimum: minimum.map(at).transpose()?,
                    p_fail_one_step_below: minimum.map(|k| at(k - 1)).transpose()?,
                    p_fail_at_full_uptime: scientific(&full, 6),
                });
            }
        }
    }
    tables.absent_seats = absent_seat_rows(config, &layouts)?;
    Ok(tables)
}

fn absent_seat_rows(config: &Config, layouts: &[FeasibilityLayout]) -> Result<Vec<AbsentSeatRow>> {
    let grid = &config.analytic.quorum_feasibility;
    let absence = &config.analytic.absence;
    let models = absence_models(config);
    let thresholds = long_absence_days(config);
    let mut rows = Vec::new();
    for layout in layouts {
        for target_f in &grid.failure_targets {
            let critical = critical_signing_probability(&layout.layout, &decimal(*target_f)?)?;
            for p_f in &grid.attacker_fractions {
                for model in &models {
                    for &c in &absence.absences_per_id_per_year {
                        for &a in &absence.departures_per_id_per_year {
                            for &days in &thresholds {
                                let share = absent_seat_share(model, c, a, days);
                                let needed = critical / ((1.0 - p_f) * (1.0 - share));
                                let reachable = share < 1.0 && needed <= 1.0;
                                rows.push(AbsentSeatRow {
                                    layout: layout.label,
                                    approvals: layout.layout.approvals_label(),
                                    attacker_fraction: *p_f,
                                    failure_target: *target_f,
                                    duration_model: model.label(),
                                    absences_per_id_per_year: c,
                                    departures_per_id_per_year: a,
                                    long_absence_days: days,
                                    long_absence_blocks: days_in_blocks(config, days),
                                    capped_mean_absence_days: model.capped_mean(days),
                                    absent_seat_share: share,
                                    required_ordinary_uptime: reachable.then_some(needed),
                                    status: status(reachable),
                                });
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(rows)
}

// ----------------------------------------------------------------------------- checks

/// Section H cross-checks.
pub fn checks(config: &Config, tables: &SectionH) -> Result<Vec<Check>> {
    let mut checks = vec![
        thinning_identity_check(config)?,
        log_space_check(config)?,
        monotonicity_check(tables),
        bracket_check(config)?,
        critical_point_check(config, tables)?,
        full_uptime_check(config)?,
        group_independence_check(config)?,
        hypergeometric_check(tables),
    ];
    checks.extend(monte_carlo_checks(config)?);
    Ok(checks)
}

fn thinning_identity_check(config: &Config) -> Result<Check> {
    let grid = &config.analytic.quorum_feasibility;
    let mut failures = 0;
    let mut rows = 0;
    for layout in layouts(config) {
        for p_f in &grid.attacker_fractions {
            let p = decimal(*p_f)?;
            for f_f in &grid.online_fractions {
                rows += 1;
                let f = decimal(*f_f)?;
                let mixture =
                    fail_probability_mixture(&layout.layout, &SeatModel::Binomial(p.clone()), &f)?;
                let thinned = fail_probability(&layout.layout, &((Q::one() - &p) * &f))?;
                failures += u64::from(mixture != thinned);
            }
        }
    }
    Ok(Check::all_rows(
        "H",
        "H-thinning-identity",
        "every layout, p and f: summing over Bin(n, p) attacker seats with Bin(n - a, f) online honest members equals P(fail) at s = (1-p)f exactly",
        failures,
        rows,
    ))
}

fn log_space_check(config: &Config) -> Result<Check> {
    let grid = &config.analytic.quorum_feasibility;
    let mut failures = 0;
    let mut rows = 0;
    for layout in layouts(config) {
        for p_f in &grid.attacker_fractions {
            let p = decimal(*p_f)?;
            for f_f in &grid.online_fractions {
                rows += 1;
                let s = (Q::one() - &p) * decimal(*f_f)?;
                let exact =
                    log10(&fail_probability(&layout.layout, &s)?).unwrap_or(f64::NEG_INFINITY);
                let reference = log10_fail_probability_logspace(&layout.layout, to_f64(&s));
                failures += u64::from((exact - reference).abs() > 1e-9);
            }
        }
    }
    Ok(Check::all_rows(
        "H",
        "H-log-space",
        "exact P(fail) agrees with an independent log-space f64 computation within 1e-9 in log10",
        failures,
        rows,
    ))
}

fn monotonicity_check(tables: &SectionH) -> Check {
    let tolerance = 1e-12;
    let mut failures = 0;
    let mut series = 0;
    let rows = &tables.feasibility;
    for a in rows {
        for b in rows {
            if a.layout != b.layout {
                continue;
            }
            let same_p = a.attacker_fraction == b.attacker_fraction;
            let same_f = a.online_fraction == b.online_fraction;
            if same_p && a.online_fraction < b.online_fraction {
                series += 1;
                failures += u64::from(b.log10_p_fail > a.log10_p_fail + tolerance);
            }
            if same_f && a.attacker_fraction < b.attacker_fraction {
                series += 1;
                failures += u64::from(b.log10_p_fail < a.log10_p_fail - tolerance);
            }
        }
    }
    Check::all_rows(
        "H",
        "H-monotone",
        "P(fail) never rises with honest uptime f and never falls with the attacker fraction p, for every layout",
        failures,
        series,
    )
}

fn bracket_check(config: &Config) -> Result<Check> {
    // Recomputes both sides of every minimum by the mixture sum, a different route from the
    // bisection's thinned formula.
    let grid = &config.analytic.quorum_feasibility;
    let mut failures = 0;
    let mut rows = 0;
    for layout in layouts(config) {
        for p_f in &grid.attacker_fractions {
            let p = decimal(*p_f)?;
            let attacker = SeatModel::Binomial(p.clone());
            for target_f in &grid.failure_targets {
                rows += 1;
                let target = decimal(*target_f)?;
                let fails =
                    |k: u64| fail_probability_mixture(&layout.layout, &attacker, &ratio(k, GRID));
                let ok = match minimum_online_fraction(&layout.layout, &p, &target)? {
                    Some(k) => fails(k)? < target && fails(k - 1)? >= target,
                    None => fails(GRID)? >= target,
                };
                failures += u64::from(!ok);
            }
        }
    }
    Ok(Check::all_rows(
        "H",
        "H-minimum-bracket",
        "every H2 minimum: P(fail) < target at f_min and >= target one 1e-4 step below (or at f = 1 when not reachable), recomputed by the mixture sum",
        failures,
        rows,
    ))
}

fn critical_point_check(config: &Config, tables: &SectionH) -> Result<Check> {
    // H3 uses s*/(1 − p) at zero absence; it must fall in H2's grid cell (f_min − 1e-4, f_min].
    let mut failures = 0;
    let mut rows = 0;
    for layout in layouts(config) {
        for target_f in &config.analytic.quorum_feasibility.failure_targets {
            let critical = critical_signing_probability(&layout.layout, &decimal(*target_f)?)?;
            for row in tables
                .minimum_uptime
                .iter()
                .filter(|r| r.layout == layout.label && r.failure_target == *target_f)
            {
                rows += 1;
                let needed = critical / (1.0 - row.attacker_fraction);
                let ok = match row.minimum_online_fraction {
                    Some(f) => needed > f - 1e-4 - 1e-12 && needed <= f + 1e-12,
                    None => needed > 1.0 - 1e-12,
                };
                failures += u64::from(!ok);
            }
        }
    }
    Ok(Check::all_rows(
        "H",
        "H-critical-point",
        "the critical signing probability s* (bisection to 2^-50) divided by (1-p) falls in H2's grid cell (f_min - 1e-4, f_min], or above 1 when not reachable",
        failures,
        rows,
    ))
}

fn full_uptime_check(config: &Config) -> Result<Check> {
    let spec = KwcSpec::forty_node(config);
    let mut failures = 0;
    let mut rows = 0;
    for layout in layouts(config) {
        for p_f in &config.analytic.quorum_feasibility.attacker_fractions {
            rows += 1;
            let p = decimal(*p_f)?;
            let at_full = fail_probability(&layout.layout, &(Q::one() - &p))?;
            let block =
                state_probability(&spec, layout.kind, KwcState::Block, &SeatModel::Binomial(p))?;
            failures += u64::from(at_full != block);
        }
    }
    Ok(Check::all_rows(
        "H",
        "H-full-uptime-equals-B-block",
        "P(fail) at f = 1 equals section B's block probability exactly, for every layout and p",
        failures,
        rows,
    ))
}

fn group_independence_check(config: &Config) -> Result<Check> {
    let grid = &config.analytic.quorum_feasibility;
    let mut failures = 0;
    let mut rows = 0;
    for layout in layouts(config) {
        for p_f in &grid.attacker_fractions {
            let p = decimal(*p_f)?;
            for f_f in &grid.online_fractions {
                let s = (Q::one() - &p) * decimal(*f_f)?;
                let QuorumLayout::TwoGroup {
                    leader_seats,
                    subordinate_seats,
                    ..
                } = layout.layout
                else {
                    continue;
                };
                if let Some((leader, subordinate)) = group_fail_probabilities(&layout.layout, &s)? {
                    rows += 1;
                    let combined = Q::one() - (Q::one() - leader) * (Q::one() - subordinate);
                    // Reference by the stall condition of section G with non-signing seats.
                    let stall = JointDistribution::new(
                        leader_seats,
                        subordinate_seats,
                        &SeatModel::Binomial(Q::one() - &s),
                    )?
                    .probability_where(|x, y| layout.layout.allows(Harm::Stall, x, y));
                    failures += u64::from(
                        combined != fail_probability(&layout.layout, &s)? || combined != stall,
                    );
                }
            }
        }
    }
    Ok(Check::all_rows(
        "H",
        "H-two-group-parts",
        "SPEC registered layout: 1 - (1 - P_leader)(1 - P_subordinates) equals P(fail) and equals section G's stall probability with non-signing seats, exactly",
        failures,
        rows,
    ))
}

fn hypergeometric_check(tables: &SectionH) -> Check {
    let mut failures = 0;
    let mut rows = 0;
    for row in &tables.feasibility {
        let binomial = row.share_of_miners_affected;
        if binomial <= 1e-6 {
            continue;
        }
        rows += 1;
        let hyper = row.expected_failing_kwcs / row.kwcs as f64;
        failures += u64::from((hyper - binomial).abs() > 0.01 * binomial);
    }
    Check::all_rows(
        "H",
        "H-hypergeometric-close",
        "where P(fail) > 1e-6, the hypergeometric value at the comparison network is within 1% of the binomial value",
        failures,
        rows,
    )
}

/// (f, p) points simulated for every layout.
const MC_POINTS: [(f64, f64); 3] = [(0.8, 0.0), (0.9, 0.1), (0.95, 0.2)];

fn monte_carlo_checks(config: &Config) -> Result<Vec<Check>> {
    let mc = &config.run.monte_carlo;
    let spec = KwcSpec::forty_node(config);
    let (n1, n2) = (spec.leader_seats(), spec.subordinate_seats());
    let layouts = layouts(config);
    let mut checks = Vec::new();
    for (f, p) in MC_POINTS {
        let id = format!("H-mc-f{f}-p{p}");
        let mut rng = rng_stream(config.run.seed, &id);
        let mut stats = vec![RunningStats::default(); layouts.len()];
        for _ in 0..mc.feasibility_samples {
            // Signing seats in the leader WC and the subordinates; attacker seats withhold.
            let mut signing = [0u64; 2];
            for seat in 0..n1 + n2 {
                if !bernoulli(&mut rng, p) && bernoulli(&mut rng, f) {
                    signing[usize::from(seat >= n1)] += 1;
                }
            }
            for (layout, stat) in layouts.iter().zip(stats.iter_mut()) {
                // Non-signing seats in each group stall the KWC exactly when it fails.
                let fails = layout
                    .layout
                    .allows(Harm::Stall, n1 - signing[0], n2 - signing[1]);
                stat.push(f64::from(u8::from(fails)));
            }
        }
        for (layout, stat) in layouts.iter().zip(&stats) {
            let s = (Q::one() - decimal(p)?) * decimal(f)?;
            checks.push(Check::monte_carlo(
                "H",
                &format!("{id}-{}", short_label(layout.label)),
                &format!(
                    "{}: share of random KWCs that cannot meet quorum (f = {f}, p = {p}, attacker members withhold) vs exact P(fail)",
                    layout.label
                ),
                to_f64(&fail_probability(&layout.layout, &s)?),
                stat.estimate(),
                mc.tolerance_standard_errors,
                0.0,
            ));
        }
    }
    Ok(checks)
}

fn short_label(label: &str) -> &'static str {
    match label {
        UNREGISTERED => "unregistered",
        REGISTERED => "registered",
        _ => "registered-single",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layout(label: &str) -> QuorumLayout {
        layouts(&Config::default())
            .into_iter()
            .find(|l| l.label == label)
            .unwrap()
            .layout
    }

    #[test]
    fn no_attacker_failure_rates_match_the_plan_preview() {
        // Plan preview (independent Python computation): 1.94%, 1.85e-5 and 4.1e-9 for 27 of
        // 40, and 17.5%, 1.32% and 0.103% for 7 + 21, at f = 0.8, 0.9 and 0.95.
        for (f, pool, registered) in [
            (ratio(8, 10), 0.0194, 0.175),
            (ratio(9, 10), 1.85e-5, 0.0132),
            (ratio(95, 100), 4.1e-9, 0.00103),
        ] {
            let a = to_f64(&fail_probability(&layout(UNREGISTERED), &f).unwrap());
            let b = to_f64(&fail_probability(&layout(REGISTERED), &f).unwrap());
            assert!((a / pool - 1.0).abs() < 0.03, "{a}");
            assert!((b / registered - 1.0).abs() < 0.01, "{b}");
        }
    }

    #[test]
    fn minimum_uptimes_match_an_independent_linear_scan() {
        // Reference: a linear scan over k/10^4 with Python's exact fractions (the plan
        // preview rounded these to 0.815, 0.907, 0.906, 0.855 and 0.950).
        let pool = layout(UNREGISTERED);
        let registered = layout(REGISTERED);
        let minimum =
            |l: &QuorumLayout, p: Q, target: Q| minimum_online_fraction(l, &p, &target).unwrap();
        let one = ratio(1, 100);
        let tenth = ratio(1, 1000);
        assert_eq!(minimum(&pool, Q::zero(), one.clone()), Some(8_150));
        assert_eq!(minimum(&registered, Q::zero(), one.clone()), Some(9_075));
        assert_eq!(minimum(&pool, ratio(1, 10), one.clone()), Some(9_055));
        assert_eq!(minimum(&pool, Q::zero(), tenth.clone()), Some(8_551));
        assert_eq!(minimum(&registered, Q::zero(), tenth.clone()), Some(9_504));
        assert_eq!(minimum(&pool, ratio(1, 10), tenth), Some(9_501));
        // 7 + 21 at p = 10%: 1.3244% of KWCs fail even at full uptime.
        assert_eq!(minimum(&registered, ratio(1, 10), one), None);
        let full = fail_probability(&registered, &ratio(9, 10)).unwrap();
        assert!((to_f64(&full) - 0.013_243_739_951_066_114).abs() < 1e-15);
    }

    #[test]
    fn absent_share_at_30_days_with_departures_is_about_4_1_percent() {
        // Plan preview: 4 absences (capped mean 3 days) and 10% departures at L = 30 days
        // give (12 + 3)/365 = 4.11%; the registered quorum then needs about 94.6% uptime.
        let lomax = AbsenceDurations::Lomax {
            scale_days: 2.0,
            shape: 1.5,
        };
        let share = absent_seat_share(&lomax, 4.0, 0.1, 30.0);
        assert!((share - 15.0 / 365.0).abs() < 1e-12);
        let critical = critical_signing_probability(&layout(REGISTERED), &ratio(1, 100)).unwrap();
        let needed = critical / (1.0 - share);
        assert!((needed - 0.946).abs() < 0.0005, "{needed}");
    }

    #[test]
    fn section_h_tables_cover_the_grid() {
        let config = Config::default();
        let h = section_h(&config).unwrap();
        let g = &config.analytic.quorum_feasibility;
        let a = &config.analytic.absence;
        assert_eq!(
            h.feasibility.len(),
            3 * g.attacker_fractions.len() * g.online_fractions.len()
        );
        assert_eq!(
            h.minimum_uptime.len(),
            3 * g.attacker_fractions.len() * g.failure_targets.len()
        );
        assert_eq!(
            h.absent_seats.len(),
            3 * g.failure_targets.len()
                * g.attacker_fractions.len()
                * 2
                * a.absences_per_id_per_year.len()
                * a.departures_per_id_per_year.len()
                * 5
        );
    }

    #[test]
    fn all_section_h_checks_pass() {
        let mut config = Config::default();
        config.run.monte_carlo.feasibility_samples = 40_000;
        let h = section_h(&config).unwrap();
        for check in checks(&config, &h).unwrap() {
            assert!(check.passed, "{check:?}");
        }
    }
}
