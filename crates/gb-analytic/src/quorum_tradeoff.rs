//! Section G — the quorum trade-off (SPEC §2 quorums, §3.4, §3.7, §4.2–§4.6).
//!
//! This section does **not** change any SPEC quorum. It shows, for a range of quorum fractions
//! `q`, what an attacker holding a fraction `p` of seats can do, so the architect can weigh
//! the options.
//!
//! # Seat conditions
//!
//! A **pool** of `n` members approves with any `k = ⌈q·n⌉` signatures (the unregistered PoWit
//! quorum, and votes on bans, MOBu/MOBr and offline requests). An attacker holding `a` seats
//! can:
//!
//! - **stall** (deny every approval) when `a ≥ n − k + 1`;
//! - **sign without honest members** when `a ≥ k`;
//! - get **two conflicting decisions approved** when `a ≥ max(0, 2k − n)`.
//!
//! The conflict condition: honest members sign at most one of two conflicting proposals,
//! while attacker members sign both, and the attacker may show different proposals to
//! different honest members. Both approvals need `k` signatures, so with `h₁` and `h₂` honest
//! signers, `a + h₁ ≥ k`, `a + h₂ ≥ k` and `h₁ + h₂ ≤ n − a`. Such `h₁, h₂` exist exactly
//! when `a ≥ 2k − n`. The seat condition is necessary; the attacker also needs a proposer
//! turn, or another way to put two proposals in front of members.
//!
//! Since SPEC v0.4 (§4.6), two conflicting decisions that are both approved are **both
//! rejected**, and every member who signed both has produced equivocation evidence and may be
//! banned. A conflict therefore cancels a decision rather than enacting two. The proposer
//! rights (§4.4) decide who can put both proposals forward: the master proposer for MOBr,
//! registered offline requests and bans; the subordinate-only proposer for MOBu and
//! unregistered offline requests (and bans of leader-chain members who refuse to witness
//! newcomers); the miner for its own offline requests.
//!
//! The **registered layout** approves with `k₁ = ⌈10q⌉` of the leader WC's 10 seats **and**
//! `k₂ = ⌈30q⌉` of the 30 subordinate seats. Each condition then applies group by group:
//! stall when `L ≥ 11 − k₁` or `S ≥ 31 − k₂`; sign when `L ≥ k₁` and `S ≥ k₂`; conflict when
//! `L ≥ max(0, 2k₁ − 10)` and `S ≥ max(0, 2k₂ − 30)`, because both approvals must meet both
//! group quorums. The SPEC default `7 + 21` is `q = 0.7` in each group; two-thirds rounded up
//! per group gives `7 + 20`, kept as a comparison.
//!
//! A quorum at or below one half is not considered: two disjoint honest halves could then
//! approve conflicting decisions with no attacker at all.
//!
//! # Probabilities
//!
//! Seats are a uniformly random draw (SPEC §4.2): hypergeometric at a network of `W` KWCs
//! (`10·W` IDs, `p·10·W` of them the attacker's), binomial for the ten-year counts. Those
//! counts use [`crate::allocation`], as section B does: **distinct episodes** (the primary
//! measure since SPEC v0.4, §10 H6), with the composition count as an upper bound. G1 has no
//! bans or absences; G4 repeats the counts under illustrative absences for the v0.3 seat rule
//! and the v0.4 rule at every long-absence threshold L. The committee part (G3) uses the seat
//! lottery's primary model of section C.

use crate::allocation::{
    BinomialSeats, EntryRates, HorizonInputs, RelinkProfile, absence_models, composition_count,
    days_in_blocks, entry_rates, episode_count, relink_profile, seat_rules,
};
use crate::cac::{CommitteeModel, seat_distribution};
use crate::dist::{ExactDistribution, JointDistribution, SeatModel};
use crate::error::{AnalyticError, Result, ensure};
use crate::exact::{Q, decimal, integer, log10, scientific, to_f64};
use crate::logspace;
use crate::validation::Check;
use crate::witness::{KwcSpec, KwcState, MinerKind, SectionB, attacker_ids, state_probability};
use gb_config::Config;
use gb_config::protocol::Fraction;
use serde::Serialize;

/// What an attacker can do with enough seats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Harm {
    /// Deny every approval.
    Stall,
    /// Meet the quorum without honest members.
    Sign,
    /// Get two conflicting decisions approved.
    Conflict,
}

/// The three harms, in table order.
pub const HARMS: [Harm; 3] = [Harm::Stall, Harm::Sign, Harm::Conflict];

/// A quorum rule over a KWC's seats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuorumLayout {
    /// Any `quorum` of `seats` members.
    Pool {
        /// Members.
        seats: u64,
        /// Signatures needed.
        quorum: u64,
    },
    /// At least `leader_quorum` of the leader WC's seats and `subordinate_quorum` of the
    /// subordinate seats.
    TwoGroup {
        /// Leader-WC seats.
        leader_seats: u64,
        /// Leader signatures needed.
        leader_quorum: u64,
        /// Subordinate seats.
        subordinate_seats: u64,
        /// Subordinate signatures needed.
        subordinate_quorum: u64,
    },
}

/// Smallest attacker seat count for a conflict in a group of `seats` with quorum `quorum`.
pub fn conflict_seats(seats: u64, quorum: u64) -> u64 {
    (2 * quorum).saturating_sub(seats)
}

/// Seats to stall a group of `seats` with quorum `quorum`: `seats − quorum + 1`.
pub fn stall_seats(seats: u64, quorum: u64) -> u64 {
    seats - quorum + 1
}

fn rounded_up(fraction: &Fraction, seats: u64) -> Result<u64> {
    ensure(
        fraction.is_proper() && fraction.exceeds_half(),
        "quorum fractions must lie above 1/2 and at most 1",
    )?;
    fraction.approvals_needed(seats).ok_or_else(|| {
        AnalyticError::InvalidInput("quorum fraction has a zero denominator".to_string())
    })
}

impl QuorumLayout {
    /// A pool of `seats` members with quorum `⌈q·seats⌉`.
    pub fn pool(seats: u64, q: &Fraction) -> Result<Self> {
        Ok(QuorumLayout::Pool {
            seats,
            quorum: rounded_up(q, seats)?,
        })
    }

    /// The registered layout with `⌈q·n⌉` in each group.
    pub fn two_group(leader_seats: u64, subordinate_seats: u64, q: &Fraction) -> Result<Self> {
        Ok(QuorumLayout::TwoGroup {
            leader_seats,
            leader_quorum: rounded_up(q, leader_seats)?,
            subordinate_seats,
            subordinate_quorum: rounded_up(q, subordinate_seats)?,
        })
    }

    /// True when an attacker holding `leader` and `subordinate` seats can cause `harm`. For a
    /// pool, the seats are `leader + subordinate`.
    pub fn allows(&self, harm: Harm, leader: u64, subordinate: u64) -> bool {
        match *self {
            QuorumLayout::Pool { seats, quorum } => {
                let a = leader + subordinate;
                match harm {
                    Harm::Stall => a >= stall_seats(seats, quorum),
                    Harm::Sign => a >= quorum,
                    Harm::Conflict => a >= conflict_seats(seats, quorum),
                }
            }
            QuorumLayout::TwoGroup {
                leader_seats,
                leader_quorum,
                subordinate_seats,
                subordinate_quorum,
            } => match harm {
                Harm::Stall => {
                    leader >= stall_seats(leader_seats, leader_quorum)
                        || subordinate >= stall_seats(subordinate_seats, subordinate_quorum)
                }
                Harm::Sign => leader >= leader_quorum && subordinate >= subordinate_quorum,
                Harm::Conflict => {
                    leader >= conflict_seats(leader_seats, leader_quorum)
                        && subordinate >= conflict_seats(subordinate_seats, subordinate_quorum)
                }
            },
        }
    }

    /// Signatures needed, for example "21 of 40" or "6 of 10 and 16 of 30".
    pub fn approvals_label(&self) -> String {
        match *self {
            QuorumLayout::Pool { seats, quorum } => format!("{quorum} of {seats}"),
            QuorumLayout::TwoGroup {
                leader_seats,
                leader_quorum,
                subordinate_seats,
                subordinate_quorum,
            } => format!(
                "{leader_quorum} of {leader_seats} and {subordinate_quorum} of {subordinate_seats}"
            ),
        }
    }

    /// Attacker seats that allow `harm`, in words.
    pub fn seats_label(&self, harm: Harm) -> String {
        match *self {
            QuorumLayout::Pool { seats, quorum } => {
                let needed = match harm {
                    Harm::Stall => stall_seats(seats, quorum),
                    Harm::Sign => quorum,
                    Harm::Conflict => conflict_seats(seats, quorum),
                };
                format!("≥ {needed}")
            }
            QuorumLayout::TwoGroup {
                leader_seats,
                leader_quorum,
                subordinate_seats,
                subordinate_quorum,
            } => match harm {
                Harm::Stall => format!(
                    "leader ≥ {} or subordinates ≥ {}",
                    stall_seats(leader_seats, leader_quorum),
                    stall_seats(subordinate_seats, subordinate_quorum)
                ),
                Harm::Sign => {
                    format!("leader ≥ {leader_quorum} and subordinates ≥ {subordinate_quorum}")
                }
                Harm::Conflict => format!(
                    "leader ≥ {} and subordinates ≥ {}",
                    conflict_seats(leader_seats, leader_quorum),
                    conflict_seats(subordinate_seats, subordinate_quorum)
                ),
            },
        }
    }

    fn groups(&self) -> (u64, u64) {
        match *self {
            QuorumLayout::Pool { seats, .. } => (seats, 0),
            QuorumLayout::TwoGroup {
                leader_seats,
                subordinate_seats,
                ..
            } => (leader_seats, subordinate_seats),
        }
    }
}

/// Exact seat distributions for one layout shape and seat model, computed once and reused for
/// every quorum.
#[derive(Debug, Clone, PartialEq)]
pub enum Seats {
    /// One pool.
    Pool(ExactDistribution),
    /// Leader and subordinate groups.
    TwoGroup(JointDistribution),
}

impl Seats {
    /// Distribution of attacker seats for `layout`'s shape under `model`.
    pub fn new(layout: &QuorumLayout, model: &SeatModel) -> Result<Self> {
        let (first, second) = layout.groups();
        Ok(match layout {
            QuorumLayout::Pool { .. } => Seats::Pool(ExactDistribution::new(first, model)?),
            QuorumLayout::TwoGroup { .. } => {
                Seats::TwoGroup(JointDistribution::new(first, second, model)?)
            }
        })
    }

    /// Exact probability that the attacker can cause `harm` under `layout`.
    pub fn probability(&self, layout: &QuorumLayout, harm: Harm) -> Q {
        match self {
            Seats::Pool(d) => d.probability_where(|a| layout.allows(harm, a, 0)),
            Seats::TwoGroup(j) => j.probability_where(|x, y| layout.allows(harm, x, y)),
        }
    }
}

/// Independent log-space computation of [`Seats::probability`], as `log10`.
pub fn log10_probability_logspace(layout: &QuorumLayout, harm: Harm, model: &SeatModel) -> f64 {
    let (n1, n2) = layout.groups();
    match (layout, model) {
        (QuorumLayout::Pool { .. }, SeatModel::Binomial(p)) => {
            let p = to_f64(p);
            let terms: Vec<f64> = (0..=n1)
                .filter(|a| layout.allows(harm, *a, 0))
                .map(|a| logspace::ln_binomial_pmf(n1, a, p))
                .collect();
            logspace::log10_sum_exp(&terms)
        }
        (
            QuorumLayout::Pool { .. },
            SeatModel::Hypergeometric {
                population,
                attackers,
            },
        ) => {
            let terms: Vec<f64> = (0..=n1)
                .filter(|a| layout.allows(harm, *a, 0))
                .map(|a| logspace::ln_hypergeometric_pmf(*population, *attackers, n1, a))
                .collect();
            logspace::log10_sum_exp(&terms)
        }
        (QuorumLayout::TwoGroup { .. }, SeatModel::Binomial(p)) => {
            let p = to_f64(p);
            let cell =
                |x, y| logspace::ln_binomial_pmf(n1, x, p) + logspace::ln_binomial_pmf(n2, y, p);
            logspace::log10_region(n1, n2, cell, |x, y| layout.allows(harm, x, y))
        }
        (
            QuorumLayout::TwoGroup { .. },
            SeatModel::Hypergeometric {
                population,
                attackers,
            },
        ) => {
            let cell =
                |x, y| logspace::ln_joint_hypergeometric(*population, *attackers, n1, n2, x, y);
            logspace::log10_region(n1, n2, cell, |x, y| layout.allows(harm, x, y))
        }
    }
}

/// A fraction as written in tables: two decimals for hundredths, otherwise `n/d`.
pub fn fraction_label(fraction: &Fraction) -> String {
    if fraction.denominator == 100 {
        format!("{:.2}", fraction.numerator as f64 / 100.0)
    } else {
        format!("{}/{}", fraction.numerator, fraction.denominator)
    }
}

// ----------------------------------------------------------------------------- tables

/// Layout label for the 40-member pool.
pub const POOL_LAYOUT: &str = "pool of 40 (unregistered PoWit; decisions)";
/// Layout label for the registered layout.
pub const REGISTERED_LAYOUT: &str = "registered PoWit (leader 10 + subordinates 30)";

/// G1: one quorum option at one attacker fraction and network size.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct QuorumRow {
    /// [`POOL_LAYOUT`] or [`REGISTERED_LAYOUT`].
    pub layout: &'static str,
    /// Quorum option, for example "0.51", "2/3" or "SPEC default".
    pub quorum: String,
    /// Quorum fraction q (for the SPEC default registered row, 28/40).
    pub quorum_fraction: f64,
    /// True for the SPEC §2 default quorum of this layout.
    pub spec_default: bool,
    /// Signatures needed.
    pub approvals: String,
    /// Attacker seats that stall.
    pub seats_to_stall: String,
    /// Attacker seats that sign without honest members.
    pub seats_to_sign: String,
    /// Attacker seats for two conflicting approved decisions.
    pub seats_to_conflict: String,
    /// Attacker fraction p of registered IDs.
    pub attacker_fraction: f64,
    /// Network size in KWCs.
    pub kwcs: u64,
    /// P(stall), hypergeometric.
    pub p_stall: String,
    /// log10 P(stall).
    pub log10_p_stall: f64,
    /// P(sign without honest members), hypergeometric.
    pub p_sign: String,
    /// log10 P(sign).
    pub log10_p_sign: f64,
    /// P(two conflicting approved decisions), hypergeometric.
    pub p_conflict: String,
    /// log10 P(conflict).
    pub log10_p_conflict: f64,
    /// Expected KWCs able to stall at one moment, `W·P`.
    pub expected_kwcs_stall: String,
    /// Expected KWCs able to sign without honest members at one moment.
    pub expected_kwcs_sign: String,
    /// Expected KWCs able to approve conflicting decisions at one moment.
    pub expected_kwcs_conflict: String,
    /// KWC compositions over the section B horizon (adopted allocation, no bans or
    /// absences), starting from `kwcs`.
    pub compositions_over_horizon: f64,
    /// P(stall), binomial (used for the counts over the horizon).
    pub p_stall_binomial: String,
    /// P(sign), binomial.
    pub p_sign_binomial: String,
    /// P(conflict), binomial.
    pub p_conflict_binomial: String,
    /// Expected distinct episodes able to stall over the horizon (primary measure).
    pub expected_episodes_stall: f64,
    /// Expected distinct episodes able to sign without honest members.
    pub expected_episodes_sign: f64,
    /// Expected distinct episodes able to approve conflicting decisions.
    pub expected_episodes_conflict: f64,
    /// Expected compositions able to stall over the horizon (upper bound on episodes).
    pub expected_compositions_stall: f64,
    /// Expected compositions able to sign without honest members (upper bound).
    pub expected_compositions_sign: f64,
    /// Expected compositions able to approve conflicting decisions (upper bound).
    pub expected_compositions_conflict: f64,
}

/// G4: ten-year counts under illustrative absences, for the v0.3 seat rule and the v0.4 rule
/// at each long-absence threshold L.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SeatRuleQuorumRow {
    /// [`POOL_LAYOUT`] or [`REGISTERED_LAYOUT`].
    pub layout: &'static str,
    /// Quorum option.
    pub quorum: String,
    /// True for the SPEC §2 default quorum of this layout.
    pub spec_default: bool,
    /// Signatures needed.
    pub approvals: String,
    /// Attacker fraction p.
    pub attacker_fraction: f64,
    /// KWCs at the start.
    pub kwcs: u64,
    /// Absence-duration model.
    pub duration_model: &'static str,
    /// Absences per registered ID per year.
    pub absences_per_id_per_year: f64,
    /// Seat rule.
    pub seat_rule: String,
    /// Long-absence threshold L in days (v0.4 rows).
    pub long_absence_days: Option<f64>,
    /// L in PoW-ID blocks at the target interval (v0.4 rows).
    pub long_absence_blocks: Option<f64>,
    /// KWC compositions over the horizon.
    pub compositions: f64,
    /// Expected distinct episodes able to stall (primary measure).
    pub expected_episodes_stall: f64,
    /// Expected distinct episodes able to sign without honest members.
    pub expected_episodes_sign: f64,
    /// Expected distinct episodes able to approve conflicting decisions.
    pub expected_episodes_conflict: f64,
    /// Expected compositions able to stall (upper bound on episodes).
    pub expected_compositions_stall: f64,
    /// Expected compositions able to sign without honest members (upper bound).
    pub expected_compositions_sign: f64,
    /// Expected compositions able to approve conflicting decisions (upper bound).
    pub expected_compositions_conflict: f64,
}

/// G2: the split rule — a lower PoWit quorum, two-thirds for decisions.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SplitRuleRow {
    /// PoWit quorum fraction, for example "0.51".
    pub powit_quorum: String,
    /// PoWit quorum fraction as a number.
    pub powit_quorum_fraction: f64,
    /// Attacker fraction p.
    pub attacker_fraction: f64,
    /// Network size in KWCs.
    pub kwcs: u64,
    /// Unregistered PoWit quorum (pool of 40).
    pub powit_pool_approvals: String,
    /// P(stall the unregistered PoWit).
    pub powit_pool_p_stall: String,
    /// P(sign an unregistered PoWit without honest members).
    pub powit_pool_p_sign: String,
    /// Registered PoWit quorum (per group).
    pub powit_registered_approvals: String,
    /// P(stall the registered PoWit).
    pub powit_registered_p_stall: String,
    /// P(sign a registered PoWit without honest members).
    pub powit_registered_p_sign: String,
    /// Decision quorum (pool of 40).
    pub decision_approvals: String,
    /// P(stall decisions).
    pub decision_p_stall: String,
    /// P(approve a decision without honest members).
    pub decision_p_sign: String,
    /// P(two conflicting decisions approved).
    pub decision_p_conflict: String,
}

/// G3: committee quorum options under the seat lottery.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CacQuorumRow {
    /// Quorum option, for example "0.51" or "2/3".
    pub quorum: String,
    /// Quorum fraction.
    pub quorum_fraction: f64,
    /// True for the SPEC default (two-thirds).
    pub spec_default: bool,
    /// Committee size n.
    pub committee_size: u64,
    /// Approvals needed.
    pub approvals: u64,
    /// Attacker seats that stall.
    pub seats_to_stall: u64,
    /// Attacker seats that approve without honest members.
    pub seats_to_sign: u64,
    /// Attacker seats for two conflicting approved blocks.
    pub seats_to_conflict: u64,
    /// Attacker fraction p of active IDs.
    pub attacker_fraction: f64,
    /// Active IDs the lottery draws from.
    pub active_ids: u64,
    /// P(stall).
    pub p_stall: String,
    /// log10 P(stall).
    pub log10_p_stall: f64,
    /// P(approve without honest members).
    pub p_sign: String,
    /// log10 P(sign).
    pub log10_p_sign: f64,
    /// P(two conflicting approved blocks).
    pub p_conflict: String,
    /// log10 P(conflict).
    pub log10_p_conflict: f64,
}

/// All section G tables.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SectionG {
    /// G1.
    pub quorum: Vec<QuorumRow>,
    /// G2.
    pub split: Vec<SplitRuleRow>,
    /// G3.
    pub cac: Vec<CacQuorumRow>,
    /// G4.
    pub seat_rule: Vec<SeatRuleQuorumRow>,
}

/// One quorum option of G1.
#[derive(Debug, Clone)]
struct QuorumOption {
    layout_label: &'static str,
    label: String,
    fraction: f64,
    spec_default: bool,
    layout: QuorumLayout,
}

fn options(config: &Config) -> Result<Vec<QuorumOption>> {
    let grid = &config.analytic.quorum_tradeoff;
    let spec = KwcSpec::forty_node(config);
    let (n1, n2) = (spec.leader_seats(), spec.subordinate_seats());
    let pool_default = spec.unregistered_min;
    let registered_default = (spec.leader_min, spec.subordinate_min);
    let mut options = Vec::new();
    for q in &grid.quorum_fractions {
        let layout = QuorumLayout::pool(n1 + n2, q)?;
        options.push(QuorumOption {
            layout_label: POOL_LAYOUT,
            label: fraction_label(q),
            fraction: q.to_f64().unwrap_or(f64::NAN),
            spec_default: matches!(layout, QuorumLayout::Pool { quorum, .. } if quorum == pool_default),
            layout,
        });
    }
    let mut default_seen = false;
    for q in &grid.quorum_fractions {
        let layout = QuorumLayout::two_group(n1, n2, q)?;
        let is_default = matches!(
            layout,
            QuorumLayout::TwoGroup { leader_quorum, subordinate_quorum, .. }
                if (leader_quorum, subordinate_quorum) == registered_default
        );
        default_seen |= is_default;
        let mut label = fraction_label(q);
        if *q == grid.decision_quorum && !is_default {
            label.push_str(" rounded up per group (comparison)");
        }
        options.push(QuorumOption {
            layout_label: REGISTERED_LAYOUT,
            label,
            fraction: q.to_f64().unwrap_or(f64::NAN),
            spec_default: is_default,
            layout,
        });
    }
    if !default_seen {
        options.push(QuorumOption {
            layout_label: REGISTERED_LAYOUT,
            label: format!(
                "SPEC default {} + {}",
                registered_default.0, registered_default.1
            ),
            fraction: (registered_default.0 + registered_default.1) as f64 / (n1 + n2) as f64,
            spec_default: true,
            layout: QuorumLayout::TwoGroup {
                leader_seats: n1,
                leader_quorum: registered_default.0,
                subordinate_seats: n2,
                subordinate_quorum: registered_default.1,
            },
        });
    }
    // Order each layout's options by quorum fraction, so tables read from low to high.
    options.sort_by(|a, b| {
        (a.layout_label != POOL_LAYOUT)
            .cmp(&(b.layout_label != POOL_LAYOUT))
            .then(a.fraction.total_cmp(&b.fraction))
    });
    Ok(options)
}

/// Entry rates of the three harms for one quorum option.
fn harm_entry_rates(
    layout: &QuorumLayout,
    seats: &BinomialSeats,
    profile: &RelinkProfile,
) -> Result<Vec<EntryRates>> {
    HARMS
        .iter()
        .map(|harm| {
            let inside = |x: u64, y: u64| layout.allows(*harm, x, y);
            entry_rates(seats, profile, &inside)
        })
        .collect()
}

/// Builds every section G table from the configuration.
pub fn section_g(config: &Config) -> Result<SectionG> {
    let grid = &config.analytic.quorum_tradeoff;
    let spec = KwcSpec::forty_node(config);
    let (n1, n2) = (spec.leader_seats(), spec.subordinate_seats());
    let options = options(config)?;
    let rates = spec.composition_rates();
    let profile = relink_profile(&spec.ring_offsets);
    let models = absence_models(config);
    let rules = seat_rules(config);
    let pool_shape = QuorumLayout::Pool {
        seats: n1 + n2,
        quorum: n1 + n2,
    };
    let two_group_shape = QuorumLayout::TwoGroup {
        leader_seats: n1,
        leader_quorum: n1,
        subordinate_seats: n2,
        subordinate_quorum: n2,
    };
    let decision = QuorumLayout::pool(n1 + n2, &grid.decision_quorum)?;
    let mut tables = SectionG::default();
    for p_f in &grid.attacker_fractions {
        let p = decimal(*p_f)?;
        let binomial = SeatModel::Binomial(p.clone());
        let pool_binomial = Seats::new(&pool_shape, &binomial)?;
        let two_binomial = Seats::new(&two_group_shape, &binomial)?;
        let seats = BinomialSeats::new(n1, n2, spec.wc_size, &p)?;
        let entries: Vec<Vec<EntryRates>> = options
            .iter()
            .map(|o| harm_entry_rates(&o.layout, &seats, &profile))
            .collect::<Result<_>>()?;
        for &kwcs in &grid.kwc_counts {
            let population = spec.wc_size * kwcs;
            let model = SeatModel::Hypergeometric {
                population,
                attackers: attacker_ids(&p, population),
            };
            let pool = Seats::new(&pool_shape, &model)?;
            let two = Seats::new(&two_group_shape, &model)?;
            let inputs = HorizonInputs::from_config(config, kwcs, 0.0, 0.0);
            let compositions = composition_count(&inputs, &rates);
            for (option, harm_entries) in options.iter().zip(&entries) {
                let (exact, approximate) = match option.layout {
                    QuorumLayout::Pool { .. } => (&pool, &pool_binomial),
                    QuorumLayout::TwoGroup { .. } => (&two, &two_binomial),
                };
                let probabilities: Vec<Q> = HARMS
                    .iter()
                    .map(|h| exact.probability(&option.layout, *h))
                    .collect();
                let binomials: Vec<Q> = HARMS
                    .iter()
                    .map(|h| approximate.probability(&option.layout, *h))
                    .collect();
                let binomial_f64: Vec<f64> = binomials.iter().map(to_f64).collect();
                let expected = |q: &Q| scientific(&(q * integer(kwcs)), 6);
                let episodes: Vec<f64> = harm_entries
                    .iter()
                    .map(|e| episode_count(&inputs, &rates, e))
                    .collect();
                tables.quorum.push(QuorumRow {
                    layout: option.layout_label,
                    quorum: option.label.clone(),
                    quorum_fraction: option.fraction,
                    spec_default: option.spec_default,
                    approvals: option.layout.approvals_label(),
                    seats_to_stall: option.layout.seats_label(Harm::Stall),
                    seats_to_sign: option.layout.seats_label(Harm::Sign),
                    seats_to_conflict: option.layout.seats_label(Harm::Conflict),
                    attacker_fraction: *p_f,
                    kwcs,
                    p_stall: scientific(&probabilities[0], 6),
                    log10_p_stall: log10(&probabilities[0]).unwrap_or(f64::NEG_INFINITY),
                    p_sign: scientific(&probabilities[1], 6),
                    log10_p_sign: log10(&probabilities[1]).unwrap_or(f64::NEG_INFINITY),
                    p_conflict: scientific(&probabilities[2], 6),
                    log10_p_conflict: log10(&probabilities[2]).unwrap_or(f64::NEG_INFINITY),
                    expected_kwcs_stall: expected(&probabilities[0]),
                    expected_kwcs_sign: expected(&probabilities[1]),
                    expected_kwcs_conflict: expected(&probabilities[2]),
                    compositions_over_horizon: compositions,
                    p_stall_binomial: scientific(&binomials[0], 6),
                    p_sign_binomial: scientific(&binomials[1], 6),
                    p_conflict_binomial: scientific(&binomials[2], 6),
                    expected_episodes_stall: episodes[0],
                    expected_episodes_sign: episodes[1],
                    expected_episodes_conflict: episodes[2],
                    expected_compositions_stall: compositions * binomial_f64[0],
                    expected_compositions_sign: compositions * binomial_f64[1],
                    expected_compositions_conflict: compositions * binomial_f64[2],
                });
                for duration in &models {
                    for &c in &config.analytic.absence.absences_per_id_per_year {
                        for rule in &rules {
                            let vacating = c * rule.vacating_share(duration);
                            let inputs = HorizonInputs::from_config(config, kwcs, 0.0, vacating);
                            let compositions = composition_count(&inputs, &rates);
                            let episodes: Vec<f64> = harm_entries
                                .iter()
                                .map(|e| episode_count(&inputs, &rates, e))
                                .collect();
                            tables.seat_rule.push(SeatRuleQuorumRow {
                                layout: option.layout_label,
                                quorum: option.label.clone(),
                                spec_default: option.spec_default,
                                approvals: option.layout.approvals_label(),
                                attacker_fraction: *p_f,
                                kwcs,
                                duration_model: duration.label(),
                                absences_per_id_per_year: c,
                                seat_rule: rule.label(),
                                long_absence_days: rule.long_absence_days(),
                                long_absence_blocks: rule
                                    .long_absence_days()
                                    .map(|d| days_in_blocks(config, d)),
                                compositions,
                                expected_episodes_stall: episodes[0],
                                expected_episodes_sign: episodes[1],
                                expected_episodes_conflict: episodes[2],
                                expected_compositions_stall: compositions * binomial_f64[0],
                                expected_compositions_sign: compositions * binomial_f64[1],
                                expected_compositions_conflict: compositions * binomial_f64[2],
                            });
                        }
                    }
                }
            }
            for q in &grid.powit_quorum_fractions {
                let powit_pool = QuorumLayout::pool(n1 + n2, q)?;
                let powit_two = QuorumLayout::two_group(n1, n2, q)?;
                let s = |seats: &Seats, layout: &QuorumLayout, harm| {
                    scientific(&seats.probability(layout, harm), 6)
                };
                tables.split.push(SplitRuleRow {
                    powit_quorum: fraction_label(q),
                    powit_quorum_fraction: q.to_f64().unwrap_or(f64::NAN),
                    attacker_fraction: *p_f,
                    kwcs,
                    powit_pool_approvals: powit_pool.approvals_label(),
                    powit_pool_p_stall: s(&pool, &powit_pool, Harm::Stall),
                    powit_pool_p_sign: s(&pool, &powit_pool, Harm::Sign),
                    powit_registered_approvals: powit_two.approvals_label(),
                    powit_registered_p_stall: s(&two, &powit_two, Harm::Stall),
                    powit_registered_p_sign: s(&two, &powit_two, Harm::Sign),
                    decision_approvals: decision.approvals_label(),
                    decision_p_stall: s(&pool, &decision, Harm::Stall),
                    decision_p_sign: s(&pool, &decision, Harm::Sign),
                    decision_p_conflict: s(&pool, &decision, Harm::Conflict),
                });
            }
        }
    }
    tables.cac = cac_rows(config)?;
    Ok(tables)
}

fn cac_rows(config: &Config) -> Result<Vec<CacQuorumRow>> {
    let grid = &config.analytic.quorum_tradeoff;
    let members = u64::from(config.cac.size.value);
    let active = config.analytic.cac.active_population;
    let spec_default = config.cac.approval_threshold.value;
    let mut rows = Vec::new();
    for p_f in &grid.attacker_fractions {
        let model = CommitteeModel::LotterySpread {
            population: active,
            attackers: attacker_ids(&decimal(*p_f)?, active),
        };
        let distribution = seat_distribution(members, &model)?;
        for q in &grid.cac_quorum_fractions {
            let layout = QuorumLayout::pool(members, q)?;
            let QuorumLayout::Pool { quorum, .. } = layout else {
                continue;
            };
            let probability = |harm| distribution.probability_where(|a| layout.allows(harm, a, 0));
            let (stall, sign, conflict) = (
                probability(Harm::Stall),
                probability(Harm::Sign),
                probability(Harm::Conflict),
            );
            rows.push(CacQuorumRow {
                quorum: fraction_label(q),
                quorum_fraction: q.to_f64().unwrap_or(f64::NAN),
                spec_default: *q == spec_default,
                committee_size: members,
                approvals: quorum,
                seats_to_stall: stall_seats(members, quorum),
                seats_to_sign: quorum,
                seats_to_conflict: conflict_seats(members, quorum),
                attacker_fraction: *p_f,
                active_ids: active,
                p_stall: scientific(&stall, 6),
                log10_p_stall: log10(&stall).unwrap_or(f64::NEG_INFINITY),
                p_sign: scientific(&sign, 6),
                log10_p_sign: log10(&sign).unwrap_or(f64::NEG_INFINITY),
                p_conflict: scientific(&conflict, 6),
                log10_p_conflict: log10(&conflict).unwrap_or(f64::NEG_INFINITY),
            });
        }
    }
    Ok(rows)
}

// ----------------------------------------------------------------------------- checks

/// True when honest members (`honest`) can be split between two conflicting proposals so both
/// reach `quorum` signatures with the attacker's `attackers` seats signing both. Found by
/// trying every assignment of each honest member to proposal A, proposal B or neither.
fn conflict_by_enumeration(attackers: u64, honest: u64, quorum: u64) -> bool {
    let assignments = 3u64.pow(honest as u32);
    (0..assignments).any(|mut code| {
        let (mut a, mut b) = (attackers, attackers);
        for _ in 0..honest {
            match code % 3 {
                0 => a += 1,
                1 => b += 1,
                _ => {}
            }
            code /= 3;
        }
        a >= quorum && b >= quorum
    })
}

fn exhaustive_pool_check() -> Check {
    let mut failures = 0;
    let mut rows = 0;
    for seats in 1..=10u64 {
        for quorum in seats / 2 + 1..=seats {
            let layout = QuorumLayout::Pool { seats, quorum };
            for attackers in 0..=seats {
                rows += 1;
                let brute = conflict_by_enumeration(attackers, seats - attackers, quorum);
                failures += u64::from(brute != layout.allows(Harm::Conflict, attackers, 0));
            }
        }
    }
    Check::all_rows(
        "G",
        "G-conflict-exhaustive-pool",
        "pools of 1-10 members, every quorum above half, every attacker count: enumerating all splits of honest signers agrees with the condition a >= 2k - n",
        failures,
        rows,
    )
}

fn exhaustive_two_group_check() -> Check {
    let mut failures = 0;
    let mut rows = 0;
    for (n1, n2) in [(3u64, 5u64), (4, 6)] {
        for k1 in n1 / 2 + 1..=n1 {
            for k2 in n2 / 2 + 1..=n2 {
                let layout = QuorumLayout::TwoGroup {
                    leader_seats: n1,
                    leader_quorum: k1,
                    subordinate_seats: n2,
                    subordinate_quorum: k2,
                };
                for l in 0..=n1 {
                    for s in 0..=n2 {
                        rows += 1;
                        // Both approvals need both group quorums; the honest members of each
                        // group are split independently.
                        let brute = conflict_by_enumeration(l, n1 - l, k1)
                            && conflict_by_enumeration(s, n2 - s, k2);
                        failures += u64::from(brute != layout.allows(Harm::Conflict, l, s));
                    }
                }
            }
        }
    }
    Check::all_rows(
        "G",
        "G-conflict-exhaustive-two-group",
        "two-group layouts (3+5, 4+6), every per-group quorum above half: enumeration agrees with L >= 2k1 - n1 and S >= 2k2 - n2",
        failures,
        rows,
    )
}

fn reproduces_section_b_check(config: &Config) -> Result<Check> {
    let grid = &config.analytic.quorum_tradeoff;
    let spec = KwcSpec::forty_node(config);
    let (n1, n2) = (spec.leader_seats(), spec.subordinate_seats());
    let pool = QuorumLayout::Pool {
        seats: n1 + n2,
        quorum: spec.unregistered_min,
    };
    let registered = QuorumLayout::TwoGroup {
        leader_seats: n1,
        leader_quorum: spec.leader_min,
        subordinate_seats: n2,
        subordinate_quorum: spec.subordinate_min,
    };
    let mut failures = 0;
    let mut rows = 0;
    for p_f in &grid.attacker_fractions {
        let p = decimal(*p_f)?;
        for &kwcs in &grid.kwc_counts {
            let population = spec.wc_size * kwcs;
            let model = SeatModel::Hypergeometric {
                population,
                attackers: attacker_ids(&p, population),
            };
            for (layout, kind) in [
                (pool, MinerKind::Unregistered),
                (registered, MinerKind::Registered),
            ] {
                let seats = Seats::new(&layout, &model)?;
                for (harm, state) in [(Harm::Stall, KwcState::Block), (Harm::Sign, KwcState::Sign)]
                {
                    rows += 1;
                    let section_b = state_probability(&spec, kind, state, &model)?;
                    failures += u64::from(seats.probability(&layout, harm) != section_b);
                }
            }
        }
    }
    Ok(Check::all_rows(
        "G",
        "G-reproduces-section-B",
        "SPEC default quorums (27 of 40; 7 + 21): section G stall and sign probabilities equal section B block and sign exactly",
        failures,
        rows,
    ))
}

fn reproduces_section_c_check(g: &SectionG, c: &crate::cac::SectionC) -> Check {
    let primary = CommitteeModel::LotterySpread {
        population: 1,
        attackers: 0,
    }
    .label();
    let mut failures = 0;
    let mut rows = 0;
    for row in g.cac.iter().filter(|r| r.spec_default) {
        let Some(odds) = c.odds.iter().find(|o| {
            o.model == primary
                && o.committee_size == row.committee_size
                && o.attacker_fraction == row.attacker_fraction
        }) else {
            continue;
        };
        rows += 1;
        failures += u64::from(
            odds.p_stall != row.p_stall
                || odds.p_capture != row.p_sign
                || odds.stall_seats != row.seats_to_stall
                || odds.approvals_needed != row.approvals,
        );
    }
    Check::all_rows(
        "G",
        "G-reproduces-section-C",
        "committee at the SPEC two-thirds quorum: section G stall and approve-alone probabilities equal section C (lottery) exactly, where the grids overlap",
        failures,
        rows,
    )
}

fn log_space_check(config: &Config) -> Result<Check> {
    let grid = &config.analytic.quorum_tradeoff;
    let spec = KwcSpec::forty_node(config);
    let options = options(config)?;
    let mut failures = 0;
    let mut rows = 0;
    for p_f in &grid.attacker_fractions {
        let p = decimal(*p_f)?;
        for &kwcs in &grid.kwc_counts {
            let population = spec.wc_size * kwcs;
            let models = [
                SeatModel::Binomial(p.clone()),
                SeatModel::Hypergeometric {
                    population,
                    attackers: attacker_ids(&p, population),
                },
            ];
            for model in &models {
                for option in &options {
                    let seats = Seats::new(&option.layout, model)?;
                    for harm in HARMS {
                        rows += 1;
                        let exact = log10(&seats.probability(&option.layout, harm))
                            .unwrap_or(f64::NEG_INFINITY);
                        let reference = log10_probability_logspace(&option.layout, harm, model);
                        if (exact - reference).abs() > 1e-9 {
                            failures += 1;
                        }
                    }
                }
            }
        }
    }
    Ok(Check::all_rows(
        "G",
        "G-log-space",
        "exact rational probabilities agree with an independent log-space f64 computation within 1e-9 in log10",
        failures,
        rows,
    ))
}

fn monotonicity_check(g: &SectionG) -> Check {
    let mut failures = 0;
    let mut series = 0;
    let mut groups: Vec<(&str, u64, u64)> = Vec::new();
    for row in &g.quorum {
        let key = (row.layout, row.attacker_fraction.to_bits(), row.kwcs);
        if !groups.contains(&key) {
            groups.push(key);
        }
    }
    for (layout, p_bits, kwcs) in groups {
        series += 1;
        let mut rows: Vec<&QuorumRow> = g
            .quorum
            .iter()
            .filter(|r| {
                r.layout == layout && r.attacker_fraction.to_bits() == p_bits && r.kwcs == kwcs
            })
            .collect();
        rows.sort_by(|a, b| a.quorum_fraction.total_cmp(&b.quorum_fraction));
        let tolerance = 1e-12;
        let broken = rows.windows(2).any(|w| {
            w[1].log10_p_stall < w[0].log10_p_stall - tolerance
                || w[1].log10_p_sign > w[0].log10_p_sign + tolerance
                || w[1].log10_p_conflict > w[0].log10_p_conflict + tolerance
        });
        failures += u64::from(broken);
    }
    Check::all_rows(
        "G",
        "G-monotone-in-quorum",
        "as the quorum rises, P(stall) never falls and P(sign) and P(conflict) never rise, for every layout, p and network size",
        failures,
        series,
    )
}

fn episode_bounds_check(g: &SectionG) -> Check {
    // Episodes count the initial KWCs in the state plus entries, and an entry needs a changed
    // composition, so W0·q <= episodes <= compositions·q for every harm.
    let mut failures = 0;
    let mut rows = 0;
    let mut test = |kwcs: u64, compositions: f64, upper: [f64; 3], episodes: [f64; 3]| {
        for (u, e) in upper.iter().zip(episodes) {
            rows += 1;
            let q = if compositions > 0.0 {
                u / compositions
            } else {
                0.0
            };
            let lower = kwcs as f64 * q;
            failures += u64::from(e < lower * (1.0 - 1e-12) || e > u * (1.0 + 1e-12));
        }
    };
    for r in &g.quorum {
        test(
            r.kwcs,
            r.compositions_over_horizon,
            [
                r.expected_compositions_stall,
                r.expected_compositions_sign,
                r.expected_compositions_conflict,
            ],
            [
                r.expected_episodes_stall,
                r.expected_episodes_sign,
                r.expected_episodes_conflict,
            ],
        );
    }
    for r in &g.seat_rule {
        test(
            r.kwcs,
            r.compositions,
            [
                r.expected_compositions_stall,
                r.expected_compositions_sign,
                r.expected_compositions_conflict,
            ],
            [
                r.expected_episodes_stall,
                r.expected_episodes_sign,
                r.expected_episodes_conflict,
            ],
        );
    }
    Check::all_rows(
        "G",
        "G-episodes-bounds",
        "every G1/G4 row and harm: initial KWCs × q <= distinct episodes <= compositions × q",
        failures,
        rows,
    )
}

fn kind_of(layout: &str) -> &'static str {
    if layout == POOL_LAYOUT {
        MinerKind::Unregistered.label()
    } else {
        MinerKind::Registered.label()
    }
}

fn episodes_reproduce_section_b_check(g: &SectionG, b: &SectionB) -> Check {
    let close = |x: f64, y: f64| (x - y).abs() <= 1e-12 * x.abs().max(y.abs());
    let mut failures = 0;
    let mut rows = 0;
    for r in g.quorum.iter().filter(|r| r.spec_default) {
        let Some(row) = b.compositions.iter().find(|o| {
            o.miner_kind == kind_of(r.layout)
                && o.attacker_fraction == r.attacker_fraction
                && o.initial_kwcs == r.kwcs
                && o.ban_rate_per_year == 0.0
        }) else {
            continue;
        };
        rows += 1;
        failures += u64::from(
            !close(r.expected_episodes_sign, row.expected_sign_episodes)
                || !close(r.compositions_over_horizon, row.compositions),
        );
    }
    for r in g.seat_rule.iter().filter(|r| r.spec_default) {
        let Some(row) = b.seat_rule.iter().find(|o| {
            o.miner_kind == kind_of(r.layout)
                && o.attacker_fraction == r.attacker_fraction
                && o.initial_kwcs == r.kwcs
                && o.duration_model == r.duration_model
                && o.absences_per_id_per_year == r.absences_per_id_per_year
                && o.seat_rule == r.seat_rule
        }) else {
            continue;
        };
        rows += 1;
        failures += u64::from(
            !close(r.expected_episodes_sign, row.expected_sign_episodes)
                || !close(r.compositions, row.compositions),
        );
    }
    Check::all_rows(
        "G",
        "G-episodes-reproduce-B",
        "SPEC default quorums: G1 and G4 sign episodes and compositions equal B4 and B5 within 1e-12 relative, where the grids overlap",
        failures,
        rows,
    )
}

/// Section G cross-checks.
pub fn checks(
    config: &Config,
    g: &SectionG,
    b: &SectionB,
    c: &crate::cac::SectionC,
) -> Result<Vec<Check>> {
    Ok(vec![
        exhaustive_pool_check(),
        exhaustive_two_group_check(),
        reproduces_section_b_check(config)?,
        reproduces_section_c_check(g, c),
        log_space_check(config)?,
        monotonicity_check(g),
        episode_bounds_check(g),
        episodes_reproduce_section_b_check(g, b),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exact::ratio;

    fn pool(q: (u64, u64)) -> QuorumLayout {
        QuorumLayout::pool(40, &Fraction::new(q.0, q.1)).unwrap()
    }

    fn registered(q: (u64, u64)) -> QuorumLayout {
        QuorumLayout::two_group(10, 30, &Fraction::new(q.0, q.1)).unwrap()
    }

    #[test]
    fn pool_thresholds_match_the_plan_preview() {
        // (q, quorum, stall seats, conflict seats), computed by hand.
        for (q, k, stall, conflict) in [
            ((51, 100), 21, 20, 2),
            ((55, 100), 22, 19, 4),
            ((60, 100), 24, 17, 8),
            ((2, 3), 27, 14, 14),
            ((75, 100), 30, 11, 20),
        ] {
            let layout = pool(q);
            assert_eq!(
                layout,
                QuorumLayout::Pool {
                    seats: 40,
                    quorum: k
                }
            );
            assert_eq!(layout.seats_label(Harm::Stall), format!("≥ {stall}"));
            assert_eq!(layout.seats_label(Harm::Conflict), format!("≥ {conflict}"));
        }
    }

    #[test]
    fn registered_thresholds_match_the_plan_preview() {
        let layout = registered((51, 100));
        assert_eq!(layout.approvals_label(), "6 of 10 and 16 of 30");
        assert_eq!(
            layout.seats_label(Harm::Stall),
            "leader ≥ 5 or subordinates ≥ 15"
        );
        assert_eq!(
            layout.seats_label(Harm::Conflict),
            "leader ≥ 2 and subordinates ≥ 2"
        );
        assert_eq!(registered((2, 3)).approvals_label(), "7 of 10 and 20 of 30");
    }

    #[test]
    fn quorums_at_or_below_half_are_rejected() {
        assert!(QuorumLayout::pool(40, &Fraction::new(1, 2)).is_err());
        assert!(QuorumLayout::two_group(10, 30, &Fraction::new(2, 5)).is_err());
    }

    #[test]
    fn conflict_at_051_with_ten_percent_attackers_is_about_92_percent() {
        // P(Bin(40, 0.1) >= 2) = 1 - 0.9^40 - 40·0.1·0.9^39.
        let seats = Seats::new(&pool((51, 100)), &SeatModel::Binomial(ratio(1, 10))).unwrap();
        let p = to_f64(&seats.probability(&pool((51, 100)), Harm::Conflict));
        let reference = 1.0 - 0.9f64.powi(40) - 4.0 * 0.9f64.powi(39);
        assert!((p - reference).abs() < 1e-12, "{p}");
        assert!((p - 0.92).abs() < 0.005);
    }

    #[test]
    fn registered_conflict_is_the_product_of_group_conditions_under_the_binomial() {
        let p = ratio(1, 10);
        let model = SeatModel::Binomial(p.clone());
        let layout = registered((51, 100));
        let joint = Seats::new(&layout, &model)
            .unwrap()
            .probability(&layout, Harm::Conflict);
        let leader = ExactDistribution::new(10, &model).unwrap().at_least(2);
        let subs = ExactDistribution::new(30, &model).unwrap().at_least(2);
        assert_eq!(joint, leader * subs);
        assert!((to_f64(&joint) - 0.215).abs() < 0.001);
    }

    #[test]
    fn enumeration_finds_conflicts_only_from_2k_minus_n_attackers() {
        // n = 5, k = 3 needs a >= 1; n = 8, k = 6 needs a >= 4.
        assert!(!conflict_by_enumeration(0, 5, 3));
        assert!(conflict_by_enumeration(1, 4, 3));
        assert!(!conflict_by_enumeration(3, 5, 6));
        assert!(conflict_by_enumeration(4, 4, 6));
    }

    #[test]
    fn fractions_are_labelled_as_written() {
        assert_eq!(fraction_label(&Fraction::new(51, 100)), "0.51");
        assert_eq!(fraction_label(&Fraction::new(60, 100)), "0.60");
        assert_eq!(fraction_label(&Fraction::new(2, 3)), "2/3");
    }

    #[test]
    fn section_g_tables_mark_the_spec_defaults() {
        let config = Config::default();
        let g = section_g(&config).unwrap();
        let grid = &config.analytic.quorum_tradeoff;
        let per_cell = grid.attacker_fractions.len() * grid.kwc_counts.len();
        assert_eq!(
            g.quorum.len(),
            per_cell * (2 * grid.quorum_fractions.len() + 1)
        );
        assert_eq!(g.split.len(), per_cell * grid.powit_quorum_fractions.len());
        // G4: every G1 row × duration models × absence rates × (v0.3 + five thresholds).
        let absences = config.analytic.absence.absences_per_id_per_year.len();
        assert_eq!(g.seat_rule.len(), g.quorum.len() * 2 * absences * 6);
        assert_eq!(
            g.cac.len(),
            grid.attacker_fractions.len() * grid.cac_quorum_fractions.len()
        );
        let defaults: Vec<_> = g
            .quorum
            .iter()
            .filter(|r| r.spec_default && r.attacker_fraction == 0.1 && r.kwcs == 100_000)
            .map(|r| (r.layout, r.approvals.clone()))
            .collect();
        assert_eq!(
            defaults,
            vec![
                (POOL_LAYOUT, "27 of 40".to_string()),
                (REGISTERED_LAYOUT, "7 of 10 and 21 of 30".to_string()),
            ]
        );
        let comparison = g
            .quorum
            .iter()
            .find(|r| r.layout == REGISTERED_LAYOUT && r.quorum.contains("comparison"))
            .unwrap();
        assert_eq!(comparison.approvals, "7 of 10 and 20 of 30");
    }

    #[test]
    fn committee_at_051_needs_only_twelve_seats_for_a_conflict() {
        let config = Config::default();
        let rows = cac_rows(&config).unwrap();
        let row = rows
            .iter()
            .find(|r| r.quorum == "0.51" && r.attacker_fraction == 0.05)
            .unwrap();
        assert_eq!(
            (row.approvals, row.seats_to_stall, row.seats_to_conflict),
            (306, 295, 12)
        );
        // Reference: 1 − Σ_{x<12} hypergeometric pmf, from Python's exact integer arithmetic.
        let p = libm::pow(10.0, row.log10_p_conflict);
        assert!((p - 0.999_953_736_469_328_4).abs() < 1e-9, "{p}");
    }

    #[test]
    fn default_episodes_match_the_plan_preview() {
        // Plan preview (independent Python computation): over 10 years from 100k KWCs at
        // p = 25%, 0.476 episodes (0.926 compositions) for 27 of 40 and 0.0263 (0.0489) for
        // 7 + 21.
        let config = Config::default();
        let g = section_g(&config).unwrap();
        let row = |layout: &str| {
            g.quorum
                .iter()
                .find(|r| {
                    r.layout == layout
                        && r.spec_default
                        && r.attacker_fraction == 0.25
                        && r.kwcs == 100_000
                })
                .unwrap()
        };
        let pool = row(POOL_LAYOUT);
        assert!((pool.expected_episodes_sign - 0.476).abs() < 0.0005);
        assert!((pool.expected_compositions_sign - 0.926).abs() < 0.0005);
        let registered = row(REGISTERED_LAYOUT);
        assert!((registered.expected_episodes_sign - 0.0263).abs() < 0.00005);
        assert!((registered.expected_compositions_sign - 0.0489).abs() < 0.00005);
    }

    #[test]
    fn all_section_g_checks_pass() {
        let mut config = Config::default();
        config.run.monte_carlo.partition_replicates = 600;
        let b = crate::witness::section_b(&config).unwrap();
        let g = section_g(&config).unwrap();
        let c = crate::cac::section_c(&config).unwrap();
        for check in checks(&config, &g, &b, &c).unwrap() {
            assert!(check.passed, "{check:?}");
        }
    }
}
