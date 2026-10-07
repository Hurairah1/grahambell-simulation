//! Section I — the KWC size trade-off (SPEC §2, §4.1–§4.2; SPEC §12 \[P\] larger KWCs).
//!
//! A KWC of `k` WCs of 10 members has `n = 10·k` members; here `k` runs from 3 to 10 (30 to
//! 100 members). This section maps what size buys and what it costs. It does not pick a size.
//!
//! # Quorums and rings
//!
//! Each size is evaluated under two single quorums over the whole KWC: two-thirds, `⌈2n/3⌉`
//! (27 of 40 at `k = 4`, the unregistered PoWit and decision quorum), and the split rule's PoWit
//! quorum `⌈0.51·n⌉` (SPEC §12 \[P\]). Each size uses a configured optimal Golomb ruler as its
//! ring; `k = 4` uses the protocol's ring {1, 4, 6}. The relink profile, and so the
//! compositions per insertion `k + (1 + d_max)/10`, follow from the ruler.
//!
//! # Tables
//!
//! - **I1, security**: P(stall), P(sign without honest members) and P(conflict) at a network of
//!   `W` KWCs (hypergeometric), and ten-year episode counts with compositions as the upper
//!   bound, from the same entry and relink machinery as sections B and G.
//! - **I2, liveness**: section H's minimum honest uptime for fewer than each target share of
//!   KWCs failing, with attacker members withholding.
//! - **I3, load**, under three capacity policies:
//!   - **A**: every WC hosts `capacity.miners_per_leader_wc` miners (250), so a node watches
//!     `250·k`;
//!   - **B**: a node watches as many miners as at the protocol size (250 × 4 = 1,000), so a WC
//!     hosts `1,000/k`;
//!   - **C** (the architect's rule): a WC hosts `⌈10 × (1 + spare target)⌉ = 14` registered
//!     miners, sized to its 10 registered IDs plus the +33% spare-capacity target, and `u`
//!     unregistered miners.
//!
//!   A and B use the SPEC §2 capacity mix (200 of 250 registered); C's mix is `14/(14 + u)`.
//!   Bandwidth uses about 295 bytes per exchange, registered miners every 1 s or 5 s and
//!   unregistered miners every 30 s (from the papers), without transport overhead.
//! - **Witness peer topology**, two options:
//!   1. persistent all-to-all among a member's `k` KWCs: `10·(1 + k(k − 1)) − 1` standing peer
//!      connections per node (129 at `k = 4`);
//!   2. the architect's design \[P\]: no persistent witness-to-witness connections; the miner
//!      relays routine messages, and members connect on demand through the global directory
//!      only for One Chance, decisions, proposer duties and catch-up. **I4** estimates those
//!      on-demand connections per node per hour (opened plus accepted): One Chance for every
//!      unannounced disappearance of a neighbour (all absences treated as unannounced, the
//!      worst case); `2(n − 1)/n` per decision in each of the node's `k` KWCs, for miner
//!      session changes and bans (the proposer contacts the other `n − 1` members; the
//!      asymmetry between master and subordinate-only proposers is averaged out); and the
//!      peer bootstrap count per return, at both ends.

use crate::allocation::{
    BinomialSeats, CompositionRates, EntryRates, HorizonInputs, composition_count, entry_rates,
    episode_count, relink_profile,
};
use crate::dist::SeatModel;
use crate::error::{Result, ensure};
use crate::exact::{Q, decimal, log10, ratio, scientific, to_f64};
use crate::quorum_feasibility::{
    fail_probability, fail_probability_mixture, minimum_online_fraction, status,
};
use crate::quorum_tradeoff::{HARMS, Harm, QuorumLayout, Seats, fraction_label};
use crate::validation::Check;
use crate::witness::{attacker_ids, golomb_ring, ring_violations};
use gb_config::Config;
use num_traits::{One, ToPrimitive};
use serde::Serialize;
use std::collections::BTreeSet;

/// Grid step of the minimum uptimes, as in section H: 10⁻⁴.
const GRID: u64 = 10_000;

/// One KWC size: `wcs` WCs of `wc_size` members on the ring with `offsets`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KwcSize {
    /// WCs per KWC, `k`.
    pub wcs: u64,
    /// Ring offsets of the subordinate WCs.
    pub offsets: Vec<u64>,
    /// Members per WC.
    pub wc_size: u64,
}

impl KwcSize {
    /// Members of a KWC, `n = wc_size·k`.
    pub fn members(&self) -> u64 {
        self.wcs * self.wc_size
    }

    /// Leader-WC seats.
    pub fn leader_seats(&self) -> u64 {
        self.wc_size
    }

    /// Subordinate seats.
    pub fn subordinate_seats(&self) -> u64 {
        self.wc_size * (self.wcs - 1)
    }

    /// Other members a node shares a KWC with: its `k` KWCs share only its own WC, so they
    /// cover `1 + k(k − 1)` WCs.
    pub fn neighbours(&self) -> u64 {
        self.wc_size * (1 + self.wcs * (self.wcs - 1)) - 1
    }

    /// Compositions per insertion and removal on this ring.
    pub fn rates(&self) -> CompositionRates {
        CompositionRates::new(self.wc_size, &self.offsets, &relink_profile(&self.offsets))
    }
}

/// The configured sizes, each with its ruler.
pub fn sizes(config: &Config) -> Vec<KwcSize> {
    let grid = &config.analytic.kwc_size;
    let wc_size = u64::from(config.witness.wc_size.value);
    grid.wcs_per_kwc
        .iter()
        .zip(&grid.ring_offsets)
        .map(|(wcs, offsets)| KwcSize {
            wcs: *wcs,
            offsets: offsets.clone(),
            wc_size,
        })
        .collect()
}

/// A capacity policy for section I's load table.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LoadPolicy {
    /// A: every WC hosts the SPEC capacity per leader WC.
    PerWc,
    /// B: every node watches as many miners as at the protocol size.
    PerNode,
    /// C: registered capacity sized to the WC's IDs plus the spare target, and `unregistered`
    /// unregistered miners.
    Architect {
        /// Unregistered miners per WC, `u`.
        unregistered: u64,
    },
}

/// Miners hosted by one WC under a policy.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WcLoad {
    /// Miners per WC (registered plus unregistered).
    pub miners: f64,
    /// Registered miners per WC.
    pub registered: f64,
}

/// Registered capacity per WC under policy C: `⌈wc_size × (1 + spare target)⌉`, exactly.
pub fn policy_c_registered(config: &Config) -> Result<u64> {
    let wc = u64::from(config.witness.wc_size.value);
    let target = decimal(config.capacity.spare_target_fraction.value)?;
    let exact = (Q::one() + target) * Q::from_integer(wc.into());
    exact
        .ceil()
        .to_integer()
        .to_u64()
        .ok_or_else(|| crate::AnalyticError::InvalidInput("spare capacity out of range".into()))
}

impl LoadPolicy {
    /// The configured policies: A, B, then C for every `u`.
    pub fn all(config: &Config) -> Vec<LoadPolicy> {
        let mut policies = vec![LoadPolicy::PerWc, LoadPolicy::PerNode];
        policies.extend(
            config
                .analytic
                .kwc_size
                .unregistered_per_wc_policy_c
                .iter()
                .map(|u| LoadPolicy::Architect { unregistered: *u }),
        );
        policies
    }

    /// Label used in tables.
    pub fn label(&self, config: &Config) -> Result<String> {
        let capacity = &config.capacity;
        Ok(match self {
            LoadPolicy::PerWc => {
                format!("A: {} miners per WC", capacity.miners_per_leader_wc.value)
            }
            LoadPolicy::PerNode => format!(
                "B: each node watches {} miners",
                grouped(protocol_node_load(config))
            ),
            LoadPolicy::Architect { unregistered } => format!(
                "C: {} registered + {unregistered} unregistered per WC",
                policy_c_registered(config)?
            ),
        })
    }

    /// Unregistered capacity `u` (policy C only).
    pub fn unregistered(&self) -> Option<u64> {
        match self {
            LoadPolicy::Architect { unregistered } => Some(*unregistered),
            _ => None,
        }
    }

    /// Miners one WC hosts at size `size`.
    pub fn wc_load(&self, config: &Config, size: &KwcSize) -> Result<WcLoad> {
        let capacity = &config.capacity;
        let total = f64::from(capacity.miners_per_leader_wc.value);
        let registered = f64::from(capacity.registered_per_leader_wc().unwrap_or(0));
        Ok(match self {
            LoadPolicy::PerWc => WcLoad {
                miners: total,
                registered,
            },
            LoadPolicy::PerNode => {
                let miners = protocol_node_load(config) as f64 / size.wcs as f64;
                WcLoad {
                    miners,
                    registered: miners * registered / total,
                }
            }
            LoadPolicy::Architect { unregistered } => {
                let registered = policy_c_registered(config)? as f64;
                WcLoad {
                    miners: registered + *unregistered as f64,
                    registered,
                }
            }
        })
    }
}

/// `n` with thousands separators, for example `1,000`.
fn grouped(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// Miners a node watches at the protocol size: capacity per WC × WCs per KWC.
pub fn protocol_node_load(config: &Config) -> u64 {
    u64::from(config.capacity.miners_per_leader_wc.value)
        * (1 + config.witness.ring_offsets.value.len() as u64)
}

// ----------------------------------------------------------------------------- tables

/// I1: security by KWC size.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SizeSecurityRow {
    /// WCs per KWC, k.
    pub wcs_per_kwc: u64,
    /// Members, n = 10·k.
    pub members: u64,
    /// Quorum option, "2/3" or "0.51".
    pub quorum: String,
    /// Signatures needed.
    pub approvals: String,
    /// Attacker seats that stall.
    pub seats_to_stall: String,
    /// Attacker seats that sign without honest members.
    pub seats_to_sign: String,
    /// Attacker seats for two conflicting approvals.
    pub seats_to_conflict: String,
    /// Attacker fraction p.
    pub attacker_fraction: f64,
    /// Network size, KWCs.
    pub kwcs: u64,
    /// P(stall), hypergeometric.
    pub p_stall: String,
    /// log10 P(stall).
    pub log10_p_stall: f64,
    /// P(sign without honest members), hypergeometric.
    pub p_sign: String,
    /// log10 P(sign).
    pub log10_p_sign: f64,
    /// P(two conflicting approvals), hypergeometric.
    pub p_conflict: String,
    /// log10 P(conflict).
    pub log10_p_conflict: f64,
    /// Compositions per insertion, k + (1 + d_max)/10.
    pub compositions_per_insertion: f64,
    /// KWC compositions over the horizon (no bans or absences).
    pub compositions: f64,
    /// Expected distinct episodes able to stall over the horizon (primary measure).
    pub expected_episodes_stall: f64,
    /// Expected distinct episodes able to sign without honest members.
    pub expected_episodes_sign: f64,
    /// Expected distinct episodes able to approve conflicting decisions.
    pub expected_episodes_conflict: f64,
    /// Expected compositions able to stall (upper bound, binomial).
    pub expected_compositions_stall: f64,
    /// Expected compositions able to sign without honest members (upper bound).
    pub expected_compositions_sign: f64,
    /// Expected compositions able to approve conflicting decisions (upper bound).
    pub expected_compositions_conflict: f64,
}

/// I2: minimum honest uptime by KWC size.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SizeLivenessRow {
    /// WCs per KWC, k.
    pub wcs_per_kwc: u64,
    /// Members.
    pub members: u64,
    /// Quorum option.
    pub quorum: String,
    /// Signatures needed.
    pub approvals: String,
    /// Attacker fraction p (its members withhold).
    pub attacker_fraction: f64,
    /// Target share of failing KWCs.
    pub failure_target: f64,
    /// Smallest f on a 10⁻⁴ grid with P(fail) below the target (empty when not reachable).
    pub minimum_online_fraction: Option<f64>,
    /// "reachable" or "not reachable".
    pub status: &'static str,
    /// P(fail) at f = 1 (the attacker's stall probability, binomial).
    pub p_fail_at_full_uptime: String,
}

/// I3: steady-state load per node and per miner.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SizeLoadRow {
    /// WCs per KWC, k.
    pub wcs_per_kwc: u64,
    /// Members (connections per miner).
    pub members: u64,
    /// Capacity policy.
    pub policy: String,
    /// Policy C: unregistered miners per WC, u.
    pub unregistered_per_wc: Option<u64>,
    /// Miners hosted per WC (as leader).
    pub miners_per_wc: f64,
    /// Registered share of those miners.
    pub registered_share: f64,
    /// Miners watched per node (= open miner connections and hashes per second per node).
    pub miners_watched_per_node: f64,
    /// Connections per miner (= KWC size).
    pub connections_per_miner: u64,
    /// Hash recomputations per second per node (one per watched miner).
    pub hashes_per_second_per_node: f64,
    /// Peer topology option 1: standing witness-peer connections per node.
    pub peer_connections_option_1: u64,
    /// Peer topology option 2 \[P\]: standing witness-peer connections per node.
    pub peer_connections_option_2: u64,
    /// Seconds between registered miners' exchanges.
    pub registered_cadence_s: f64,
    /// Steady-state bandwidth per node, bytes per second, each direction, without transport
    /// overhead.
    pub bandwidth_bytes_per_s: f64,
    /// Network miner capacity at the comparison network of W WCs.
    pub network_miner_capacity: f64,
    /// Network size of that capacity, WCs.
    pub wcs: u64,
    /// Registered witness capacity ÷ registered IDs (each WC holds 10 registered IDs).
    pub registered_capacity_per_registered_id: f64,
}

/// I4: on-demand witness connections per node per hour under peer topology option 2 \[P\].
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct OnDemandRow {
    /// WCs per KWC, k.
    pub wcs_per_kwc: u64,
    /// Members.
    pub members: u64,
    /// Capacity policy.
    pub policy: String,
    /// Policy C: unregistered miners per WC, u.
    pub unregistered_per_wc: Option<u64>,
    /// Miners hosted per WC.
    pub miners_per_wc: f64,
    /// Absences per member per year, all treated as unannounced (worst case).
    pub absences_per_id_per_year: f64,
    /// Miner session changes (starts plus ends) per miner per day.
    pub session_changes_per_miner_per_day: f64,
    /// Bans per registered ID per year.
    pub ban_rate_per_year: f64,
    /// Neighbours: members of the node's k KWCs other than itself.
    pub neighbours: u64,
    /// One Chance contacts per hour.
    pub one_chance_per_hour: f64,
    /// Connections for session decisions (MOBu/MOBr, offline requests) per hour.
    pub decisions_per_hour: f64,
    /// Connections for ban decisions per hour.
    pub bans_per_hour: f64,
    /// Catch-up connections after returns per hour.
    pub catch_up_per_hour: f64,
    /// Total on-demand connections per hour.
    pub total_per_hour: f64,
    /// For comparison: standing peer connections under option 1.
    pub standing_peers_option_1: u64,
}

/// All section I tables.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SectionI {
    /// I1.
    pub security: Vec<SizeSecurityRow>,
    /// I2.
    pub liveness: Vec<SizeLivenessRow>,
    /// I3.
    pub load: Vec<SizeLoadRow>,
    /// I4.
    pub on_demand: Vec<OnDemandRow>,
}

fn harm_entries(
    layout: &QuorumLayout,
    seats: &BinomialSeats,
    offsets: &[u64],
) -> Result<Vec<EntryRates>> {
    let profile = relink_profile(offsets);
    HARMS
        .iter()
        .map(|harm| {
            let inside = |x: u64, y: u64| layout.allows(*harm, x, y);
            entry_rates(seats, &profile, &inside)
        })
        .collect()
}

/// Builds every section I table from the configuration.
pub fn section_i(config: &Config) -> Result<SectionI> {
    let grid = &config.analytic.kwc_size;
    let kwcs = grid.comparison_kwcs;
    let mut tables = SectionI::default();
    for size in sizes(config) {
        let n = size.members();
        let rates = size.rates();
        let population = size.wc_size * kwcs;
        let inputs = HorizonInputs::from_config(config, kwcs, 0.0, 0.0);
        let compositions = composition_count(&inputs, &rates);
        for q in &grid.quorum_fractions {
            let layout = QuorumLayout::pool(n, q)?;
            for p_f in &grid.attacker_fractions {
                let p = decimal(*p_f)?;
                let model = SeatModel::Hypergeometric {
                    population,
                    attackers: attacker_ids(&p, population),
                };
                let exact = Seats::new(&layout, &model)?;
                let probabilities: Vec<Q> = HARMS
                    .iter()
                    .map(|h| exact.probability(&layout, *h))
                    .collect();
                let binomial = Seats::new(&layout, &SeatModel::Binomial(p.clone()))?;
                let q_binomial: Vec<f64> = HARMS
                    .iter()
                    .map(|h| to_f64(&binomial.probability(&layout, *h)))
                    .collect();
                let seats = BinomialSeats::new(
                    size.leader_seats(),
                    size.subordinate_seats(),
                    size.wc_size,
                    &p,
                )?;
                let episodes: Vec<f64> = harm_entries(&layout, &seats, &size.offsets)?
                    .iter()
                    .map(|e| episode_count(&inputs, &rates, e))
                    .collect();
                let log = |x: &Q| log10(x).unwrap_or(f64::NEG_INFINITY);
                tables.security.push(SizeSecurityRow {
                    wcs_per_kwc: size.wcs,
                    members: n,
                    quorum: fraction_label(q),
                    approvals: layout.approvals_label(),
                    seats_to_stall: layout.seats_label(Harm::Stall),
                    seats_to_sign: layout.seats_label(Harm::Sign),
                    seats_to_conflict: layout.seats_label(Harm::Conflict),
                    attacker_fraction: *p_f,
                    kwcs,
                    p_stall: scientific(&probabilities[0], 6),
                    log10_p_stall: log(&probabilities[0]),
                    p_sign: scientific(&probabilities[1], 6),
                    log10_p_sign: log(&probabilities[1]),
                    p_conflict: scientific(&probabilities[2], 6),
                    log10_p_conflict: log(&probabilities[2]),
                    compositions_per_insertion: rates.per_insertion,
                    compositions,
                    expected_episodes_stall: episodes[0],
                    expected_episodes_sign: episodes[1],
                    expected_episodes_conflict: episodes[2],
                    expected_compositions_stall: compositions * q_binomial[0],
                    expected_compositions_sign: compositions * q_binomial[1],
                    expected_compositions_conflict: compositions * q_binomial[2],
                });
            }
            for p_f in &grid.liveness_attacker_fractions {
                let p = decimal(*p_f)?;
                for target_f in &config.analytic.quorum_feasibility.failure_targets {
                    let minimum = minimum_online_fraction(&layout, &p, &decimal(*target_f)?)?;
                    let full = fail_probability(&layout, &(Q::one() - &p))?;
                    tables.liveness.push(SizeLivenessRow {
                        wcs_per_kwc: size.wcs,
                        members: n,
                        quorum: fraction_label(q),
                        approvals: layout.approvals_label(),
                        attacker_fraction: *p_f,
                        failure_target: *target_f,
                        minimum_online_fraction: minimum.map(|k| k as f64 / GRID as f64),
                        status: status(minimum.is_some()),
                        p_fail_at_full_uptime: scientific(&full, 6),
                    });
                }
            }
        }
        for policy in LoadPolicy::all(config) {
            let load = policy.wc_load(config, &size)?;
            let label = policy.label(config)?;
            let watched = load.miners * size.wcs as f64;
            let registered_share = load.registered / load.miners;
            for &cadence in &grid.registered_cadences_s {
                let per_miner = registered_share * grid.message_bytes / cadence
                    + (1.0 - registered_share) * grid.message_bytes / grid.unregistered_cadence_s;
                tables.load.push(SizeLoadRow {
                    wcs_per_kwc: size.wcs,
                    members: n,
                    policy: label.clone(),
                    unregistered_per_wc: policy.unregistered(),
                    miners_per_wc: load.miners,
                    registered_share,
                    miners_watched_per_node: watched,
                    connections_per_miner: n,
                    hashes_per_second_per_node: watched,
                    peer_connections_option_1: size.neighbours(),
                    peer_connections_option_2: 0,
                    registered_cadence_s: cadence,
                    bandwidth_bytes_per_s: watched * per_miner,
                    network_miner_capacity: load.miners * kwcs as f64,
                    wcs: kwcs,
                    registered_capacity_per_registered_id: load.registered / size.wc_size as f64,
                });
            }
            tables
                .on_demand
                .extend(on_demand_rows(config, &size, &label, policy, load));
        }
    }
    Ok(tables)
}

fn on_demand_rows(
    config: &Config,
    size: &KwcSize,
    label: &str,
    policy: LoadPolicy,
    load: WcLoad,
) -> Vec<OnDemandRow> {
    let grid = &config.analytic.kwc_size;
    let hours_per_year = config.model.seconds_per_year as f64 / 3_600.0;
    let n = size.members() as f64;
    let k = size.wcs as f64;
    let per_decision = 2.0 * (n - 1.0) / n;
    let bootstrap = f64::from(config.admission.peer_bootstrap_count.value);
    let mut rows = Vec::new();
    for &c in &config.analytic.absence.absences_per_id_per_year {
        for &changes in &grid.miner_session_changes_per_day {
            for &ban in &config.analytic.witness.ban_rates_per_year {
                let one_chance = c * size.neighbours() as f64 / hours_per_year;
                let decisions = k * load.miners * changes / 24.0 * per_decision;
                let bans = k * size.wc_size as f64 * ban / hours_per_year * per_decision;
                let catch_up = 2.0 * c * bootstrap / hours_per_year;
                rows.push(OnDemandRow {
                    wcs_per_kwc: size.wcs,
                    members: size.members(),
                    policy: label.to_string(),
                    unregistered_per_wc: policy.unregistered(),
                    miners_per_wc: load.miners,
                    absences_per_id_per_year: c,
                    session_changes_per_miner_per_day: changes,
                    ban_rate_per_year: ban,
                    neighbours: size.neighbours(),
                    one_chance_per_hour: one_chance,
                    decisions_per_hour: decisions,
                    bans_per_hour: bans,
                    catch_up_per_hour: catch_up,
                    total_per_hour: one_chance + decisions + bans + catch_up,
                    standing_peers_option_1: size.neighbours(),
                });
            }
        }
    }
    rows
}

// ----------------------------------------------------------------------------- checks

/// Section I cross-checks.
pub fn checks(
    config: &Config,
    tables: &SectionI,
    g: &crate::quorum_tradeoff::SectionG,
    h: &crate::quorum_feasibility::SectionH,
) -> Result<Vec<Check>> {
    Ok(vec![
        ring_check(config),
        relink_check(config),
        neighbour_check(config),
        reproduces_section_g_check(config, tables, g),
        reproduces_section_h_check(config, tables, h),
        bracket_check(config)?,
        episode_bounds_check(tables),
        load_arithmetic_check(config, tables),
        spare_capacity_check(config, tables)?,
    ])
}

fn ring_check(config: &Config) -> Check {
    let mut violations = 0;
    let mut rings = 0;
    for size in sizes(config) {
        let largest = size.offsets.iter().copied().max().unwrap_or(0);
        for extra in [0u64, 1, 13, 101, 500] {
            rings += 1;
            violations += ring_violations(&golomb_ring(2 * largest + 1 + extra, &size.offsets));
        }
    }
    Check::all_rows(
        "I",
        "I-golomb-rings",
        "every configured ruler: each WC leads one KWC, is subordinate in exactly k - 1, no mutual pairs, KWCs share at most one WC, at five ring sizes",
        violations,
        rings,
    )
}

fn relink_check(config: &Config) -> Check {
    // Exactly d_max KWCs relink when the ring changes by one WC, and the replaced subordinate
    // WCs sum to the offsets; so compositions per insertion are k + (1 + d_max)/10.
    let mut failures = 0;
    let mut rows = 0;
    for size in sizes(config) {
        let profile = relink_profile(&size.offsets);
        let largest = size.offsets.iter().copied().max().unwrap_or(0);
        let total: u64 = size.offsets.iter().sum();
        for pairs in [&profile.growth, &profile.shrink] {
            rows += 1;
            let kwcs: u64 = pairs.iter().map(|(_, c)| c).sum();
            let replaced: u64 = pairs.iter().map(|(j, c)| j * c).sum();
            failures += u64::from(kwcs != largest || replaced != total);
        }
        rows += 1;
        let expected = size.wcs as f64 + (1 + largest) as f64 / size.wc_size as f64;
        failures += u64::from((size.rates().per_insertion - expected).abs() > 1e-12);
    }
    Check::all_rows(
        "I",
        "I-relink-profile",
        "every ruler: d_max KWCs relink on growth and shrink, replaced subordinate WCs sum to the offsets, and compositions per insertion are k + (1 + d_max)/10",
        failures,
        rows,
    )
}

fn neighbour_check(config: &Config) -> Check {
    // Counts, on an actual ring, the distinct WCs in the KWCs that contain one WC.
    let mut failures = 0;
    let mut rows = 0;
    for size in sizes(config) {
        rows += 1;
        let largest = size.offsets.iter().copied().max().unwrap_or(0);
        let wcs = 4 * largest + 13;
        let ring = golomb_ring(wcs, &size.offsets);
        let target = 2 * largest + 1;
        let covered: BTreeSet<u64> = ring
            .iter()
            .filter(|kwc| kwc.contains(&target))
            .flat_map(|kwc| kwc.iter().copied())
            .collect();
        let members = covered.len() as u64 * size.wc_size - 1;
        failures += u64::from(members != size.neighbours());
    }
    Check::all_rows(
        "I",
        "I-neighbours",
        "members sharing a KWC with a node, counted on the ring, equal 10(1 + k(k - 1)) - 1 for every size",
        failures,
        rows,
    )
}

fn reproduces_section_g_check(
    config: &Config,
    tables: &SectionI,
    g: &crate::quorum_tradeoff::SectionG,
) -> Check {
    let close = |x: f64, y: f64| (x - y).abs() <= 1e-12 * x.abs().max(y.abs());
    let protocol = 1 + config.witness.ring_offsets.value.len() as u64;
    let mut failures = 0;
    let mut rows = 0;
    for r in tables.security.iter().filter(|r| r.wcs_per_kwc == protocol) {
        let Some(o) = g.quorum.iter().find(|o| {
            o.layout == crate::quorum_tradeoff::POOL_LAYOUT
                && o.quorum == r.quorum
                && o.attacker_fraction == r.attacker_fraction
                && o.kwcs == r.kwcs
        }) else {
            continue;
        };
        rows += 1;
        failures += u64::from(
            o.p_stall != r.p_stall
                || o.p_sign != r.p_sign
                || o.p_conflict != r.p_conflict
                || !close(o.expected_episodes_stall, r.expected_episodes_stall)
                || !close(o.expected_episodes_sign, r.expected_episodes_sign)
                || !close(o.expected_episodes_conflict, r.expected_episodes_conflict)
                || !close(o.compositions_over_horizon, r.compositions),
        );
    }
    Check::all_rows(
        "I",
        "I-reproduces-section-G",
        "protocol size (k = 4): I1 probabilities equal section G's pool rows exactly and episodes and compositions within 1e-12, for both quorums, where the grids overlap",
        failures,
        rows,
    )
}

fn reproduces_section_h_check(
    config: &Config,
    tables: &SectionI,
    h: &crate::quorum_feasibility::SectionH,
) -> Check {
    let protocol = 1 + config.witness.ring_offsets.value.len() as u64;
    let mut failures = 0;
    let mut rows = 0;
    for r in tables.liveness.iter().filter(|r| r.wcs_per_kwc == protocol) {
        let Some(o) = h.minimum_uptime.iter().find(|o| {
            o.layout == crate::quorum_feasibility::UNREGISTERED
                && o.approvals == r.approvals
                && o.attacker_fraction == r.attacker_fraction
                && o.failure_target == r.failure_target
        }) else {
            continue;
        };
        rows += 1;
        failures += u64::from(
            o.minimum_online_fraction != r.minimum_online_fraction
                || o.p_fail_at_full_uptime != r.p_fail_at_full_uptime,
        );
    }
    Check::all_rows(
        "I",
        "I-reproduces-section-H",
        "protocol size (k = 4) at two-thirds: I2 minimum uptimes equal section H's unregistered rows exactly",
        failures,
        rows,
    )
}

fn bracket_check(config: &Config) -> Result<Check> {
    let grid = &config.analytic.kwc_size;
    let mut failures = 0;
    let mut rows = 0;
    for size in sizes(config) {
        for q in &grid.quorum_fractions {
            let layout = QuorumLayout::pool(size.members(), q)?;
            for p_f in &grid.liveness_attacker_fractions {
                let p = decimal(*p_f)?;
                let attacker = SeatModel::Binomial(p.clone());
                for target_f in &config.analytic.quorum_feasibility.failure_targets {
                    rows += 1;
                    let target = decimal(*target_f)?;
                    let fails =
                        |k: u64| fail_probability_mixture(&layout, &attacker, &ratio(k, GRID));
                    let ok = match minimum_online_fraction(&layout, &p, &target)? {
                        Some(k) => fails(k)? < target && fails(k - 1)? >= target,
                        None => fails(GRID)? >= target,
                    };
                    failures += u64::from(!ok);
                }
            }
        }
    }
    Ok(Check::all_rows(
        "I",
        "I-minimum-bracket",
        "every I2 minimum: P(fail) < target at f_min and >= target one 1e-4 step below (or at f = 1 when not reachable), recomputed by the mixture sum",
        failures,
        rows,
    ))
}

fn episode_bounds_check(tables: &SectionI) -> Check {
    let mut failures = 0;
    let mut rows = 0;
    for r in &tables.security {
        for (upper, episodes) in [
            (r.expected_compositions_stall, r.expected_episodes_stall),
            (r.expected_compositions_sign, r.expected_episodes_sign),
            (
                r.expected_compositions_conflict,
                r.expected_episodes_conflict,
            ),
        ] {
            rows += 1;
            let q = upper / r.compositions;
            let lower = r.kwcs as f64 * q;
            failures +=
                u64::from(episodes < lower * (1.0 - 1e-12) || episodes > upper * (1.0 + 1e-12));
        }
    }
    Check::all_rows(
        "I",
        "I-episodes-bounds",
        "every I1 row and harm: initial KWCs × q <= distinct episodes <= compositions × q",
        failures,
        rows,
    )
}

fn load_arithmetic_check(config: &Config, tables: &SectionI) -> Check {
    // Hand values at the protocol size under policy A (the current SPEC): 4 × 250 = 1,000
    // miners watched, 800 registered every second and 200 unregistered every 30 s at 295
    // bytes: 236,000 + 1,966.67 = 237,966.67 bytes/s; 129 peers; 40 connections per miner;
    // 25,000,000 miners per 100,000 WCs; 200 registered per 10 IDs = 20.
    let label = LoadPolicy::PerWc.label(config).unwrap_or_default();
    let row = tables
        .load
        .iter()
        .find(|r| r.wcs_per_kwc == 4 && r.policy == label && r.registered_cadence_s == 1.0);
    let expected = 800.0 * 295.0 + 200.0 * 295.0 / 30.0;
    let (value, ok) = match row {
        Some(r) => (
            r.bandwidth_bytes_per_s,
            (r.bandwidth_bytes_per_s - expected).abs() < 1e-6
                && r.miners_watched_per_node == 1_000.0
                && r.peer_connections_option_1 == 129
                && r.connections_per_miner == 40
                && r.network_miner_capacity == 25_000_000.0
                && r.registered_capacity_per_registered_id == 20.0,
        ),
        None => (f64::NAN, false),
    };
    Check::exact(
        "I",
        "I-load-arithmetic",
        "k = 4, policy A, 1 s cadence: bandwidth equals 800 × 295 + 200 × 295/30 bytes/s by hand, with 1,000 miners watched, 129 peers, 40 connections per miner, 25M miners per 100k WCs and 20 registered slots per registered ID",
        expected,
        value,
        ok,
    )
}

fn spare_capacity_check(config: &Config, tables: &SectionI) -> Result<Check> {
    let target = 1.0 + config.capacity.spare_target_fraction.value;
    let mut failures = 0;
    let mut rows = 0;
    for r in tables
        .load
        .iter()
        .filter(|r| r.unregistered_per_wc.is_some())
    {
        rows += 1;
        failures += u64::from(r.registered_capacity_per_registered_id < target);
    }
    ensure(rows > 0, "policy C rows are missing")?;
    Ok(Check::all_rows(
        "I",
        "I-policy-c-spare-capacity",
        "policy C at every size and u: network registered witness capacity ÷ registered IDs >= 1 + spare target (1.33)",
        failures,
        rows,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn neighbours_are_129_at_the_protocol_size() {
        let config = Config::default();
        let protocol = sizes(&config).into_iter().find(|s| s.wcs == 4).unwrap();
        assert_eq!(protocol.offsets, vec![1, 4, 6]);
        assert_eq!(protocol.neighbours(), 129);
        assert_eq!(protocol.members(), 40);
        assert!((protocol.rates().per_insertion - 4.7).abs() < 1e-12);
    }

    #[test]
    fn policy_c_hosts_fourteen_registered_miners_per_wc() {
        // ⌈10 × 1.33⌉ = ⌈13.3⌉ = 14.
        let config = Config::default();
        assert_eq!(policy_c_registered(&config).unwrap(), 14);
        let size = sizes(&config).into_iter().find(|s| s.wcs == 10).unwrap();
        let load = LoadPolicy::Architect { unregistered: 235 }
            .wc_load(&config, &size)
            .unwrap();
        assert_eq!(
            load,
            WcLoad {
                miners: 249.0,
                registered: 14.0
            }
        );
        let b = LoadPolicy::PerNode.wc_load(&config, &size).unwrap();
        assert_eq!(
            b,
            WcLoad {
                miners: 100.0,
                registered: 80.0
            }
        );
    }

    #[test]
    fn on_demand_decisions_dominate_at_the_protocol_size() {
        // k = 4, policy A, 4 absences per year, 8 session changes per miner per day, no bans:
        // One Chance 4 × 129/8760; decisions 4 × 250 × 8/24 × 2 × 39/40 = 650; catch-up
        // 2 × 4 × 8/8760.
        let config = Config::default();
        let i = section_i(&config).unwrap();
        let label = LoadPolicy::PerWc.label(&config).unwrap();
        let row = i
            .on_demand
            .iter()
            .find(|r| {
                r.wcs_per_kwc == 4
                    && r.policy == label
                    && r.absences_per_id_per_year == 4.0
                    && r.session_changes_per_miner_per_day == 8.0
                    && r.ban_rate_per_year == 0.0
            })
            .unwrap();
        assert!((row.one_chance_per_hour - 4.0 * 129.0 / 8_760.0).abs() < 1e-12);
        assert!((row.decisions_per_hour - 650.0).abs() < 1e-9);
        assert!((row.catch_up_per_hour - 64.0 / 8_760.0).abs() < 1e-12);
        assert_eq!(row.bans_per_hour, 0.0);
    }

    #[test]
    fn stall_odds_match_an_independent_computation_at_every_size() {
        // Reference: log10 of the hypergeometric stall tail at 1,000,000 IDs from Python's
        // exact integers, for k = 3, 4, 5, 6, 8, 10 at two-thirds. Below one third the odds
        // fall with size; above it they rise towards 1, but not strictly, because ⌈2n/3⌉
        // rounds differently at each size (k = 5 to 6 at p = 0.45).
        let config = Config::default();
        let i = section_i(&config).unwrap();
        for (p, reference) in [
            (0.25, [-0.976, -0.986, -1.007, -1.266, -1.302, -1.559]),
            (0.45, [-0.063, -0.034, -0.019, -0.020, -0.007, -0.004]),
        ] {
            let values: Vec<f64> = i
                .security
                .iter()
                .filter(|r| r.quorum == "2/3" && r.attacker_fraction == p)
                .map(|r| r.log10_p_stall)
                .collect();
            assert_eq!(values.len(), reference.len());
            for (v, r) in values.iter().zip(reference) {
                assert!((v - r).abs() < 0.0006, "p = {p}: {values:?}");
            }
        }
    }

    #[test]
    fn section_i_tables_cover_the_grid() {
        let config = Config::default();
        let i = section_i(&config).unwrap();
        let g = &config.analytic.kwc_size;
        let sizes = g.wcs_per_kwc.len();
        let quorums = g.quorum_fractions.len();
        let policies = 2 + g.unregistered_per_wc_policy_c.len();
        assert_eq!(
            i.security.len(),
            sizes * quorums * g.attacker_fractions.len()
        );
        assert_eq!(
            i.liveness.len(),
            sizes
                * quorums
                * g.liveness_attacker_fractions.len()
                * config.analytic.quorum_feasibility.failure_targets.len()
        );
        assert_eq!(
            i.load.len(),
            sizes * policies * g.registered_cadences_s.len()
        );
        assert_eq!(
            i.on_demand.len(),
            sizes
                * policies
                * config.analytic.absence.absences_per_id_per_year.len()
                * g.miner_session_changes_per_day.len()
                * config.analytic.witness.ban_rates_per_year.len()
        );
    }

    #[test]
    fn all_section_i_checks_pass() {
        let mut config = Config::default();
        config.run.monte_carlo.partition_replicates = 600;
        let i = section_i(&config).unwrap();
        let g = crate::quorum_tradeoff::section_g(&config).unwrap();
        let h = crate::quorum_feasibility::section_h(&config).unwrap();
        for check in checks(&config, &i, &g, &h).unwrap() {
            assert!(check.passed, "{check:?}");
        }
    }
}
