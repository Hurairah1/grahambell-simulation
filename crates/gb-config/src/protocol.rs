//! Protocol parameters from SPEC section 2, grouped into sections.
//!
//! Every SPEC row maps to one or more [`Param`]s. Where a row carries a combined status
//! (for example "D / P"), it is split into separate parameters that each carry a single tag;
//! [`crate::registry`] records the mapping from SPEC rows to configuration keys.

use crate::param::{Param, Status, Sweep};
use serde::{Deserialize, Serialize};

/// PoW-ID issuance-rate mode (SPEC §3.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RateMode {
    /// Fixed target of one PoW-ID block per target interval.
    #[default]
    Fixed,
    /// Rate may rise with demand, capped at `registered_IDs / (k × T_min)`.
    Adaptive,
}

/// How the number of KWCs relates to the number of WCs (SPEC §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KwcCountRule {
    /// Each WC leads exactly one KWC and is a subordinate in exactly as many KWCs as a KWC
    /// has subordinate WCs.
    #[default]
    EqualsWcCount,
}

/// Which KWC members must sign the entropy aggregate (SPEC §3.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntropySigners {
    /// Every online member; the online count must be at least the quorum.
    #[default]
    AllOnlineMembers,
}

/// Chain Allocation Committee membership policy (SPEC §4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacMembershipPolicy {
    /// First in, first out.
    #[default]
    FirstInFirstOut,
}

/// Whether one ID may hold more than one CAC seat at a time (SPEC §4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacSeatRule {
    /// Proposed rule (status P): a member's 10th-block win passes to the next 10th-block miner who is not a member.
    #[default]
    NextNonMember,
    /// Comparison: the 10th-block miner joins even if already a member.
    AllowDuplicates,
}

/// Approval threshold as a fraction of members, rounded up (SPEC §4.3, §4.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalThreshold {
    /// Numerator of the approval fraction.
    pub numerator: u64,
    /// Denominator of the approval fraction.
    pub denominator: u64,
}

impl ApprovalThreshold {
    /// Approvals needed out of `members`: `⌈numerator × members / denominator⌉`.
    ///
    /// Returns `None` when the denominator is zero.
    pub fn approvals_needed(&self, members: u64) -> Option<u64> {
        if self.denominator == 0 {
            return None;
        }
        let scaled = u128::from(self.numerator) * u128::from(members);
        let denominator = u128::from(self.denominator);
        u64::try_from(scaled.div_ceil(denominator)).ok()
    }
}

/// How genesis IDs are distributed (SPEC §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GenesisDistribution {
    /// KYC, one ID per verified person.
    #[default]
    KycOnePerVerifiedPerson,
}

/// Last step of the penalty ladder for lesser offences (SPEC §4.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PenaltyFinalStep {
    /// Permanent ban.
    #[default]
    Permanent,
}

/// Signature scheme (SPEC §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureScheme {
    /// BLS12-381 aggregate signatures with signer bitfield and proof of possession.
    #[default]
    #[serde(rename = "bls12_381_aggregate_bitfield_pop")]
    Bls12381AggregateBitfieldPop,
}

/// Hash function (SPEC §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HashFunction {
    /// SHA-256.
    #[default]
    Sha256,
}

/// Where the PoW-ID hash chain starts (SPEC §3.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StartRule {
    /// Rule (a): always at `t0 = timestamp(previous PoW-ID block) + 1 s`.
    #[default]
    A,
    /// Rule (b), comparison only: when the miner's entropy arrives locally.
    B,
}

/// Choice between two valid PoW-ID blocks at the same height (SPEC §3.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TieBreak {
    /// Proposed rule (status P): keep the block with the lower block hash.
    #[default]
    LowerBlockHash,
    /// Comparison: keep the block seen first.
    FirstSeen,
}

/// Hash pacing (SPEC §2 "Hash pacing").
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pacing {
    /// Hash attempts per second per admitted /64 (unregistered) or per ID (registered).
    pub hashes_per_second: Param<f64>,
}

impl Default for Pacing {
    fn default() -> Self {
        Pacing {
            hashes_per_second: Param::decided(1.0),
        }
    }
}

/// PoW-ID issuance parameters (SPEC §2, §3.5, §3.7, §3.9).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Issuance {
    /// Target interval between PoW-ID blocks, in seconds.
    pub pow_id_target_interval_s: Param<f64>,
    /// Fixed or adaptive issuance rate.
    pub rate_mode: Param<RateMode>,
    /// Minimum attack time floor `T_min` for adaptive issuance, in years.
    pub min_attack_time_floor_years: Param<f64>,
    /// Adaptive-cap checkpoint interval as a fraction of `T_min` ("—" until chosen).
    pub cap_checkpoint_interval_fraction_of_t_min: Param<Option<f64>>,
    /// Confirmation depth before a new ID becomes active, in PoW-ID blocks.
    pub confirmation_depth_blocks: Param<u32>,
    /// Hash-chain start rule.
    pub start_rule: Param<StartRule>,
    /// Tie-break between two valid PoW-ID blocks at the same height.
    pub same_height_tie_break: Param<TieBreak>,
}

impl Default for Issuance {
    fn default() -> Self {
        Issuance {
            pow_id_target_interval_s: Param::decided(30.0),
            rate_mode: Param::with_status(RateMode::Fixed, Status::P).swept(
                Sweep::values(vec![RateMode::Fixed, RateMode::Adaptive])
                    .with_note("fixed is decided; adaptive is the proposed variant (SPEC §3.9)"),
            ),
            min_attack_time_floor_years: Param::with_status(2.0, Status::P)
                .swept(Sweep::range(1.0, 10.0)),
            cap_checkpoint_interval_fraction_of_t_min: Param::with_status(None, Status::O)
                .swept(Sweep::values(vec![Some(0.25), Some(0.5), Some(1.0)])),
            confirmation_depth_blocks: Param::with_status(6, Status::O).swept(Sweep::range(3, 12)),
            start_rule: Param::decided(StartRule::A).swept(
                Sweep::values(vec![StartRule::A, StartRule::B])
                    .with_note("rule (b) is the rejected alternative, kept for S13"),
            ),
            same_height_tie_break: Param::with_status(TieBreak::LowerBlockHash, Status::P).swept(
                Sweep::values(vec![TieBreak::LowerBlockHash, TieBreak::FirstSeen]),
            ),
        }
    }
}

/// Transaction-layer parameters (SPEC §2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transactions {
    /// Interval between PoW-Tx blocks, in seconds.
    pub pow_tx_interval_s: Param<f64>,
}

impl Default for Transactions {
    fn default() -> Self {
        Transactions {
            pow_tx_interval_s: Param::with_status(10.0, Status::O).swept(Sweep::range(1.0, 10.0)),
        }
    }
}

/// Witness Chain structure (SPEC §2, §4.1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Witness {
    /// Witness nodes per WC.
    pub wc_size: Param<u32>,
    /// Subordinate WCs per KWC (3 gives 40-node KWCs; 2 is the 30-node comparison).
    pub subordinate_wcs_per_kwc: Param<u32>,
    /// Relation between the number of KWCs and WCs.
    pub kwc_count_rule: Param<KwcCountRule>,
    /// Registered miners watched per witness node.
    pub watched_registered_per_node: Param<u32>,
    /// Unregistered miners watched per witness node.
    pub watched_unregistered_per_node: Param<u32>,
}

impl Default for Witness {
    fn default() -> Self {
        Witness {
            wc_size: Param::decided(10),
            subordinate_wcs_per_kwc: Param::decided(3)
                .swept(Sweep::values(vec![3, 2]).with_note("1 + 2 (30 nodes) for comparison")),
            kwc_count_rule: Param::decided(KwcCountRule::EqualsWcCount),
            watched_registered_per_node: Param::decided(800),
            watched_unregistered_per_node: Param::decided(200),
        }
    }
}

/// PoWit quorums (SPEC §2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Quorum {
    /// Registered miners: minimum signatures from the leader WC.
    pub registered_leader_min: Param<u32>,
    /// Registered miners: minimum signatures from the subordinate WCs (40-node KWC).
    pub registered_subordinate_min: Param<u32>,
    /// Registered miners: minimum subordinate signatures in the 30-node comparison.
    pub registered_subordinate_min_30_node: Param<u32>,
    /// Unregistered miners: minimum signatures from any KWC members (40-node KWC).
    pub unregistered_total_min: Param<u32>,
    /// Unregistered miners: minimum signatures in the 30-node comparison.
    pub unregistered_total_min_30_node: Param<u32>,
}

impl Default for Quorum {
    fn default() -> Self {
        Quorum {
            registered_leader_min: Param::decided(7),
            registered_subordinate_min: Param::decided(21),
            registered_subordinate_min_30_node: Param::decided(14),
            unregistered_total_min: Param::decided(27),
            unregistered_total_min_30_node: Param::decided(20),
        }
    }
}

/// Entropy lock (SPEC §2, §3.4).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entropy {
    /// Who must sign the entropy aggregate.
    pub signers: Param<EntropySigners>,
}

impl Default for Entropy {
    fn default() -> Self {
        Entropy {
            signers: Param::decided(EntropySigners::AllOnlineMembers),
        }
    }
}

/// Miner capacity and spare witnessing capacity (SPEC §2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capacity {
    /// Total miners (registered + unregistered) per leader WC.
    pub miners_per_leader_wc: Param<u32>,
    /// Unregistered miners per leader WC; the registered share is the remainder.
    pub unregistered_per_leader_wc: Param<u32>,
    /// Spare witnessing capacity target over demand (0.33 means +33%).
    pub spare_target_fraction: Param<f64>,
}

impl Default for Capacity {
    fn default() -> Self {
        Capacity {
            miners_per_leader_wc: Param::decided(250),
            unregistered_per_leader_wc: Param::with_status(50, Status::O).swept(
                Sweep::values(vec![50, 150, 235])
                    .with_note("registered/unregistered split 200/50, 100/150, 15/235"),
            ),
            spare_target_fraction: Param::decided(0.33),
        }
    }
}

impl Capacity {
    /// Registered miners per leader WC implied by the total and the unregistered share.
    pub fn registered_per_leader_wc(&self) -> Option<u32> {
        self.miners_per_leader_wc
            .value
            .checked_sub(self.unregistered_per_leader_wc.value)
    }
}

/// Network limits (SPEC §2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    /// Per-node request rate limit, in requests per second.
    pub node_request_rate_limit_per_s: Param<u32>,
}

impl Default for Network {
    fn default() -> Self {
        Network {
            node_request_rate_limit_per_s: Param::decided(1000),
        }
    }
}

/// Timing parameters (SPEC §2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Timing {
    /// Grace epoch, in rounds of the miner's own block type.
    pub grace_epoch_rounds: Param<u32>,
    /// Clock tolerance δ, in seconds.
    pub clock_tolerance_s: Param<f64>,
}

impl Default for Timing {
    fn default() -> Self {
        Timing {
            grace_epoch_rounds: Param::decided(5),
            clock_tolerance_s: Param::with_status(2.0, Status::O).swept(Sweep::range(0.5, 10.0)),
        }
    }
}

/// Admission lifecycle parameters (SPEC §2, §3.1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Admission {
    /// Wait after admission before mining, in rounds.
    pub post_admission_wait_rounds: Param<u32>,
    /// Convergence interval, in epochs.
    pub convergence_interval_epochs: Param<f64>,
    /// Registered peers a newcomer bootstraps from.
    pub peer_bootstrap_count: Param<u32>,
}

impl Default for Admission {
    fn default() -> Self {
        Admission {
            post_admission_wait_rounds: Param::with_status(5, Status::O).swept(Sweep::range(1, 10)),
            convergence_interval_epochs: Param::with_status(1.0, Status::O)
                .swept(Sweep::range(0.5, 3.0)),
            peer_bootstrap_count: Param::decided(8).swept(Sweep::range(4, 8)),
        }
    }
}

/// Chain Allocation Committee (SPEC §2, §4.3).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cac {
    /// Committee size.
    pub size: Param<u32>,
    /// Membership policy.
    pub membership_policy: Param<CacMembershipPolicy>,
    /// The miner of every n-th PoW-Tx block joins.
    pub join_every_n_tx_blocks: Param<u32>,
    /// Approval threshold, rounded up.
    pub approval_threshold: Param<ApprovalThreshold>,
    /// Whether one ID may hold two seats at once.
    pub seat_rule: Param<CacSeatRule>,
}

impl Default for Cac {
    fn default() -> Self {
        Cac {
            size: Param::decided(600)
                .swept(Sweep::range(100, 1000).with_note("100–1,000 for comparison")),
            membership_policy: Param::decided(CacMembershipPolicy::FirstInFirstOut),
            join_every_n_tx_blocks: Param::decided(10),
            approval_threshold: Param::decided(ApprovalThreshold {
                numerator: 2,
                denominator: 3,
            }),
            seat_rule: Param::with_status(CacSeatRule::NextNonMember, Status::P).swept(
                Sweep::values(vec![
                    CacSeatRule::NextNonMember,
                    CacSeatRule::AllowDuplicates,
                ]),
            ),
        }
    }
}

/// Genesis distribution (SPEC §2, §10).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Genesis {
    /// Number of genesis IDs, G.
    pub ids: Param<u64>,
    /// Distribution method.
    pub distribution: Param<GenesisDistribution>,
    /// Fraction of genesis IDs secretly controlled by one party.
    pub secretly_controlled_fraction: Param<f64>,
}

impl Default for Genesis {
    fn default() -> Self {
        Genesis {
            ids: Param::decided(2_100_000).swept(Sweep::values(vec![
                500_000, 1_000_000, 2_000_000, 2_100_000, 3_000_000,
            ])),
            distribution: Param::decided(GenesisDistribution::KycOnePerVerifiedPerson),
            secretly_controlled_fraction: Param::with_status(0.0, Status::O)
                .swept(Sweep::range(0.0, 0.2)),
        }
    }
}

/// Offline handling (SPEC §2, §4.7).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Offline {
    /// Absence after which an ID is deactivated, in seconds ("—" until chosen).
    pub deactivation_threshold_s: Param<Option<f64>>,
    /// Wait before a returning ID is re-activated, in seconds ("—" until chosen).
    pub reactivation_wait_s: Param<Option<f64>>,
}

impl Default for Offline {
    fn default() -> Self {
        const HOUR: f64 = 3_600.0;
        const DAY: f64 = 86_400.0;
        Offline {
            deactivation_threshold_s: Param::with_status(None, Status::O).swept(Sweep::values(
                vec![
                    Some(HOUR),
                    Some(6.0 * HOUR),
                    Some(24.0 * HOUR),
                    Some(3.0 * DAY),
                    Some(7.0 * DAY),
                ],
            )),
            reactivation_wait_s: Param::with_status(None, Status::O).swept(Sweep::values(vec![
                Some(DAY),
                Some(7.0 * DAY),
                Some(14.0 * DAY),
                Some(30.0 * DAY),
            ])),
        }
    }
}

/// Penalties for lesser offences (SPEC §2, §4.8).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Penalties {
    /// Successive suspensions before the final step, in seconds (24 h, then 30 days).
    pub suspension_ladder_s: Param<Vec<u64>>,
    /// Final step of the ladder.
    pub final_step: Param<PenaltyFinalStep>,
}

impl Default for Penalties {
    fn default() -> Self {
        Penalties {
            suspension_ladder_s: Param::decided(vec![86_400, 2_592_000]),
            final_step: Param::decided(PenaltyFinalStep::Permanent),
        }
    }
}

/// Cryptographic primitives (SPEC §2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Crypto {
    /// Signature scheme.
    pub signature_scheme: Param<SignatureScheme>,
    /// Hash function.
    pub hash_function: Param<HashFunction>,
}

impl Default for Crypto {
    fn default() -> Self {
        Crypto {
            signature_scheme: Param::decided(SignatureScheme::Bls12381AggregateBitfieldPop),
            hash_function: Param::with_status(HashFunction::Sha256, Status::P),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_thirds_rounded_up_gives_spec_values() {
        let rule = ApprovalThreshold {
            numerator: 2,
            denominator: 3,
        };
        assert_eq!(rule.approvals_needed(600), Some(400));
        assert_eq!(rule.approvals_needed(40), Some(27));
        assert_eq!(rule.approvals_needed(30), Some(20));
        assert_eq!(rule.approvals_needed(100), Some(67));
        assert_eq!(rule.approvals_needed(1000), Some(667));
    }

    #[test]
    fn zero_denominator_has_no_threshold() {
        let rule = ApprovalThreshold {
            numerator: 2,
            denominator: 0,
        };
        assert_eq!(rule.approvals_needed(600), None);
    }

    #[test]
    fn registered_capacity_is_total_minus_unregistered() {
        assert_eq!(Capacity::default().registered_per_leader_wc(), Some(200));
    }

    #[test]
    fn genesis_default_is_two_point_one_million_decided() {
        let genesis = Genesis::default();
        assert_eq!(genesis.ids.value, 2_100_000);
        assert_eq!(genesis.ids.status, Status::D);
    }
}
