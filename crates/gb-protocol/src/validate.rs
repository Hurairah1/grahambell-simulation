//! The witness signing condition and global validation (SPEC §3.6–§3.7).
//!
//! [`validate`] checks one PoW-ID block in the order of SPEC §3.7 and returns the first
//! failure as a [`Rejection`]. Time values are seconds on the validator's own clock.

use crate::chain::{ChainInputs, StartRule, below_target, chain_start};
use crate::encoding::{Header, block_hash};
use crate::entropy::{
    Bitfield, PublicKeyBytes, SignatureBytes, entropy_output, powit_message, verify_entropy,
    verify_proof_of_possession, verify_same_message,
};
use crate::error::ProtocolError;
use crate::hash::Hash;
use gb_config::Config;
use std::cmp::Ordering;

/// Which miners a quorum applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MinerKind {
    /// Unregistered miners (PoW-ID): any `unregistered_total_min` of all seats.
    Unregistered,
    /// Registered miners (PoW-Tx): leader-WC and subordinate minimums.
    Registered,
}

/// A PoWit quorum over the KWC's seats in seat order (leader WC first).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuorumRule {
    /// Any `quorum` of `seats`.
    Pool {
        /// Seats.
        seats: usize,
        /// Signatures needed.
        quorum: usize,
    },
    /// At least `leader_quorum` of the first `leader_seats` and `subordinate_quorum` of the
    /// rest.
    TwoGroup {
        /// Leader-WC seats.
        leader_seats: usize,
        /// Leader signatures needed.
        leader_quorum: usize,
        /// Subordinate seats.
        subordinate_seats: usize,
        /// Subordinate signatures needed.
        subordinate_quorum: usize,
    },
}

impl QuorumRule {
    /// The SPEC §2 quorum for a 40-node KWC from the configuration.
    pub fn from_config(config: &Config, kind: MinerKind) -> QuorumRule {
        let wc = config.witness.wc_size.value as usize;
        let subordinates = wc * config.witness.subordinate_wcs_per_kwc.value as usize;
        let q = &config.quorum;
        match kind {
            MinerKind::Unregistered => QuorumRule::Pool {
                seats: wc + subordinates,
                quorum: q.unregistered_total_min.value as usize,
            },
            MinerKind::Registered => QuorumRule::TwoGroup {
                leader_seats: wc,
                leader_quorum: q.registered_leader_min.value as usize,
                subordinate_seats: subordinates,
                subordinate_quorum: q.registered_subordinate_min.value as usize,
            },
        }
    }

    /// Seats in the KWC.
    pub fn seats(&self) -> usize {
        match *self {
            QuorumRule::Pool { seats, .. } => seats,
            QuorumRule::TwoGroup {
                leader_seats,
                subordinate_seats,
                ..
            } => leader_seats + subordinate_seats,
        }
    }

    /// True when the signers in `bitfield` meet the quorum.
    pub fn is_met(&self, bitfield: &Bitfield) -> bool {
        if bitfield.seats() != self.seats() {
            return false;
        }
        match *self {
            QuorumRule::Pool { quorum, .. } => bitfield.count() >= quorum,
            QuorumRule::TwoGroup {
                leader_seats,
                leader_quorum,
                subordinate_quorum,
                ..
            } => {
                let signers = bitfield.signers();
                let leader = signers.iter().filter(|s| **s < leader_seats).count();
                leader >= leader_quorum && signers.len() - leader >= subordinate_quorum
            }
        }
    }
}

/// The KWC's member keys in seat order, each with a checked proof of possession.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KwcKeys {
    keys: Vec<PublicKeyBytes>,
}

impl KwcKeys {
    /// Accepts member keys only with valid proofs of possession.
    pub fn new(members: &[(PublicKeyBytes, SignatureBytes)]) -> Result<KwcKeys, ProtocolError> {
        for (pk, pop) in members {
            if !verify_proof_of_possession(pk, pop) {
                return Err(ProtocolError::Bls(
                    "invalid proof of possession".to_string(),
                ));
            }
        }
        Ok(KwcKeys {
            keys: members.iter().map(|(pk, _)| *pk).collect(),
        })
    }

    /// Keys in seat order.
    pub fn keys(&self) -> &[PublicKeyBytes] {
        &self.keys
    }
}

/// A PoW-ID block with its entropy and its PoWit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    /// The header.
    pub header: Header,
    /// The miner's signature on the header.
    pub miner_signature: SignatureBytes,
    /// The entropy aggregate (σ_m and the online members' signatures).
    pub entropy_aggregate: SignatureBytes,
    /// Members whose entropy signatures are in the aggregate.
    pub entropy_signers: Bitfield,
    /// The winning step N.
    pub winning_step: u64,
    /// The block timestamp, which must equal `t0 + N`.
    pub timestamp: u64,
    /// The PoWit aggregate signature on `"GB/powit" ‖ block hash`.
    pub powit_aggregate: SignatureBytes,
    /// PoWit signers.
    pub powit_signers: Bitfield,
}

impl Block {
    /// The entropy E this block commits to.
    pub fn entropy(&self) -> Hash {
        entropy_output(&self.entropy_aggregate, &self.entropy_signers)
    }

    /// The block hash.
    pub fn hash(&self) -> Hash {
        block_hash(&self.header, &self.entropy(), self.winning_step)
    }
}

/// The chain tip the block extends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tip {
    /// Hash of the tip.
    pub hash: Hash,
    /// Height of the tip.
    pub height: u64,
    /// Timestamp of the tip.
    pub timestamp: u64,
}

/// When the validator received the block and its PoWit, on its own clock.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Reception {
    /// Arrival time of the block.
    pub block_at: f64,
    /// Arrival time of the PoWit.
    pub powit_at: f64,
}

/// Validation parameters (SPEC §2).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Rules {
    /// Clock tolerance δ, seconds.
    pub clock_tolerance_s: f64,
    /// PoWit arrival deadline D, seconds after the block timestamp; `None` disables it.
    pub powit_deadline_s: Option<f64>,
    /// Chain start rule (rule (a) is the protocol; (b) is the S13 comparison).
    pub start_rule: StartRule,
    /// Steps a validator recomputes at most before rejecting.
    pub max_steps: u64,
}

impl Rules {
    /// Rules from the configuration, with start rule (a).
    pub fn from_config(config: &Config) -> Rules {
        Rules {
            clock_tolerance_s: config.timing.clock_tolerance_s.value,
            powit_deadline_s: config.timing.powit_deadline_s.value,
            start_rule: StartRule::A,
            max_steps: 1_000_000,
        }
    }
}

/// Why a block is invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// Not the next height on the tip, or the previous hash does not match (serialisation).
    NotOnTip,
    /// The candidate key or address is already registered or active (uniqueness).
    NotUnique,
    /// Fewer online members signed the entropy than the quorum.
    EntropyBelowQuorum,
    /// The entropy aggregate does not verify.
    BadEntropy,
    /// `h_N` is not below the target.
    NotWinning,
    /// An earlier step already wins, so N is not the first winning step.
    EarlierWinningStep,
    /// `timestamp ≠ t0 + N`.
    TimestampMismatch,
    /// The block arrived before its own timestamp (beyond δ).
    ReceivedEarly,
    /// The PoWit signers do not meet the quorum.
    PowitBelowQuorum,
    /// The PoWit aggregate does not verify.
    BadPowit,
    /// The PoWit arrived later than D after the block timestamp.
    PowitLate,
}

/// SPEC §3.6: an honest member signs the PoWit only when its own clock has reached
/// `t0 + N`, within tolerance δ.
pub fn may_sign(own_clock: f64, t0: u64, winning_step: u64, clock_tolerance_s: f64) -> bool {
    own_clock >= (t0 + winning_step) as f64 - clock_tolerance_s
}

/// SPEC §3.7 same-height tie-break \[P\]: the block with the lower hash wins. Returns
/// `Ordering::Less` when `a` is preferred.
pub fn prefer(a: &Hash, b: &Hash) -> Ordering {
    a.cmp(b)
}

/// Validates `block` on `tip` (SPEC §3.7). `unique` reports whether the candidate key and the
/// address are free. Returns the block hash when valid.
pub fn validate(
    block: &Block,
    tip: &Tip,
    kwc: &KwcKeys,
    quorum: &QuorumRule,
    reception: &Reception,
    rules: &Rules,
    unique: &dyn Fn(&Header) -> bool,
) -> Result<Hash, Rejection> {
    let h = &block.header;
    if h.height != tip.height + 1 || h.prev_hash != tip.hash {
        return Err(Rejection::NotOnTip);
    }
    if !unique(h) {
        return Err(Rejection::NotUnique);
    }
    if !quorum.is_met(&block.entropy_signers) {
        return Err(Rejection::EntropyBelowQuorum);
    }
    if !verify_entropy(
        h,
        &block.miner_signature,
        kwc.keys(),
        &block.entropy_signers,
        &block.entropy_aggregate,
    ) {
        return Err(Rejection::BadEntropy);
    }
    let t0 = chain_start(tip.timestamp, rules.start_rule);
    let inputs = ChainInputs::new(h, block.entropy(), t0);
    if block.winning_step >= rules.max_steps {
        return Err(Rejection::NotWinning);
    }
    let mut first_win = None;
    let mut last = [0u8; 32];
    for (n, hash) in inputs.steps().take(block.winning_step as usize + 1) {
        if below_target(&hash, &h.target) && first_win.is_none() {
            first_win = Some(n);
        }
        last = hash;
    }
    if !below_target(&last, &h.target) {
        return Err(Rejection::NotWinning);
    }
    if first_win != Some(block.winning_step) {
        return Err(Rejection::EarlierWinningStep);
    }
    if block.timestamp != t0 + block.winning_step {
        return Err(Rejection::TimestampMismatch);
    }
    if reception.block_at < block.timestamp as f64 - rules.clock_tolerance_s {
        return Err(Rejection::ReceivedEarly);
    }
    if !quorum.is_met(&block.powit_signers) {
        return Err(Rejection::PowitBelowQuorum);
    }
    let hash = block.hash();
    if !verify_same_message(
        kwc.keys(),
        &block.powit_signers,
        &powit_message(&hash),
        &block.powit_aggregate,
    ) {
        return Err(Rejection::BadPowit);
    }
    if let Some(deadline) = rules.powit_deadline_s {
        if reception.powit_at > block.timestamp as f64 + deadline {
            return Err(Rejection::PowitLate);
        }
    }
    Ok(hash)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::encoding::Address;
    use crate::entropy::{Keypair, aggregate, entropy_aggregate, member_message, miner_message};

    /// A complete valid block on a test KWC of `seats` members (all sign), with a target that
    /// wins about one step in 8.
    pub(crate) struct Fixture {
        pub(crate) block: Block,
        pub(crate) tip: Tip,
        pub(crate) kwc: KwcKeys,
        pub(crate) quorum: QuorumRule,
    }

    pub(crate) fn fixture(seats: usize, quorum: QuorumRule) -> Fixture {
        let members: Vec<Keypair> = (0..seats)
            .map(|i| Keypair::from_seed(&[i as u8 + 1; 32]).unwrap())
            .collect();
        let kwc = KwcKeys::new(
            &members
                .iter()
                .map(|k| (k.public, k.proof_of_possession()))
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let miner = Keypair::from_seed(&[200; 32]).unwrap();
        let tip = Tip {
            hash: [3; 32],
            height: 9,
            timestamp: 1_000,
        };
        let mut target = [0u8; 32];
        target[0] = 0x20;
        let header = Header {
            version: crate::PROTOCOL_VERSION,
            height: 10,
            prev_hash: tip.hash,
            candidate_pk: miner.public,
            reward_wallet: [4; 32],
            address: Address::Ipv6Prefix64([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 2]),
            kwc_id: 7,
            target,
        };
        let sig_m = miner.sign(&miner_message(&header));
        let msg = member_message(&header, &sig_m);
        let sigs: Vec<SignatureBytes> = members.iter().map(|k| k.sign(&msg)).collect();
        let all = Bitfield::from_seats(seats, &(0..seats).collect::<Vec<_>>());
        let (agg, e) = entropy_aggregate(&sig_m, &sigs, &all).unwrap();
        let t0 = tip.timestamp + 1;
        let (n, _) = ChainInputs::new(&header, e, t0)
            .winning_step(&target, 10_000)
            .unwrap();
        let mut block = Block {
            header,
            miner_signature: sig_m,
            entropy_aggregate: agg,
            entropy_signers: all.clone(),
            winning_step: n,
            timestamp: t0 + n,
            powit_aggregate: [0; 96],
            powit_signers: all,
        };
        let pmsg = powit_message(&block.hash());
        let psigs: Vec<SignatureBytes> = members.iter().map(|k| k.sign(&pmsg)).collect();
        block.powit_aggregate = aggregate(&psigs).unwrap();
        Fixture {
            block,
            tip,
            kwc,
            quorum,
        }
    }

    fn on_time(block: &Block) -> Reception {
        Reception {
            block_at: block.timestamp as f64,
            powit_at: block.timestamp as f64 + 1.0,
        }
    }

    fn rules(deadline: Option<f64>) -> Rules {
        Rules {
            clock_tolerance_s: 2.0,
            powit_deadline_s: deadline,
            start_rule: StartRule::A,
            max_steps: 1_000_000,
        }
    }

    fn pool(seats: usize, quorum: usize) -> QuorumRule {
        QuorumRule::Pool { seats, quorum }
    }

    fn run(f: &Fixture, block: &Block, reception: Reception, r: Rules) -> Result<Hash, Rejection> {
        validate(block, &f.tip, &f.kwc, &f.quorum, &reception, &r, &|_| true)
    }

    #[test]
    fn a_complete_block_is_valid() {
        let f = fixture(4, pool(4, 3));
        assert_eq!(
            run(&f, &f.block, on_time(&f.block), rules(Some(5.0))),
            Ok(f.block.hash())
        );
    }

    #[test]
    fn each_rule_rejects_its_violation() {
        let f = fixture(4, pool(4, 3));
        let r = rules(Some(5.0));
        let mut b = f.block.clone();
        b.timestamp += 1;
        assert_eq!(
            run(&f, &b, on_time(&f.block), r),
            Err(Rejection::TimestampMismatch)
        );
        let early = Reception {
            block_at: f.block.timestamp as f64 - 2.5,
            powit_at: f.block.timestamp as f64,
        };
        assert_eq!(run(&f, &f.block, early, r), Err(Rejection::ReceivedEarly));
        let late = Reception {
            block_at: f.block.timestamp as f64,
            powit_at: f.block.timestamp as f64 + 5.5,
        };
        assert_eq!(run(&f, &f.block, late, r), Err(Rejection::PowitLate));
        assert!(
            run(&f, &f.block, late, rules(None)).is_ok(),
            "no deadline set"
        );
        let mut b = f.block.clone();
        b.winning_step += 1;
        b.timestamp += 1;
        let outcome = run(&f, &b, on_time(&b), r);
        assert!(matches!(
            outcome,
            Err(Rejection::NotWinning | Rejection::EarlierWinningStep)
        ));
        let mut b = f.block.clone();
        b.powit_signers = Bitfield::from_seats(4, &[0, 1]);
        assert_eq!(
            run(&f, &b, on_time(&b), r),
            Err(Rejection::PowitBelowQuorum)
        );
        let mut b = f.block.clone();
        b.powit_signers = Bitfield::from_seats(4, &[0, 1, 2]);
        assert_eq!(run(&f, &b, on_time(&b), r), Err(Rejection::BadPowit));
        let mut b = f.block.clone();
        b.header.kwc_id += 1;
        assert_eq!(run(&f, &b, on_time(&b), r), Err(Rejection::BadEntropy));
        let other_tip = Tip {
            height: 10,
            ..f.tip
        };
        assert_eq!(
            validate(
                &f.block,
                &other_tip,
                &f.kwc,
                &f.quorum,
                &on_time(&f.block),
                &r,
                &|_| true
            ),
            Err(Rejection::NotOnTip)
        );
        assert_eq!(
            validate(
                &f.block,
                &f.tip,
                &f.kwc,
                &f.quorum,
                &on_time(&f.block),
                &r,
                &|_| false
            ),
            Err(Rejection::NotUnique)
        );
    }

    #[test]
    fn quorum_rules_count_groups_in_seat_order() {
        let two = QuorumRule::TwoGroup {
            leader_seats: 10,
            leader_quorum: 7,
            subordinate_seats: 30,
            subordinate_quorum: 21,
        };
        let seats = |set: Vec<usize>| Bitfield::from_seats(40, &set);
        assert!(two.is_met(&seats((0..7).chain(10..31).collect())));
        assert!(
            !two.is_met(&seats((0..6).chain(10..40).collect())),
            "6 leaders"
        );
        assert!(
            !two.is_met(&seats((0..10).chain(10..30).collect())),
            "20 subordinates"
        );
        let config = Config::default();
        assert_eq!(QuorumRule::from_config(&config, MinerKind::Registered), two);
        assert_eq!(
            QuorumRule::from_config(&config, MinerKind::Unregistered),
            QuorumRule::Pool {
                seats: 40,
                quorum: 27
            }
        );
    }

    #[test]
    fn members_sign_only_from_t0_plus_n_within_tolerance() {
        assert!(!may_sign(1_007.9, 1_001, 9, 2.0));
        assert!(may_sign(1_008.0, 1_001, 9, 2.0));
    }

    #[test]
    fn the_lower_block_hash_wins_a_tie() {
        assert_eq!(prefer(&[1; 32], &[2; 32]), Ordering::Less);
    }

    #[test]
    fn keys_without_a_valid_proof_of_possession_are_refused() {
        let a = Keypair::from_seed(&[1; 32]).unwrap();
        let b = Keypair::from_seed(&[2; 32]).unwrap();
        assert!(KwcKeys::new(&[(a.public, b.proof_of_possession())]).is_err());
    }
}
