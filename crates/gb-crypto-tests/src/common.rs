//! Shared helpers: seeded random bytes, keys, headers and the winning step.

use gb_protocol::chain::{ChainInputs, StartRule, chain_start};
use gb_protocol::encoding::{Address, Header};
use gb_protocol::entropy::Keypair;
use gb_protocol::hash::Hash;
use gb_protocol::issuance::variant_b_target;
use rand_core::Rng;

/// 32 random bytes from a seeded stream.
pub fn random_hash<R: Rng + ?Sized>(rng: &mut R) -> Hash {
    let mut out = [0u8; 32];
    for chunk in out.chunks_mut(8) {
        chunk.copy_from_slice(&rng.next_u64().to_be_bytes());
    }
    out
}

/// A key pair from a seeded stream.
pub fn random_keypair<R: Rng + ?Sized>(rng: &mut R) -> Keypair {
    loop {
        if let Ok(k) = Keypair::from_seed(&random_hash(rng)) {
            return k;
        }
    }
}

/// The target at which each step wins with probability `1 / expected_attempts`.
pub fn target_for(expected_attempts: u64) -> Hash {
    variant_b_target(1, expected_attempts)
}

/// A header for the miner key `candidate_pk` with a random previous hash (so every trial has a
/// fresh chain).
pub fn header_for<R: Rng + ?Sized>(rng: &mut R, candidate_pk: [u8; 48], target: Hash) -> Header {
    Header {
        version: gb_protocol::PROTOCOL_VERSION,
        height: 100,
        prev_hash: random_hash(rng),
        candidate_pk,
        reward_wallet: random_hash(rng),
        address: Address::Ipv6Prefix64([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 9]),
        kwc_id: 1,
        target,
    }
}

/// Attempts until the first win, `N + 1`, for `header` with entropy `entropy` (start rule (a)
/// after a tip at t = 1,000), capped at `cap`.
pub fn attempts_to_win(header: &Header, entropy: Hash, cap: u64) -> u64 {
    let t0 = chain_start(1_000, StartRule::A);
    ChainInputs::new(header, entropy, t0)
        .winning_step(&header.target, cap)
        .map_or(cap, |(n, _)| n + 1)
}

/// Expected attempts to win for the best of `budget` independent tries with per-step success
/// probability `1 / expected`: `1 / (1 − (1 − 1/expected)^budget)`.
pub fn expected_best_of(expected: u64, budget: u64) -> f64 {
    let q = 1.0 - 1.0 / expected as f64;
    1.0 / (1.0 - libm::pow(q, budget as f64))
}
