//! C5 — threshold BLS for the entropy (SPEC §12 \[P\]): cost of key setup and signing.
//!
//! **Benchmark only, not audited, not used by gb-protocol.** This is a prototype of the
//! Joint-Feldman (Pedersen) distributed key generation, built only to measure cost. Its group
//! arithmetic uses the `bls12_381` crate; signatures and verification use `blst` exactly as
//! `gb-protocol` does, and the combined threshold signature must verify under `blst`.
//!
//! With n members and threshold t = ⌈2n/3⌉, every member deals a random polynomial of degree
//! t − 1: it broadcasts t commitments (G1, 48 bytes) and sends each other member one share
//! (a scalar, 32 bytes). Each member checks n − 1 shares against the commitments. Any t members
//! then sign with their shares, and the signatures combine by Lagrange interpolation in G2.

use crate::common::random_hash;
use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use blst::min_pk::{PublicKey, SecretKey};
use gb_config::CryptoTestsConfig;
use gb_protocol::entropy::{SIG_DST, verify};
use gb_runlog::rng_stream;
use serde::Serialize;
use std::time::Instant;

fn random_scalar(rng: &mut rand_chacha::ChaCha20Rng) -> Scalar {
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&random_hash(rng));
    wide[32..].copy_from_slice(&random_hash(rng));
    Scalar::from_bytes_wide(&wide)
}

/// `f(x)` for coefficients `coeffs` (constant first), by Horner's rule.
fn evaluate(coeffs: &[Scalar], x: u64) -> Scalar {
    let x = Scalar::from(x);
    coeffs
        .iter()
        .rev()
        .fold(Scalar::from(0u64), |acc, c| acc * x + c)
}

/// `Σ_k C_k x^k` in G1, by Horner's rule.
fn evaluate_commitments(commitments: &[G1Projective], x: u64) -> G1Projective {
    let x = Scalar::from(x);
    commitments
        .iter()
        .rev()
        .fold(G1Projective::identity(), |acc, c| acc * x + c)
}

/// Lagrange coefficient at 0 for member `j` among `signers` (indices are evaluation points).
fn lagrange_at_zero(j: u64, signers: &[u64]) -> Scalar {
    let mut num = Scalar::from(1u64);
    let mut den = Scalar::from(1u64);
    for &m in signers {
        if m != j {
            num *= Scalar::from(m);
            den *= Scalar::from(m) - Scalar::from(j);
        }
    }
    num * den.invert().unwrap_or(Scalar::from(0u64))
}

/// Deterministic sizes and the correctness result for one KWC size (table K5).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ThresholdRow {
    /// Members n.
    pub members: u64,
    /// Threshold t.
    pub threshold: u64,
    /// Messages a member sends: n − 1 private shares and 1 broadcast of commitments.
    pub messages_sent: u64,
    /// Messages a member receives: n − 1 shares and n − 1 commitment broadcasts.
    pub messages_received: u64,
    /// Bytes a member sends: (n − 1) × 32 + t × 48 (broadcast counted once).
    pub bytes_sent: u64,
    /// Bytes a member receives: (n − 1) × 32 + (n − 1) × t × 48.
    pub bytes_received: u64,
    /// G1 scalar multiplications per member: t to deal, (n − 1)(t + 1) to check shares.
    pub g1_multiplications: u64,
    /// The combined threshold signature verified under `blst` against the group key.
    pub combined_signature_verifies: bool,
}

/// Timings for one KWC size (machine-dependent; `bench/`).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ThresholdTimingRow {
    /// Members n.
    pub members: u64,
    /// Threshold t.
    pub threshold: u64,
    /// Seconds for one member to deal (commitments and n shares).
    pub deal_s: f64,
    /// Seconds for one member to check the n − 1 shares it receives.
    pub verify_shares_s: f64,
    /// Key setup per member: deal + check.
    pub setup_per_member_s: f64,
    /// Seconds for one partial signature.
    pub partial_sign_s: f64,
    /// Seconds to combine t partial signatures.
    pub combine_s: f64,
    /// Seconds to verify the combined signature.
    pub verify_s: f64,
}

/// Runs the prototype for every configured size.
pub fn threshold(
    seed: u64,
    config: &CryptoTestsConfig,
) -> (Vec<ThresholdRow>, Vec<ThresholdTimingRow>) {
    let (mut rows, mut timings) = (Vec::new(), Vec::new());
    for &n in &config.dkg_member_counts {
        let t = config
            .dkg_threshold
            .approvals_needed(n)
            .unwrap_or(n)
            .clamp(1, n);
        let (row, timing) = one_size(seed, n, t);
        rows.push(row);
        timings.push(timing);
    }
    (rows, timings)
}

fn one_size(seed: u64, n: u64, t: u64) -> (ThresholdRow, ThresholdTimingRow) {
    let mut rng = rng_stream(seed, &format!("K5-n{n}"));
    let g1 = G1Projective::generator();
    let polys: Vec<Vec<Scalar>> = (0..n)
        .map(|_| (0..t).map(|_| random_scalar(&mut rng)).collect())
        .collect();
    // Dealing (timed for dealer 0).
    let start = Instant::now();
    let commitments0: Vec<G1Projective> = polys[0].iter().map(|a| g1 * a).collect();
    let _shares0: Vec<Scalar> = (1..=n).map(|j| evaluate(&polys[0], j)).collect();
    let deal_s = start.elapsed().as_secs_f64();
    let mut commitments = vec![commitments0];
    commitments.extend(
        polys[1..]
            .iter()
            .map(|p| p.iter().map(|a| g1 * a).collect::<Vec<_>>()),
    );
    let share = |dealer: usize, member: u64| evaluate(&polys[dealer], member);
    // Member 1 checks the n − 1 shares it receives (timed).
    let start = Instant::now();
    let mut all_ok = true;
    for (dealer, dealt) in commitments.iter().enumerate().skip(1) {
        let s = share(dealer, 1);
        all_ok &= g1 * s == evaluate_commitments(dealt, 1);
    }
    let verify_shares_s = start.elapsed().as_secs_f64();
    // Final shares, group key, threshold signature by members 1..=t.
    let group_pk = G1Affine::from(
        commitments
            .iter()
            .fold(G1Projective::identity(), |acc, c| acc + c[0]),
    );
    let message = b"GB/entropy threshold benchmark";
    let signers: Vec<u64> = (1..=t).collect();
    let mut partials = Vec::new();
    let mut partial_sign_s = 0.0;
    for &j in &signers {
        let x_j = (0..n as usize).fold(Scalar::from(0u64), |acc, d| acc + share(d, j));
        let mut be = x_j.to_bytes();
        be.reverse();
        let start = Instant::now();
        let sig = SecretKey::from_bytes(&be).map(|sk| sk.sign(message, SIG_DST, &[]).to_bytes());
        partial_sign_s = start.elapsed().as_secs_f64();
        match sig {
            Ok(s) => partials.push((j, s)),
            Err(_) => all_ok = false,
        }
    }
    let start = Instant::now();
    let combined = partials
        .iter()
        .fold(G2Projective::identity(), |acc, (j, s)| {
            let point = Option::<G2Affine>::from(G2Affine::from_compressed(s)).unwrap_or_default();
            acc + G2Projective::from(point) * lagrange_at_zero(*j, &signers)
        });
    let combined = G2Affine::from(combined).to_compressed();
    let combine_s = start.elapsed().as_secs_f64();
    let pk_bytes = group_pk.to_compressed();
    let start = Instant::now();
    let verifies =
        PublicKey::from_bytes(&pk_bytes).is_ok() && verify(&pk_bytes, message, &combined);
    let verify_s = start.elapsed().as_secs_f64();
    let row = ThresholdRow {
        members: n,
        threshold: t,
        messages_sent: n,
        messages_received: 2 * (n - 1),
        bytes_sent: (n - 1) * 32 + t * 48,
        bytes_received: (n - 1) * 32 + (n - 1) * t * 48,
        g1_multiplications: t + (n - 1) * (t + 1),
        combined_signature_verifies: verifies && all_ok,
    };
    let timing = ThresholdTimingRow {
        members: n,
        threshold: t,
        deal_s,
        verify_shares_s,
        setup_per_member_s: deal_s + verify_shares_s,
        partial_sign_s,
        combine_s,
        verify_s,
    };
    (row, timing)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn any_threshold_of_members_produces_a_signature_valid_under_blst() {
        let (row, _) = one_size(9, 7, 5);
        assert!(row.combined_signature_verifies);
        assert_eq!(row.bytes_sent, 6 * 32 + 5 * 48);
    }

    #[test]
    fn lagrange_coefficients_recover_the_constant_term() {
        // f(x) = 3 + 5x + 7x²: Σ λ_j f(j) over three points equals f(0) = 3.
        let f = [Scalar::from(3u64), Scalar::from(5u64), Scalar::from(7u64)];
        let points = [1u64, 2, 4];
        let total = points.iter().fold(Scalar::from(0u64), |acc, j| {
            acc + lagrange_at_zero(*j, &points) * evaluate(&f, *j)
        });
        assert_eq!(total, Scalar::from(3u64));
    }
}
