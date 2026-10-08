//! C6 — equivalence of the M3 simulator's entropy stand-in.
//!
//! The simulator may replace the real entropy (BLS aggregate of the miner and its members,
//! hashed) by 32 uniform random bytes. This module checks, with real signatures, that the two
//! give the same winning-step distribution (two-sample χ²) and that both look uniform (KS on
//! the top 53 bits of E).

use crate::common::{attempts_to_win, header_for, random_hash, random_keypair, target_for};
use crate::stats::{chi_square_two_sample, ks_uniform};
use gb_config::CryptoTestsConfig;
use gb_protocol::entropy::{Bitfield, entropy_aggregate, member_message, miner_message};
use gb_runlog::rng_stream;
use serde::Serialize;

/// One row of table K6.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EquivalenceRow {
    /// Test.
    pub test: &'static str,
    /// Trials per sample.
    pub trials: u64,
    /// Test statistic.
    pub statistic: f64,
    /// p-value.
    pub p_value: f64,
    /// True when the p-value is at least the configured minimum.
    pub passes: bool,
}

fn top_bits(e: &[u8; 32]) -> f64 {
    let mut top = [0u8; 8];
    top.copy_from_slice(&e[..8]);
    (u64::from_be_bytes(top) >> 11) as f64 / (1u64 << 53) as f64
}

/// Bin index of attempts-to-win, with edges at 1/8, 1/4, … 4 times the expected attempts.
fn bin(attempts: u64, expected: u64) -> usize {
    let x = attempts as f64 / expected as f64;
    [0.125, 0.25, 0.5, 0.75, 1.0, 1.5, 2.0, 3.0, 4.0]
        .iter()
        .position(|edge| x <= *edge)
        .unwrap_or(9)
}

/// Runs C6.
pub fn equivalence(seed: u64, config: &CryptoTestsConfig) -> Vec<EquivalenceRow> {
    let e = config.expected_winning_attempts;
    let target = target_for(e);
    let cap = 1_000 * e;
    let mut rng = rng_stream(seed, "K6-real");
    let mut stand_in = rng_stream(seed, "K6-stand-in");
    let miner = random_keypair(&mut rng);
    let m = config.equivalence_members as usize;
    let members: Vec<_> = (0..m).map(|_| random_keypair(&mut rng)).collect();
    let all = Bitfield::from_seats(m, &(0..m).collect::<Vec<_>>());
    let (mut real_bins, mut fake_bins) = (vec![0u64; 10], vec![0u64; 10]);
    let (mut real_u, mut fake_u) = (Vec::new(), Vec::new());
    for _ in 0..config.equivalence_trials {
        let h = header_for(&mut rng, miner.public, target);
        let sig_m = miner.sign(&miner_message(&h));
        let msg = member_message(&h, &sig_m);
        let sigs: Vec<[u8; 96]> = members.iter().map(|k| k.sign(&msg)).collect();
        let real = entropy_aggregate(&sig_m, &sigs, &all)
            .map(|(_, e)| e)
            .unwrap_or([0; 32]);
        let fake = random_hash(&mut stand_in);
        real_bins[bin(attempts_to_win(&h, real, cap), e)] += 1;
        fake_bins[bin(attempts_to_win(&h, fake, cap), e)] += 1;
        real_u.push(top_bits(&real));
        fake_u.push(top_bits(&fake));
    }
    let n = config.equivalence_trials;
    let min = config.equivalence_min_p_value;
    let (chi, _, chi_p) = chi_square_two_sample(&real_bins, &fake_bins);
    let (d_real, p_real) = ks_uniform(&real_u);
    let (d_fake, p_fake) = ks_uniform(&fake_u);
    vec![
        EquivalenceRow {
            test: "winning-step distribution, real entropy vs stand-in (two-sample χ², 10 bins)",
            trials: n,
            statistic: chi,
            p_value: chi_p,
            passes: chi_p >= min,
        },
        EquivalenceRow {
            test: "real entropy uniform (KS on the top 53 bits)",
            trials: n,
            statistic: d_real,
            p_value: p_real,
            passes: p_real >= min,
        },
        EquivalenceRow {
            test: "stand-in entropy uniform (KS on the top 53 bits)",
            trials: n,
            statistic: d_fake,
            p_value: p_fake,
            passes: p_fake >= min,
        },
    ]
}
