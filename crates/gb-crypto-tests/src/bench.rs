//! C4 — timings of the protocol's cryptography, and a CPU estimate for a §13 testnet witness
//! server. Timings depend on the machine, so `gb crypto` writes them under `bench/`, outside
//! the reproducible outputs. `cargo bench -p gb-crypto-tests` runs the same operations under
//! criterion.

use crate::common::{header_for, random_keypair, target_for};
use blst::min_pk::{AggregateSignature, PublicKey, Signature};
use gb_config::CryptoTestsConfig;
use gb_protocol::chain::ChainInputs;
use gb_protocol::entropy::{
    Bitfield, Keypair, SIG_DST, entropy_aggregate, member_message, miner_message, verify,
    verify_entropy,
};
use gb_runlog::rng_stream;
use serde::Serialize;
use std::hint::black_box;
use std::time::Instant;

/// Operations per second of `op`, run for at least `min_seconds` on one core.
pub fn ops_per_second(min_seconds: f64, mut op: impl FnMut()) -> f64 {
    op();
    let start = Instant::now();
    let mut count = 0u64;
    loop {
        op();
        count += 1;
        let elapsed = start.elapsed().as_secs_f64();
        if elapsed >= min_seconds {
            return count as f64 / elapsed;
        }
    }
}

/// One timing row.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TimingRow {
    /// Operation.
    pub operation: &'static str,
    /// Signers involved (1 for single operations).
    pub signers: u64,
    /// Operations per second on one core.
    pub ops_per_second: f64,
    /// Microseconds per operation.
    pub microseconds: f64,
}

fn timing(operation: &'static str, signers: u64, ops: f64) -> TimingRow {
    TimingRow {
        operation,
        signers,
        ops_per_second: ops,
        microseconds: 1e6 / ops,
    }
}

/// Times BLS sign, verify, aggregate, aggregate-verify and entropy verification for each
/// signer count, and one SHA-256 chain step.
pub fn timings(seed: u64, config: &CryptoTestsConfig) -> Vec<TimingRow> {
    let t = config.bench_min_seconds;
    let mut rng = rng_stream(seed, "K4");
    let max = config
        .bench_signer_counts
        .iter()
        .copied()
        .max()
        .unwrap_or(1) as usize;
    let keys: Vec<Keypair> = (0..max).map(|_| random_keypair(&mut rng)).collect();
    let miner = random_keypair(&mut rng);
    let header = header_for(&mut rng, miner.public, target_for(64));
    let msg = miner_message(&header);
    let sig = miner.sign(&msg);
    let mut rows = vec![
        timing(
            "BLS sign",
            1,
            ops_per_second(t, || {
                black_box(miner.sign(black_box(&msg)));
            }),
        ),
        timing(
            "BLS verify",
            1,
            ops_per_second(t, || {
                black_box(verify(&miner.public, &msg, &sig));
            }),
        ),
    ];
    let inputs = ChainInputs::new(&header, [1; 32], 1_001);
    let h0 = inputs.first();
    rows.push(timing(
        "SHA-256 chain step",
        1,
        ops_per_second(t, || {
            black_box(inputs.next(black_box(&h0), 1));
        }),
    ));
    let member_msg = member_message(&header, &sig);
    let member_sigs: Vec<[u8; 96]> = keys.iter().map(|k| k.sign(&member_msg)).collect();
    let points: Vec<Signature> = member_sigs
        .iter()
        .filter_map(|s| Signature::from_bytes(s).ok())
        .collect();
    let pks: Vec<PublicKey> = keys
        .iter()
        .filter_map(|k| PublicKey::from_bytes(&k.public).ok())
        .collect();
    for &n in &config.bench_signer_counts {
        let n_us = n as usize;
        let refs: Vec<&Signature> = points[..n_us].iter().collect();
        rows.push(timing(
            "aggregate signatures (with subgroup checks)",
            n,
            ops_per_second(t, || {
                black_box(AggregateSignature::aggregate(black_box(&refs), true).ok());
            }),
        ));
        let agg = AggregateSignature::aggregate(&refs, true)
            .map(|a| a.to_signature())
            .ok();
        let pk_refs: Vec<&PublicKey> = pks[..n_us].iter().collect();
        if let Some(agg) = agg {
            rows.push(timing(
                "aggregate-verify, one message (PoWit)",
                n,
                ops_per_second(t, || {
                    black_box(agg.fast_aggregate_verify(
                        true,
                        &member_msg,
                        SIG_DST,
                        black_box(&pk_refs),
                    ));
                }),
            ));
        }
        let bitfield = Bitfield::from_seats(n_us, &(0..n_us).collect::<Vec<_>>());
        let member_keys: Vec<[u8; 48]> = keys[..n_us].iter().map(|k| k.public).collect();
        if let Ok((entropy_agg, _)) = entropy_aggregate(&sig, &member_sigs[..n_us], &bitfield) {
            rows.push(timing(
                "entropy verify (miner + members, SPEC §3.4)",
                n,
                ops_per_second(t, || {
                    black_box(verify_entropy(
                        &header,
                        &sig,
                        &member_keys,
                        &bitfield,
                        black_box(&entropy_agg),
                    ));
                }),
            ));
        }
    }
    rows
}

/// One row of the §13 witness-server CPU estimate.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ServerCpuRow {
    /// Miners served by the server's WC.
    pub miners: u64,
    /// Witness nodes on the server.
    pub witnesses: u64,
    /// Seconds per round.
    pub round_s: f64,
    /// CPU-seconds per round: miners × witnesses × (verify + sign + entropy verify + one
    /// chain step per second of the round).
    pub cpu_seconds_per_round: f64,
    /// Cores kept busy: CPU-seconds per round ÷ round length.
    pub cores_needed: f64,
    /// Logical cores of the machine the timings ran on.
    pub cores_on_this_machine: u64,
}

/// The §13 testnet estimate from the timings.
pub fn server_cpu(config: &CryptoTestsConfig, rows: &[TimingRow]) -> Vec<ServerCpuRow> {
    let w = config.testnet_witnesses_per_server;
    let seconds = |op: &str, signers: u64| {
        rows.iter()
            .find(|r| r.operation == op && r.signers == signers)
            .map_or(f64::NAN, |r| r.microseconds / 1e6)
    };
    let entropy = seconds("entropy verify (miner + members, SPEC §3.4)", w);
    let per_miner_witness = seconds("BLS verify", 1)
        + seconds("BLS sign", 1)
        + entropy
        + config.testnet_round_s * seconds("SHA-256 chain step", 1);
    let cores = std::thread::available_parallelism().map_or(1, |n| n.get() as u64);
    config
        .testnet_miners
        .iter()
        .map(|&m| {
            let cpu = m as f64 * w as f64 * per_miner_witness;
            ServerCpuRow {
                miners: m,
                witnesses: w,
                round_s: config.testnet_round_s,
                cpu_seconds_per_round: cpu,
                cores_needed: cpu / config.testnet_round_s,
                cores_on_this_machine: cores,
            }
        })
        .collect()
}
