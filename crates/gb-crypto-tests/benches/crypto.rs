//! C4 benchmarks under criterion: BLS sign, verify, aggregate, aggregate-verify and entropy
//! verification for 3, 10, 27, 40, 60 and 100 signers, and one SHA-256 chain step.
//!
//! Run with `cargo bench -p gb-crypto-tests`. `gb crypto` records a quicker timing of the same
//! operations with machine information.

use blst::min_pk::{AggregateSignature, PublicKey, Signature};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use gb_crypto_tests::common::{header_for, random_keypair, target_for};
use gb_protocol::chain::ChainInputs;
use gb_protocol::entropy::{
    Bitfield, Keypair, SIG_DST, entropy_aggregate, member_message, miner_message, verify,
    verify_entropy,
};
use gb_runlog::rng_stream;
use std::hint::black_box;

const SIGNERS: [usize; 6] = [3, 10, 27, 40, 60, 100];

fn benches(c: &mut Criterion) {
    let mut rng = rng_stream(20261005, "bench");
    let keys: Vec<Keypair> = (0..100).map(|_| random_keypair(&mut rng)).collect();
    let miner = random_keypair(&mut rng);
    let header = header_for(&mut rng, miner.public, target_for(64));
    let msg = miner_message(&header);
    let sig = miner.sign(&msg);
    c.bench_function("bls_sign", |b| b.iter(|| miner.sign(black_box(&msg))));
    c.bench_function("bls_verify", |b| {
        b.iter(|| verify(&miner.public, black_box(&msg), &sig))
    });
    let inputs = ChainInputs::new(&header, [1; 32], 1_001);
    let h0 = inputs.first();
    c.bench_function("sha256_chain_step", |b| {
        b.iter(|| inputs.next(black_box(&h0), 1))
    });
    let member_msg = member_message(&header, &sig);
    let sigs: Vec<[u8; 96]> = keys.iter().map(|k| k.sign(&member_msg)).collect();
    let points: Vec<Signature> = sigs
        .iter()
        .filter_map(|s| Signature::from_bytes(s).ok())
        .collect();
    let pks: Vec<PublicKey> = keys
        .iter()
        .filter_map(|k| PublicKey::from_bytes(&k.public).ok())
        .collect();
    let mut group = c.benchmark_group("by_signers");
    for n in SIGNERS {
        let refs: Vec<&Signature> = points[..n].iter().collect();
        group.bench_with_input(BenchmarkId::new("aggregate", n), &refs, |b, r| {
            b.iter(|| AggregateSignature::aggregate(black_box(r), true).ok())
        });
        if let Ok(agg) = AggregateSignature::aggregate(&refs, true).map(|a| a.to_signature()) {
            let pk_refs: Vec<&PublicKey> = pks[..n].iter().collect();
            group.bench_with_input(
                BenchmarkId::new("aggregate_verify_one_message", n),
                &pk_refs,
                |b, p| {
                    b.iter(|| agg.fast_aggregate_verify(true, &member_msg, SIG_DST, black_box(p)))
                },
            );
        }
        let bitfield = Bitfield::from_seats(n, &(0..n).collect::<Vec<_>>());
        let member_keys: Vec<[u8; 48]> = keys[..n].iter().map(|k| k.public).collect();
        if let Ok((agg, _)) = entropy_aggregate(&sig, &sigs[..n], &bitfield) {
            group.bench_with_input(BenchmarkId::new("entropy_verify", n), &agg, |b, a| {
                b.iter(|| verify_entropy(&header, &sig, &member_keys, &bitfield, black_box(a)))
            });
        }
    }
    group.finish();
}

criterion_group!(crypto, benches);
criterion_main!(crypto);
