//! C2 — the older "sort fields by hexadecimal value before hashing" rule (SPEC §8 S14)
//! against fixed field order (Appendix A).
//!
//! Sorting discards which field a value came from, so any two fields of the same width can
//! exchange values without changing the hash. Fixed order hashes each field in its place.

use crate::common::{header_for, random_hash, target_for};
use gb_protocol::encoding::{Address, Header};
use gb_protocol::hash::{tagged, to_hex};
use gb_runlog::rng_stream;
use rand_core::Rng;
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Hash under the old rule: hex of each field, sorted, concatenated, SHA-256.
pub fn sorted_hex_hash(fields: &[Vec<u8>]) -> [u8; 32] {
    let mut hex: Vec<String> = fields.iter().map(|f| to_hex(f)).collect();
    hex.sort();
    Sha256::digest(hex.concat().as_bytes()).into()
}

/// A header's fields in canonical order.
pub fn header_fields(h: &Header) -> Vec<Vec<u8>> {
    let (kind, field) = h.address.encode();
    vec![
        h.version.to_be_bytes().to_vec(),
        h.height.to_be_bytes().to_vec(),
        h.prev_hash.to_vec(),
        h.candidate_pk.to_vec(),
        h.reward_wallet.to_vec(),
        vec![kind],
        field.to_vec(),
        h.kwc_id.to_be_bytes().to_vec(),
        h.target.to_vec(),
    ]
}

/// Chain-step inputs `(prev_hash, height, timestamp, nonce, E, header_digest)` (SPEC §3.5).
fn step_fields(
    prev: [u8; 32],
    height: u64,
    timestamp: u64,
    nonce: u64,
    e: [u8; 32],
    d: [u8; 32],
) -> Vec<Vec<u8>> {
    vec![
        prev.to_vec(),
        height.to_be_bytes().to_vec(),
        timestamp.to_be_bytes().to_vec(),
        nonce.to_be_bytes().to_vec(),
        e.to_vec(),
        d.to_vec(),
    ]
}

/// Produces a pair of distinct inputs from the random stream.
type PairMaker<'a> = dyn FnMut(&mut rand_chacha::ChaCha20Rng) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) + 'a;

fn fixed_hash(fields: &[Vec<u8>]) -> [u8; 32] {
    let refs: Vec<&[u8]> = fields.iter().map(|f| f.as_slice()).collect();
    tagged(b"GB/fixed", &refs)
}

/// One row of table K2.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SortedHexRow {
    /// Experiment.
    pub experiment: &'static str,
    /// Pairs of distinct inputs compared.
    pub pairs: u64,
    /// Pairs with equal hashes under the sorted-hex rule.
    pub sorted_hex_collisions: u64,
    /// Pairs with equal hashes under fixed field order.
    pub fixed_order_collisions: u64,
}

/// Runs C2.
pub fn sorted_hex(seed: u64, trials: u64) -> Vec<SortedHexRow> {
    let mut rng = rng_stream(seed, "K2");
    let target = target_for(64);
    let mut rows = Vec::new();
    let mut run = |experiment: &'static str, make: &mut PairMaker<'_>| {
        let (mut s, mut f) = (0, 0);
        for _ in 0..trials {
            let (a, b) = make(&mut rng);
            debug_assert_ne!(a, b);
            s += u64::from(sorted_hex_hash(&a) == sorted_hex_hash(&b));
            f += u64::from(fixed_hash(&a) == fixed_hash(&b));
        }
        rows.push(SortedHexRow {
            experiment,
            pairs: trials,
            sorted_hex_collisions: s,
            fixed_order_collisions: f,
        });
    };
    run(
        "header: previous hash and reward wallet swapped (32 bytes each)",
        &mut |r| {
            let pk = random_pk(r);
            let a = header_for(r, pk, target);
            let mut b = a;
            std::mem::swap(&mut b.prev_hash, &mut b.reward_wallet);
            (header_fields(&a), header_fields(&b))
        },
    );
    run(
        "header: height and KWC ID swapped (8 bytes each)",
        &mut |r| {
            let pk = random_pk(r);
            let mut a = header_for(r, pk, target);
            a.kwc_id = r.next_u64();
            let mut b = a;
            std::mem::swap(&mut b.height, &mut b.kwc_id);
            (header_fields(&a), header_fields(&b))
        },
    );
    run(
        "chain step: height and nonce swapped, timestamps matched",
        &mut |r| {
            let (prev, e, d) = (random_hash(r), random_hash(r), random_hash(r));
            let (height, nonce) = (1_000 + r.next_u64() % 1_000_000, r.next_u64() % 1_000);
            let ts = 2_000_000 + r.next_u64() % 1_000;
            (
                step_fields(prev, height, ts, nonce, e, d),
                step_fields(prev, nonce, ts, height, e, d),
            )
        },
    );
    run("random distinct headers", &mut |r| {
        let (p1, p2) = (random_pk(r), random_pk(r));
        (
            header_fields(&header_for(r, p1, target)),
            header_fields(&header_for(r, p2, target)),
        )
    });
    rows
}

fn random_pk<R: Rng + ?Sized>(r: &mut R) -> [u8; 48] {
    let mut pk = [0u8; 48];
    pk[..32].copy_from_slice(&random_hash(r));
    pk[32..].copy_from_slice(&random_hash(r)[..16]);
    pk
}

/// Distinct headers that share one sorted-hex hash with `h`, found by permuting values among
/// fields of equal width (32-byte: previous hash, wallet, target; 8-byte: height, address,
/// KWC ID). Fixed order gives 1.
pub fn equivalent_headers(h: &Header) -> usize {
    const PERMS: [[usize; 3]; 6] = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    let reference = sorted_hex_hash(&header_fields(h));
    let wide = [h.prev_hash, h.reward_wallet, h.target];
    let (_, addr) = h.address.encode();
    let narrow = [h.height, u64::from_be_bytes(addr), h.kwc_id];
    let mut distinct = std::collections::BTreeSet::new();
    for p in PERMS {
        for q in PERMS {
            let mut x = *h;
            x.prev_hash = wide[p[0]];
            x.reward_wallet = wide[p[1]];
            x.target = wide[p[2]];
            x.height = narrow[q[0]];
            x.address = Address::Ipv6Prefix64(narrow[q[1]].to_be_bytes());
            x.kwc_id = narrow[q[2]];
            if sorted_hex_hash(&header_fields(&x)) == reference {
                distinct.insert(x.encode());
            }
        }
    }
    distinct.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swaps_collide_under_sorting_but_not_under_fixed_order() {
        let rows = sorted_hex(1, 200);
        for r in &rows[..3] {
            assert_eq!(r.sorted_hex_collisions, r.pairs, "{r:?}");
            assert_eq!(r.fixed_order_collisions, 0, "{r:?}");
        }
        assert_eq!(rows[3].sorted_hex_collisions, 0);
    }

    #[test]
    fn thirty_six_field_assignments_share_one_sorted_hash() {
        let mut rng = rng_stream(2, "test");
        let pk = random_pk(&mut rng);
        let h = header_for(&mut rng, pk, target_for(64));
        assert_eq!(equivalent_headers(&h), 36);
    }
}
