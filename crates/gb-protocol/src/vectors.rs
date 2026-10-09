//! Test vectors: inputs and the expected hashes, signatures and verdicts, which the M3
//! simulator and the Stage 3 node must reproduce.
//!
//! [`render`] produces `vectors/protocol_v1.json` deterministically from fixed seeds; the
//! `gb vectors` command writes it, and a test requires the committed file to equal a fresh
//! rendering byte for byte.

use crate::allocation::insertion_position;
use crate::chain::{ChainInputs, StartRule, chain_start};
use crate::committee::lottery_position;
use crate::encoding::{Address, Header, block_hash};
use crate::entropy::{
    Bitfield, Keypair, SignatureBytes, aggregate, entropy_aggregate, member_message, miner_message,
    powit_message,
};
use crate::error::ProtocolError;
use crate::hash::{Hash, tagged, to_hex};
use crate::issuance::variant_b_target;
use crate::validate::{
    Block, ForkCandidate, KwcKeys, QuorumRule, Reception, Rejection, Rules, Tip, fork_choice,
    validate, witness_equivocators,
};
use serde_json::{Value, json};

/// File name of the vectors, in `crates/gb-protocol/vectors/`.
pub const VECTOR_FILE: &str = "protocol_v1.json";

fn seed(label: &str, i: u64) -> Hash {
    tagged(b"GB/vectors", &[label.as_bytes(), &i.to_be_bytes()])
}

fn header(miner: &Keypair, address: Address, target: Hash) -> Header {
    Header {
        version: crate::PROTOCOL_VERSION,
        height: 10,
        prev_hash: seed("prev", 0),
        candidate_pk: miner.public,
        reward_wallet: seed("wallet", 0),
        address,
        kwc_id: 7,
        target,
    }
}

fn header_json(h: &Header) -> Value {
    let (kind, field) = h.address.encode();
    json!({
        "version": h.version,
        "height": h.height,
        "prev_hash": to_hex(&h.prev_hash),
        "candidate_pk": to_hex(&h.candidate_pk),
        "reward_wallet": to_hex(&h.reward_wallet),
        "address_type": kind,
        "address": to_hex(&field),
        "kwc_id": h.kwc_id,
        "target": to_hex(&h.target),
        "encoding": to_hex(&h.encode()),
        "header_digest": to_hex(&h.digest()),
    })
}

fn rejection_name(r: Result<Hash, Rejection>) -> String {
    match r {
        Ok(_) => "valid".to_string(),
        Err(e) => format!("{e:?}"),
    }
}

/// Builds every vector.
pub fn generate() -> Result<Value, ProtocolError> {
    let members: Vec<Keypair> = (0..4)
        .map(|i| Keypair::from_seed(&seed("member", i)))
        .collect::<Result<_, _>>()?;
    let miner = Keypair::from_seed(&seed("miner", 0))?;
    let keys: Vec<Value> = std::iter::once(("miner", &miner))
        .chain(members.iter().map(|k| ("member", k)))
        .map(|(role, k)| {
            json!({
                "role": role,
                "secret": to_hex(&k.secret_bytes()),
                "public": to_hex(&k.public),
                "proof_of_possession": to_hex(&k.proof_of_possession()),
            })
        })
        .collect();

    let mut target = [0u8; 32];
    target[0] = 0x20;
    let h6 = header(
        &miner,
        Address::Ipv6Prefix64([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1]),
        target,
    );
    let h4 = header(&miner, Address::Ipv4([192, 0, 2, 7]), target);

    // Entropy for the IPv6 header, all four members signing.
    let sig_m = miner.sign(&miner_message(&h6));
    let msg = member_message(&h6, &sig_m);
    let sigs: Vec<SignatureBytes> = members.iter().map(|k| k.sign(&msg)).collect();
    let all = Bitfield::from_seats(4, &[0, 1, 2, 3]);
    let (agg, e) = entropy_aggregate(&sig_m, &sigs, &all)?;

    // The chain under start rule (a) after a tip at t = 1,000.
    let tip = Tip {
        hash: h6.prev_hash,
        height: 9,
        timestamp: 1_000,
    };
    let t0 = chain_start(tip.timestamp, StartRule::A);
    let inputs = ChainInputs::new(&h6, e, t0);
    let steps: Vec<String> = inputs.steps().take(5).map(|(_, h)| to_hex(&h)).collect();
    let (n, h_n) = inputs
        .winning_step(&target, 100_000)
        .ok_or(ProtocolError::Empty("no winning step"))?;

    // A full block with a 3-of-4 PoWit, and its verdicts.
    let mut block = Block {
        header: h6,
        miner_signature: sig_m,
        entropy_aggregate: agg,
        entropy_signers: all.clone(),
        winning_step: n,
        timestamp: t0 + n,
        powit_aggregate: [0; 96],
        powit_signers: Bitfield::from_seats(4, &[0, 1, 2]),
    };
    let bhash = block.hash();
    let pmsg = powit_message(&bhash);
    let psigs: Vec<SignatureBytes> = members[..3].iter().map(|k| k.sign(&pmsg)).collect();
    block.powit_aggregate = aggregate(&psigs)?;
    let kwc = KwcKeys::new(
        &members
            .iter()
            .map(|k| (k.public, k.proof_of_possession()))
            .collect::<Vec<_>>(),
    )?;
    let quorum = QuorumRule::Pool {
        seats: 4,
        quorum: 3,
    };
    let rules = Rules {
        clock_tolerance_s: 2.0,
        powit_deadline_s: Some(10.0),
        start_rule: StartRule::A,
        max_steps: 1_000_000,
    };
    let ts = block.timestamp as f64;
    let check = |b: &Block, block_at: f64, powit_at: f64| {
        rejection_name(validate(
            b,
            &tip,
            &kwc,
            &quorum,
            &Reception { block_at, powit_at },
            &rules,
            &|_| true,
        ))
    };
    let mut wrong_time = block.clone();
    wrong_time.timestamp += 1;
    let verdicts = json!([
        { "case": "valid block", "block_at": ts, "powit_at": ts + 1.0, "verdict": check(&block, ts, ts + 1.0) },
        { "case": "received 2.5 s before its timestamp (δ = 2 s)", "block_at": ts - 2.5, "powit_at": ts, "verdict": check(&block, ts - 2.5, ts) },
        { "case": "PoWit 10.5 s after the timestamp (D = 10 s)", "block_at": ts, "powit_at": ts + 10.5, "verdict": check(&block, ts, ts + 10.5) },
        { "case": "timestamp is t0 + N + 1", "block_at": ts + 1.0, "powit_at": ts + 1.0, "verdict": check(&wrong_time, ts + 1.0, ts + 1.0) },
    ]);

    // Witness double-signing (§4.6): a second block from the same miner at the same height, its
    // PoWit signed by seats 1, 2 and 3, against the first block's seats 0, 1 and 2.
    let mut second = block.clone();
    second.header.reward_wallet = seed("wallet", 1);
    let second_hash = second.hash();
    let second_msg = powit_message(&second_hash);
    let second_sigs: Vec<SignatureBytes> =
        members[1..].iter().map(|k| k.sign(&second_msg)).collect();
    second.powit_signers = Bitfield::from_seats(4, &[1, 2, 3]);
    second.powit_aggregate = aggregate(&second_sigs)?;
    let witness_equivocation = json!({
        "first_block_hash": to_hex(&bhash),
        "first_powit_signers": to_hex(block.powit_signers.as_bytes()),
        "second_block_hash": to_hex(&second_hash),
        "second_powit_signers": to_hex(second.powit_signers.as_bytes()),
        "second_powit_aggregate": to_hex(&second.powit_aggregate),
        "equivocating_seats": witness_equivocators(&block, &second, &kwc),
    });

    // Fork choice (§3.7): longest chain, then earlier timestamp, then lower hash.
    let candidate = |height: u64, timestamp: u64, label: &str| ForkCandidate {
        height,
        timestamp,
        hash: seed(label, 0),
    };
    let fork_cases: Vec<Value> = [
        (
            "longer chain wins",
            candidate(11, 2_000, "fork-a"),
            candidate(10, 1_000, "fork-b"),
        ),
        (
            "same height: earlier timestamp wins",
            candidate(10, 1_005, "fork-c"),
            candidate(10, 1_006, "fork-d"),
        ),
        (
            "same height and timestamp: lower hash wins",
            candidate(10, 1_005, "fork-e"),
            candidate(10, 1_005, "fork-f"),
        ),
    ]
    .iter()
    .map(|(case, a, b)| {
        json!({
            "case": case,
            "a": { "height": a.height, "timestamp": a.timestamp, "hash": to_hex(&a.hash) },
            "b": { "height": b.height, "timestamp": b.timestamp, "hash": to_hex(&b.hash) },
            "preferred": if fork_choice(a, b) == std::cmp::Ordering::Greater { "b" } else { "a" },
        })
    })
    .collect();

    let allocation: Vec<Value> = [(0u64, 0u64), (1, 9), (2, 999), (3, 2_899_999)]
        .iter()
        .map(|(i, filled)| {
            let (id, beacon) = (seed("id", *i), seed("beacon", *i));
            json!({
                "id": to_hex(&id),
                "beacon": to_hex(&beacon),
                "filled": filled,
                "position": insertion_position(&id, &beacon, *filled),
            })
        })
        .collect();
    let committee: Vec<Value> = (0..4u64)
        .map(|draw| {
            let beacon = seed("cac-beacon", 0);
            json!({
                "beacon": to_hex(&beacon),
                "draw": draw,
                "active": 2_900_000,
                "position": lottery_position(&beacon, draw, 2_900_000),
            })
        })
        .collect();
    let issuance: Vec<Value> = [(1_000u64, 30u64), (2_900_000, 30)]
        .iter()
        .map(|(m, i)| json!({ "online_miners": m, "interval_s": i, "target": to_hex(&variant_b_target(*m, *i)) }))
        .collect();

    Ok(json!({
        "protocol_version": crate::PROTOCOL_VERSION,
        "spec": "SPEC v0.5 Appendix A [P]",
        "keys": keys,
        "headers": [header_json(&h6), header_json(&h4)],
        "entropy": {
            "header_digest": to_hex(&h6.digest()),
            "miner_signature": to_hex(&sig_m),
            "member_signatures": sigs.iter().map(|s| to_hex(s)).collect::<Vec<_>>(),
            "signer_bitfield": to_hex(all.as_bytes()),
            "aggregate": to_hex(&agg),
            "entropy": to_hex(&e),
        },
        "chain": {
            "t0": t0,
            "first_steps": steps,
            "target": to_hex(&target),
            "winning_step": n,
            "winning_hash": to_hex(&h_n),
            "timestamp": t0 + n,
            "block_hash": to_hex(&block_hash(&h6, &e, n)),
        },
        "powit": {
            "signer_bitfield": to_hex(block.powit_signers.as_bytes()),
            "aggregate": to_hex(&block.powit_aggregate),
        },
        "validation": verdicts,
        "witness_equivocation": witness_equivocation,
        "fork_choice": fork_cases,
        "allocation": allocation,
        "committee": committee,
        "issuance": issuance,
    }))
}

/// The vectors as pretty-printed JSON with a trailing newline.
pub fn render() -> Result<String, ProtocolError> {
    let value = generate()?;
    let mut text = serde_json::to_string_pretty(&value)
        .map_err(|e| ProtocolError::Bls(format!("JSON: {e}")))?;
    text.push('\n');
    Ok(text)
}
