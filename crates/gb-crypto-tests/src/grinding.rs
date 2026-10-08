//! C1 — entropy grinding (SPEC §8 S11) with real SHA-256 and BLS12-381.
//!
//! Each trial builds a fresh header and the KWC's entropy under one flow, then measures the
//! attempts to the first winning step, `N + 1`, at a small test difficulty. An attacker with a
//! budget of G tries keeps the best of G candidate entropies; an honest miner has one.
//! Advantage = mean honest attempts ÷ mean attacker attempts, with a 95% confidence interval
//! from batch means.
//!
//! - **(a) old flow, miner signs last with a non-unique signature.** Members sign the header
//!   first; the miner's signature over the header and a free nonce stands in for a randomised
//!   signature scheme, so each nonce gives a new valid entropy.
//! - **(b) subset selection.** Current signatures, but the miner may aggregate any subset of
//!   member signatures that meets the quorum.
//! - **(c) colluding last witness, old flow.** The last member signs with a free nonce.
//! - **(c′) colluding last witness, current flow.** Its only choices are to sign or withhold
//!   (withholding while online triggers One Chance, SPEC §4.5): at most two entropies.
//! - **(d) header equivocation** must be detected (SPEC §3.4).
//! - **(e) current flow:** BLS signatures are unique, so re-signing yields the same bytes and
//!   the same entropy; the attacker's attempts follow the honest distribution.

use crate::common::{attempts_to_win, expected_best_of, header_for, random_hash, target_for};
use blst::min_pk::{AggregateSignature, SecretKey, Signature};
use gb_analytic::mc::ratio_of_sums;
use gb_config::CryptoTestsConfig;
use gb_protocol::encoding::Header;
use gb_protocol::entropy::{
    Bitfield, ENTROPY_TAG, MINER_TAG, SIG_DST, SignedHeader, entropy_output, is_equivocation,
    miner_message,
};
use gb_runlog::rng_stream;
use rand_core::Rng;
use serde::Serialize;

/// A signer with its `blst` key (signatures kept as points to avoid re-parsing).
struct Signer {
    secret: SecretKey,
    public: [u8; 48],
}

impl Signer {
    fn new<R: Rng + ?Sized>(rng: &mut R) -> Signer {
        loop {
            if let Ok(secret) = SecretKey::key_gen(&random_hash(rng), &[]) {
                let public = secret.sk_to_pk().to_bytes();
                return Signer { secret, public };
            }
        }
    }

    fn sign(&self, message: &[u8]) -> Signature {
        self.secret.sign(message, SIG_DST, &[])
    }
}

fn aggregate(points: &[&Signature]) -> [u8; 96] {
    AggregateSignature::aggregate(points, false)
        .map(|a| a.to_signature().to_bytes())
        .unwrap_or([0; 96])
}

/// One row of table K1.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GrindingRow {
    /// Experiment: a, b, c, c′ or e.
    pub experiment: &'static str,
    /// What the attacker controls.
    pub description: &'static str,
    /// Grinding budget G.
    pub budget: u64,
    /// Trials.
    pub trials: u64,
    /// Mean attempts to win for an honest miner, `E[N + 1]`.
    pub honest_mean_attempts: f64,
    /// Mean attempts to win for the attacker with this budget.
    pub attacker_mean_attempts: f64,
    /// Advantage = honest ÷ attacker.
    pub advantage: f64,
    /// Lower end of the 95% confidence interval.
    pub ci_low: f64,
    /// Upper end of the 95% confidence interval.
    pub ci_high: f64,
    /// Advantage if the G candidate entropies were independent:
    /// `E[N+1] ÷ 1/(1 − (1 − 1/E)^G)` (1 when only one entropy exists).
    pub independent_tries_advantage: f64,
    /// Mean distinct entropies among the G candidates per trial.
    pub distinct_entropies: f64,
}

/// Table K1(d): equivocation detection.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EquivocationRow {
    /// Case.
    pub case: &'static str,
    /// Pairs tested.
    pub pairs: u64,
    /// Pairs flagged as equivocation.
    pub flagged: u64,
    /// Expected number flagged.
    pub expected: u64,
}

struct Trials {
    /// attempts[trial][candidate]
    attempts: Vec<Vec<u64>>,
    distinct: Vec<Vec<f64>>,
}

fn rows(
    experiment: &'static str,
    description: &'static str,
    budgets: &[u64],
    trials: &Trials,
    honest: &[u64],
    config: &CryptoTestsConfig,
    single_entropy: bool,
) -> Vec<GrindingRow> {
    budgets
        .iter()
        .map(|&g| {
            let attacker: Vec<f64> = trials
                .attempts
                .iter()
                .map(|c| c.iter().take(g as usize).copied().min().unwrap_or(0) as f64)
                .collect();
            let honest_f: Vec<f64> = honest.iter().map(|x| *x as f64).collect();
            let est = ratio_of_sums(&honest_f, &attacker, config.batches as usize);
            let n = attacker.len() as f64;
            let distinct = trials
                .distinct
                .iter()
                .map(|d| d.get(g as usize - 1).copied().unwrap_or(1.0))
                .sum::<f64>()
                / n;
            let e = config.expected_winning_attempts;
            GrindingRow {
                experiment,
                description,
                budget: g,
                trials: attacker.len() as u64,
                honest_mean_attempts: honest_f.iter().sum::<f64>() / n,
                attacker_mean_attempts: attacker.iter().sum::<f64>() / n,
                advantage: est.value,
                ci_low: est.value - 1.96 * est.standard_error,
                ci_high: est.value + 1.96 * est.standard_error,
                independent_tries_advantage: if single_entropy {
                    1.0
                } else {
                    e as f64 / expected_best_of(e, g)
                },
                distinct_entropies: distinct,
            }
        })
        .collect()
}

/// Distinct-entropy counts after each candidate.
fn running_distinct(entropies: &[[u8; 32]]) -> Vec<f64> {
    let mut seen = std::collections::BTreeSet::new();
    entropies
        .iter()
        .map(|e| {
            seen.insert(*e);
            seen.len() as f64
        })
        .collect()
}

/// Subsets of `m` members with at least `quorum`, largest first, then lexicographic.
fn subsets(m: usize, quorum: usize, limit: usize) -> Vec<Vec<usize>> {
    let mut all: Vec<Vec<usize>> = (0u64..(1 << m))
        .map(|mask| (0..m).filter(|i| mask >> i & 1 == 1).collect::<Vec<_>>())
        .filter(|s| s.len() >= quorum)
        .collect();
    all.sort_by(|a, b| b.len().cmp(&a.len()).then(a.cmp(b)));
    all.truncate(limit);
    all
}

/// Runs C1 (a), (b), (c), (c′) and (e).
pub fn grinding(seed: u64, config: &CryptoTestsConfig) -> Vec<GrindingRow> {
    let m = config.grinding_members as usize;
    let gmax = config.grinding_budgets.iter().copied().max().unwrap_or(1) as usize;
    let target = target_for(config.expected_winning_attempts);
    let cap = 1_000 * config.expected_winning_attempts;
    let mut key_rng = rng_stream(seed, "K1-keys");
    let miner_key = Signer::new(&mut key_rng);
    let members: Vec<Signer> = (0..m).map(|_| Signer::new(&mut key_rng)).collect();
    let all = Bitfield::from_seats(m, &(0..m).collect::<Vec<_>>());
    let header_with =
        |rng: &mut rand_chacha::ChaCha20Rng| header_for(rng, miner_key.public, target);
    let trials = config.grinding_trials as usize;
    let mut out = Vec::new();

    // (a) old flow: members sign the header first; the miner signs last with a free nonce.
    let mut rng = rng_stream(seed, "K1-a");
    let mut ta = Trials {
        attempts: vec![],
        distinct: vec![],
    };
    for _ in 0..trials {
        let h = header_with(&mut rng);
        let hb = h.encode();
        let member_msg = [b"GB/entropy-old".as_slice(), &hb].concat();
        let member_sigs: Vec<Signature> = members.iter().map(|s| s.sign(&member_msg)).collect();
        let mut entropies = Vec::with_capacity(gmax);
        for nonce in 0..gmax as u64 {
            let msg = [MINER_TAG, &hb, &nonce.to_be_bytes()].concat();
            let sig_m = miner_key.sign(&msg);
            let mut refs: Vec<&Signature> = member_sigs.iter().collect();
            refs.push(&sig_m);
            entropies.push(entropy_output(&aggregate(&refs), &all));
        }
        ta.attempts.push(
            entropies
                .iter()
                .map(|e| attempts_to_win(&h, *e, cap))
                .collect(),
        );
        ta.distinct.push(running_distinct(&entropies));
    }
    let honest_a: Vec<u64> = ta.attempts.iter().map(|c| c[0]).collect();
    out.extend(rows(
        "a",
        "old flow: miner signs last with a non-unique signature (free nonce)",
        &config.grinding_budgets,
        &ta,
        &honest_a,
        config,
        false,
    ));

    // (b) subset selection under current signatures.
    let mut rng = rng_stream(seed, "K1-b");
    let sets = subsets(m, config.subset_quorum as usize, gmax);
    let mut tb = Trials {
        attempts: vec![],
        distinct: vec![],
    };
    for _ in 0..trials {
        let h = header_with(&mut rng);
        let sig_m = miner_key.sign(&miner_message(&h));
        let msg = [ENTROPY_TAG, &h.encode()[..], &sig_m.to_bytes()[..]].concat();
        let member_sigs: Vec<Signature> = members.iter().map(|s| s.sign(&msg)).collect();
        let entropies: Vec<[u8; 32]> = sets
            .iter()
            .map(|set| {
                let mut refs: Vec<&Signature> = vec![&sig_m];
                refs.extend(set.iter().map(|i| &member_sigs[*i]));
                entropy_output(&aggregate(&refs), &Bitfield::from_seats(m, set))
            })
            .collect();
        tb.attempts.push(
            entropies
                .iter()
                .map(|e| attempts_to_win(&h, *e, cap))
                .collect(),
        );
        tb.distinct.push(running_distinct(&entropies));
    }
    let honest_b: Vec<u64> = tb.attempts.iter().map(|c| c[0]).collect();
    let budgets_b: Vec<u64> = config
        .grinding_budgets
        .iter()
        .copied()
        .filter(|g| *g as usize <= sets.len())
        .collect();
    out.extend(rows(
        "b",
        "miner aggregates any member subset meeting the quorum",
        &budgets_b,
        &tb,
        &honest_b,
        config,
        false,
    ));

    // (c) colluding last witness, old flow (free nonce), and (c′) current flow (sign or withhold).
    let mut rng = rng_stream(seed, "K1-c");
    let (mut tc, mut tc2) = (
        Trials {
            attempts: vec![],
            distinct: vec![],
        },
        Trials {
            attempts: vec![],
            distinct: vec![],
        },
    );
    for _ in 0..trials {
        let h = header_with(&mut rng);
        let hb = h.encode();
        let old_msg = [b"GB/entropy-old".as_slice(), &hb].concat();
        let rest: Vec<Signature> = members[..m - 1].iter().map(|s| s.sign(&old_msg)).collect();
        let sig_m_old = miner_key.sign(&[MINER_TAG, &hb].concat());
        let mut entropies = Vec::with_capacity(gmax);
        for nonce in 0..gmax as u64 {
            let last = members[m - 1].sign(&[old_msg.as_slice(), &nonce.to_be_bytes()].concat());
            let mut refs: Vec<&Signature> = rest.iter().collect();
            refs.push(&last);
            refs.push(&sig_m_old);
            entropies.push(entropy_output(&aggregate(&refs), &all));
        }
        tc.attempts.push(
            entropies
                .iter()
                .map(|e| attempts_to_win(&h, *e, cap))
                .collect(),
        );
        tc.distinct.push(running_distinct(&entropies));
        // Current flow: the last member signs (unique) or withholds.
        let sig_m = miner_key.sign(&miner_message(&h));
        let msg = [ENTROPY_TAG, &hb[..], &sig_m.to_bytes()[..]].concat();
        let sigs: Vec<Signature> = members.iter().map(|s| s.sign(&msg)).collect();
        let options: Vec<[u8; 32]> = [m, m - 1]
            .iter()
            .map(|count| {
                let mut refs: Vec<&Signature> = vec![&sig_m];
                refs.extend(sigs[..*count].iter());
                entropy_output(
                    &aggregate(&refs),
                    &Bitfield::from_seats(m, &(0..*count).collect::<Vec<_>>()),
                )
            })
            .collect();
        tc2.attempts.push(
            options
                .iter()
                .map(|e| attempts_to_win(&h, *e, cap))
                .collect(),
        );
        tc2.distinct.push(running_distinct(&options));
    }
    let honest_c: Vec<u64> = tc.attempts.iter().map(|c| c[0]).collect();
    out.extend(rows(
        "c",
        "old flow: colluding last witness signs with a free nonce",
        &config.grinding_budgets,
        &tc,
        &honest_c,
        config,
        false,
    ));
    let honest_c2: Vec<u64> = tc2.attempts.iter().map(|c| c[0]).collect();
    out.extend(rows(
        "c′",
        "current flow: colluding last witness signs or withholds (withholding triggers One Chance)",
        &[1, 2],
        &tc2,
        &honest_c2,
        config,
        false,
    ));

    // (e) current flow: re-signing gives identical bytes, so every candidate is the same entropy.
    let mut rng = rng_stream(seed, "K1-e");
    let mut honest_rng = rng_stream(seed, "K1-e-honest");
    let mut te = Trials {
        attempts: vec![],
        distinct: vec![],
    };
    let mut honest_e = Vec::with_capacity(trials);
    let current = |h: &Header| -> [u8; 32] {
        let sig_m = miner_key.sign(&miner_message(h));
        let msg = [ENTROPY_TAG, &h.encode()[..], &sig_m.to_bytes()[..]].concat();
        let sigs: Vec<Signature> = members.iter().map(|s| s.sign(&msg)).collect();
        let mut refs: Vec<&Signature> = vec![&sig_m];
        refs.extend(sigs.iter());
        entropy_output(&aggregate(&refs), &all)
    };
    for t in 0..trials {
        let h = header_with(&mut rng);
        // Re-sign the whole flow up to G times for the first trials (costly), once otherwise.
        let tries = if t < 20 { gmax } else { 1 };
        let entropies: Vec<[u8; 32]> = (0..tries).map(|_| current(&h)).collect();
        let a = attempts_to_win(&h, entropies[0], cap);
        te.attempts.push(vec![a; gmax]);
        let mut distinct = running_distinct(&entropies);
        distinct.resize(gmax, distinct.last().copied().unwrap_or(1.0));
        te.distinct.push(distinct);
        let hh = header_with(&mut honest_rng);
        honest_e.push(attempts_to_win(&hh, current(&hh), cap));
    }
    out.extend(rows(
        "e",
        "current flow: BLS signatures are unique; re-signing changes nothing",
        &config.grinding_budgets,
        &te,
        &honest_e,
        config,
        true,
    ));
    out
}

/// Runs C1(d): equivocation detection and false positives.
pub fn equivocation(seed: u64, config: &CryptoTestsConfig) -> Vec<EquivocationRow> {
    let mut rng = rng_stream(seed, "K1-d");
    let target = target_for(config.expected_winning_attempts);
    let (mut flagged, mut same, mut heights, mut keys) = (0, 0, 0, 0);
    let n = config.equivocation_trials;
    for _ in 0..n {
        let miner = crate::common::random_keypair(&mut rng);
        let other = crate::common::random_keypair(&mut rng);
        let a = header_for(&mut rng, miner.public, target);
        let mut b = a;
        match rng.next_u64() % 3 {
            0 => b.reward_wallet = random_hash(&mut rng),
            1 => b.kwc_id ^= 1 + rng.next_u64() % 1_000,
            _ => b.target[31] ^= 1,
        }
        let sign = |h: &Header, k: &gb_protocol::entropy::Keypair| SignedHeader {
            header: h.encode(),
            signature: k.sign(&miner_message(h)),
        };
        flagged += u64::from(is_equivocation(&sign(&a, &miner), &sign(&b, &miner)));
        same += u64::from(is_equivocation(&sign(&a, &miner), &sign(&a, &miner)));
        let mut c = b;
        c.height += 1;
        heights += u64::from(is_equivocation(&sign(&a, &miner), &sign(&c, &miner)));
        let mut d = b;
        d.candidate_pk = other.public;
        keys += u64::from(is_equivocation(&sign(&a, &miner), &sign(&d, &other)));
    }
    vec![
        EquivocationRow {
            case: "two different headers, same height, same key",
            pairs: n,
            flagged,
            expected: n,
        },
        EquivocationRow {
            case: "the same header twice",
            pairs: n,
            flagged: same,
            expected: 0,
        },
        EquivocationRow {
            case: "different heights (next round)",
            pairs: n,
            flagged: heights,
            expected: 0,
        },
        EquivocationRow {
            case: "different candidate keys",
            pairs: n,
            flagged: keys,
            expected: 0,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small() -> CryptoTestsConfig {
        CryptoTestsConfig {
            grinding_trials: 60,
            grinding_budgets: vec![1, 4, 16],
            batches: 10,
            equivocation_trials: 20,
            ..CryptoTestsConfig::default()
        }
    }

    #[test]
    fn subsets_start_with_the_full_set_and_respect_the_quorum() {
        let s = subsets(10, 7, 64);
        assert_eq!(s[0], (0..10).collect::<Vec<_>>());
        assert_eq!(s.len(), 64);
        assert!(s.iter().all(|x| x.len() >= 7));
        assert_eq!(subsets(10, 7, 1_000).len(), 120 + 45 + 10 + 1);
    }

    #[test]
    fn old_flow_grinding_helps_and_the_current_flow_does_not() {
        let rows = grinding(7, &small());
        let get = |e: &str, g: u64| {
            rows.iter()
                .find(|r| r.experiment == e && r.budget == g)
                .unwrap()
        };
        assert!(get("a", 16).advantage > 4.0, "{:?}", get("a", 16));
        assert_eq!(get("a", 16).distinct_entropies, 16.0);
        assert_eq!(
            get("e", 16).distinct_entropies,
            1.0,
            "unique BLS signatures"
        );
        assert!(
            get("e", 16).ci_low < 1.0 && get("e", 16).ci_high > 1.0,
            "{:?}",
            get("e", 16)
        );
        assert_eq!(get("a", 1).advantage, 1.0);
    }

    #[test]
    fn equivocation_is_always_detected_and_never_falsely_flagged() {
        for row in equivocation(3, &small()) {
            assert_eq!(row.flagged, row.expected, "{row:?}");
        }
    }
}
