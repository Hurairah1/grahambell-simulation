# GrahamBell — Stage 1 Simulation Specification

**Version:** 0.2 (compiled from the protocol architect's papers and design decisions; amended 2026-10-05, see the Changelog at the end)
**Owner:** Hurairah Shamsi, Protocol Architect
**Purpose of this file:** single source of truth for building and running the Stage 1 simulation. Where this file and older papers disagree, **this file wins**. Where this file is silent or ambiguous, the implementer must **stop and ask**, not guess.

### Status legend

- **[D] Decided** by the protocol architect.
- **[P] Proposed**: recommended during design review; must be implemented so it can be compared against the alternative named.
- **[O] Open**: undecided value or rule; implement as a configurable parameter and sweep it.

All numbers are provisional defaults. Every number in this file must be a configurable parameter in code, never a hard-coded constant.

---

## 0. What Stage 1 must establish

Stage 1 tests whether **Proof of Infrastructure Endurance (PoIE)**, GrahamBell's time-based Sybil resistance built on serialized, paced identity issuance, holds up under realistic and adversarial conditions. The claims under test:

- **C1 Linearity.** An attacker's share of newly issued IDs is proportional to its share of admitted /64s. No strategy produces more than proportional share.
- **C2 Time floor.** Reaching a threshold T of 33%, 51% or 67% of **active** IDs requires time bounded below by (T/(1−T)) × H_active / R, where H_active is the existing active base and R the issuance rate, even for an attacker who wins every ID.
- **C3 No acceleration.** Hardware, parallelism, precomputation and entropy grinding give no advantage per /64 or per ID.
- **C4 Witness integrity.** Random allocation plus quorum rules make witness capture or stalling expensive; misbehaviour is attributable; honest participants are not cheaply harmed.
- **C5 Cost.** The real-world cost of sustaining a given attacker share is quantified in money and scales linearly.

The deliverable is not "the model works." It is a **reproducible map** of the conditions under which each claim holds, and where its margins become thin, with code anyone can rerun.

### In scope

Unregistered-to-registered identity issuance (PoW-ID); the witness layer as it affects issuance; the Chain Allocation Committee; a minimal transaction-layer model only where needed (witness seats come from IDs; committee seats come from transaction-block winners; active-ID share).

### Out of scope for Stage 1

Proof of Call, Murphy, Data Saving Groups, Proof of Funds, Shamsi OS, smart contracts, storage pruning, the full reward schedule (used only as economic inputs), and the Stage 3 centralized-witness testnet itself.

---

## 1. Terminology

| Term | Meaning |
|---|---|
| /64 | Externally visible IPv6 /64 prefix, derived from the socket source address **after a transport handshake** that proves the sender controls the address. |
| Unregistered miner | A /64 competing for an ID. |
| ID (registered ID) | An identity. Its value is the hash of the winning PoW-ID block. Bound to a key pair registered in that block. |
| PoW-ID block | Identity-issuance block (older papers: PoW1). |
| PoW-Tx block | Transaction block (older papers: PoW2). |
| PoWit | Proof of Witness block accompanying a PoW block. |
| Round | Interval between consecutive blocks of one type. PoW-ID target: 30 s. |
| Epoch (grace) | 5 rounds of the miner's own block type (PoW-ID for unregistered, PoW-Tx for registered). |
| WC | Witness Chain: 10 registered IDs acting as witness nodes. |
| KWC | King Witness Chain: 1 leader WC + 3 subordinate WCs = 40 nodes. |
| Leader WC / Sultan | The WC that leads a KWC and is paid when a block is mined through it. |
| Subordinate WC / Wazir | A WC that monitors another WC's KWC without being paid for it. |
| CAC | Chain Allocation Committee. |
| MOBu / MOBr | Miner Online Block for unregistered / registered miners. |
| One Chance | Relay-and-retry procedure run before any member or miner is penalized for a missing signature. |

---

## 2. Parameters

| Parameter | Default | Sweep / variants | Status |
|---|---|---|---|
| Hash pacing | 1 hash/s per admitted /64 (unregistered) or per ID (registered) | — | D |
| PoW-ID target interval | 30 s (≈1.05M IDs/yr) | adaptive variant (§3.9) | D / P |
| PoW-Tx interval | 10 s | 1–10 s | O |
| WC size | 10 | 10 | D |
| KWC composition | 1 leader + 3 subordinate WCs (40 nodes) | 1 + 2 (30 nodes) for comparison | D |
| Number of KWCs | equals number of WCs (each WC leads exactly one KWC, subordinate in exactly three) | — | D |
| Registered-miner PoWit quorum | ≥7 of 10 leader WC **and** ≥21 of 30 subordinates (28 total) | 30-node comparison: ≥7 of 10 leader **and** ≥14 of 20 subordinates (21 total) | D |
| Unregistered-miner PoWit quorum | any ≥27 of 40 | 30-node comparison: any ≥20 of 30 | D |
| Entropy signatures | **every online member** of the KWC (online must be ≥ quorum) | — | D |
| Miner capacity per leader WC | 200 registered + 50 unregistered | registered/unregistered split: 200/50, 100/150, 15/235 | D default, O split |
| Miners watched per witness node | 1,000 (800 registered + 200 unregistered) | — | D |
| Spare witnessing capacity target | +33% over demand | — | D |
| Per-node request rate limit | 1,000 req/s | — | D |
| Grace epoch | 5 rounds of own block type (~150 s unregistered) | — | D |
| Post-admission wait before mining | 5 rounds | 1–10 | O |
| Convergence interval (admission) | 1 epoch | 0.5–3 epochs | O |
| Peer bootstrap count (newcomers) | 8 | 4–8 | D |
| CAC size | 600, first-in first-out | 100–1,000 for comparison | D |
| CAC new member | miner of every 10th PoW-Tx block | — | D |
| CAC approval threshold | at least two-thirds of members, rounded up: ⌈2n/3⌉ (400 of 600) | — | D |
| CAC seat uniqueness | one seat per ID at a time (§4.3) | duplicates allowed, for comparison | P |
| Genesis IDs (G) | 2,100,000 ¹ | 0.5M, 1M, 2M, 2.1M, 3M | D |
| Genesis distribution | KYC, one per verified person | fraction secretly controlled by one party: 0–20% | D / O |
| Confirmation depth for new IDs | 6 PoW-ID blocks | 3–12 | O |
| Clock tolerance δ | 2 s | 0.5–10 s | O |
| Offline deactivation threshold | — | 1 h, 6 h, 24 h, 3 d, 7 d | O |
| Re-activation wait after return | — | 1 d, 7 d, 14 d, 30 d | O |
| Penalty ladder (lesser offences) | 24 h, then 30 days, then permanent | — | D |
| Minimum attack time floor (adaptive issuance) | 2 years | 1–10 years | P |
| Adaptive-cap checkpoint interval (§3.9) | — | T_min/4, T_min/2, T_min | O |
| Signature scheme | BLS12-381 aggregate signatures with signer bitfield and proof of possession | — | D |
| Hash function | SHA-256 | — | P |

¹ With a 30 s rate (R ≈ 1,051,200 IDs per year), a 100%-capture attacker needs about 2.02M active IDs in the existing base before reaching 51% takes 2 years ((0.51/0.49) × H_active / R = 2 years). 2.1M adds a margin (about 2.08 years). The floor depends on genesis IDs staying **active**: it holds only while at least about 96% of 2.1M genesis IDs remain active.

---

## 3. Identity issuance (PoW-ID)

### 3.1 Admission lifecycle [D]

States, in order: **Locally Validated → Globally Pending → Canonically Selected → Convergence Complete → Globally Active.** Only Globally Active grants mining rights.

1. **Bootstrap.** A newcomer connects to 4–8 registered peers chosen at random, which supply recent PoW-ID headers, KWC membership, free capacity, and the current CAC. Registered peers accept only a narrow message set from unregistered nodes.
2. **Local validation** by the chosen KWC: structure, signature, and the /64 derived from the socket source after a handshake **[P: handshake mandatory; compare with no-handshake in the spoofing scenario]**.
3. **Global claim broadcast** to all WCs and validators; checked against all active and pending claims.
4. **Canonical tie-break** between conflicting pending claims for the same /64 or ID: **hash priority [P]**, not timestamps (timestamps are sender-controlled).
5. **Convergence interval**, then activation. For unregistered miners the MOBu is proposed by the subordinate-side proposer (§4.4).
6. **Wait** the post-admission period before mining.

A KWC at capacity rejects new joins; newcomers wait or try another KWC. Each chain accepts only as many new requests as it has free slots.

### 3.2 Uniqueness [D]

- One active session per /64 (unregistered). One active mining channel per ID (registered).
- A miner may not join a KWC in which its own ID is a witness. If it does, its blocks are rejected even if valid.
- Joining a different KWC while still counted live elsewhere is treated as parallel mining: rejected, and grounds for a ban.
- Moving to another KWC is allowed at any time, but takes the grace epoch plus admission (a few minutes).
- **Self-service offline:** before rejoining, a miner may query peers; if still listed online, it broadcasts its own signed offline request, waits one epoch, then rejoins.
- **Replay protection:** a signed join request names its target KWC; any other KWC ignores it. Only a request signed by the candidate key **for a different KWC** counts as evidence of duplication.

### 3.3 PoW-ID header [D]

Fixed contents for the round, including: candidate public key, reward wallet, /64, KWC ID, difficulty, version, **previous PoW-ID block hash (mandatory, so entropy refreshes every round)**, height. No free-data or extra-nonce field.

### 3.4 Entropy lock [D]

1. Miner builds header `H`, signs it with the candidate key: `σ_m = Sign(sk_m, "GB/PoW-ID/miner" ‖ H)`.
2. Miner sends `(H, σ_m)` to **every** KWC member. Each member verifies, then signs: `σ_i = Sign(sk_i, "GB/entropy" ‖ H ‖ σ_m)`, and shares `σ_i` with all members and the miner.
3. `E = SHA256("GB/entropy-out" ‖ AggregateBLS(σ_m, σ_i for every online member i) ‖ signer_bitfield)`.
4. The aggregate **must include every online member's signature**. A missing online signature triggers One Chance (§4.5). Online members must number at least the quorum.
5. `E` is committed into the header. The header is then immutable for the round.

Rules:

- **One header per miner per round.** Two headers signed by the same miner key in the same round are proof of equivocation and grounds for a ban.
- **Abandoning a header** means waiting for the next PoW-ID block before starting again.
- **Proof of possession:** the miner's signature on the PoWit, verified with the public key in the PoW-ID block body, domain-separated from other signatures.

### 3.5 Hash chain [D]

Let `t0 = timestamp(previous PoW-ID block) + 1 s`.

- **Start rule (a):** the chain always starts at `t0`, regardless of when `E` arrives. A miner whose entropy arrives late computes the missed steps immediately; its witnesses do the same.
- **Start rule (b), comparison only:** the hash chain starts when the miner's entropy arrives locally, rather than at `t0`. This is the rejected alternative, kept only for comparison in S13.
- `h_0 = SHA256("GB/chain" ‖ prev_hash ‖ height ‖ t0 ‖ nonce=0 ‖ E ‖ header_digest)`
- `h_{n+1} = SHA256("GB/chain" ‖ h_n ‖ prev_hash ‖ height ‖ (t0+n+1) ‖ nonce=n+1 ‖ E ‖ header_digest)`
- **Fixed field order, fixed-length encodings, domain tags [P].** The older "sort fields by hexadecimal value before hashing" rule is tested separately (scenario S14), not used in the simulator.
- The miner wins at the first `n` with `h_n < target`. Block timestamp = `t0 + n`.

### 3.6 Witnessing and signing [D]

Every member recomputes the chain independently. An honest member signs the PoWit **only when its own clock reaches `t0 + N` (within tolerance δ)**, where `N` is the winning step. The miner collects at least the quorum, aggregates, and broadcasts the PoW-ID block with its PoWit (also to the CAC).

### 3.7 Global validation [D]

Validators check: quorum signatures with bitfield and proof of possession; full chain recomputation from inputs; `timestamp = t0 + N`; the block was not received before its own timestamp (local clock, tolerance δ); serialization of issuance; uniqueness. Fork choice: longest chain. A new ID becomes active only after confirmation depth.

**Same-height tie-break [P]:** if two valid PoW-ID blocks arrive for the same height, keep the one with the lower block hash. The rule is deterministic, so network latency cannot influence it. Compare against first-seen in M3.

### 3.8 Difficulty [P compare]

- **Variant A (default): Bitcoin-style retarget** from recent block times over a window.
- **Variant B: count-based.** Per-hash success probability `p = 1 / (admitted online unregistered miners × target interval)`, with a small correction from recent block times.

### 3.9 Issuance rate [D default, P variant]

- **Default:** fixed target, one PoW-ID block per 30 s.
- **Adaptive variant:** rate may rise with demand, but is capped at `R ≤ registered_IDs / T_min`, so the minimum time for a 100%-capture attacker to reach majority never falls below `T_min`.
- The cap counts **registered** IDs, not active IDs, because an attacker can inflate the active count by coming online. It is recalculated only at **fixed checkpoints**. The checkpoint interval is a parameter **[O]** (§2).
- The cap may set the rate **below** the fixed 30 s target. That is its purpose.
- **Note (from the M1 analysis):** with checkpoints, an attacker that chooses when to start relative to the checkpoint schedule can reach majority sooner than `T_min`. Holding the floor at the worst start phase needs a safety factor `k` in the cap, `R ≤ registered_IDs / (k × T_min)`. For a checkpoint interval of `T_min`, `k = 7/6`. M1 reports `k` for the other intervals.

### 3.10 After winning

The winning miner is treated as offline once its PoW-ID block passes confirmation depth, freeing its slot. A new ID may mine transactions before it is allocated to a WC.

---

## 4. Witness layer

### 4.1 Duty [D]

Every registered ID is a witness node in exactly one WC, permanently on duty. A WC leads one KWC and is a subordinate in three others; each node therefore watches about 1,000 miners. Registered IDs must keep witnessing whether or not they mine.

### 4.2 Allocation [D]

- **Deterministic and publicly recomputable:** `chain(ID) = f(SHA256(ID ‖ beacon))`, where `beacon` is the hash of a block a fixed number of blocks after the ID's confirmation, so not even the ID's owner knows its placement when minting.
- The CAC records and attests the result; it cannot choose it, and rejecting a block cannot produce a different shuffle.
- Constraint: **no mutual monitoring pairs** (two WCs must not monitor each other in different KWCs).
- **[P, optional test]** diversity constraints within a KWC (for example, no two members from the same /48 or the same network operator).

### 4.3 Chain Allocation Committee [D]

600 members, first in, first out; the miner of every 10th PoW-Tx block joins. 66% approval for an Allocation Committee Block, meaning at least two-thirds of members, rounded up: ⌈2n/3⌉ (400 of 600). Leader rotates. A leader that gets two conflicting blocks approved has both rejected.

**Seat uniqueness [P]:** one ID cannot hold two CAC seats at once. If the miner of a 10th PoW-Tx block is already a member, the seat goes to the next 10th-block miner who is not.

### 4.4 Proposers [D]

Each KWC has two rotating proposers, changing every 2 PoW-Tx blocks: a **master** drawn from all 40 members, and a **subordinate-only** proposer drawn from the three subordinate WCs (responsible for MOBu, unregistered offline requests, and banning leader-chain members who refuse to witness newcomers). If a proposer fails to act, the next in rotation does.

### 4.5 One Chance [D]

If an online member's signature is missing from a miner's aggregate, every other member relays the miner's original signed request to that member. The member gets one chance to sign and send its signature to the miner and all members; members relay it to the miner, who gets one chance to include it. A member that still refuses is penalized; a miner that still omits it is refused entry. A proposer that issues a false blacklist or offline request gets One Chance itself; repeating it gets it banned by the next proposer, using the first request embedded in the second as proof. Each exchange has a time limit of *n* blocks.

### 4.6 Ban principle [D]

- **Network-level bans require verifiable evidence** (for example, two conflicting signed statements, a signed false statement, or documented refusal through One Chance).
- **Miner complaints may trigger a check but never decide a ban.** Witnesses vote (66% of the KWC, meaning at least two-thirds rounded up: 27 of 40) only on behaviour they observed themselves after One Chance.
- **[P] Unreachable is not refusal.** A member that cannot be reached is treated as offline under the allowance; a ban requires proof it refused while demonstrably online. Implement both this rule and the strict alternative (ban on failed One Chance) for comparison.

### 4.7 Offline handling [D rules, O values]

Grace epoch; self-service offline requests; forced signing via One Chance for members that withhold while online. Long absence: **deactivation (not destruction)**, with a **re-activation wait** on return. Both durations are swept.

### 4.8 Penalties [D]

Lesser offences: 24-hour suspension, then 30 days, then permanent. A suspended ID still performs witness duty but earns nothing. Proven fraud may be permanent immediately. A banned member's signature is excluded from entropy aggregates.

---

## 5. Transaction layer (minimal model)

Longest chain; one ID = one channel at 1 hash/s. Modeled only to the extent needed for: CAC seat assignment, active-ID share, pool concentration, and a selfish-mining sanity check against active-ID share.

---

## 6. Economic inputs (not design decisions)

Example values per PoW-Tx block: miner 1 Shamsi + ~80% of fees; each signing leader-WC member 0.1 Shamsi + 1.9% of fees (at least 7); CAC leader 0.1 Shamsi + 1% of fees when applicable; public rewards pool (Murphy) 1 Shamsi. **PoW-ID blocks carry no reward.** Token price, hosting prices and bandwidth prices are external parameters.

---

## 7. Threat model

The adversary may: obtain arbitrary compute; acquire large IPv6 allocations; lease cloud infrastructure across many providers and autonomous systems; perform temporary routing hijacks; flood admissions; sustain long-term spending; run many witness IDs and collude; bribe; operate botnets or rent residential proxies; flood specific home nodes offline; manipulate clocks and time sources; control a share of a newcomer's peers; behave irrationally (non-profit motives).

The adversary cannot: break SHA-256, BLS12-381 or VRF security; forge signatures.

---

## 8. Scenario catalogue

**A. Issuance and time**

- **S1** Baseline honest network (sanity check: share ∝ /64 share).
- **S2** Well-funded datacenter attacker; attacker share 5–60%; honest growth and churn swept.
- **S3** Patient accumulator over multi-year horizons.
- **S4** Botnet / residential proxies: free nodes with high churn (100k, 500k, 1M devices).
- **S5** Restart attack: fixed-for-duration entropy (old design) versus per-round entropy (current).
- **S6** Difficulty hopping: Variant A versus Variant B.
- **S7** Adaptive issuance manipulation, with and without the `T_min` cap.
- **S8** Unregistered-slot exhaustion and honest demand surges.
- **S9** Honest churn, patience and dropout, and the offline-handling sweep (honest attrition).
- **S10** Genesis size sweep, including a fraction of genesis IDs secretly controlled by one party.

**B. Entropy and pacing integrity**

- **S11** Grinding: (a) old flow with miner signing last using non-unique signatures; (b) subset selection; (c) colluding last witness; (d) header equivocation; (e) current BLS all-online-members flow. Expected: advantage in (a)–(c), detection in (d), none in (e).
- **S12** Early signing: fraction of KWCs that could sign early versus attacker share; detection via timestamp checks; clock skew sweep.
- **S13** Targeted delay of entropy: start rule (a) versus (b).
- **S14** Sorted-hash collision test (separate unit test).

**C. Witness layer**

- **S15** KWC stall and capture probabilities versus attacker share: exact calculation plus simulation over allocation and network growth.
- **S16** Intermittent stalling that stays within the offline allowance.
- **S17** Targeted flooding of honest witnesses and One Chance griefing; strict rule versus §4.6 [P].
- **S18** Stalling proposers trapping honest miners as "online"; self-service recovery time.
- **S19** Lazy onboarding by chains; effect of the subordinate-only proposer.
- **S20** Lazy subordinates that sign without recomputing.
- **S21** CAC capture and stalling over multi-year runs.
- **S22** Correlated operators: a deliberately "ugly" operator graph (shared cloud regions, one hidden owner of many IDs).
- **S23** Regional partition plus provider outage plus miner stampede at peak demand; client reroute backoff policy.
- **S24** Eclipsed newcomers, with a varying fraction of poisoned peer-discovery sources.
- **S25** Prefix-hijack replay attempting to frame an honest /64 as a duplicate.
- **S26** Spoofed-source framing, with and without a mandatory handshake.

**D. Cost**

- **S27** Real-hardware benchmark: persistent sessions per server, memory, CPU and bandwidth at protocol message rates.
- **S28** Money cost model: attacker cost per /64-year and per ID; break-even against rewards; bribery cost priced as detection probability × (loss + future rewards).

**E. Transaction-layer sanity**

- **S29** Pool concentration and selfish-mining thresholds measured against active-ID share.

---

## 9. Metrics (every run records config, seed and git commit)

- Attacker share of **issued** and **active** IDs over time; time to 33%, 51%, 67%.
- **Amplification factor:** attacker issuance share ÷ attacker /64 share.
- Honest expected wait to first ID; honest dropout.
- Honest attrition: IDs lost without misbehaviour.
- Fraction of KWCs stallable / capturable; witness share reachable from each region.
- Detection latency, reroute time, failed observer lookups, ambiguity window, recovery cost.
- Fork / orphan rate; deviation of issuance rate from target.
- Per-node load on a household witness (CPU, bandwidth, messages).
- Attack cost: money to affect X% of the network at size N; money per honest victim.
- Concentration over time (Gini coefficient, Nakamoto coefficient).

---

## 10. Pre-registered hypotheses

Thresholds below are proposals. **The architect confirms them before results are generated, and results are published whether each passes or fails.**

- **H1 Linearity.** For every protocol-compliant attacker strategy in S1–S4, the amplification factor's 95% confidence interval lies within [0.95, 1.05].
- **H2 Time floor.** With 100% issuance capture, time to 51% of active IDs matches the analytic value `(0.51/0.49) × H_active / R` within ±5%.
- **H3 No grinding.** Under S11(e), no strategy reduces the expected winning step relative to an honest miner beyond statistical noise.
- **H4 No restart advantage.** Under per-round entropy (S5 current), the restart strategy's advantage factor is ≤ 1.05.
- **H5 Hopping.** Under Variant B, the hopping gain is ≤ 2%; report Variant A's gain.
- **H6 Witness capture.** At attacker share ≤ 25%, the expected number of KWCs capable of early signing over 10 years at 100,000 KWCs is < 1. Stall fractions are reported without a threshold.
  - *Refresh model:* every KWC composition ever formed counts as an independent draw. New KWCs form as new IDs are allocated (about R/10 new WCs per year), plus replacements after bans.
  - Report for both the registered quorum and the unregistered quorum. PoW-ID uses the unregistered quorum.
- **H7 Honest attrition.** Under a realistic household downtime profile, IDs lost per year without misbehaviour ≤ 1% for the chosen offline parameters.
- **H8 Griefing.** Under the §4.6 [P] rule, griefing bans of honest witnesses are impossible; report the cost per victim under the strict rule.
- **H9 Cost.** Report the money required for an attacker to hold 33% and 51% of active IDs for one year at several honest network sizes (no threshold; reported).

---

## 11. Methodology requirements

1. **Two-tier modelling.**
   - *Tier 1:* protocol-level discrete-event simulation with real message exchange, regional latency distributions and churn, at reduced scale (up to ~100,000 miners).
   - *Tier 2:* aggregate statistical model at full scale (millions), **validated against Tier 1** wherever their scales overlap.
2. **Real cryptography** for micro-tests (SHA-256, BLS12-381); simulators may substitute statistically equivalent abstractions only after the equivalence is tested and documented.
3. **Analytical ground truth first.** Anything with a closed form is computed exactly, and the simulator must match it before being trusted beyond it.
4. **Determinism.** Every run is seeded; config, seed and commit are recorded; results are bit-for-bit reproducible.
5. **No silent assumptions.** Every modelling assumption is listed in `ASSUMPTIONS.md` with its source (this spec section, a paper, or an external data source).
6. **Outputs** are machine-readable (CSV / JSON / Parquet) plus plots. Any front end reads outputs only and never recomputes.
7. **Implementation language:** Rust, for the simulation and the Stage 3 testnet. Protocol-core logic is shared between them.

---

## 12. Open questions

- PoW-Tx block interval.
- Post-admission wait, convergence interval, clock tolerance δ.
- Offline deactivation and re-activation durations.
- Registered / unregistered capacity split.
- Strict versus [P] rule for unreachable members (§4.6).
- Mining-API streaming: format and whether mandatory.
- Witness beneficiary details.
- Key compromise and revocation (for example, a pre-registered backup key): post-Stage 1.
- Diversity constraints in allocation.
- Witness Chain decentralization trigger for Stage 4 (published criteria).
---

## Changelog

### v0.2 — 2026-10-05

Decisions by the protocol architect, recorded after the M0/M1 plan review.

- **§0 C2.** The time floor now reads "(T/(1−T)) × H_active / R" instead of "the existing active base divided by the issuance rate". Reason: for a 100%-capture attacker the exact bound is (T/(1−T)) × H_active / R. That is about 0.49 × H_active / R at 33%, so the old wording overstated the floor below 50%.
- **§2 Genesis IDs (G).**
  - Default changed from 1,000,000 [O] to 2,100,000 [D]. Sweep changed to 0.5M, 1M, 2M, 2.1M, 3M.
  - Reason, in footnote ¹: with a 30 s rate, about 2.02M active IDs are needed before a 100%-capture attacker takes 2 years to reach 51%. 2.1M adds a margin, and the floor depends on genesis IDs staying active.
- **§2 PoWit quorums.** Added the 30-node comparison values: registered ≥7 of 10 leader and ≥14 of 20 subordinates; unregistered any ≥20 of 30.
- **§2 new rows.**
  - Adaptive-cap checkpoint interval [O], sweep T_min/4, T_min/2, T_min.
  - CAC approval threshold ⌈2n/3⌉ [D].
  - CAC seat uniqueness [P].
- **§2 sweeps added.**
  - Offline deactivation threshold: 1 h, 6 h, 24 h, 3 d, 7 d.
  - Re-activation wait: 1 d, 7 d, 14 d, 30 d.
  - Capacity split per leader WC (registered/unregistered): 200/50, 100/150, 15/235.
- **§3.5.** Defined start rule (b): the chain starts when the miner's entropy arrives locally. It is the rejected alternative, kept only for comparison in S13.
- **§3.7.** Added the [P] same-height tie-break: keep the lower block hash. First-seen is the comparison in M3.
- **§3.9.**
  - The cap counts registered IDs (not active IDs) and is recalculated at fixed checkpoints. The interval is [O].
  - The cap may set the rate below the fixed 30 s target.
  - Added a note on the safety factor k needed so the floor holds at the worst start phase (k = 7/6 for checkpoint interval T_min).
- **§4.3.**
  - "66%" means at least two-thirds rounded up, ⌈2n/3⌉ (400 of 600).
  - Added the [P] rule that one ID cannot hold two CAC seats at once; a member's 10th-block win passes to the next 10th-block miner who is not a member.
- **§4.6.** "66% of the KWC" means at least two-thirds rounded up: 27 of 40.
- **§10 H6.**
  - Added the refresh model: every KWC composition ever formed counts as an independent draw. About R/10 new WCs form per year, plus replacements after bans.
  - Results are reported for both the registered and the unregistered quorum.
- **§11.** Added item 7: implementation language is Rust, for the simulation and the Stage 3 testnet, with protocol-core logic shared between them.

### v0.1

Initial compiled specification.
