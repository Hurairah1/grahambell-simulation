# GrahamBell — Stage 1 Simulation Specification

**Version:** 0.4 (compiled from the protocol architect's papers and design decisions; amended 2026-10-05, 2026-10-06 and 2026-10-07, see the Changelog at the end)
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

Unregistered-to-registered identity issuance (PoW-ID); the witness layer as it affects issuance; the Chain Allocation Committee; a minimal transaction-layer model only where needed (witness seats come from IDs; committee seats come from a lottery over active IDs, §4.3; active-ID share).

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
| Difficulty rule (§3.8) | Variant B: count-based, from the exact admitted online count | Variant A (Bitcoin-style retarget), for comparison | D |
| Variant A comparison settings (§3.8) | window K = 144 blocks, 4× clamp per retarget | — | D |
| Variant B correction from recent block times (§3.8) | — | no preferred form; M3 proposes one and tests it | P |
| PoW-Tx interval | 10 s | 1–10 s | O |
| WC size | 10 | 10 | D |
| KWC composition | 1 leader + 3 subordinate WCs (40 nodes) | 1 + 2 (30 nodes) for comparison | D |
| Number of KWCs | equals number of WCs (each WC leads exactly one KWC, subordinate in exactly three) | — | D |
| KWC ring offsets (§4.2) | 1, 4, 6 | 1, 3 for the 30-node comparison | D |
| Allocation beacon delay (§4.2) | 6 blocks after the ID's confirmation, or after its re-activation is confirmed when a returning ID is re-inserted | 3, 6, 12 | O |
| Registered-miner PoWit quorum | ≥7 of 10 leader WC **and** ≥21 of 30 subordinates (28 total) | 30-node comparison: ≥7 of 10 leader **and** ≥14 of 20 subordinates (21 total) | D |
| Unregistered-miner PoWit quorum | any ≥27 of 40 | 30-node comparison: any ≥20 of 30 | D |
| Entropy signatures | **every online member** of the KWC (online must be ≥ quorum) | — | D |
| Miner capacity per leader WC | 200 registered + 50 unregistered ² | registered/unregistered split: 200/50, 100/150, 15/235 | D default, O split |
| Miners watched per witness node | 1,000 (800 registered + 200 unregistered) | — | D |
| Spare witnessing capacity target | +33% over demand | — | D |
| Per-node request rate limit | 1,000 req/s | — | D |
| Grace epoch | 5 rounds of own block type (~150 s unregistered) | — | D |
| Post-admission wait before mining | 5 rounds | 1–10 | O |
| Convergence interval (admission) | 1 epoch | 0.5–3 epochs | O |
| Peer bootstrap count (newcomers) | 8 | 4–8 | D |
| CAC size | 600, first-in first-out | 100–1,000 for comparison | D |
| CAC seat selection (§4.3) | lottery over the canonical active list, one new member per 10th PoW-Tx block; a seat left by a banned or deactivated member is filled by an extra draw at the next 10th PoW-Tx block, at position SHA256("GB/cac" ‖ hash of block B+k ‖ i) with i = 1, 2, … [P] | old rule (miner of every 10th PoW-Tx block), for comparison | D |
| CAC lottery beacon offset k (§4.3) | 3 blocks | 1, 3, 6, 12 | O |
| CAC approval threshold | at least two-thirds of members, rounded up: ⌈2n/3⌉ (400 of 600) | — | D |
| Genesis IDs (G) | 2,900,000 ¹ | 1M, 2.1M, 2.9M, 5M, 10M | D |
| Genesis distribution | KYC, one per verified person | fraction secretly controlled by one party: 0–20% | D / O |
| Confirmation depth for new IDs | 6 PoW-ID blocks | 3–12 | O |
| Clock tolerance δ | 2 s | 0.5–10 s | O |
| Offline deactivation threshold | — | 1 h, 6 h, 24 h, 3 d, 7 d | O |
| Re-activation wait after return | — | 1 d, 7 d, 14 d, 30 d | O |
| Long-absence threshold L (§4.7) | 30 days (86,400 PoW-ID blocks at 30 s) | 3 d (8,640 blocks), 7 d (20,160), 30 d (86,400), 90 d (259,200), 365 d (1,051,200) | O |
| Penalty ladder (lesser offences) | 24 h, then 30 days, then permanent | — | D |
| Minimum attack time floor (adaptive issuance) | 2 years | 1–10 years | P |
| Adaptive-cap checkpoint interval (§3.9) | T_min | T_min/4, T_min/2, T_min | D |
| Adaptive-cap safety factor k (§3.9) | 7/6, for checkpoints every T_min | k for the other intervals is reported by M1 | D |
| Signature scheme | BLS12-381 aggregate signatures with signer bitfield and proof of possession | — | D |
| Hash function | SHA-256 | — | P |

¹ With a 30 s rate (R ≈ 1,051,200 IDs per year), a 100%-capture attacker needs about 2.02M active IDs in the existing base before reaching 51% takes 2 years ((0.51/0.49) × H_active / R = 2 years). The floor depends on genesis IDs staying **active**. With 2.9M genesis IDs it holds while at least 69.7% of them remain active, that is with up to 30.3% inactive. At full activity the time is about 2.87 years.

² Each registered ID sits in exactly one WC and mines at most one channel, so a KWC averages at most 10 registered miners. The registered capacity of 200 per leader WC (and 800 registered miners watched per node) cannot be reached network-wide; it is reached only where miners concentrate. The registered/unregistered split stays a sweep.

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

The confirmation depth stays as in §2. M1 finds that same-step ties end about 1.66% of rounds at the 30 s target; M3 measures the resulting fork and orphan rate under both tie-break rules.

### 3.8 Difficulty [D; P correction]

- **Variant B (default): count-based.** Per-hash success probability `p = 1 / (admitted online unregistered miners × target interval)`, computed from the exact admitted online count, which admission (§3.1) already tracks.
- **[P] Variant B correction:** a small correction from recent block times. There is no preferred form. M3 proposes one and tests it (for example, the target interval ÷ the average interval over the last 144 blocks, bounded to ±10%); until then Variant B uses the count alone.
- **Variant A (comparison): Bitcoin-style retarget** from recent block times over a window of K = 144 PoW-ID blocks, each retarget clamped to a factor of 4 in either direction.

### 3.9 Issuance rate [D default, P variant]

- **Default:** fixed target, one PoW-ID block per 30 s.
- **Adaptive variant (optional):** the rate may rise with demand, but is capped at `R ≤ registered_IDs / (k × T_min)`, where `k` is a safety factor.
- The cap counts **registered** IDs, not active IDs, because an attacker can inflate the active count by coming online. It is recalculated only at **fixed checkpoints**, every `T_min` by default (§2).
- With checkpoints every `T_min`, `k = 7/6`. M1 reports `k` for the other checkpoint intervals in the §2 sweep.
- **Guarantee:** With the safety factor k for the chosen checkpoint interval, a 100%-capture attacker cannot reach 51% in less than T_min, at any start phase.
- **Why `k` is needed:** an attacker that chooses when to start relative to the public checkpoint schedule reaches majority sooner than `T_min` under the cap without `k` (M1: 0.857 `T_min` for checkpoints every `T_min`).
- The cap may set the rate **below** the fixed 30 s target. That is its purpose.

### 3.10 After winning

The winning miner is treated as offline once its PoW-ID block passes confirmation depth, freeing its slot. A new ID may mine transactions before it is allocated to a WC.

### 3.11 Registration index and canonical active list [D]

- **Registration index.** Every registered ID has one. Genesis IDs are numbered first, in their published order; each new ID then takes the next index, in PoW-ID confirmation order.
- **Canonical active list.** All registered IDs in index order, excluding banned and deactivated IDs.
- Every node builds both from chain data alone. Allocation (§4.2) and the committee lottery (§4.3) use them.

---

## 4. Witness layer

### 4.1 Duty [D]

Every registered ID is a witness node in exactly one WC, permanently on duty. A WC leads one KWC and is a subordinate in three others; each node therefore watches about 1,000 miners. Registered IDs must keep witnessing whether or not they mine.

### 4.2 Allocation [D]

Allocation is deterministic and publicly recomputable from chain data. Not even an ID's owner knows its placement when minting. The rationale is in `docs/ARCHITECTURE.md` §8.

**Beacon.** The beacon for an ID is the hash of the PoW-ID block a fixed delay after the ID's confirmation: 6 blocks by default, equal to the confirmation depth (§2). A returning ID whose seat was vacated (§4.7) uses the hash of the block the same delay after its re-activation is confirmed. Genesis IDs are allocated first, in registration-index order, using a public launch seed in place of a beacon.

**When placement takes effect [D].** At the ID's beacon block (its confirmation, or its re-activation's confirmation, plus the allocation beacon delay), with no further delay, whether or not an Allocation Committee Block has appeared. Every node computes the placement from chain data.

**Seats: inside-out Fisher–Yates insertion.**

1. Seats are numbered 0, 1, 2, …; WC `w` is seats `10w` to `10w + 9`.
2. IDs are inserted in registration-index order (§3.11). When an ID is inserted while `n` seats are filled (seats 0 to `n − 1`), compute `j = SHA256("GB/alloc" ‖ ID ‖ beacon) mod (n + 1)`, reading the hash as a 256-bit integer.
   - If `j = n`, the ID takes seat `n`.
   - Otherwise the ID in seat `j` moves to seat `n`, and the new ID takes seat `j`.
3. A WC is **active** when all 10 of its seats are filled, so the number of active WCs is `W = ⌊filled seats / 10⌋`. The partial tail WC is **pending**: its members may mine (§3.10) but do not witness until it fills.
4. **Removal** (a ban, or a continuous absence longer than the long-absence threshold L, §4.6–§4.7): the ID in the last filled seat moves into the vacated seat. If that empties a seat of the last active WC, that WC returns to pending, `W` decreases by one, and the KWC ring is recomputed. Going offline or being deactivated does not remove an ID from its seat (§4.7).
5. **Re-insertion.** A returning ID whose seat was vacated is re-inserted by step 2, with the re-activation beacon above. An ID that returns within L never left its seat.

**KWCs: a Golomb-ruler ring.** KWC `w` has leader WC `w` and subordinate WCs `(w + 1)`, `(w + 4)` and `(w + 6)`, all mod `W`. The 30-node comparison uses `(w + 1)` and `(w + 3)`.

- Each WC leads exactly one KWC and is a subordinate in exactly three.
- There are **no mutual monitoring pairs** (two WCs must not monitor each other in different KWCs), and any two KWCs share at most one WC.
- These properties need `W ≥ 13` (`W ≥ 7` for the comparison), which holds from genesis.

**Consequences.**

- Each new ID changes the membership of one existing WC and moves one existing ID into the pending tail WC. Chain membership is therefore not fixed. In exchange, every WC's composition tracks the attacker's share of the population, not its share of recent issuance.
- This replaces the per-ID formula `chain(ID) = f(SHA256(ID ‖ beacon))` and the older rule that a vacancy is filled by a newly registered ID.

**Role of the CAC.** The Allocation Committee records and attests the placement in its block. Placement does not wait for that record (above), so a stalled committee cannot delay it. Every node recomputes the record and rejects a mismatch. The committee cannot choose a placement, and rejecting a block cannot produce a different one.

**[P, optional test]** Diversity constraints within a KWC (for example, no two members from the same /48 or the same network operator).

### 4.3 Chain Allocation Committee [D]

600 members, first in, first out. 66% approval for an Allocation Committee Block, meaning at least two-thirds of members, rounded up: ⌈2n/3⌉ (400 of 600). Leader rotates. A leader that gets two conflicting blocks approved has both rejected. The committee's block is a record and attestation: no placement waits for it (§4.2).

**Seat lottery [D].** For every 10th PoW-Tx block B, the new CAC member is the ID at position SHA256("GB/cac" || hash of block B+k) mod N_active in the canonical active list, where N_active is the length of that list. If that ID is already a member, take the next position, wrapping around, until a non-member is found. The oldest member leaves (first in, first out, unchanged). k = 3 [O] (using a later block limits the influence of whoever mines block B). Every node computes the committee from chain data; nothing extra is broadcast.

- **Timing.** The new member is drawn before the oldest member leaves, so the oldest member counts as a member during the draw. The canonical active list (§3.11) is read as of block B, so it is fixed before beacon block B+k exists.
- **Modulo bias.** Hashes are 256-bit, so each position's probability differs from 1/N_active by a relative amount below N_active / 2²⁵⁶. That is below 10⁻⁶⁸ at 10⁹ IDs, and negligible far beyond.
- **Result.** An attacker's expected share of committee seats equals its share of active IDs. Mining power plays no part.

**Departures [D].** A member that is banned or deactivated leaves the committee at once. An extra lottery draw fills its seat at the next 10th PoW-Tx block, using the same next-position rule. **[P] Extra-draw position:** SHA256("GB/cac" ‖ hash of block B+k ‖ i), where i = 1, 2, … counts the extra draws from the same beacon; the regular draw keeps its formula above.

**Duties of the leader's block.**

- A record and attestation of the placement of new and re-inserted IDs (§4.2); placement takes effect without it.
- Committee joins and leaves, which every node can recompute from the lottery.
- Bans already approved by KWCs, compiled into Master Blacklisting Blocks, one for registered and one for unregistered miners.

**Stalling.** An attacker holding enough seats can stall Allocation Committee Blocks. A stall delays the committee's record and its compilation of approved bans; it cannot delay or change any placement, which takes effect at each ID's beacon block (§4.2). M4 tests the impact.

**Comparison rule (v0.2).** The miner of every 10th PoW-Tx block joins; if it is already a member, the seat goes to the next 10th-block miner who is not. It is kept only as a labelled comparison in M1.

### 4.4 Proposers [D]

Each KWC has two rotating proposers, changing every 2 PoW-Tx blocks: a **master** drawn from all 40 members, and a **subordinate-only** proposer drawn from the three subordinate WCs. If a proposer fails to act, the next in rotation does.

**Proposer rights [D].**

- **Master proposer:** MOBr, offline requests for registered miners, and ban proposals.
- **Subordinate-only proposer:** MOBu and offline requests for unregistered miners. As the one exception to the master's ban rights, it may propose bans of leader-chain members who refuse to witness newcomers.
- **The miner:** its own self-service offline request (§3.2).

### 4.5 One Chance [D]

If an online member's signature is missing from a miner's aggregate, every other member relays the miner's original signed request to that member. The member gets one chance to sign and send its signature to the miner and all members; members relay it to the miner, who gets one chance to include it. A member that still refuses is penalized; a miner that still omits it is refused entry. A proposer that issues a false blacklist or offline request gets One Chance itself; repeating it gets it banned by the next proposer, using the first request embedded in the second as proof. Each exchange has a time limit of *n* blocks.

### 4.6 Ban principle [D]

- **Network-level bans require verifiable evidence** (for example, two conflicting signed statements, a signed false statement, or documented refusal through One Chance).
- **Bans are only for proven misbehaviour.** Being offline is not misbehaviour: offline beyond the allowance leads to deactivation (§4.7), never a ban.
- **Miner complaints may trigger a check but never decide a ban.** Witnesses vote (66% of the KWC, meaning at least two-thirds rounded up: 27 of 40) only on behaviour they observed themselves after One Chance.
- **Voting pool.** The full 40-member KWC votes on bans, MOBu/MOBr and offline requests. The subordinate-only proposer (§4.4) only proposes.
- **[P] Unreachable is not refusal.** A member that cannot be reached is treated as offline under the allowance; a ban requires proof it refused while demonstrably online. Implement both this rule and the strict alternative (ban on failed One Chance) for comparison.
- **Conflicting decisions [D].** If two conflicting KWC decisions are both approved, both are rejected. A member who signed both has produced equivocation evidence and may be banned.

### 4.7 Offline handling [D rules, O values]

Grace epoch; self-service offline requests; forced signing via One Chance for members that withhold while online.

**Offline beyond the allowance leads to deactivation, never a ban.**

- A deactivated ID stops counting as active and leaves the canonical active list (§3.11).
- **Seat rule [D].** Going offline or being deactivated does not change any seat. A deactivated ID keeps its WC seat as an **offline member** of its KWC: it does not sign, and quorums are met by online members.
- A seat is vacated (swap-with-last, §4.2) **only** on a ban, or after a continuous absence longer than the **long-absence threshold L** (§2: 30 days [O], which is 86,400 PoW-ID blocks at 30 s).
- On return an ID waits the **re-activation wait** and counts as active again. If its seat was vacated, it is re-inserted by §4.2, with the beacon of the block 6 blocks after its re-activation is confirmed.
- The durations (deactivation threshold, re-activation wait, L) are [O] and swept (§2).
- Only bans and absences longer than L change KWC compositions (§10 H6). Absent members that keep their seats reduce how many members are online to meet quorums; M1 section H maps the honest uptime this requires.

### 4.8 Penalties [D]

Lesser offences: 24-hour suspension, then 30 days, then permanent. A suspended ID still performs witness duty but earns nothing. Proven fraud may be permanent immediately. A banned member's signature is excluded from entropy aggregates.

---

## 5. Transaction layer (minimal model)

Longest chain; one ID = one channel at 1 hash/s. Modeled only to the extent needed for: CAC seat assignment, active-ID share, pool concentration, and a selfish-mining sanity check against active-ID share.

---

## 6. Economic inputs (not design decisions)

Example values per PoW-Tx block: miner 1 Shamsi + ~80% of fees; each signing leader-WC member 0.1 Shamsi + 1.9% of fees (at least 7); CAC leader 0.1 Shamsi + 1% of fees when applicable; public rewards pool (Murphy) 1 Shamsi. **PoW-ID blocks carry no reward.** Token price, hosting prices and bandwidth prices are external parameters.

A [P] proposal to separate PoWit validity from payment is recorded in §12 for M4; the payment rule above is unchanged.

---

## 7. Threat model

The adversary may: obtain arbitrary compute; acquire large IPv6 allocations; lease cloud infrastructure across many providers and autonomous systems; perform temporary routing hijacks; flood admissions; sustain long-term spending; run many witness IDs and collude; bribe; operate botnets or rent residential proxies; flood specific home nodes offline; manipulate clocks and time sources; control a share of a newcomer's peers; behave irrationally (non-profit motives).

The adversary cannot: break SHA-256 or BLS12-381 security; forge signatures.

---

## 8. Scenario catalogue

**A. Issuance and time**

- **S1** Baseline honest network (sanity check: share ∝ /64 share).
- **S2** Well-funded datacenter attacker; attacker share 5–60%; honest growth and churn swept.
- **S3** Patient accumulator over multi-year horizons.
- **S4** Botnet / residential proxies: free nodes with high churn (100k, 500k, 1M devices).
- **S5** Restart attack: fixed-for-duration entropy (old design) versus per-round entropy (current). Realistic restart cost C = grace epoch + convergence interval + post-admission wait (450 s at the §2 defaults).
- **S6** Difficulty hopping: Variant A versus Variant B.
- **S7** Adaptive issuance manipulation, with and without the `T_min` cap.
- **S8** Unregistered-slot exhaustion and honest demand surges.
- **S9** Honest churn, patience and dropout, and the offline-handling sweep: deactivation threshold, re-activation wait and long-absence threshold L (honest attrition).
- **S10** Genesis size sweep, including a fraction of genesis IDs secretly controlled by one party.

**B. Entropy and pacing integrity**

- **S11** Grinding: (a) old flow with miner signing last using non-unique signatures; (b) subset selection; (c) colluding last witness; (d) header equivocation; (e) current BLS all-online-members flow. Expected: advantage in (a)–(c), detection in (d), none in (e).
- **S12** Early signing: fraction of KWCs capable of signing without honest members versus attacker share; detection via timestamp checks (§3.7); clock skew sweep.
- **S13** Targeted delay of entropy: start rule (a) versus (b).
- **S14** Sorted-hash collision test (separate unit test).

**C. Witness layer**

- **S15** KWC stall and capture probabilities versus attacker share: exact calculation plus simulation over allocation and network growth.
- **S16** Intermittent stalling that stays within the offline allowance.
- **S17** Targeted flooding of honest witnesses and One Chance griefing; strict rule versus §4.6 [P].
- **S18** Stalling proposers trapping honest miners as "online"; self-service recovery time.
- **S19** Lazy onboarding by chains; effect of the subordinate-only proposer.
- **S20** Lazy subordinates that sign without recomputing.
- **S21** CAC capture and stalling over multi-year runs, under the seat lottery (§4.3), with the v0.2 rule as a comparison. Primary measures: exact entries into each state per year, and the share of time spent in it. The M1 brief's independent-composition estimate is reported only as a labelled comparison.
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
- **H6 Witness capture.** At attacker share ≤ 25%, the expected number of distinct episodes in which a KWC can sign without honest members, over 10 years at 100,000 KWCs, is < 1. Stall fractions are reported without a threshold.
  - *Meaning:* the attacker's seats alone meet the quorum. Such a KWC still cannot make an early-signed block valid beyond δ, because §3.7 rejects a block received before its own timestamp. Its powers are stalling and censoring miners in that KWC; entropy grinding needs every seat.
  - *Primary measure [D]:* **distinct episodes**, the expected number of times a KWC enters the state (entries into the state). Raw compositions in the state are reported as an upper bound.
  - *Refresh model:* compositions form when an ID is inserted (a new ID, or a returning ID whose seat was vacated: about 4.7 compositions each) and when an ID is removed (a ban, or an absence longer than L: about 4.6 each). Going offline within L changes no composition (§4.7). The v0.2 count (about R/10 new KWCs per year, plus 4 per ban replacement) is reported as a comparison.
  - *Ban rate:* 0 per year in the base case; 1% and 5% of registered IDs per year as labelled sensitivities.
  - Report for both quorums: the unregistered quorum governs PoW-ID, the registered quorum governs PoW-Tx.
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
- Offline deactivation and re-activation durations, and the long-absence threshold L.
- Registered / unregistered capacity split.
- Strict versus [P] rule for unreachable members (§4.6).
- Mining-API streaming: format and whether mandatory.
- Witness beneficiary details.
- Key compromise and revocation (for example, a pre-registered backup key): post-Stage 1.
- Diversity constraints in allocation.
- Witness Chain decentralization trigger for Stage 4 (published criteria).
- The Variant B correction from recent block times (§3.8): no preferred form; M3 proposes one and tests it.
- How often a household ID is absent per year and how long absences last (§4.7); M3 household downtime profiles supply them.
- **The leader-WC requirement is the main stall risk for registered KWCs.** The registered PoWit needs 7 of the leader WC's 10 members as well as 21 of the 30 subordinates; M1 section H shows this fails far more often under honest downtime than any 27 of 40. M4 compares it with a single 27-of-40 rule, together with the forced-signing (§4.5) and ban (§4.6) rules.
- **[P] Separate validity from payment (M4).** Any 27 of 40 signatures make a PoWit valid, with no separate leader-WC requirement. A leader-WC member is paid only if its own signature is in the PoWit. The reward share of a leader member who did not sign is never generated: it is not created and does not go to the miner, so no one gains by omitting signatures. M4 compares this rule with 7 + 21 on liveness (M1 section H), on the incentive for leaders to stay online and sign, and on total issuance per block. The payment rule of §6 is unchanged until then.
- **[P] Raising the attacker share that ID issuance can tolerate without relying on bans (M2/M4):**
  - (a) **Split rule:** a lower quorum for PoWits only, for example 51%, since validators recompute every PoWit (§3.7). M1 section G maps it.
  - (b) **Larger KWCs**, for example 60 or 100 seats. M1 section I maps the trade-off.
  - (c) **Threshold BLS entropy:** any quorum of members produce the same signature, which removes the single-member entropy stall and entropy grinding. M2 measures the key-setup cost.
  - Decisions that validators cannot recompute (bans, MOBu/MOBr, offline requests, committee records) remain bound by the one-third limit and rely on the ban rules.
- **[P] Witness peer topology (option 2).** No persistent witness-to-witness connections: the miner relays routine messages. Members connect on demand, through the global directory of member addresses, only for One Chance, decisions (MOBu/MOBr, offline requests, bans), proposer duties and catch-up. Online status comes from the network record, not from heartbeats: a member counts as online until an offline request is recorded, by the member itself or by its KWC proposer after One Chance fails. Address changes are announced network-wide and update the directory. M1 section I estimates the on-demand connections; M3/M4 measure how often a member that disappears without announcing it stalls its KWCs' entropy until One Chance fails (about one grace epoch). The alternative is persistent connections among all members of a node's KWCs.

---

## Changelog

### v0.4 — 2026-10-07

Decisions by the protocol architect, recorded after reviewing the M1.1 results.

- **§4.7 and §4.2 seat rule [D].**
  - Going offline or being deactivated no longer changes any seat. A deactivated ID keeps its WC seat as an offline member: it does not sign, and quorums are met by online members.
  - A seat is vacated (swap-with-last) only on a ban or after a continuous absence longer than the long-absence threshold L.
  - A returning ID whose seat was vacated is re-inserted by Fisher–Yates, with the beacon 6 blocks after its re-activation is confirmed.
  - This replaces v0.3's "deactivation vacates the seat".
  - Reason: under v0.3 every absence long enough to deactivate an ID changed about 9.3 KWC compositions (a removal and a re-insertion). Under v0.4 only absences longer than L do (M1.2 table B5).
- **§2 new row: long-absence threshold L** = 30 days [O] (86,400 PoW-ID blocks at 30 s), sweep 3, 7, 30, 90 and 365 days. The allocation beacon row now covers re-insertion. **§8 S9** adds L to the offline-handling sweep.
- **§4.2 placement takes effect without the committee [D]**, at the ID's beacon block (its confirmation plus the allocation beacon delay), with no further delay. **§4.3:** the Allocation Committee Block becomes a record and attestation only, so a stall cannot delay placement. Reason: every node computes placement from chain data, so a committee stall need not hold it up.
- **§4.3 departures [D].** A banned or deactivated member leaves the committee at once; an extra lottery draw fills its seat at the next 10th PoW-Tx block. The extra draw's position [P] is SHA256("GB/cac" ‖ hash of block B+k ‖ i), with i = 1, 2, … counting extra draws from the same beacon; the regular draw keeps its formula. Reason: a draw from the same beacon without a counter would land on the first draw's position.
- **§4.4 proposer rights [D].** The master proposer proposes MOBr, registered offline requests and bans. The subordinate-only proposer proposes MOBu and unregistered offline requests, and keeps one exception: bans of leader-chain members who refuse to witness newcomers. The miner makes its own self-service offline request.
- **§4.6 conflicting decisions [D].** If two conflicting KWC decisions are both approved, both are rejected, and a member who signed both has produced equivocation evidence and may be banned. Reason: a conflict then cancels a decision rather than enacting two (M1 section G).
- **§3.8.** The Variant B correction stays [P] with no preferred form; M3 proposes and tests one.
- **§10 H6.** The primary measure is now distinct episodes (entries into the state); raw compositions are an upper bound. Compositions follow the v0.4 seat rule. Reason: consecutive compositions share all but one seat, so counting each as an independent draw counts one episode several times.
- **§2 quorums unchanged** (27 of 40; 7 + 21; ⌈2n/3⌉ for the committee). **§12** records that the leader-WC requirement (7 of 10) is the main stall risk for registered KWCs, for M4 to compare with a single 27-of-40 rule together with the forced-signing and ban rules.
- **§12 new [P] proposals:**
  - separate PoWit validity from payment (any 27 of 40 makes a PoWit valid; an unsigned leader member's share is never generated), for M4; **§6** gains a pointer, and the payment rule is unchanged;
  - three ways to raise the attacker share that ID issuance can tolerate without relying on bans: the split rule, larger KWCs and threshold BLS entropy, for M2/M4;
  - witness peer topology option 2: no persistent witness-to-witness connections, on-demand connections through the global directory, online status from the network record.
- **§12 housekeeping.** Removed the answered questions (the re-insertion beacon, committee seats of deactivated or banned members, the Variant B form). Added the absence-duration question, the long-absence threshold, and the proposals above.
- **§7 (editorial, 2026-10-07).** Removed VRF from §7; no VRF in the design.

### v0.3 — 2026-10-06

Decisions by the protocol architect, recorded after reviewing the M1 results.

- **§2 Genesis IDs (G).**
  - Default changed from 2,100,000 to 2,900,000 [D]. Sweep changed to 1M, 2.1M, 2.9M, 5M, 10M.
  - Reason: M1 showed that with 2.1M genesis IDs the 2-year floor holds only while at least 96.2% of them stay active. With 2.9M it holds with up to 30.3% of genesis IDs inactive (footnote ¹).
- **§2 and §3.9 adaptive cap.**
  - The cap is now `registered_IDs / (k × T_min)`. The checkpoint interval defaults to `T_min` [D], with `k = 7/6` [D].
  - The guarantee sentence now reads: "With the safety factor k for the chosen checkpoint interval, a 100%-capture attacker cannot reach 51% in less than T_min, at any start phase."
  - The adaptive cap remains an optional variant; the fixed 30 s rate remains the default.
  - Reason: M1 showed that without `k` an attacker choosing its start phase reaches 51% in 0.857 `T_min` (checkpoints every `T_min`), and that `k = 7/6` restores the floor exactly.
- **§2 and §3.8 difficulty.**
  - Variant B (count-based, from the exact admitted online count) becomes the default [D]. Variant A (Bitcoin-style, K = 144, 4× clamp) is the comparison [D]. Variant B's small correction is [P], to be proposed and tested in M3.
  - Reason: M1 found that an attacker hopping in for one Variant A window earns (1 + m) times the fair rate per miner-second, while Variant B, which follows the exact admitted count rather than recent block times, gives no first-order gain.
- **§3.7.** The lower-hash tie-break stays [P] and the confirmation depth is unchanged. M3 measures the orphan rate. Reason: M1 found same-step ties end about 1.66% of rounds at 30 s.
- **§3.11 (new).** Registration index and canonical active list [D]. Reason: allocation and the committee lottery need an order every node can rebuild from chain data.
- **§4.2 allocation.**
  - The allocation algorithm proposed in `docs/ARCHITECTURE.md` §8 becomes the rule [D], numbered by the §3.11 index. It uses inside-out Fisher–Yates insertion, the Golomb ring {1, 4, 6} and swap-with-last removal.
  - The CAC publishes the placement; every node recomputes it and rejects a mismatch.
  - It replaces the per-ID formula `chain(ID) = f(SHA256(ID ‖ beacon))` and the older rule that a vacancy is filled by a newly registered ID.
  - New §2 rows: ring offsets [D]; allocation beacon delay of 6 blocks [O], sweep 3, 6, 12.
  - Deactivation vacates a seat by the removal step, and re-activation re-inserts by Fisher–Yates.
  - Reason: a per-ID hash cannot keep every WC at exactly 10 members. Append-only filling would make new WCs mirror the attacker's share of recent issuance rather than of the population.
- **§4.3 committee.**
  - The seat lottery over the canonical active list [D] replaces "the miner of every 10th PoW-Tx block joins" and the v0.2 seat-uniqueness rule [P]. The lottery's next-position rule keeps one seat per ID. Beacon offset k = 3 [O], sweep 1, 3, 6, 12.
  - The new member is drawn before the oldest leaves, from the list as of block B.
  - Added a note that 256-bit hashes make the modulo bias negligible, and a list of the leader block's duties.
  - Stalling is accepted for now because allocation is deterministic; M4 tests the impact.
  - Reason: the attacker's expected committee share now equals its share of active IDs, independent of mining power, and the committee can announce placements but not choose them.
- **§4.6–§4.7.** Offline beyond the allowance leads to deactivation, never a ban. Bans are only for proven misbehaviour, and the full 40-member KWC votes on bans, MOBu/MOBr and offline requests. Durations stay [O] and swept. Reason: honest household downtime must not cost an ID.
- **§2 capacity.** Footnote ² notes that 200 registered miners per leader WC cannot be reached network-wide. The split stays a sweep. Reason: each ID mines at most one channel, so a KWC averages at most 10 registered miners.
- **§8.**
  - S5 now defines the realistic restart cost C = grace epoch + convergence interval + post-admission wait (450 s). Reason: needed for the restart analysis.
  - S12 and S21 updated to the new wording and measures.
- **§10 H6.**
  - "Capable of early signing" is renamed "capable of signing without honest members", keeping the §3.7 explanation.
  - Results are reported for both quorums: unregistered for PoW-ID, registered for PoW-Tx.
  - The ban rate is 0 per year in the base case, with 1% and 5% as sensitivities.
  - Compositions are counted under the §4.2 allocation, including deactivation, with the v0.2 count as a comparison.
  - Reason: §3.7 already rejects early-signed blocks beyond δ, and the adopted allocation changes how compositions form.
- **§0 scope** updated for the committee lottery, and **§12** gained four open questions.

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
