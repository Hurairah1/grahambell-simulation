# Architecture — GrahamBell Stage 1

This document describes how the Stage 1 code is organised, how later milestones plug in, and how the protocol core will be shared with the Stage 3 testnet. It is a design document: crates marked *planned* below do not exist yet.

`docs/SPEC.md` is the source of truth for protocol rules. Nothing in this document changes a rule. The allocation algorithm in the last section is a **proposal for architect review**.

## 1. Goals and constraints

- **Reproducible.** One master seed, a recorded configuration and a recorded git commit fully determine every output (SPEC §11.4). Reruns are checked byte for byte through a SHA-256 manifest.
- **Ground truth first.** Every quantity with a closed form is computed exactly in M1. The simulators must match those values before their other results are trusted (SPEC §11.3).
- **Two tiers** (SPEC §11.1):
  - Tier 1 simulates protocol messages at reduced scale.
  - Tier 2 models millions of participants statistically, and is validated against Tier 1 where their scales overlap.
- **One protocol core.** The rules a simulator enforces are the same code the Stage 3 testnet runs (SPEC §11.7).
- **Configurable everything.** Every SPEC number is a typed parameter with its status tag and sweep (`gb-config`).

## 2. Crate map

| Crate | Status | Milestone | Responsibility |
|---|---|---|---|
| `gb-config` | exists | M0 | Typed parameters for every SPEC §2 row (value, status D/P/O, sweep), M1 grids, run settings; TOML loading by deep merge over defaults. |
| `gb-runlog` | exists | M0 | Run id, git commit and dirty flag, UTC timestamp, resolved-config hash, SHA-256 manifest of outputs, seeded ChaCha20 streams. |
| `gb-analytic` | M1 | M1 | Exact closed forms and exact probabilities (sections A–F), with independent cross-checks. Pure functions; no I/O. |
| `gb-cli` | exists | M0+ | Binary `gb`: loads config, runs analyses, writes CSV/PNG/SUMMARY and the run log. Front end only; never recomputes results. |
| `gb-protocol` | planned | M2 | Shared protocol core, listed in section 5. |
| `gb-crypto-tests` | planned | M2 | Micro-tests with real SHA-256 and BLS12-381: S11 grinding, S14, proof of possession, equivocation, and equivalence tests for any abstraction a simulator uses. |
| `gb-sim` | planned | M3, M4 | Tier 1 discrete-event simulator. |
| `gb-scale` | planned | M6 | Tier 2 aggregate model at full scale. |
| `gb-bench` | planned | M5 | S27 hardware benchmark and S28 money-cost model. |

Dependencies point one way: `gb-cli` → analysis crates (`gb-analytic`, `gb-sim`, `gb-scale`, `gb-bench`) → `gb-protocol`, `gb-config`, `gb-runlog`. No analysis crate depends on `gb-cli`.

## 3. The two tiers

### Tier 1 — `gb-sim` (protocol-level discrete-event simulation)

- **Event engine:** a priority queue of timestamped events with a deterministic tie order (time, then event sequence number).
- **Actors:** unregistered miners (/64s), registered IDs acting as witness nodes and miners, KWC proposers, and the CAC.
- **Network:** messages with regional latency distributions, loss, partitions and per-node rate limits.
- **Clocks:** per-node clocks with configurable skew, so δ-tolerance rules can be tested (S12).
- **Churn and adversaries:** household downtime profiles (H7), botnet churn (S4), and attacker strategies as pluggable policies (restart, hopping, stalling, griefing, eclipsing).
- **Cryptography:** real `gb-protocol` code where affordable. Where a statistically equivalent abstraction is used for speed, M2 must first document and test the equivalence.
- **Scale:** up to about 100,000 miners.
- **Milestones:**
  - M3 covers issuance scenarios S1–S10, including S5 restart, S6 difficulty hopping and S7 adaptive issuance.
  - M4 covers the witness layer, S12–S26.

### Tier 2 — `gb-scale` (aggregate model)

- Represents populations by counts and distributions instead of individual messages: issuance shares, KWC compositions, committee compositions, attrition.
- Uses M1 closed forms wherever they are exact. Stochastic components are calibrated against Tier 1.
- **Validated against Tier 1** on overlapping scales (10³ to 10⁵ miners) before results are reported at millions (M6).

## 4. Validation ladder

Each M1 table becomes a check that a later simulator must pass.

| M1 output | Later check |
|---|---|
| A1–A3, A7 time to threshold, long-run share | M3 issuance simulator (S2, S3) within its confidence interval; H2 within ±5% |
| A4 adaptive cap (checkpoints, worst phase, safety factor) | M3 S7 |
| A6 genesis to issue | M3/M6 with household downtime profiles |
| B1–B3 per-KWC capture/stall probabilities | M4 allocation simulation (S15) at the same p and network sizes |
| B4 KWC compositions over 10 years | M4 count of compositions and their effective independence |
| C1–C2 committee stall/capture and onset rates | M4 S21, including the independent-composition approximation |
| D1 restart advantage | M3 S5 (H4) |
| E1 difficulty-hopping gain | M3 S6 (H5) |
| F1 same-step tie rate | M3 fork/orphan rate |

## 5. `gb-protocol` and the Stage 3 testnet

`gb-protocol` holds protocol rules as pure, deterministic functions with no networking, storage or clock access:

- **§3.3 headers:** fixed-length encodings and domain tags.
- **§3.4 entropy lock:** miner signature, member signatures, BLS aggregate (via `blst`), and `E = SHA256("GB/entropy-out" ‖ aggregate ‖ bitfield)`.
- **§3.5 hash chain:** `h_n`, start rule (a), and rule (b) for S13.
- **§3.6 witness signing condition** and **§3.7 validation:** quorum with bitfield and proof of possession, full chain recomputation, timestamp rules, the same-height tie-break, uniqueness.
- **§3.8 difficulty** variants A and B, and **§3.9 issuance** (fixed; adaptive with checkpointed cap).
- **§4.2 allocation**, once the architect fixes the algorithm (see section 8).

**Sharing.** `gb-sim` calls these functions directly, and so will the Stage 3 node. M2 produces test vectors (inputs and expected hashes, signatures and validation verdicts) that both the simulator and the testnet node must reproduce. A rule change therefore lands in one place and is caught by the vectors everywhere.

**Versioning.** `gb-protocol` carries a protocol version. Simulator outputs record it next to the git commit.

## 6. Determinism and outputs

- **Randomness:** one master seed. Each component draws from `rng_stream(seed, label)`, a ChaCha20 stream seeded by `SHA-256(seed ‖ label)`. Samplers (uniform, geometric, exponential) are written in-repo, so outputs do not depend on another crate's sampling algorithms.
- **Arithmetic:**
  - Exact rationals for tail probabilities.
  - `libm` (pure Rust) for transcendental functions, so results do not depend on the platform math library.
  - No hash-map iteration in output paths.
- **Parallelism** (Tier 2) uses deterministic partitioning and ordered reductions only.
- **Run directory:** `results/<analysis>/<run-id>/` holds the tables (CSV), charts (PNG), `SUMMARY.md`, `config.resolved.toml` and `run.json`. `run.json` records commit, dirty flag, seed, config hash, toolchain and a SHA-256 for every output file.
- **Front ends** read these outputs only (SPEC §11.6).

## 7. Configuration toggles to add with M3/M4

These [P] rules and comparisons are defined in the SPEC but not needed by M1. They will become typed `gb-config` parameters when the simulators use them:

- mandatory handshake vs none (§3.1, S26);
- hash-priority tie-break for pending claims vs timestamps (§3.1);
- sorted-hash field ordering (S14);
- "unreachable is not refusal" vs strict One Chance (§4.6, S17);
- diversity constraints in allocation (§4.2);
- proposer rotation and failure behaviour (§4.4).

## 8. Allocation proposal — for architect review

SPEC §4.2 requires allocation to be deterministic and publicly recomputable, with placement unknown to an ID's owner at minting time. SPEC §2 requires:

- every WC to have exactly 10 members;
- each WC to lead exactly one KWC and be a subordinate in exactly three;
- no mutual monitoring pairs.

The SPEC does not yet give an algorithm that meets all of these at once. M1 models allocation as a uniform random partition and does not depend on this proposal.

### 8.1 Seats: inside-out Fisher–Yates insertion

1. IDs are allocated in canonical order: the order in which they are confirmed on the PoW-ID chain. Genesis IDs are allocated first, using a public launch seed in place of a beacon.
2. **Seats.** Seats are numbered 0, 1, 2, …, and WC `w` is seats `10w` to `10w + 9`.
3. **Inserting an ID.** When ID number `n` is allocated (counting from 0), compute `j = SHA256("GB/alloc" ‖ ID ‖ beacon) mod (n + 1)`, reading the hash as a 256-bit integer; the modulo bias is below 2⁻²⁰⁰. The beacon is the hash of the block a fixed number of blocks after the ID's confirmation, as in §4.2.
   - If `j = n`, the ID takes seat `n`.
   - Otherwise the ID in seat `j` moves to seat `n`, and the new ID takes seat `j`.
4. **Why it is uniform.** This is the inside-out Fisher–Yates shuffle. After every step, the assignment of allocated IDs to seats is a uniformly random permutation, given uniform hash outputs.
5. **Active and pending WCs.** A WC is active when all 10 of its seats are filled, so the number of active WCs is `W = ⌊allocated / 10⌋`. The partial tail WC is pending. Its members may mine (§3.10) but do not witness until it fills, about 5 minutes at 30 s per ID.
6. **Removals** (ban or deactivation). The ID in the last filled seat moves into the vacated seat. If that empties a seat of the last active WC, that WC returns to pending, `W` decreases by one, and the KWC ring (8.2) is recomputed.

### 8.2 KWCs: a Golomb-ruler ring

For `W ≥ 13` active WCs, KWC `w` has leader WC `w` and subordinate WCs `(w + 1)`, `(w + 4)` and `(w + 6)`, all mod `W`.

- **Each WC leads exactly one KWC and is a subordinate in exactly three:** the KWCs led by `w − 1`, `w − 4` and `w − 6`.
- **No mutual monitoring pairs.** WC `j` monitors WC `i` exactly when `(j − i) mod W ∈ {1, 4, 6}`. A mutual pair would need `d₁ + d₂ ≡ 0 (mod W)` for some `d₁, d₂ ∈ {1, 4, 6}`, but every such sum is at most 12, which is less than `W`.
- **Any two KWCs share at most one WC.** `{0, 1, 4, 6}` is a Golomb ruler: its 12 nonzero pairwise differences, ±1 to ±6, are distinct mod `W` for `W ≥ 13`. So each KWC overlaps exactly 12 others, each in one WC. That is the overlap degree M1 uses for its structure-free bound.
- **30-node comparison.** Use marks `{0, 1, 3}`, so subordinates are `(w + 1)` and `(w + 3)`, and `W ≥ 7`.

Everything depends only on chain data: the ID order, the beacons and the removal record. Anyone can recompute it. The CAC attests a hash of the resulting assignment but cannot choose it.

### 8.3 Conflicts with the current design

- **§4.2 formula.** §4.2 writes placement as a pure per-ID function, `chain(ID) = f(SHA256(ID ‖ beacon))`. Under this proposal, placement also depends on earlier allocations, and an existing ID moves when a new ID displaces it.
- **Fixed-membership principle.** The architect's principle is that chain membership stays fixed unless someone is banned. This proposal breaks it: every new ID changes the membership of one existing WC, and moves one existing ID into the pending tail WC.

### 8.4 Security reason for accepting the conflict

The alternative that keeps membership fixed is **append-only** allocation: new IDs fill new WCs in arrival order, and existing WCs never change. Under append-only allocation, a new WC's composition mirrors the attacker's share of **recent issuance** (s), not its share of the **population** (p).

- An attacker pays to sustain issuance share at the margin. Early in an attack, s is far above p.
- In any ring layout, a new WC's KWC neighbours are also recent WCs. So a whole new KWC reflects s.
- **Example.** An attacker winning 60% of recent issuance holds at least 7 of 10 seats in about 38% of new WCs (P[Bin(10, 0.6) ≥ 7] = 0.382). Under uniform allocation with a 10% population share, the same event has probability about 9 × 10⁻⁶.

Insertion keeps every WC's composition at the population share, so the section B probabilities apply to new KWCs too.

### 8.5 Cost: composition changes

- **Seat changes:** each new ID changes one existing WC, and so 4 KWC compositions (a WC sits in 4 KWCs). That is 40 per new WC.
- **Ring relinks:** each new active WC adds its own KWC and relinks the 6 KWCs whose subordinate offsets wrap around the ring. That is 7 per new WC.
- **Total:** about 47 composition changes per new WC, against 1 for append-only.
- **Effect on the H6 count:** the SPEC §10 counting model treats every composition as an independent draw, so the proposal raises that count. However, each changed composition differs from its predecessor by one seat, so the changes are strongly correlated. M4 should measure the effective number of independent draws rather than count raw changes.

### 8.6 Open risks

- **Beacon withholding.** The miner of the beacon block can withhold it to re-roll placements, at the cost of that block.
- **Placement grinding.** An unregistered miner cannot choose its ID hash freely, because the ID is the hash of the winning PoW-ID block and §3.4 allows one header per round. The residual freedom should still be measured in M2.
