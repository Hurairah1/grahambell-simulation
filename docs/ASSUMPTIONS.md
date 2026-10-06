# Modelling assumptions — M1 analytical baseline

SPEC §11.5 requires every modelling assumption to be listed with its source. This file covers milestone M1 and its update M1.1 (`crates/gb-analytic`).

- Each entry has an identifier, the assumption, its source, and the later milestone that tests it.
- "Architect, 2026-10-05" refers to the decisions recorded in the SPEC v0.2 changelog; "architect, 2026-10-06" to those in the SPEC v0.3 changelog.
- Section letters match the tables in `results/analytic/<run>/`.

## General

| ID | Assumption | Source | Tested in |
|---|---|---|---|
| G-1 | A year is 365 days (31,536,000 s), so a 30 s PoW-ID interval gives R = 1,051,200 IDs per year. Configurable as `model.seconds_per_year`. | M1 brief (R = 1,051,200) | — |
| G-2 | Decimal inputs mean the decimal as written: 0.33 is exactly 33/100, not the nearest binary float. | Reasoning: exact tails need exact inputs | unit tests |
| G-3 | Closed forms follow expected values: the attacker gains exactly s·R IDs per year. Block-by-block randomness is checked by Monte Carlo. By Wald's identity, the mean first-passage time differs from the closed form by less than one block's overshoot. | M1 brief (closed form) | M3 |
| G-4 | "Reaching T" means the attacker's share is at least T. | Reasoning | — |
| G-5 | Confirmation depth (6 PoW-ID blocks, about 3 minutes) is ignored next to horizons measured in years. | Reasoning; SPEC §3.7 | M3 |
| G-6 | Random numbers come from ChaCha20 streams seeded by SHA-256(seed ‖ label), with in-repo samplers and pure-Rust `libm`, so a seed reproduces bit-for-bit on any platform. | M1 brief; SPEC §11.4 | reproducibility test |
| G-7 | **All M1 results assume the attacker's IDs are online 100% of the time while honest IDs are online a fraction f of the time.** This is a deliberate worst case. | Architect, 2026-10-06 (D1) | M3 (outages for both sides) |

## A. Time to threshold, adaptive cap, genesis size

| ID | Assumption | Source | Tested in |
|---|---|---|---|
| A-1 | The historical base G is honest. In the base model all of G is active and every newly issued ID is active. | SPEC §0 C2; M1 brief | M3 |
| A-2 | Attacker IDs are always online (G-7). | M1 brief; architect, 2026-10-06 | M3 |
| A-3 | **Realistic online fraction (primary):** a fraction f of all honest IDs, old and new, is online. **Optimistic bound:** f applies only to G, and new honest IDs are always online. | Architect, 2026-10-05 (Q2); M1 brief | M3 with household downtime profiles (H7) |
| A-4 | **Honest growth:** active IDs are N = G + g·t + s·R·t and attacker IDs are A = s·R·t, with g a free parameter. g = (1 − s)·R recovers the base model. | Architect, 2026-10-05 (Q1) | M3 |
| A-5 | **Adaptive cap:** the rate is registered IDs / (k × T_min), recalculated at fixed checkpoints, and the attacker's demand keeps the rate at the cap. All registered IDs are active, and the network is static before the attack, so registered = G at the last checkpoint. The attacker may choose when to start relative to the public checkpoint schedule ("worst start phase"). | SPEC v0.3 §3.9; reasoning | M3 (S7) |
| A-6 | The time floor and the safety factor k are defined for a 100%-capture attacker reaching 51% (SPEC §3.9). Other s and T values are reported but are not part of the floor. | SPEC §3.9 | M3 |
| A-7 | **Genesis size to issue:** a fraction f of genesis IDs stays active, the attacker wins every new ID, and the rate is the fixed 30 s rate. | Architect genesis decisions, 2026-10-05 and 2026-10-06 | M3, M6 |
| A-8 | No IDs are lost over the horizon (no deactivation, bans or key loss) except through the online fraction f. | Reasoning; offline handling is swept from M3 | M3 (S9, H7) |
| A-9 | **Safety factor rows:** for each checkpoint interval x, the factor k comes from bisection on the worst-start time of the 100%-capture attacker at 51%. A cap of registered/(k·T_min) is the same problem in units of k·T_min with checkpoints every x/k, so its worst time is k·t_worst(ρ, x/k). The configured cap uses k = 7/6 and x = T_min. | SPEC v0.3 §3.9; reasoning | M3 (S7) |

## B. Witness capture and stall

| ID | Assumption | Source | Tested in |
|---|---|---|---|
| B-1 | Every registered ID is a witness in exactly one WC of exactly 10 members. With W WCs there are W KWCs and M = 10·W registered IDs. | SPEC §2, §4.1 | M4 |
| B-2 | Seats are a uniformly random partition of IDs into WCs. Under the adopted allocation (SPEC §4.2) this is exact: inside-out Fisher–Yates insertion keeps every assignment a uniformly random permutation. The KWC layout is independent of which ID sits where, so a KWC's 40 seats are a uniformly random subset of all seated IDs. | Architect, 2026-10-05 (Q5) and 2026-10-06 (Q7); reasoning | M4 (S15) |
| B-3 | The attacker holds exactly p·M registered IDs (hypergeometric, primary model). The binomial model is the infinite-network limit. p·M is rounded to the nearest integer when not whole; every default grid value is whole. | Reasoning | M4 |
| B-4 | **Blocking** means withholding PoWit signatures so the quorum cannot be met. A single online member refusing to sign the entropy is handled by One Chance and is not modelled here. | SPEC §3.4, §4.5; reasoning | M4 (S16, S17) |
| B-5 | **Signing without honest members** means the attacker's seats alone meet the quorum. Attacker members are all online. | Reasoning; SPEC v0.3 §10 H6 | M4 |
| B-6 | **What each state enables** follows from the SPEC. A KWC in state (ii) cannot make an early-signed block valid, because §3.7 rejects a block received before its own timestamp, within δ. Its powers are stalling and censoring miners in that KWC. Entropy grinding needs state (iii). | Architect, 2026-10-05 and 2026-10-06 (Q5); SPEC §3.4, §3.7 | M2 (S11), M4 (S12) |
| B-7 | **P(at least one KWC in a state):** the independence value 1 − (1 − q)^W is a rigorous upper bound under the binomial model, because the states are increasing events (Harris' inequality). The lower bound uses the ⌈W/13⌉ KWCs that share no WC: each KWC overlaps at most (1 + 3)·3 = 12 others, from the SPEC §2 structure. Under the hypergeometric model the independence value is an approximation. | Reasoning; SPEC §2 | M4 |
| B-8 | **10-year count (H6 refresh model):** every KWC composition counts as an independent draw. Each composition is marginally a uniform draw (B-2), so the expected number in a state is the count times the per-composition probability, whatever the correlation. | Architect, 2026-10-05 (Q6); SPEC v0.3 §10 H6 | M4 |
| B-9 | **10-year count, how compositions arise (adopted allocation):** each insertion (new or re-activated ID) changes the 4 KWCs of one WC, and one insertion in 10 completes a WC whose KWC forms while the 6 KWCs whose offsets wrap relink: 4 + 7/10 = 4.7 compositions. Each removal (ban or deactivation) changes 4 + 6/10 = 4.6. Insertions that land in the pending tail WC (a fraction below 10/M) are ignored. A seat-by-seat simulation of the rule checks both rates within 2%. | Architect, 2026-10-06 (Q7, answer 2); reasoning | M4 |
| B-10 | **10-year count, rates held fixed:** the ban rate is a labelled sensitivity (0 in the base case; 1% and 5% of registered IDs per year). The attacker fraction p stays constant over 10 years, and the per-composition probability is the binomial one. Registered IDs grow linearly from 10·W0 at R per year. | Architect (Q6, R1) | M4 |
| B-11 | **Deactivation cycles:** an illustrative sensitivity of 0, 1 and 4 cycles per registered ID per year, each cycle changing about 9.3 compositions. It is applied to all registered IDs, although under G-7 attacker IDs never go offline; that overstates the count by at most a factor 1/(1 − p), which is pessimistic for the protocol. | Architect, 2026-10-06 (answer 2); reasoning | M3 (downtime profiles), M4 |
| B-12 | **One-seat entry ratio:** one uniformly chosen seat of a KWC is replaced by a member who is the attacker's with probability p (binomial). The ratio of the entry probability to the per-composition probability measures how much the composition count overstates distinct episodes. Ring relinks, which change 10 seats, are not covered by it. | Reasoning | M4 |
| B-13 | The Monte Carlo cross-check builds KWCs on the configured Golomb ring (SPEC §4.2). The exact per-KWC probability does not depend on the layout. | Reasoning | M4 |
| B-14 | **30-node comparison quorums:** 7 of 10 plus 14 of 20 (registered); any 20 of 30 (unregistered); ring offsets {1, 3}. | Architect, 2026-10-05 (Q7); SPEC v0.3 §2 | M4 |

## C. Chain Allocation Committee

| ID | Assumption | Source | Tested in |
|---|---|---|---|
| C-1 | **Seat lottery (primary).** For every 10th PoW-Tx block, the new member is the ID at a uniformly random position of the canonical active list; a draw that lands on a member moves to the next position. The 256-bit hash makes the position uniform up to a relative bias below N/2²⁵⁶. | SPEC v0.3 §4.3 (R2) | M2 (beacon), M4 (S21) |
| C-2 | **Attacker IDs spread through the list (primary model):** a draw that lands on a member passes to a neighbour of random type, so the new member is treated as uniform over the N − n non-members. The FIFO chain is then doubly stochastic, and the seat count is hypergeometric over the N active IDs. The real next-position rule differs by O(n/N) per draw; a Monte Carlo of the real rule (N = 100,000, n = 30 and 100) checks the formulas. | Reasoning | M4 |
| C-3 | **Attacker IDs in one block of the list (sensitivity):** a draw that lands on a member passes to a neighbour of the same type, so each new member is the attacker's with probability K/N regardless of the committee, and the seat count is binomial. The canonical list follows registration order, so IDs won in a burst do sit together; the real layout lies between the two models. | Reasoning; SPEC §3.11 | M4 |
| C-4 | **Timing:** the new member is drawn before the oldest member leaves, and the canonical active list is read as of block B. N is the active count at that block. | Architect, 2026-10-06 (answer 1) | M4 |
| C-5 | Approvals needed are ⌈2n/3⌉. The attacker stalls with n − ⌈2n/3⌉ + 1 seats and captures with ⌈2n/3⌉. | Architect, 2026-10-05 (Q4) | M4 |
| C-6 | The committee is at its stationary distribution. Transients right after genesis are not modelled. | Reasoning | M4 |
| C-7 | **Events per year:** exact entries into each state and the share of time in it are the primary measures; the mean episode length is their ratio. The M1 brief's estimate (one independent composition per n refreshes) is reported as a labelled comparison only. | Architect, 2026-10-06 (Q4) | **M4** |
| C-8 | **Refreshes per year:** under the lottery, every 10th PoW-Tx block refreshes the committee: seconds per year ÷ PoW-Tx interval ÷ 10 = 315,360 at 10 s. The PoW-Tx interval is [O]. | SPEC §2, §4.3 | M4 |
| C-9 | The active population defaults to the 2.9M genesis IDs, all active. | Architect, 2026-10-06 (Q2) | M4 |
| C-10 | **v0.2 comparison rule:** the miner of each 10th PoW-Tx block is a uniformly random mining ID; a member's win passes to the next 10th-block miner who is not a member. When only a fraction μ of honest IDs mines, the attacker's share of mining IDs is p / (p + μ(1 − p)). Member wins delay refreshes by the factor N/(N − n). | SPEC v0.2 §4.3; architect, 2026-10-05 (R4) | — (comparison only) |
| C-11 | The lottery beacon offset k does not enter M1, because the draws are modelled as uniform. | Reasoning | M2, M4 (beacon withholding) |
| C-12 | **Stalling is accepted for now:** allocation is deterministic, so a stalled committee delays the announcement of placements but cannot change them. | Architect, 2026-10-06 (Q3) | M4 |
| C-13 | **Remaining committee power (open risk):** besides placement (recomputed by every node) and joins and leaves (recomputable from the lottery), the leader's block compiles bans already approved by KWCs into Master Blacklisting Blocks. A committee the attacker controls could delay or omit those approved bans. M1 does not model this. | Architect, 2026-10-06 (answer 6) | **M4** |

## D. Restart attack

| ID | Assumption | Source | Tested in |
|---|---|---|---|
| D-1 | **Old design:** entropy is fixed for the whole connection, so the miner can compute its future winning steps at connection time. | M1 brief | M3 (S5) |
| D-2 | **Win probability:** each one-second step wins with probability q = 1/(N·I). A winning step becomes an ID with the same probability for honest and restarting miners, so round competition and ties cancel in the ratio. | M1 brief; reasoning | M3 |
| D-3 | **Restart cost:** C covers disconnecting and re-admission. There is no other penalty, detection or reconnection limit. The honest miner pays one admission C too. | M1 brief | M3 |
| D-4 | **Current design:** the argument that the advantage is 1 rests on three SPEC rules. The header names the previous PoW-ID block (§3.3). Entropy aggregates every online member's unique BLS signature (§3.4). A miner gets one header per round, and abandoning it means waiting for the next block (§3.4). | SPEC §3.3–§3.4 | M2 (S11e), M3 (S5, H4) |
| D-5 | **Realistic restart cost:** C = I × (grace epoch + convergence interval in rounds + post-admission wait) = 30 × (5 + 5 + 5) = 450 s at the §2 defaults. It is always added to the cost grid. | Architect, 2026-10-06 (Q8); SPEC v0.3 §8 S5 | M3 (S5) |

## E. Difficulty hopping

| ID | Assumption | Source | Tested in |
|---|---|---|---|
| E-1 | Variant A (the comparison) retargets every K = 144 blocks so that the last window would have lasted K·I, with a 4× clamp per retarget. The table also shows it without a clamp, as a sensitivity. | Architect, 2026-10-06 (Q9); SPEC v0.3 §3.8 | M3 (S6) |
| E-2 | Honest miners H are constant. The attacker adds m·H miners for exactly one window starting at a retarget boundary. | M1 brief; reasoning | M3 |
| E-3 | The first-order estimate sets each window's duration to its expectation. The Monte Carlo includes the randomness, and its recovery window carries the known K/(K − 1) factor. | M1 brief ("first order") | M3 |
| E-4 | Variant B (the default) follows the exact admitted online count with no lag. Its correction from recent block times is [P] and not yet defined, so it is not modelled. | Architect, 2026-10-06 (Q9) | M3 |
| E-5 | Gain is the attacker's IDs per miner-second relative to Variant B's fair rate, 1/((H + M)·I). | Reasoning | M3 (H5) |
| E-6 | The Monte Carlo draws block arrivals as a Poisson process, a continuous-time stand-in for one-second steps with small per-step success probability. | Reasoning | M3 |

## F. Same-step ties

| ID | Assumption | Source | Tested in |
|---|---|---|---|
| F-1 | **Step model:** miners succeed independently at each step with q = 1/(N·I). Every chain starts at the same t0 (start rule (a)). A round ends at the first step with at least one success, and network propagation is ignored. | SPEC §3.5; reasoning | M3 |
| F-2 | Tied rounds per year = R × P(tie): one round per PoW-ID block. The lower-hash tie-break [P] and the confirmation depth are unchanged; M3 measures the orphan rate. | Reasoning; architect, 2026-10-06 (Q10) | M3 |

## G. Quorum trade-off

Section G changes no SPEC quorum; it maps what each quorum option allows. Identifiers use the prefix Q to avoid a clash with the general entries.

| ID | Assumption | Source | Tested in |
|---|---|---|---|
| Q-1 | **Conflict model:** honest members sign at most one of two conflicting proposals; attacker members sign both; the attacker may show different proposals to different honest members. A pool of n with quorum k then allows two conflicting approvals exactly when the attacker holds at least 2k − n seats. An exhaustive enumeration over pools of up to 10 members checks the condition. | Reasoning | M4 |
| Q-2 | The seat condition is **necessary, not sufficient**: the attacker also needs a proposer turn (§4.4) or another way to put two proposals in front of members. M1 does not model proposer access. | Reasoning; SPEC §4.4 | M4 |
| Q-3 | **Registered layout:** the quorum applies per group (k₁ = ⌈10q⌉ of the leader WC and k₂ = ⌈30q⌉ of the subordinates), so each harm's condition applies per group. Two-thirds rounded up per group gives 7 + 20 and is a comparison; the SPEC default 7 + 21 is q = 0.7 per group. | Architect, 2026-10-06 (answer 7) | M4 |
| Q-4 | **Decision pool:** the full 40-member KWC votes on bans, MOBu/MOBr and offline requests (two-thirds: 27 of 40); the subordinate-only proposer only proposes. | Architect, 2026-10-06 (answer 5) | M4 |
| Q-5 | Seats are uniformly random (B-2): hypergeometric at 100,000 and 1,000,000 KWCs for per-KWC probabilities; binomial for the counts over ten years, which use the B-9 composition count with no bans or deactivation. | Reasoning | M4 |
| Q-6 | The committee part (G3) uses the lottery's primary model (C-2) with n = 600 and 2.9M active IDs. | SPEC v0.3 §4.3 | M4 |
| Q-7 | **What global validation neutralises** follows from the SPEC: validators recompute every PoWit's hash chain and timing (§3.7), resolve two blocks at one height by the lower hash (§3.7), treat two headers from one miner in a round as equivocation (§3.4), recompute placement and the committee's joins and leaves (§4.2, §4.3), and reject both of a leader's conflicting committee blocks (§4.3). Decisions based on witnesses' observations (bans, MOBu/MOBr, offline requests) cannot be recomputed. | SPEC v0.3; reasoning | M4 |
| Q-8 | Quorums at or below one half are not considered: two disjoint honest groups could then approve conflicting decisions with no attacker. The configuration rejects them. | Architect, 2026-10-06 (G4) | — |

---

## Questions for the architect

**Resolved.** The ten M1 questions, R1–R5 and the seven M1.1 plan questions were answered on 2026-10-06; the answers are recorded in the SPEC v0.3 changelog and in the entries above.

**New questions raised by M1.1:**

1. **H6 under the adopted allocation.** Counting every composition as an independent draw (the SPEC §10 H6 refresh model), the expected number of compositions able to sign without honest members over 10 years from 100,000 KWCs at p = 25% is 0.926 for the unregistered quorum and 0.0489 for the registered quorum (B4). The v0.2 count gave 0.0215 and 0.00114.
   - One deactivation cycle per ID per year multiplies the count by 12.8; four cycles by 48.
   - Most changes replace one seat, and a one-seat change enters the state with about 0.43 (unregistered) and 0.46 (registered) times the probability of a fresh draw.
   - Should H6 be judged on compositions, as now, or on distinct episodes? Which deactivation rate should it assume?
2. **Re-activation beacon.** Which block supplies the beacon when a re-activated ID is re-inserted (SPEC §4.2, §12)?
3. **Committee members who are deactivated or banned.** Do they keep their seat until first-in first-out removes them, or leave at once (SPEC §4.3, §12)?
4. **Placement during a committee stall.** Every node can compute a placement without the committee. Does a placement take effect while the committee is stalled, or wait for the Allocation Committee Block? At p = 33% of active IDs the committee can be stalled 41% of the time, in episodes averaging 1.5 hours; at p = 40%, more than 99.9% of the time (C2).
5. **Conflicting KWC decisions.** What happens when two conflicting decisions are both approved, for example a MOBu and an offline request for the same miner? The committee rule rejects both; is the same intended for KWC decisions? Which members may propose each decision type? (Section G's conflict condition is necessary; whether it is sufficient depends on proposer rights.)
6. **Variant B's correction.** SPEC §3.8 leaves the correction from recent block times [P]. Is there a preferred form for M3 to test first, for example a bounded multiplicative adjustment over a recent window?

## Observations about the SPEC

These are not errors in M1's inputs, but they affect how results should be read.

- **Registration order and the lottery.** The canonical active list follows registration order (§3.11), so IDs an attacker wins in a burst sit next to each other. With all of them in one block, the lottery's next-position rule gives a binomial rather than hypergeometric seat count. At 2.9M active IDs the two differ by less than 0.25% wherever the probability exceeds 10⁻⁶; the gap grows only in far tails, reaching 85% at a probability of 1.9 × 10⁻⁴⁰⁸ (C1 rows for both layouts).
- **Lower quorums and conflicts.** At a PoWit-style quorum of 0.51, two conflicting decisions need only 2 attacker seats in a pool of 40 (section G). Global validation neutralises this for PoWits but not for observation-based decisions, which is why section G reports the split rule.
- **§2 KWC structure.** "Each WC leads one KWC and is subordinate in three, with no mutual monitoring" needs at least 13 active WCs on the adopted ring (7 for the 30-node comparison). SPEC v0.3 §4.2 notes that this holds from genesis.
