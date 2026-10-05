# Modelling assumptions — M1 analytical baseline

SPEC §11.5 requires every modelling assumption to be listed with its source. This file covers milestone M1 (`crates/gb-analytic`).

- Each entry has an identifier, the assumption, its source, and the later milestone that tests it.
- "Architect, 2026-10-05" refers to the decisions recorded in the SPEC v0.2 changelog.
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

## A. Time to threshold, adaptive cap, genesis size

| ID | Assumption | Source | Tested in |
|---|---|---|---|
| A-1 | The historical base G is honest. In the base model all of G is active and every newly issued ID is active. | SPEC §0 C2; M1 brief | M3 |
| A-2 | Attacker IDs are always online. | M1 brief | M3 |
| A-3 | **Realistic online fraction (primary):** a fraction f of all honest IDs, old and new, is online. **Optimistic bound:** f applies only to G, and new honest IDs are always online. | Architect, 2026-10-05 (Q2); M1 brief | M3 with household downtime profiles (H7) |
| A-4 | **Honest growth:** active IDs are N = G + g·t + s·R·t and attacker IDs are A = s·R·t, with g a free parameter. g = (1 − s)·R recovers the base model. | Architect, 2026-10-05 (Q1) | M3 |
| A-5 | **Adaptive cap:** the rate is registered IDs / T_min, recalculated at fixed checkpoints, and the attacker's demand keeps the rate at the cap. All registered IDs are active, and the network is static before the attack, so registered = G at the last checkpoint. The attacker may choose when to start relative to the public checkpoint schedule ("worst start phase"). | Architect, 2026-10-05 (Q3); reasoning | M3 (S7) |
| A-6 | The time floor and the safety factor k are defined for a 100%-capture attacker reaching 51% (SPEC §3.9). Other s and T values are reported but are not part of the floor. | SPEC §3.9 | M3 |
| A-7 | **Genesis size to issue:** a fraction f of genesis IDs stays active, the attacker wins every new ID, and the rate is the fixed 30 s rate. | Architect genesis decision, 2026-10-05 | M3, M6 |
| A-8 | No IDs are lost over the horizon (no deactivation, bans or key loss) except through the online fraction f. | Reasoning; offline handling is swept from M3 | M3 (S9, H7) |

## B. Witness capture and stall

| ID | Assumption | Source | Tested in |
|---|---|---|---|
| B-1 | Every registered ID is a witness in exactly one WC of exactly 10 members. With W WCs there are W KWCs and M = 10·W registered IDs. | SPEC §2, §4.1 | M4 |
| B-2 | Allocation is a uniformly random partition of IDs into WCs, and the KWC layout is independent of which ID sits where. A KWC's 40 seats are therefore a uniformly random subset of all IDs. | Architect, 2026-10-05 (Q5) | M4 (S15) |
| B-3 | The attacker holds exactly p·M registered IDs (hypergeometric, primary model). The binomial model is the infinite-network limit. p·M is rounded to the nearest integer when not whole; every default grid value is whole. | Reasoning | M4 |
| B-4 | **Blocking** means withholding PoWit signatures so the quorum cannot be met. A single online member refusing to sign the entropy is handled by One Chance and is not modelled here. | SPEC §3.4, §4.5; reasoning | M4 (S16, S17) |
| B-5 | **Signing without honest members** means the attacker's seats alone meet the quorum. Attacker members are all online. | Reasoning | M4 |
| B-6 | **What each state enables** follows from the SPEC. A KWC in state (ii) cannot make an early-signed block valid, because §3.7 rejects a block received before its own timestamp, within δ. Its powers are stalling and censoring miners in that KWC. Entropy grinding needs state (iii). | Architect, 2026-10-05; SPEC §3.4, §3.7 | M2 (S11), M4 (S12) |
| B-7 | **P(at least one KWC in a state):** the independence value 1 − (1 − q)^W is a rigorous upper bound under the binomial model, because the states are increasing events (Harris' inequality). The lower bound uses the ⌈W/13⌉ KWCs that share no WC: each KWC overlaps at most (1 + 3)·3 = 12 others, from the SPEC §2 structure. Under the hypergeometric model the independence value is an approximation. | Reasoning; SPEC §2 | M4 |
| B-8 | **10-year count (H6 refresh model):** every KWC composition counts as an independent draw. | Architect, 2026-10-05 (Q6) | M4 |
| B-9 | **10-year count, how compositions arise:** one new KWC forms per 10 new IDs, so R/10 per year. Each ban replacement creates 4 compositions, because the replaced member's WC sits in 4 KWCs. Registered IDs grow linearly from 10·W0 at R per year. | Architect (Q6); reasoning | M4 |
| B-10 | **10-year count, rates held fixed:** the ban rate is a labelled sensitivity (0 in the base case; 1% and 5% of registered IDs per year). The attacker fraction p stays constant over 10 years, and the per-composition probability is the binomial one. | Architect (R1); reasoning | M4 |
| B-11 | The Monte Carlo cross-check builds KWCs on the proposed Golomb ring (`docs/ARCHITECTURE.md` §8). The exact per-KWC probability does not depend on the layout. | Reasoning | M4 |
| B-12 | **30-node comparison quorums:** 7 of 10 plus 14 of 20 (registered); any 20 of 30 (unregistered). | Architect, 2026-10-05 (Q7) | M4 |

## C. Chain Allocation Committee

| ID | Assumption | Source | Tested in |
|---|---|---|---|
| C-1 | The miner of each 10th PoW-Tx block is a uniformly random mining ID: every ID mines one channel at 1 hash/s. The attacker's share of mining IDs is p when every ID mines. When only a fraction μ of honest IDs mines, it is p / (p + μ(1 − p)). | SPEC §5; architect, 2026-10-05 (R4) | M4 (S21) |
| C-2 | Approvals needed are ⌈2n/3⌉. The attacker stalls with n − ⌈2n/3⌉ + 1 seats and captures with ⌈2n/3⌉. | Architect, 2026-10-05 (Q4) | M4 |
| C-3 | **Seat rule [P]:** at selection time the oldest member is still a member, so a new member is uniform over the N − n non-members. The FIFO chain is doubly stochastic, so the committee's stationary distribution is uniform over n-subsets (hypergeometric). Duplicates-allowed is the binomial comparison. | Architect (Q4); reasoning | M4; Monte Carlo cross-check |
| C-4 | The committee is at its stationary distribution. Transients right after genesis are not modelled. | Reasoning | M4 |
| C-5 | **Events per year, the M1 brief's approximation:** one independent composition per n refreshes. **This approximation is to be checked by simulation in M4.** It is reported next to the exact stationary rate of entries into each state under the same seat model. | M1 brief | **M4** |
| C-6 | Refreshes per year = seconds per year ÷ PoW-Tx interval ÷ 10 × (N − n)/N, where (N − n)/N accounts for skipped member wins. The PoW-Tx interval defaults to 10 s ([O]). | SPEC §2, §4.3 | M4 |
| C-7 | The mining population defaults to the 2.1M genesis IDs, all mining. | Architect (R4) | M4 |

## D. Restart attack

| ID | Assumption | Source | Tested in |
|---|---|---|---|
| D-1 | **Old design:** entropy is fixed for the whole connection, so the miner can compute its future winning steps at connection time. | M1 brief | M3 (S5) |
| D-2 | **Win probability:** each one-second step wins with probability q = 1/(N·I). A winning step becomes an ID with the same probability for honest and restarting miners, so round competition and ties cancel in the ratio. | M1 brief; reasoning | M3 |
| D-3 | **Restart cost:** C covers disconnecting and re-admission. There is no other penalty, detection or reconnection limit. The honest miner pays one admission C too. | M1 brief | M3 |
| D-4 | **Current design:** the argument that the advantage is 1 rests on three SPEC rules. The header names the previous PoW-ID block (§3.3). Entropy aggregates every online member's unique BLS signature (§3.4). A miner gets one header per round, and abandoning it means waiting for the next block (§3.4). | SPEC §3.3–§3.4 | M2 (S11e), M3 (S5, H4) |

## E. Difficulty hopping

| ID | Assumption | Source | Tested in |
|---|---|---|---|
| E-1 | Variant A retargets every K blocks so that the last window would have lasted K·I. It is computed with no clamp and with a 4× clamp, for K ∈ {144, 2016}. | Architect, 2026-10-05 (Q8) | M3 (S6) |
| E-2 | Honest miners H are constant. The attacker adds m·H miners for exactly one window starting at a retarget boundary. | M1 brief; reasoning | M3 |
| E-3 | The first-order estimate sets each window's duration to its expectation. The Monte Carlo includes the randomness, and its recovery window carries the known K/(K − 1) factor. | M1 brief ("first order") | M3 |
| E-4 | Variant B follows the exact admitted online count with no lag. Its "small correction from recent block times" is not modelled. | Architect, 2026-10-05 (Q8) | M3 |
| E-5 | Gain is the attacker's IDs per miner-second relative to Variant B's fair rate, 1/((H + M)·I). | Reasoning | M3 (H5) |
| E-6 | The Monte Carlo draws block arrivals as a Poisson process, a continuous-time stand-in for one-second steps with small per-step success probability. | Reasoning | M3 |

## F. Same-step ties

| ID | Assumption | Source | Tested in |
|---|---|---|---|
| F-1 | **Step model:** miners succeed independently at each step with q = 1/(N·I). Every chain starts at the same t0 (start rule (a)). A round ends at the first step with at least one success, and network propagation is ignored. | SPEC §3.5; reasoning | M3 |
| F-2 | Tied rounds per year = R × P(tie): one round per PoW-ID block. | Reasoning | M3 |

---

## Questions for the architect

These were raised by M1. Questions already answered on 2026-10-05 are recorded in the SPEC v0.2 changelog and are not repeated here.

1. **§3.9 floor guarantee.** M1 finds that the cap as written keeps a 100%-capture attacker at or above T_min only when frozen at the attack start.
   - Recalculated continuously, the time is 0.713 T_min.
   - With checkpoints and an attacker who picks its start moment, it is 0.786, 0.833 and 0.857 T_min for intervals of T_min/4, T_min/2 and T_min.
   - Should §3.9 adopt the safety factor k (7/6 for checkpoints every T_min) or some other mechanism, such as a lagged count, and should the sentence "never falls below T_min" change?
2. **Genesis activity.** With 2.1M genesis IDs, the 2-year floor at the fixed rate holds only while at least 96.2% of them stay active (A6). Should the genesis size allow for expected inactivity?
3. **Committee stalling.** With one seat per ID and n = 600, an attacker holding 30% of mining IDs can stall 3.5% of the time, and at 33%, 41% of the time. Is that acceptable, or should the stall threshold or committee design change?
4. **Committee events.** Which definition of "capture events per year" should M4 test: the M1 brief's independent compositions, or exact entries into the state? They can differ greatly, in either direction (C2).
   - At n = 600, the exact count is between 0.019 and 340 times the estimate.
   - Across all committee sizes it reaches 567 times the estimate.
   - Where a state is near-certain, entries become rare and the ratio falls far below 1.
5. **H6.** Under the refresh model with 100,000 initial KWCs and no bans, expected sign-capable compositions over 10 years are 0.0011 (registered quorum) and 0.022 (unregistered quorum) at p = 25%. At p = 30% they are 0.089 and 1.27. Two points to confirm:
   - that H6 is judged on the unregistered quorum, which PoW-ID uses;
   - that "capable of early signing" should read "capable of signing without honest members", given B-6.
6. **Ban rate.** What ban/replacement rate should M4 use? M1 uses 0 with 1% and 5% per year as sensitivities.
7. **Allocation.** Please review the proposal in `docs/ARCHITECTURE.md` §8. It moves one existing ID per new ID and changes about 47 KWC compositions per new WC, which affects the H6 count.
8. **Restart cost.** Is the realistic restart cost C the grace epoch + convergence interval + post-admission wait (150 + 150 + 150 s = 450 s at defaults)? M1's grid of 60, 300 and 600 s brackets it.
9. **Difficulty variants.** Which window K and clamp should the protocol use for Variant A? How is Variant B's "small correction from recent block times" defined? (Needed for M3.)
10. **Ties.** Same-step ties end about 1.66% of rounds at 30 s, about 17,400 per year. Should confirmation depth or fork handling account for them, beyond the lower-hash tie-break?

## Observations about the SPEC

These are not errors in M1's inputs, but they affect how results should be read.

- **§10 H6 wording.** H6 speaks of KWCs "capable of early signing", but under §3.7 state (ii) cannot make an early-signed block valid beyond δ (B-6).
- **§4.2 allocation.** A per-ID hash `chain(ID) = f(SHA256(ID ‖ beacon))` cannot by itself keep every WC at exactly 10 members (balls into bins), so an algorithm is needed. See `docs/ARCHITECTURE.md` §8.
- **§2 capacity.** Each registered ID sits in one WC and mines one channel, so a KWC can average at most 10 registered miners. The per-KWC registered capacity of 200, and the 800 registered miners watched per node, are ceilings that cannot be reached network-wide. They can be reached only where miners concentrate.
- **§2 KWC structure.** "Each WC leads one KWC and is subordinate in three, with no mutual monitoring" needs at least 7 WCs, and the proposed Golomb ring needs 13. This is irrelevant at genesis scale.
