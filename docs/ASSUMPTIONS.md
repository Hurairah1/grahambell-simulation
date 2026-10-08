# Modelling assumptions — M1 analytical baseline and M2 protocol core

SPEC §11.5 requires every modelling assumption to be listed with its source. This file covers milestone M1 and its updates M1.1 and M1.2 (`crates/gb-analytic`), and M2 (`crates/gb-protocol`, section P; `crates/gb-crypto-tests`, section K).

- Each entry has an identifier, the assumption, its source, and the later milestone that tests it.
- "Architect, 2026-10-05" refers to the decisions recorded in the SPEC v0.2 changelog; "architect, 2026-10-06" to those in the SPEC v0.3 changelog; "architect, 2026-10-07" to those in the SPEC v0.4 changelog and the M1.2 plan; "architect, 2026-10-08" to the SPEC v0.5 changelog and the M2 plan.
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
| B-8 | **10-year count (SPEC v0.4 §10 H6):** the primary measure is **distinct episodes**, the expected number of entries into a state. The KWCs in the state at the start contribute W0·q; every change of membership adds its probability P(before ∉ S, after ∈ S). Counting every composition as an independent draw, as v0.3 did, gives an upper bound (compositions × q); each composition is marginally a uniform draw (B-2), so that bound holds whatever the correlation. | Architect, 2026-10-07 (item 3); SPEC v0.4 §10 H6 | M4 |
| B-9 | **10-year count, how compositions arise (adopted allocation):** each insertion (a new ID, or a returning ID whose seat was vacated) changes the 4 KWCs of one WC, and one insertion in 10 completes a WC whose KWC forms while the 6 KWCs whose offsets wrap relink: 4 + 7/10 = 4.7 compositions. Each removal (a ban, or an absence longer than L) changes 4 + 6/10 = 4.6. The relink profile comes from the ring offsets: for {1, 4, 6}, when the ring grows or shrinks by one WC, 2 KWCs change one subordinate WC, 3 change two and 1 changes three. Insertions that land in the pending tail WC (a fraction below 10/M) are ignored. A seat-by-seat simulation of the rule checks both rates within 2%. | Architect, 2026-10-06 (Q7, answer 2) and 2026-10-07 (item 1); reasoning | M4 |
| B-10 | **10-year count, rates held fixed:** the ban rate is a labelled sensitivity (0 in the base case; 1% and 5% of registered IDs per year). The attacker fraction p stays constant over 10 years, and the per-composition probability is the binomial one. Registered IDs grow linearly from 10·W0 at R per year. | Architect (Q6, R1) | M4 |
| B-11 | **Absences (illustrative until M3):** c = 1 or 4 absences per registered ID per year, realised rates, each long enough to deactivate the ID. Durations follow a Lomax distribution, P(D > x) = (1 + x/σ)^(−α) with σ = 2 days and α = 1.5 (primary), or an exponential with mean 7 days (comparison). Under the v0.4 seat rule an absence vacates a seat only if it lasts longer than L, so at rate c·P(D > L); it then counts as a removal and, on return, an insertion (about 9.3 compositions). Under the v0.3 rule, the comparison, every absence does. Absences are applied to all registered IDs, although attacker IDs never go offline (G-7); that overstates counts by at most 1/(1 − p), which is pessimistic for the protocol. M3 replaces these inputs with cited published measurements where they exist and keeps these Lomax values as the fallback. | Architect, 2026-10-07 (answers 1–2; M1.2 answer Q3); SPEC v0.4 §4.7 | M3 (household profiles), M4 |
| B-12 | **One-seat entry ratio:** one uniformly chosen seat of a KWC is replaced by a member who is the attacker's with probability p (binomial). The ratio of the entry probability to the per-composition probability shows how much the composition count overstates distinct episodes for one-seat changes. | Reasoning | M4 |
| B-13 | The Monte Carlo cross-check builds KWCs on the configured Golomb ring (SPEC §4.2). The exact per-KWC probability does not depend on the layout. | Reasoning | M4 |
| B-14 | **30-node comparison quorums:** 7 of 10 plus 14 of 20 (registered); any 20 of 30 (unregistered); ring offsets {1, 3}. | Architect, 2026-10-05 (Q7); SPEC v0.3 §2 | M4 |
| B-15 | **Episode model:** seats are independent draws with attacker probability p. A one-seat change replaces a uniformly chosen seat with a fresh member; a ring change replaces j subordinate WCs with independent fresh WCs, j from the relink profile (B-9); a newly formed KWC enters with probability q. Treating relinked WCs as fresh ignores that they are existing WCs shared with other KWCs. A cross-check confirms that every count lies between W0·q and compositions × q. | Reasoning | M4 |
| B-16 | **Permanent departures** are left out of composition counts: under both seat rules a departed ID vacates its seat once (v0.3 at deactivation, v0.4 after L), so they change both counts alike. They matter for liveness, through seats held by absent IDs (QF-6). | Architect, 2026-10-07 (answer 2); reasoning | M3, M4 |

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
| C-12 | **Placement does not wait for the committee (SPEC v0.4 §4.2):** it takes effect at each ID's beacon block. The Allocation Committee Block is a record and attestation, so a stall delays that record and the compilation of approved bans, never a placement. | Architect, 2026-10-07 (item 5) | M4 |
| C-13 | **Remaining committee power (open risk):** besides placement (recomputed by every node) and joins and leaves (recomputable from the lottery), the leader's block compiles bans already approved by KWCs into Master Blacklisting Blocks. A committee the attacker controls could delay or omit those approved bans. M1 does not model this. | Architect, 2026-10-06 (answer 6) | **M4** |
| C-14 | **Departures (table C3):** a banned or deactivated member leaves the committee at once, and an extra draw fills its seat at the next 10th PoW-Tx block (SPEC v0.4 §4.3). An honest member deactivates during a refresh interval with probability δ = 1 − e^(−c/R), for absences starting as a Poisson process at c per year and R refreshes per year; attacker members never do (G-7). By Little's law the attacker's seat share is p/(p + (1 − p)·r), with r = (1 − (1 − δ)^n)/(nδ). This is an approximation: it ignores the seat left empty until the next 10th block and the shortening of every tenure by departures ahead in the queue, both second order in nδ (about 0.008 at n = 600 and c = 4). A Monte Carlo at an exaggerated δ checks the formula. p is the attacker's share of active IDs, as in C1, so deactivated honest IDs are already outside the list. | Architect, 2026-10-07 (item 4); reasoning | M4 |
| C-15 | The extra draw's position [P], SHA256("GB/cac" ‖ hash of block B+k ‖ i), does not enter M1, because draws are modelled as uniform (C-11). | Architect, 2026-10-07 (answer 6) | M2, M4 |

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
| Q-2 | The seat condition is **necessary, not sufficient**: the attacker also has to put both proposals forward. SPEC v0.4 §4.4 assigns proposer rights: the master proposer for MOBr, registered offline requests and bans; the subordinate-only proposer for MOBu, unregistered offline requests and bans of leader-chain members who refuse to witness newcomers; the miner for its own offline request. M1 does not model proposer access. Under SPEC v0.4 §4.6 two conflicting approved decisions are both rejected, and members who signed both may be banned, so a conflict cancels a decision rather than enacting two. | Architect, 2026-10-07 (item 6); SPEC v0.4 §4.4, §4.6 | M4 |
| Q-3 | **Registered layout:** the quorum applies per group (k₁ = ⌈10q⌉ of the leader WC and k₂ = ⌈30q⌉ of the subordinates), so each harm's condition applies per group. Two-thirds rounded up per group gives 7 + 20 and is a comparison; the SPEC default 7 + 21 is q = 0.7 per group. | Architect, 2026-10-06 (answer 7) | M4 |
| Q-4 | **Decision pool:** the full 40-member KWC votes on bans, MOBu/MOBr and offline requests (two-thirds: 27 of 40); the subordinate-only proposer only proposes. | Architect, 2026-10-06 (answer 5) | M4 |
| Q-5 | Seats are uniformly random (B-2): hypergeometric at 100,000 and 1,000,000 KWCs for per-KWC probabilities; binomial for the counts over ten years, which use the episode and composition counts of B-8 and B-9 with no bans or absences (G1) and with the absences of B-11 under each seat rule (G4). | Reasoning | M4 |
| Q-6 | The committee part (G3) uses the lottery's primary model (C-2) with n = 600 and 2.9M active IDs. | SPEC v0.3 §4.3 | M4 |
| Q-7 | **What global validation neutralises** follows from the SPEC: validators recompute every PoWit's hash chain and timing (§3.7), resolve two blocks at one height by the lower hash (§3.7), treat two headers from one miner in a round as equivocation (§3.4), recompute placement and the committee's joins and leaves (§4.2, §4.3), and reject both of a leader's conflicting committee blocks (§4.3) and both of two conflicting approved KWC decisions (§4.6). Decisions based on witnesses' observations (bans, MOBu/MOBr, offline requests) cannot be recomputed. | SPEC v0.4; reasoning | M4 |
| Q-8 | Quorums at or below one half are not considered: two disjoint honest groups could then approve conflicting decisions with no attacker. The configuration rejects them. | Architect, 2026-10-06 (G4) | — |

## H. Quorum feasibility under honest downtime

Identifiers use the prefix QF to avoid a clash with the SPEC hypotheses H1–H9.

| ID | Assumption | Source | Tested in |
|---|---|---|---|
| QF-1 | **Seat model:** each seat is the attacker's with probability p (binomial; hypergeometric at 100,000 KWCs as a comparison), and attacker members never sign. Each honest member is online, and signs, with probability f, independently of other members. A seat therefore signs with probability (1 − p)·f. Correlated outages (shared ISPs, regions, power cuts) are not modelled. | Architect, 2026-10-07 (item 2); reasoning | M3 (household profiles, correlated outages), M4 |
| QF-2 | **Failure** means the KWC cannot meet its PoWit quorum at that moment: fewer than 27 of 40 sign (unregistered, and the registered single-quorum comparison), or fewer than 7 of the leader WC's 10 or 21 of the 30 subordinates sign (registered, SPEC). The entropy rule (every online member signs) is not part of the condition; One Chance handles one online member that withholds (B-4). | SPEC §2, §3.4; reasoning | M4 |
| QF-3 | **Withholding is free:** attacker members that withhold suffer no penalty. Under SPEC §4.5–§4.6 an online member that refuses to sign after One Chance is banned; M4 models that. Every "not reachable" entry with an attacker rests on this assumption. M4 models the One Chance ban, so withholding is no longer free there. | Architect, 2026-10-07 (addendum; M1.2 answer Q1) | M4 |
| QF-4 | **Local liveness:** a failing KWC affects only its own miners, who move to another KWC after the grace epoch plus admission (about 450 s, D-5); the rest of the network continues. Miners are spread evenly over KWCs, so the share of miners affected equals P(fail). | Architect, 2026-10-07 (addendum); SPEC §3.2 | M3, M4 |
| QF-5 | **Minimum uptime:** the smallest f on a 10⁻⁴ grid with P(fail) below the target, by exact bisection on rationals and verified on both sides by an independent sum. The targets are 1% of KWCs (primary) and 0.1% (stricter secondary). | Architect, 2026-10-07 (item 2; M1.2 answer Q1) | M4 |
| QF-6 | **Absent seats (table H3):** by Little's law with realised rates, honest seat-holders are absent a share (c·E[min(D, L)] + a·L)/365 of the time, for c absences per ID per year with durations D (B-11) and a permanent departures per ID per year (0, 10% or 25%), each departed ID holding its seat for L. Members who are present are online with an ordinary uptime f_o, so the online fraction is (1 − share)·f_o; the uptime needed is s*/((1 − p)(1 − share)), where s* is the signing probability at which P(fail) equals the target. | Architect, 2026-10-07 (answers 1–2); reasoning | M3, M4 |
| QF-7 | **No incentives:** M1 models no rewards or payments. The registered single 27-of-40 layout is the validity rule of the [P] proposal to separate validity from payment (SPEC §12); its effect on leaders' incentives to stay online and sign, and on issuance per block, is for M4. | Architect, 2026-10-07 (addendum) | M4 |

## I. KWC size trade-off

| ID | Assumption | Source | Tested in |
|---|---|---|---|
| KS-1 | **Sizes and rings:** KWCs of k = 3, 4, 5, 6, 8 or 10 WCs of 10 members, each on a configured optimal Golomb ruler ({1, 3}, {1, 4, 6}, {1, 4, 9, 11}, {1, 4, 10, 12, 17}, {1, 4, 9, 15, 22, 32, 34}, {1, 6, 10, 23, 26, 34, 41, 53, 55}); k = 4 must equal the protocol's ring. Each ruler is checked for the ring properties of SPEC §4.2. | Architect, 2026-10-07 (addendum, section I); reasoning | M2 (if sizes change) |
| KS-2 | **Quorums:** one quorum over the whole KWC, either ⌈2n/3⌉ or ⌈0.51·n⌉, with no separate leader requirement. Probabilities are hypergeometric at 100,000 KWCs; episodes follow B-8 and B-15 with each size's relink profile. | Architect, 2026-10-07 (addendum) | M4 |
| KS-3 | **Load policies:** (A) every WC hosts 250 miners (`capacity.miners_per_leader_wc`), so a node watches 250·k; (B) every node watches 1,000 miners, as at the protocol size, so a WC hosts 1,000/k; (C) a WC hosts ⌈10 × 1.33⌉ = 14 registered miners, sized to its 10 registered IDs plus the spare-capacity target, and u = 50, 100 or 235 unregistered. A and B use the SPEC §2 mix, 200 of 250 registered; C's mix is 14/(14 + u). Registered capacity ÷ registered IDs is registered miners per WC ÷ 10, since each WC holds 10 registered IDs and leads one KWC. | Architect, 2026-10-07 (addendum); SPEC §2 | M5 |
| KS-4 | **Message inputs:** about 295 bytes per exchange between a miner and one witness; registered miners exchange every 1 s or 5 s, unregistered every 30 s (from the papers); one direction, no transport overhead. A node recomputes one hash per watched miner per second. | Architect's papers; architect, 2026-10-07 (addendum) | M5 (S27) |
| KS-5 | **Peer topology, option 1:** each member keeps a standing connection to every member of its k KWCs: 10·(1 + k(k − 1)) − 1 peers, because the k KWCs share only the member's own WC (Golomb property). | Reasoning; SPEC §4.2 | M5 |
| KS-6 | **Peer topology, option 2 [P], on-demand estimate (table I4):** One Chance: every absence is treated as an unannounced disappearance (the worst case), and each makes every neighbour contact the member once. Decisions: miner session changes at an illustrative 2 or 8 per miner per day, each a decision in its KWC in which the proposer contacts the other n − 1 members, so a member averages 2(n − 1)/n connections per decision in each of its k KWCs; the asymmetry between master and subordinate-only proposers is averaged out. Bans: at the B4 ban rates, one decision each. Catch-up: 8 connections (the peer bootstrap count) per return, counted at both ends. Connections are counted when opened or accepted. | Architect, 2026-10-07 (addendum) | M3, M5 |
| KS-7 | **(a) The miner cannot be the only channel between witnesses.** One Chance requires direct contact with the member whose signature is missing, so option 2 still needs on-demand witness-to-witness connections. | Architect, 2026-10-07 (addendum); SPEC §4.5 | M3, M4 |
| KS-8 | **(b) A member that disappears without announcing it still counts as online.** Under option 2 online status comes from the network record, so its KWCs' entropy waits for its signature until One Chance fails and the proposer records it offline, about one grace epoch. M3 and M4 measure how often this stalls KWCs. One Chance is the intended mechanism; M3 and M4 sweep the wait over 1, 2 and 5 rounds. | Architect, 2026-10-07 (addendum; M1.2 answer Q4); SPEC §3.4, §4.5 | M3, M4 |
| KS-9 | **Household limits** (router connection tables, upload bandwidth) are not modelled; M5 measures them. Section I does not pick a size. M2 and M5 benchmark k = 4 and 6 (primary) and k = 3 and 10 (edges). | Architect, 2026-10-07 (addendum; M1.2 answer Q5) | M2, M5 |

## P. Protocol core (`gb-protocol`)

| ID | Assumption | Source | Tested in |
|---|---|---|---|
| P-1 | **Byte layouts** follow SPEC v0.5 Appendix A [P]: big-endian fixed widths, domain-tagged SHA-256, the canonical 173-byte header with an address type, the signer bitfield in seat order. `vectors/protocol_v1.json` pins every output; a test requires the committed file to equal a fresh rendering. | Architect, 2026-10-08 (byte formats, address type) | M3, Stage 3 node |
| P-2 | **BLS:** `blst` only, min-pk (keys in G1, signatures in G2), ciphersuite `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`. Keys are validated (subgroup check) whenever parsed. A KWC's keys are accepted only with valid proofs of possession (`KwcKeys::new`), which makes aggregating different members' keys safe. The protocol core contains no hand-written cryptographic arithmetic. | Architect, 2026-10-08 (BLS variant; amendment 2) | M2 tests |
| P-3 | **Equivocation** ("two headers signed by the same miner key in the same round", SPEC §3.4) is read as two different headers at the same height, both validly signed by the same candidate key. | Reasoning; SPEC §3.4 | M2 C1(d) |
| P-4 | **Signing condition** (SPEC §3.6): a member signs the PoWit when its own clock is at least `t0 + N − δ`. | SPEC §3.6 | M3, M4 |
| P-5 | **Validation** checks rules in a fixed order and reports the first failure: tip and serialisation, uniqueness, entropy signers meeting the quorum, the entropy aggregate, the full chain (N must be the first winning step), `timestamp = t0 + N`, reception no earlier than the timestamp minus δ, the PoWit quorum and aggregate, and the PoWit deadline D when set. "Online members must number at least the quorum" (§3.4) is read as the entropy signers meeting the miner kind's quorum rule. A validator cannot see who was online, so "every online member signed" is enforced by One Chance, not by validation. | Reasoning; SPEC §3.4, §3.7 | M3, M4 |
| P-6 | **Uniqueness** of the candidate key and address is a predicate the caller supplies from chain state. | Reasoning | M3 |
| P-7 | **Adaptive interval:** the larger of the interval demand asks for and `k × T_min / registered IDs` at the last checkpoint. | SPEC §3.9 | M3 (S7) |
| P-8 | **Committee refresh:** the regular draw joins first; the oldest member leaves when members plus seats awaiting extra draws exceed the size; extra draws `i = 1, 2, …` follow. While the committee is filling, nobody leaves. | SPEC §4.3; reasoning | M4 (S21) |
| P-9 | **IDs** are block hashes, `SHA256("GB/block" ‖ header ‖ E ‖ N)` (Appendix A). | Architect, 2026-10-08 | — |

## K. Cryptography measurements (`gb-crypto-tests`, `gb crypto`)

| ID | Assumption | Source | Tested in |
|---|---|---|---|
| K-1 | **Test difficulty:** each step wins with probability 1/64, so trials are fast. For independent candidate entropies the advantage is `E / (1/(1 − (1 − 1/E)^G))`, which depends little on E; each row reports this formula next to the measured value. | Reasoning | — |
| K-2 | **Non-unique signature stand-in (C1 a, c):** a BLS signature over the message and a free nonce represents a randomised signature scheme, in which every new nonce gives another valid signature and so another entropy. | Reasoning; SPEC §8 S11 | — |
| K-3 | **Group size in C1:** 10 members; the subset experiment (b) uses a quorum of 7. The advantage depends on the number of distinct entropies the attacker can choose from, not on the group size. | Reasoning | — |
| K-4 | **C1(c′):** a colluding member's choice to withhold is measured as if free, to size the lever. Under SPEC §4.5 withholding while online triggers One Chance and then a penalty. | SPEC §4.5 | M4 |
| K-5 | **C1(e):** the full current flow is re-signed G times on the first 20 trials to confirm that it yields one entropy; later trials compute it once. The honest comparison uses an independent stream of trials. | Reasoning | — |
| K-6 | **Beacon withholding (C3):** the attacker mines each candidate beacon block independently with probability s and withholds it when the outcome is unfavourable, giving up that block; a block mined by someone else is final. For the committee lottery the attacker's share of PoW-Tx blocks equals its share of active IDs, and committee membership is ignored (the next-position rule rarely applies when n ≪ N). | Reasoning; SPEC §4.2–§4.3 | M4 |
| K-7 | **Placement grinding (C3):** the allocation beacon does not exist when an ID is minted (it is 6 blocks after confirmation), so the experiment applies a selection rule at minting and checks that kept IDs land in the target seats at the target rate. | SPEC §4.2 | — |
| K-8 | **Timings (C4, C5):** single-threaded on the machine named in `bench/BENCH.md`, release build. Verification times include parsing and validating keys from bytes; a node that caches parsed keys would be faster. | Reasoning | M5 (S27) |
| K-9 | **§13 witness-server estimate (C4):** per miner and witness every round: one miner-signature verify, one entropy signature, one entropy-aggregate verify, and one SHA-256 chain step per second of the round; 3 witnesses per server; 30 s rounds. PoWit signing, networking, serialisation and storage are not counted. | Architect, 2026-10-08 (§13); reasoning | M5, Stage 3 staging |
| K-10 | **Threshold BLS prototype (C5): benchmark only, not audited, not used by `gb-protocol`.** Joint-Feldman DKG with honest dealers (no complaint round), t = ⌈2n/3⌉. Shares are counted at 32 bytes without encryption overhead, and commitment broadcasts once per sender. Group arithmetic uses the `bls12_381` crate; signing and verification use `blst`. | Architect, 2026-10-08 (threshold, amendment 2) | M4 decision |
| K-11 | **Entropy stand-in for M3 (C6):** 32 uniform random bytes in place of the real BLS-derived entropy. It passes when a two-sample χ² on the winning-step distribution (10 bins, edges at 1/8 to 4 times the expected attempts) and KS tests on the top 53 bits of E all give p ≥ 0.001. | Architect, 2026-10-08 (C6) | M3 |

---

## Questions for the architect

**Resolved.** The ten M1 questions, R1–R5 and the seven M1.1 plan questions were answered on 2026-10-06, and the six M1.1 questions and the five M1.2 questions on 2026-10-07. The answers are recorded in the SPEC v0.3 and v0.4 changelogs, in the entries above and, for M1.2, below.

**M1.2 questions, answered by the architect on 2026-10-07:**

1. **Failure target.** Keep 1% of KWCs as the primary target and 0.1% as a stricter secondary one. M4 judges the [P] single 27-of-40 rule and the split quorum against these, with the One Chance ban modelled, so withholding is no longer free (QF-3, QF-5).
2. **Long-absence threshold L.** Keep 30 days as the primary value, and keep the sweep {3, 7, 30, 90, 365} days.
3. **Household absence inputs for M3.** Replace the illustrative inputs with published measurements where they exist, each cited in this file, and keep the current Lomax values as the fallback (B-11).
   - Separate short outages (within the grace epoch) from absences long enough to deactivate an ID.
   - Device profiles: an always-on device (mini-PC, Raspberry Pi), a desktop left on, and a laptop or PC switched off at night.
   - Regional profiles: a reliable-grid region (US/EU) and an unreliable-grid region with scheduled power cuts (for example, load-shedding in Pakistan).
   - Candidate sources: RIPE Atlas probe connection histories for home connectivity; national SAIDI/SAIFI power-reliability statistics.
   - Model correlated outages (a region or ISP going down at once). Keep 0–25% permanent departures per year as a sweep.
4. **Unannounced disappearances.** One Chance is the intended mechanism (KS-8).
   - Default wait: one grace epoch; M3 and M4 sweep 1, 2 and 5 rounds.
   - Measure the entropy stall in all 4 KWCs the member sits in, and how often a member with a brief network glitch is wrongly recorded offline.
   - Client requirement: a node that shuts down normally sends its offline request first, so only crashes and power cuts are unannounced. M3 and M4 model that share explicitly.
5. **KWC sizes to benchmark** in M2 (threshold BLS key setup) and M5 (household limits) (KS-9):
   - primary: k = 4 (40 members, the protocol default) and k = 6 (60 members, the smallest size at which two-thirds stays under 1% failing at p = 20%);
   - edges: k = 3 (30 members) and k = 10 (100 members).

**Open questions raised by M2:**

1. **Pre-registered thresholds for H1–H9 (SPEC §10).** Proposals, for you to confirm or change before M3 generates results:
   - **H1 linearity:** keep: the amplification factor's 95% CI lies within [0.95, 1.05] for every strategy in S1–S4. M1 shows proportionality holds exactly in expectation; ±5% leaves room for Tier 1 sample noise.
   - **H2 time floor:** keep ±5% of `(0.51/0.49) × H_active / R`. M1's closed form differs from block-by-block outcomes by less than one block.
   - **H3 no grinding:** tighten to "the advantage's 95% CI includes 1 and its upper end is at most 1.02, with at least 10,000 trials under S11(e)". M2 measured 1.012 (0.933–1.091) with 1,000 trials, and the current flow yields exactly one entropy, so a measurable gain would point to a bug.
   - **H4 restart:** tighten from 1.05 to 1.02. Per-round entropy makes the advantage exactly 1 analytically (M1 section D); only simulation noise remains.
   - **H5 hopping:** keep ≤ 2% for Variant B, and require the same of whatever correction M3 proposes.
   - **H6 witness capture:** fewer than 1 expected distinct sign-alone episode over 10 years at p ≤ 25% and 100,000 KWCs, for the unregistered quorum, under the v0.4 seat rule with L = 30 days and M3's household profiles. M1 gives 0.476 with no absences and 0.821 with 4 absences per year, so this passes narrowly and is a meaningful test.
   - **H7 attrition:** at most 1% of IDs lost per year without misbehaviour, under both M3 regional profiles (reliable and unreliable grid).
   - **H8 griefing:** zero griefing bans of honest witnesses under the [P] "unreachable is not refusal" rule; report the cost per victim under the strict rule.
   - **H9 cost:** reported without a threshold, at 1M and 10M honest active IDs.
2. **The online set as a grinding lever.** C1(c′) shows that a member able to choose between signing and withholding without cost gives the miner two entropies (advantage 1.88 measured, 1.98 for independent tries). More generally, c such members give up to 2^c. SPEC §4.5 makes withholding while online costly (One Chance, then a penalty), but an unannounced disappearance is treated as online until One Chance fails. Should M4 measure this lever explicitly, for example with colluding members timing offline requests?
3. **Witness-server CPU for §13.** On this 2019 laptop CPU (Intel i5-8257U), 30,000 miners need about 12 cores busy, dominated by verifying each miner's entropy aggregate (about 2.4 ms with key parsing). Is per-miner entropy verification by every witness required, given that each witness helped build that entropy? Dropping it would roughly halve the load.

## Observations about the SPEC

These are not errors in M1's inputs, but they affect how results should be read.

- **Registration order and the lottery.** The canonical active list follows registration order (§3.11), so IDs an attacker wins in a burst sit next to each other. With all of them in one block, the lottery's next-position rule gives a binomial rather than hypergeometric seat count. At 2.9M active IDs the two differ by less than 0.25% wherever the probability exceeds 10⁻⁶; the gap grows only in far tails, reaching 85% at a probability of 1.9 × 10⁻⁴⁰⁸ (C1 rows for both layouts).
- **Lower quorums and conflicts.** At a PoWit-style quorum of 0.51, two conflicting decisions need only 2 attacker seats in a pool of 40 (section G). Global validation neutralises this for PoWits but not for observation-based decisions, which is why section G reports the split rule. Under SPEC v0.4 two conflicting approved decisions are both rejected, so the harm becomes a cancelled decision.
- **Rounding of ⌈2n/3⌉.** The two-thirds quorum leaves a stall threshold between 33.75% and 36.7% of seats depending on KWC size (section I), so comparisons between sizes near p = 1/3 reflect rounding as much as size.
- **§2 KWC structure.** "Each WC leads one KWC and is subordinate in three, with no mutual monitoring" needs at least 13 active WCs on the adopted ring (7 for the 30-node comparison). SPEC v0.3 §4.2 notes that this holds from genesis.
