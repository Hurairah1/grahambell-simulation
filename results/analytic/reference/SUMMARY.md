# M1 analytical baseline — summary

- Git commit: `a44311f4c5d79f49e7b167ec14181e18a2227ea1` (clean working tree)
- Seed: 20261005 (used only by the Monte Carlo cross-checks)
- Configuration SHA-256: `52747e18d24c0e321f95362ddaa67892f1c7754d3da8ec86a6f0953f70f68050` (`config.resolved.toml`)

These results are exact calculations: closed-form formulas and exact probabilities. They are not a simulation of the network. Seeded Monte Carlo runs appear only as cross-checks of the formulas (section 13). Every number below comes from a CSV table in this directory, and every modelling assumption is listed in `docs/ASSUMPTIONS.md`.

Terms used throughout: the attacker wins a share **s** of newly issued IDs; **G** is the existing base of active IDs (default 2,900,000 genesis IDs); **R** = 1,051,200 new IDs per year (one every 30 s); **T** is a target share of active IDs; **f** is the fraction of honest IDs that are online.

## 1. Attackers that win less than half of new IDs

> All M1 results assume the attacker's IDs are online 100% of the time while honest IDs are online a fraction f of the time. This is a deliberate worst case; M3 adds realistic outages for both sides.

Tables `A7_long_run_share.csv` and `A2_online_fraction.csv`; charts `A7_long_run_share.png`, `A5_share_trajectories.png`.

An attacker that wins a share s of new IDs sees its share of active IDs rise towards a long-run value and never above it. If only a fraction f of honest IDs is online, applied to old and new honest IDs alike (the realistic variant), the long-run share is s / (s + f(1 − s)). If every honest ID is online, it is s.

- An attacker winning 5% of new IDs settles at about 5.0% of active IDs when every honest ID is online (never reaching 33%), and at about 9.5% when 50% of honest IDs are online (never reaching 33%).
- An attacker winning 10% of new IDs settles at about 10.0% of active IDs when every honest ID is online (never reaching 33%), and at about 18.2% when 50% of honest IDs are online (never reaching 33%).
- An attacker winning 20% of new IDs settles at about 20.0% of active IDs when every honest ID is online (never reaching 33%), and at about 33.3% when 50% of honest IDs are online (eventually crossing 33%).
- An attacker winning 25% of new IDs settles at about 25.0% of active IDs when every honest ID is online (never reaching 33%), and at about 40.0% when 50% of honest IDs are online (eventually crossing 33%).
- An attacker winning 30% of new IDs settles at about 30.0% of active IDs when every honest ID is online (never reaching 33%), and at about 46.2% when 50% of honest IDs are online (eventually crossing 33%).
- An attacker winning 34% of new IDs settles at about 34.0% of active IDs when every honest ID is online (eventually crossing 33%), and at about 50.7% when 50% of honest IDs are online (eventually crossing 33%).
- An attacker winning 40% of new IDs settles at about 40.0% of active IDs when every honest ID is online (eventually crossing 33%), and at about 57.1% when 50% of honest IDs are online (eventually crossing 33% and 51%).

**Long-run attacker share of active IDs** (realistic variant):

| s | f = 100% | f = 90% | f = 80% | f = 70% | f = 60% | f = 50% |
|---|---|---|---|---|---|---|
| 5% | 5.0% | 5.5% | 6.2% | 7.0% | 8.1% | 9.5% |
| 10% | 10.0% | 11.0% | 12.2% | 13.7% | 15.6% | 18.2% |
| 20% | 20.0% | 21.7% | 23.8% | 26.3% | 29.4% | 33.3% |
| 25% | 25.0% | 27.0% | 29.4% | 32.3% | 35.7% | 40.0% |
| 30% | 30.0% | 32.3% | 34.9% | 38.0% | 41.7% | 46.2% |
| 34% | 34.0% | 36.4% | 39.2% | 42.4% | 46.2% | 50.7% |
| 40% | 40.0% | 42.6% | 45.5% | 48.8% | 52.6% | 57.1% |

**Years to reach each threshold, G = 2.9M** (realistic variant; "never" means never reached):

| s | 33% at f = 100% | 33% at f = 70% | 33% at f = 50% | 51% at f = 100% | 51% at f = 70% | 51% at f = 50% | 67% at f = 100% | 67% at f = 70% | 67% at f = 50% |
|---|---|---|---|---|---|---|---|---|---|
| 5% | never | never | never | never | never | never | never | never | never |
| 10% | never | never | never | never | never | never | never | never | never |
| 20% | never | never | 228 | never | never | never | never | never | never |
| 25% | never | never | 10.4 | never | never | never | never | never | never |
| 30% | never | 16.2 | 5.32 | never | never | never | never | never | never |
| 34% | 91.0 | 8.46 | 3.83 | never | never | never | never | never | never |
| 40% | 13.0 | 4.92 | 2.69 | never | never | 16.4 | never | never | never |

Under the M1 brief's formulation, the optimistic bound, f reduces only the historical base and new honest IDs are always online. The long-run share is then exactly s, so none of these attackers ever reaches 51% or 67% (table `A2_online_fraction.csv`, variant "optimistic bound").

## 2. Attackers that win more than half of new IDs

Table `A1_time_to_threshold.csv`; chart `A1_time_to_threshold.png`. Base model: every honest ID is online.

**Years until the attacker holds 51% of active IDs:**

| s | G = 1M | G = 2.1M | G = 2.9M | G = 5M | G = 10M |
|---|---|---|---|---|---|
| 52% | 48.5 | 102 | 141 | 243 | 485 |
| 55% | 12.1 | 25.5 | 35.2 | 60.6 | 121 |
| 60% | 5.39 | 11.3 | 15.6 | 27.0 | 53.9 |
| 75% | 2.02 | 4.25 | 5.86 | 10.1 | 20.2 |

**Years until the attacker holds 67% of active IDs:**

| s | G = 1M | G = 2.1M | G = 2.9M | G = 5M | G = 10M |
|---|---|---|---|---|---|
| 52% | never | never | never | never | never |
| 55% | never | never | never | never | never |
| 60% | never | never | never | never | never |
| 75% | 7.97 | 16.7 | 23.1 | 39.8 | 79.7 |

The time grows in proportion to G and shrinks as s moves away from T. When s equals T exactly, T is never reached in finite time.

## 3. Worst-case bounds: an attacker that wins every new ID

Everything in this section is a **worst-case bound**. It assumes the attacker wins 100% of new IDs and every honest ID stays online. The exact time is (T/(1−T)) × G/R, the SPEC §0 C2 floor.

**Fixed 30 s rate, 100% capture** (table `A1_time_to_threshold.csv`, rows s = 100%):

| G | years to 33% | years to 51% | years to 67% |
|---|---|---|---|
| 1M | 0.469 | 0.990 | 1.93 |
| 2.1M | 0.984 | 2.08 | 4.06 |
| 2.9M | 1.36 | 2.87 | 5.60 |
| 5M | 2.34 | 4.95 | 9.66 |
| 10M | 4.69 | 9.90 | 19.3 |

**Genesis IDs to issue so that the floor holds at the fixed rate** (table `A6_genesis_to_issue.csv`, chart `A6_genesis_to_issue.png`). A 100%-capture attacker needs at least T_min to reach 51% only if the active base is at least T_min × R × 0.49/0.51. If only a fraction f of genesis IDs stays active, the number to issue is that base ÷ f:

| active fraction f | T_min = 1 yr | T_min = 2 yr | T_min = 5 yr | T_min = 10 yr |
|---|---|---|---|---|
| 100% | 1.01M | 2.02M | 5.05M | 10.1M |
| 90% | 1.12M | 2.24M | 5.61M | 11.2M |
| 80% | 1.26M | 2.52M | 6.31M | 12.6M |
| 70% | 1.44M | 2.89M | 7.21M | 14.4M |
| 60% | 1.68M | 3.37M | 8.42M | 16.8M |
| 50% | 2.02M | 4.04M | 10.1M | 20.2M |

With 2.9M genesis IDs issued, the 2-year floor at the fixed rate needs 2.02M of them active, so it holds only while at least 69.7% of genesis IDs stay active.

**Adaptive cap R ≤ registered IDs / (k × T_min) (SPEC §3.9, an optional variant; the fixed 30 s rate stays the default): time for a 100%-capture attacker to reach 51%, in units of T_min** (table `A4_adaptive_cap.csv`, chart `A4_adaptive_cap.png`). "Worst start" is the fastest time over all possible start moments relative to the public checkpoint schedule.

| cap recalculation | start at a checkpoint, k = 1 | worst start, k = 1 | worst start, with safety factor k |
|---|---|---|---|
| cap frozen at attack start | 1.04 | — | — |
| recalculated continuously | 0.713 | 0.713 | — |
| checkpoint every 0.25 T_min | 0.795 | 0.786 | 1.00 (k = 1.2959) |
| checkpoint every 0.5 T_min | 0.861 | 0.833 | 1.00 (k = 1.2257) |
| checkpoint every 1 T_min | 1.02 | 0.857 | 1.00 (k = 1.1667) |

Times at or above 1.00 meet the floor. Without a safety factor (k = 1) the floor holds at every start moment only for: cap frozen at attack start. The safety factor k for each checkpoint interval (table `A4_safety_factor.csv`):

| cap | worst time / T_min with k = 1 | safety factor k |
|---|---|---|
| frozen | 1.04 | 0.9608 |
| continuous | 0.713 | 1.4018 |
| checkpoint every 0.25 T_min | 0.786 | 1.2959 |
| checkpoint every 0.5 T_min | 0.833 | 1.2257 |
| checkpoint every 1 T_min | 0.857 | 1.1667 |

**SPEC v0.3 default:** k = 1.1667 with checkpoints every T_min. Its worst-start time is 1.000 T_min, so a 100%-capture attacker cannot reach 51% in less than T_min at any start phase (cross-checks `A-cap-configured-floor` and `A-cap-configured-vs-grid`). A factor k above 1 tightens the cap; below 1, the floor already holds with room to spare.

## 4. Honest active-base growth

Table `A3_honest_growth.csv`. In the architect's general form, honest active IDs grow by g per year while the attacker gains s × R. Setting g = (1 − s)R is the base model. A larger g only slows the attacker: it reaches T in finite time only if s > T·g / (R(1 − T)).

| growth g | minimum s to reach 33% | minimum s to reach 51% | minimum s to reach 67% |
|---|---|---|---|
| 0 (no growth) | any s > 0 | any s > 0 | any s > 0 |
| 0.5 × R | 24.6% | 52.0% | impossible (above 100%) |
| 1 × R | 49.3% | impossible (above 100%) | impossible (above 100%) |
| 2 × R | 98.5% | impossible (above 100%) | impossible (above 100%) |

## 5. Witness Chains: chance an attacker controls a KWC

Tables `B1_kwc_probabilities.csv`, `B2_network_counts.csv`, `B3_binomial_vs_hypergeometric.csv`, `B4_kwc_compositions_10y.csv`, `B5_seat_rule_10y.csv`; charts `B1_kwc_probabilities.png`, `B4_kwc_compositions_10y.png`. The attacker controls a fraction p of registered IDs, and seats are assigned uniformly at random. A 40-node KWC is a 10-seat leader WC plus 30 subordinate seats.

**What each state lets the attacker do.** This follows from the SPEC rules; it is not a simulation result.

| state | registered quorum (7 of 10 and 21 of 30) | unregistered quorum (any 27 of 40) | harms it enables | harms it does not enable |
|---|---|---|---|---|
| (i) block | ≥ 4 leader or ≥ 10 subordinate seats | ≥ 14 seats | stalling the KWC; censoring miners in that KWC (they can move to another KWC after the grace epoch) | signing anything |
| (ii) sign without honest members | ≥ 7 leader and ≥ 21 subordinate seats | ≥ 27 seats | the same stalling and censoring | making an early-signed block valid: §3.7 global validation rejects a block received before its own timestamp (within the clock tolerance δ) |
| (iii) every seat | all 40 | all 40 | stalling, censoring and entropy grinding (the entropy aggregate then contains only attacker signatures) | — |

**Probability that one KWC is in each state** (exact hypergeometric, 100,000 KWCs):

| p | (i) block, registered | (i) block, unregistered | (ii) sign, registered | (ii) sign, unregistered | (iii) all seats |
|---|---|---|---|---|---|
| 5% | 1.03 × 10⁻³ | 4.10 × 10⁻⁹ | 3.58 × 10⁻²⁸ | 4.69 × 10⁻²⁶ | 8.96 × 10⁻⁵³ |
| 10% | 1.32% | 1.85 × 10⁻⁵ | 5.28 × 10⁻²⁰ | 3.21 × 10⁻¹⁸ | 9.93 × 10⁻⁴¹ |
| 15% | 5.91% | 1.40 × 10⁻³ | 2.39 × 10⁻¹⁵ | 8.98 × 10⁻¹⁴ | 1.10 × 10⁻³³ |
| 20% | 17.5% | 1.94% | 3.87 × 10⁻¹² | 1.00 × 10⁻¹⁰ | 1.10 × 10⁻²⁸ |
| 25% | 37.7% | 10.3% | 9.87 × 10⁻¹⁰ | 1.87 × 10⁻⁸ | 8.25 × 10⁻²⁵ |
| 30% | 61.8% | 29.7% | 7.70 × 10⁻⁸ | 1.10 × 10⁻⁶ | 1.21 × 10⁻²¹ |
| 33% | 74.6% | 45.2% | 6.94 × 10⁻⁷ | 8.47 × 10⁻⁶ | 5.49 × 10⁻²⁰ |
| 40% | 93.3% | 78.9% | 4.69 × 10⁻⁵ | 4.02 × 10⁻⁴ | 1.21 × 10⁻¹⁶ |

**Expected number of KWCs in state (ii) at one moment** (= number of KWCs × per-KWC probability). The chance that at least one exists is in `B2_network_counts.csv`, with a rigorous upper bound (independence value) and lower bound (KWCs sharing no WC).

| p | registered, 10k KWCs | registered, 100k KWCs | registered, 1M KWCs | unregistered, 10k KWCs | unregistered, 100k KWCs | unregistered, 1M KWCs |
|---|---|---|---|---|---|---|
| 5% | 3.36 × 10⁻²⁴ | 3.58 × 10⁻²³ | 3.60 × 10⁻²² | 4.43 × 10⁻²² | 4.69 × 10⁻²¹ | 4.71 × 10⁻²⁰ |
| 10% | 5.13 × 10⁻¹⁶ | 5.28 × 10⁻¹⁵ | 5.29 × 10⁻¹⁴ | 3.13 × 10⁻¹⁴ | 3.21 × 10⁻¹³ | 3.22 × 10⁻¹² |
| 15% | 2.35 × 10⁻¹¹ | 2.39 × 10⁻¹⁰ | 2.39 × 10⁻⁹ | 8.85 × 10⁻¹⁰ | 8.98 × 10⁻⁹ | 8.99 × 10⁻⁸ |
| 20% | 3.82 × 10⁻⁸ | 3.87 × 10⁻⁷ | 3.87 × 10⁻⁶ | 9.92 × 10⁻⁷ | 1.00 × 10⁻⁵ | 1.00 × 10⁻⁴ |
| 25% | 9.80 × 10⁻⁶ | 9.87 × 10⁻⁵ | 9.88 × 10⁻⁴ | 1.86 × 10⁻⁴ | 1.87 × 10⁻³ | 0.0187 |
| 30% | 7.66 × 10⁻⁴ | 7.70 × 10⁻³ | 0.0771 | 0.0110 | 0.110 | 1.10 |
| 33% | 6.91 × 10⁻³ | 0.0694 | 0.694 | 0.0844 | 0.847 | 8.48 |
| 40% | 0.468 | 4.69 | 46.9 | 4.01 | 40.2 | 402 |

**KWCs able to sign without honest members over 10 years** (table `B4_kwc_compositions_10y.csv`, chart `B4_kwc_compositions_10y.png`; SPEC v0.4 §10 H6). The primary measure is the expected number of **distinct episodes**: an episode starts when a change of membership moves a KWC into state (ii), and lasts while it stays there. Under the adopted allocation (SPEC §4.2) each new ID changes one existing WC, so the 4 KWCs it sits in, and one new ID in 10 completes a WC whose KWC forms while 6 others relink: about 4.7 changed compositions per new ID. With 100,000 KWCs at the start and no bans or absences, that is 49,506,400 compositions. Counting every composition as an independent draw, as M1.1 did, gives an upper bound on episodes. The v0.2 count, one new KWC per 10 new IDs (1,151,200 compositions), is a comparison:

| p | episodes, registered quorum (PoW-Tx) | episodes, unregistered quorum (PoW-ID) | upper bound, registered | upper bound, unregistered | v0.2 count, registered | v0.2 count, unregistered |
|---|---|---|---|---|---|---|
| 5% | 1.25 × 10⁻²⁰ | 1.59 × 10⁻¹⁸ | 1.78 × 10⁻²⁰ | 2.34 × 10⁻¹⁸ | 4.15 × 10⁻²² | 5.43 × 10⁻²⁰ |
| 10% | 1.74 × 10⁻¹² | 1.02 × 10⁻¹⁰ | 2.62 × 10⁻¹² | 1.60 × 10⁻¹⁰ | 6.10 × 10⁻¹⁴ | 3.71 × 10⁻¹² |
| 15% | 7.36 × 10⁻⁸ | 2.66 × 10⁻⁶ | 1.19 × 10⁻⁷ | 4.45 × 10⁻⁶ | 2.76 × 10⁻⁹ | 1.04 × 10⁻⁷ |
| 20% | 1.11 × 10⁻⁴ | 2.76 × 10⁻³ | 1.92 × 10⁻⁴ | 4.96 × 10⁻³ | 4.46 × 10⁻⁶ | 1.15 × 10⁻⁴ |
| 25% | 0.0263 | 0.476 | 0.0489 | 0.926 | 1.14 × 10⁻³ | 0.0215 |
| 30% | 1.89 | 25.7 | 3.82 | 54.6 | 0.0887 | 1.27 |
| 33% | 16.2 | 187 | 34.4 | 420 | 0.799 | 9.76 |
| 40% | 955 | 7,627 | 2,322 | 19,921 | 54.0 | 463 |

Episodes are fewer than compositions because consecutive compositions of a KWC share all but one seat. At p = 25% a one-seat change enters state (ii) with 0.457 (registered) and 0.429 (unregistered) times the probability of a fresh draw (column `one_seat_entry_ratio`); the unregistered count is 0.476 episodes against an upper bound of 0.926.

Ban sensitivities, without absences: 1% of registered IDs banned per year gives 52,384,160 compositions and 0.503 unregistered episodes at p = 25%; 5% of registered IDs banned per year gives 63,895,200 compositions and 0.611 unregistered episodes at p = 25%. Each ban is a removal, about 4.6 changed compositions.

**Seat rule (SPEC v0.4 §4.7)** (table `B5_seat_rule_10y.csv`). Going offline no longer changes seats: an absent or deactivated ID keeps its seat as an offline member, and a seat is vacated only on a ban or after a continuous absence longer than the threshold L. Under v0.3 every absence that deactivated an ID vacated its seat and the ID was re-inserted on return, about 9.3 changed compositions per absence. The absences here are illustrative until M3 supplies household profiles: c absences per ID per year, each long enough to deactivate the ID, with Lomax durations (scale 2 days, shape 1.5: median 1.17 days; 1.56% of absences last longer than 30 days) and, as a comparison, exponential durations with mean 7 days. At 100,000 KWCs and p = 25%, unregistered quorum, Lomax durations:

| seat rule | L in PoW-ID blocks | absences that vacate | c = 1: compositions (share of v0.3) | c = 1: episodes | c = 4: compositions (share of v0.3) | c = 4: episodes |
|---|---|---|---|---|---|---|
| v0.3: every absence vacates the seat | — | 100% | 631,314,400 (100%) | 6.00 | 2,376,738,400 (100%) | 22.6 |
| v0.4: L = 3 days | 8,640 | 25.3% | 196,693,475 (31.2%) | 1.87 | 638,254,701 (26.9%) | 6.07 |
| v0.4: L = 7 days | 20,160 | 10.5% | 110,454,605 (17.5%) | 1.05 | 293,299,219 (12.3%) | 2.79 |
| v0.4: L = 30 days | 86,400 | 1.56% | 58,597,150 (9.28%) | 0.562 | 85,869,400 (3.61%) | 0.821 |
| v0.4: L = 90 days | 259,200 | 0.321% | 51,371,246 (8.14%) | 0.494 | 56,965,783 (2.40%) | 0.547 |
| v0.4: L = 365 days | 1,051,200 | 0.0402% | 49,740,459 (7.88%) | 0.478 | 50,442,637 (2.12%) | 0.485 |

With exponential durations fewer absences are long: at the default L = 30 days, 1.38% of absences vacate a seat against 1.56% under Lomax, and compositions at c = 4 are 3.43% of the v0.3 count (Lomax: 3.61%).

In every row of table B5, episodes fall by the same factor as compositions to within 10% (column `episodes_ratio_to_v03`).

**Binomial versus hypergeometric** (`B3_binomial_vs_hypergeometric.csv`). The hypergeometric model is exact for a finite network in which the attacker owns exactly p of the IDs. The binomial model is its infinite-network limit. Largest relative gap at each network size, over all layouts, states and p:

| KWCs | largest relative gap | where | absolute gap |
|---|---|---|---|
| 10k | -13.81% | 40-node, unregistered, (iii) all seats, p = 5% | -1.256e-53 |
| 100k | -1.47% | 40-node, unregistered, (iii) all seats, p = 5% | -1.338e-54 |
| 1M | -0.15% | 40-node, unregistered, (iii) all seats, p = 5% | -1.347e-55 |

For states (ii) and (iii), the hypergeometric value is at or below the binomial value in every row. For blocking, the sign of the gap varies with p.

30-node comparison (1 leader + 2 subordinate WCs; 7 of 10 and 14 of 20, or any 20 of 30), binomial, p = 25%: state (ii) has probability 1.03 × 10⁻⁷ (registered) and 1.82 × 10⁻⁶ (unregistered), against 9.88 × 10⁻¹⁰ and 1.87 × 10⁻⁸ for 40 nodes.

## 6. Chain Allocation Committee

Tables `C1_cac_probabilities.csv`, `C2_cac_events_per_year.csv`; chart `C1_cac_probabilities.png`. Under SPEC §4.3 a new member joins for every 10th PoW-Tx block by a lottery over the canonical active list (2.9M active IDs here); a draw that lands on a member moves to the next position. With the attacker's IDs spread through the list, its seat count is hypergeometric, so its expected committee share equals its share p of active IDs. Mining power plays no part. An Allocation Committee Block needs ⌈2n/3⌉ approvals; the attacker stalls with n − ⌈2n/3⌉ + 1 seats and approves alone with ⌈2n/3⌉.

| committee size n | approvals needed | seats to stall |
|---|---|---|
| 30 | 20 | 11 |
| 100 | 67 | 34 |
| 600 | 400 | 201 |
| 1000 | 667 | 334 |

**Probability the attacker can stall** (lottery):

| p | n = 30 | n = 100 | n = 600 | n = 1,000 |
|---|---|---|---|---|
| 10% | 8.91 × 10⁻⁵ | 6.99 × 10⁻¹¹ | 3.40 × 10⁻⁵⁵ | 4.47 × 10⁻⁹⁰ |
| 20% | 2.56% | 7.37 × 10⁻⁴ | 6.72 × 10⁻¹⁵ | 2.25 × 10⁻²³ |
| 25% | 10.6% | 2.76% | 1.94 × 10⁻⁶ | 1.69 × 10⁻⁹ |
| 30% | 27.0% | 22.1% | 3.49% | 1.09% |
| 33% | 40.0% | 45.3% | 41.2% | 40.6% |
| 40% | 70.9% | 90.9% | > 99.9% | > 99.9% |

**Probability the attacker can hold two-thirds (approve alone)** (lottery):

| p | n = 30 | n = 100 | n = 600 | n = 1,000 |
|---|---|---|---|---|
| 10% | 1.11 × 10⁻¹³ | 9.57 × 10⁻⁴³ | 1.50 × 10⁻²⁴⁵ | 1.91 × 10⁻⁴⁰⁸ |
| 20% | 3.83 × 10⁻⁸ | 3.13 × 10⁻²⁴ | 2.82 × 10⁻¹³⁵ | 1.71 × 10⁻²²⁴ |
| 25% | 1.82 × 10⁻⁶ | 1.21 × 10⁻¹⁸ | 4.38 × 10⁻¹⁰² | 3.91 × 10⁻¹⁶⁹ |
| 30% | 3.69 × 10⁻⁵ | 2.66 × 10⁻¹⁴ | 2.26 × 10⁻⁷⁶ | 2.99 × 10⁻¹²⁶ |
| 33% | 1.66 × 10⁻⁴ | 3.86 × 10⁻¹² | 1.34 × 10⁻⁶³ | 5.98 × 10⁻¹⁰⁵ |
| 40% | 2.85 × 10⁻³ | 4.49 × 10⁻⁸ | 1.05 × 10⁻³⁹ | 4.10 × 10⁻⁶⁵ |

**Stalls and captures over time at n = 600** (315,360 refreshes per year, one every 100 s). Primary measures: the share of time in each state and the exact number of entries into it per year; the mean episode length is the first divided by the second. Since SPEC v0.4 placement takes effect at each ID's beacon block without the committee (§4.2): the Allocation Committee Block is a record and attestation, so a stall delays that record and the compilation of approved bans, never a placement. The M1 brief's estimate (one independent composition per n refreshes) is the last column, for comparison only.

| p | state | share of time in state | entries per year (exact) | mean episode | brief's estimate, events/yr (comparison) |
|---|---|---|---|---|---|
| 10% | stall | 3.40 × 10⁻⁵⁵ | 2.53 × 10⁻⁵⁰ | 7.08 min | 1.79 × 10⁻⁵² |
| 10% | capture | 1.50 × 10⁻²⁴⁵ | 2.68 × 10⁻²⁴⁰ | 2.94 min | 7.89 × 10⁻²⁴³ |
| 20% | stall | 6.72 × 10⁻¹⁵ | 2.90 × 10⁻¹⁰ | 12.2 min | 3.53 × 10⁻¹² |
| 20% | capture | 2.82 × 10⁻¹³⁵ | 4.15 × 10⁻¹³⁰ | 3.57 min | 1.48 × 10⁻¹³² |
| 25% | stall | 1.94 × 10⁻⁶ | 0.0538 | 18.9 min | 1.02 × 10⁻³ |
| 25% | capture | 4.38 × 10⁻¹⁰² | 5.76 × 10⁻⁹⁷ | 4.00 min | 2.30 × 10⁻⁹⁹ |
| 30% | stall | 3.49% | 459 | 39.9 min | 18.3 |
| 30% | capture | 2.26 × 10⁻⁷⁶ | 2.62 × 10⁻⁷¹ | 4.54 min | 1.19 × 10⁻⁷³ |
| 33% | stall | 41.2% | 2,360 | 1.53 h | 217 |
| 33% | capture | 1.34 × 10⁻⁶³ | 1.43 × 10⁻⁵⁸ | 4.94 min | 7.05 × 10⁻⁶¹ |
| 40% | stall | > 99.9% | 9.90 | 36.8 days | 525 |
| 40% | capture | 1.05 × 10⁻³⁹ | 8.83 × 10⁻³⁵ | 6.23 min | 5.50 × 10⁻³⁷ |

A sliding committee changes one seat at a time. Where a state is rare, the committee enters it more often than the brief's estimate assumes; where it is in the state most of the time, it seldom leaves, so entries are fewer. The mean-episode column shows how long the committee stays in a state once there.

**Where the attacker's IDs sit in the list.** The canonical list is in registration order, so IDs won in a burst sit next to each other. If all of the attacker's IDs formed one block, a draw landing on a member would pass to a neighbour of the same type, and the seat count would be binomial instead of hypergeometric. At n = 600 and p = 30% the stall probability changes from 3.487% to 3.488%, and the capture probability from 2.26 × 10⁻⁷⁶ to 2.35 × 10⁻⁷⁶.

**Comparison with the v0.2 rule**, in which the miner of every 10th PoW-Tx block joined (rows of the tables with an honest mining fraction). An attacker that mines with all its IDs while only 50% of honest IDs mine then gains seats: with 25% of active IDs it holds 40.0% of mining IDs. At n = 600 its stall probability would be > 99.9% instead of 1.94 × 10⁻⁶ under the lottery.

**Departures (SPEC v0.4 §4.3)** (table `C3_cac_departures.csv`). A banned or deactivated member now leaves the committee at once, and an extra lottery draw fills its seat at the next 10th PoW-Tx block. Attacker IDs never go offline, so honest members serve shorter tenures on average and the attacker's seat share rises a little. By Little's law the share becomes p / (p + (1 − p)·r), where r is an honest member's mean tenure relative to the full tenure of n refreshes (16.7 h at n = 600). This is an approximation; M4 simulates the committee. Attacker share p of active IDs, c absences per honest ID per year:

| p | seat share, c = 1 | seat share, c = 4 | P(stall) at p | P(stall), c = 4 |
|---|---|---|---|---|
| 10% | 10.01% | 10.03% | 3.40 × 10⁻⁵⁵ | 5.81 × 10⁻⁵⁵ |
| 20% | 20.02% | 20.06% | 6.72 × 10⁻¹⁵ | 9.17 × 10⁻¹⁵ |
| 25% | 25.02% | 25.07% | 1.94 × 10⁻⁶ | 2.37 × 10⁻⁶ |
| 30% | 30.02% | 30.08% | 3.49% | 3.83% |
| 33% | 33.02% | 33.08% | 41.2% | 42.9% |
| 40% | 40.02% | 40.09% | > 99.9% | > 99.9% |

At p = 25% and 4 absences per ID per year the attacker's share moves from 25% to 25.07%: a full tenure (16.7 h) is short compared with the time between absences (2,190 h).

## 7. Restart attack

Tables `D1_restart_advantage.csv`, `D2_restart_advantage_curve.csv`; chart `D1_restart_advantage.png`. In the old design, entropy stayed fixed for the whole connection, so a miner could see its future winning steps at connection time and reconnect until one fell within a keep window W. Each reconnection costs C seconds. Advantage = expected time to an ID for a miner that stays connected ÷ expected time for the restarting miner. The realistic restart cost (SPEC v0.3 §8 S5) is the grace epoch + convergence interval + post-admission wait: 150 + 150 + 150 = 450 s at the §2 defaults. The other costs bracket it.

| miners N | restart cost C | keep window W | advantage | best W | best advantage |
|---|---|---|---|---|---|
| 1M | 60 s | 1.00 h | 59.8× | 16.7 h | 499.8× |
| 1M | 60 s | 1.00 d | 468.4× | 16.7 h | 499.8× |
| 1M | 60 s | 3.00 d | 220.0× | 16.7 h | 499.8× |
| 1M | 300 s | 1.00 h | 12.0× | 1.55 d | 223.4× |
| 1M | 300 s | 1.00 d | 203.4× | 1.55 d | 223.4× |
| 1M | 300 s | 3.00 d | 182.6× | 1.55 d | 223.4× |
| 1M | 450 s (realistic) | 1.00 h | 8.0× | 1.90 d | 182.4× |
| 1M | 450 s (realistic) | 1.00 d | 150.3× | 1.90 d | 182.4× |
| 1M | 450 s (realistic) | 3.00 d | 165.1× | 1.90 d | 182.4× |
| 1M | 600 s | 1.00 h | 6.0× | 2.20 d | 158.0× |
| 1M | 600 s | 1.00 d | 119.1× | 2.20 d | 158.0× |
| 1M | 600 s | 3.00 d | 150.6× | 2.20 d | 158.0× |
| 5M | 60 s | 1.00 h | 60.0× | 1.55 d | 1117.9× |
| 5M | 60 s | 1.00 d | 1017.7× | 1.55 d | 1117.9× |
| 5M | 60 s | 3.00 d | 912.9× | 1.55 d | 1117.9× |
| 5M | 300 s | 1.00 h | 12.0× | 3.47 d | 499.8× |
| 5M | 300 s | 1.00 d | 265.9× | 3.47 d | 499.8× |
| 5M | 300 s | 3.00 d | 494.5× | 3.47 d | 499.8× |
| 5M | 450 s (realistic) | 1.00 h | 8.0× | 4.25 d | 408.1× |
| 5M | 450 s (realistic) | 1.00 d | 181.9× | 4.25 d | 408.1× |
| 5M | 450 s (realistic) | 3.00 d | 384.4× | 4.25 d | 408.1× |
| 5M | 600 s | 1.00 h | 6.0× | 4.91 d | 353.4× |
| 5M | 600 s | 1.00 d | 138.2× | 4.91 d | 353.4× |
| 5M | 600 s | 3.00 d | 314.4× | 4.91 d | 353.4× |

At the realistic cost and a one-day keep window, the old design gave a restarting miner 150.3× the honest rate with 1M competing miners and 181.9× with 5M. Its best keep window gave 182.4× and 408.1×.

**Per-round entropy (current design): the advantage is exactly 1.** Each round's entropy is fresh and unpredictable and does not depend on what the miner did before: the header names the previous PoW-ID block, and the entropy aggregates every online member's signature. A miner gets one header per round, and abandoning it means waiting for the next block. So a connected miner wins each round with the same probability, 1/N, whatever it did before. A disconnected miner cannot win. Restarting can only remove rounds, never improve them, and never restarting is the fastest policy. The Monte Carlo check `D-per-round-entropy` (section 11) agrees.

## 8. Difficulty hopping

Table `E1_difficulty_hopping.csv`. SPEC v0.3 §3.8 makes Variant B the default: difficulty follows the exact admitted online count, so there is no window to exploit. Variant A, a Bitcoin-style retarget every K = 144 blocks with a 4× clamp, is kept as the comparison. Against Variant A an attacker adds m times the honest miners for exactly one window, then leaves. Gain = the attacker's IDs per miner-second compared with Variant B. First-order formula: Variant A pays (1 + m) times Variant B's rate, a gain of m.

| m | gain against Variant A | hop window (h) | recovery window with the clamp (h) | recovery window without a clamp (h) | issuance over both windows ÷ target (with the clamp) |
|---|---|---|---|---|---|
| 0.05 | +5% | 1.14 | 1.26 | 1.26 | 0.999 |
| 0.1 | +10% | 1.09 | 1.32 | 1.32 | 0.995 |
| 0.25 | +25% | 0.960 | 1.50 | 1.50 | 0.976 |
| 0.5 | +50% | 0.800 | 1.80 | 1.80 | 0.923 |
| 1 | +100% | 0.600 | 2.40 | 2.40 | 0.800 |
| 2 | +200% | 0.400 | 3.60 | 3.60 | 0.600 |
| 4 | +400% | 0.240 | 4.80 | 6.00 | 0.476 |

The clamp only shortens the recovery window. The gain is earned before any retarget, so the clamp does not change it. Under Variant B with exact counts the first-order gain is 0; its Monte Carlo cross-checks gave gain factors between 0.997 and 1.002. Variant B's small correction from recent block times is [P] and will be proposed and tested in M3; it is not modelled here.

## 9. Same-step ties between PoW-ID blocks

Table `F1_tie_rate.csv`. All chains start at the same t0 and step once per second, so two miners can win at the same step. That gives two valid blocks for one height. The [P] tie-break keeps the lower block hash.

| miners N | target interval | rounds ending in a tie | tied rounds per year |
|---|---|---|---|
| 1M | 10 s | 4.92% | 155,052 |
| 1M | 30 s | 1.66% | 17,423 |
| 1M | 60 s | 0.831% | 4,368 |
| 5M | 10 s | 4.92% | 155,052 |
| 5M | 30 s | 1.66% | 17,423 |
| 5M | 60 s | 0.831% | 4,368 |

## 10. Quorum trade-off (section G)

Tables `G1_quorum_kwc.csv`, `G2_split_rule.csv`, `G3_cac_quorum.csv`; chart `G1_quorum_tradeoff.png`. This section changes no SPEC quorum. For each quorum fraction q it shows what an attacker holding a fraction p of the seats can do: **stall** (deny every approval), **sign without honest members**, or get **two conflicting decisions approved**. Honest members sign at most one of two conflicting proposals; the attacker signs both and may show different proposals to different members. A pool of n members with quorum k therefore allows a conflict from 2k − n attacker seats. In the registered layout each condition applies to the leader WC and to the subordinates separately. The seat condition is necessary; the attacker also has to put both proposals forward, and the proposer rights (SPEC v0.4 §4.4) decide who can: the master proposer for MOBr, registered offline requests and bans; the subordinate-only proposer for MOBu and unregistered offline requests, and bans of leader-chain members who refuse to witness newcomers; the miner for its own offline request. Since SPEC v0.4 (§4.6), two conflicting decisions that are both approved are **both rejected**, and every member who signed both has produced equivocation evidence and may be banned. A conflict therefore cancels a decision rather than enacting two.

**Attacker seats each option allows:**

| layout | quorum | signatures needed | seats to stall | seats to sign alone | seats for conflicting approvals |
|---|---|---|---|---|---|
| pool of 40 (unregistered PoWit; decisions) | 0.51 | 21 of 40 | ≥ 20 | ≥ 21 | ≥ 2 |
| pool of 40 (unregistered PoWit; decisions) | 0.55 | 22 of 40 | ≥ 19 | ≥ 22 | ≥ 4 |
| pool of 40 (unregistered PoWit; decisions) | 0.60 | 24 of 40 | ≥ 17 | ≥ 24 | ≥ 8 |
| pool of 40 (unregistered PoWit; decisions) | 2/3 (SPEC default) | 27 of 40 | ≥ 14 | ≥ 27 | ≥ 14 |
| pool of 40 (unregistered PoWit; decisions) | 0.75 | 30 of 40 | ≥ 11 | ≥ 30 | ≥ 20 |
| registered PoWit (leader 10 + subordinates 30) | 0.51 | 6 of 10 and 16 of 30 | leader ≥ 5 or subordinates ≥ 15 | leader ≥ 6 and subordinates ≥ 16 | leader ≥ 2 and subordinates ≥ 2 |
| registered PoWit (leader 10 + subordinates 30) | 0.55 | 6 of 10 and 17 of 30 | leader ≥ 5 or subordinates ≥ 14 | leader ≥ 6 and subordinates ≥ 17 | leader ≥ 2 and subordinates ≥ 4 |
| registered PoWit (leader 10 + subordinates 30) | 0.60 | 6 of 10 and 18 of 30 | leader ≥ 5 or subordinates ≥ 13 | leader ≥ 6 and subordinates ≥ 18 | leader ≥ 2 and subordinates ≥ 6 |
| registered PoWit (leader 10 + subordinates 30) | 2/3 rounded up per group (comparison) | 7 of 10 and 20 of 30 | leader ≥ 4 or subordinates ≥ 11 | leader ≥ 7 and subordinates ≥ 20 | leader ≥ 4 and subordinates ≥ 10 |
| registered PoWit (leader 10 + subordinates 30) | SPEC default 7 + 21 | 7 of 10 and 21 of 30 | leader ≥ 4 or subordinates ≥ 10 | leader ≥ 7 and subordinates ≥ 21 | leader ≥ 4 and subordinates ≥ 12 |
| registered PoWit (leader 10 + subordinates 30) | 0.75 | 8 of 10 and 23 of 30 | leader ≥ 3 or subordinates ≥ 8 | leader ≥ 8 and subordinates ≥ 23 | leader ≥ 6 and subordinates ≥ 16 |

The SPEC registered default, 7 of 10 and 21 of 30, is q = 0.7 in each group. Two-thirds rounded up per group gives 7 + 20 and is shown only as a comparison.

**pool of 40 (unregistered PoWit; decisions): probability that the attacker can stall** (per KWC, exact hypergeometric, 100k KWCs):

| p | 0.51 | 0.55 | 0.60 | 2/3 (SPEC default) | 0.75 |
|---|---|---|---|---|---|
| 5% | 4.94 × 10⁻¹⁶ | 9.00 × 10⁻¹⁵ | 2.22 × 10⁻¹² | 4.10 × 10⁻⁹ | 2.91 × 10⁻⁶ |
| 10% | 1.87 × 10⁻¹⁰ | 1.62 × 10⁻⁹ | 9.14 × 10⁻⁸ | 1.85 × 10⁻⁵ | 1.47 × 10⁻³ |
| 20% | 2.17 × 10⁻⁵ | 8.51 × 10⁻⁵ | 9.91 × 10⁻⁴ | 1.94% | 16.1% |
| 25% | 5.72 × 10⁻⁴ | 1.71 × 10⁻³ | 1.16% | 10.3% | 41.6% |
| 30% | 6.25 × 10⁻³ | 1.48% | 6.33% | 29.7% | 69.1% |
| 33% | 1.92% | 3.99% | 13.4% | 45.2% | 81.7% |
| 40% | 13.0% | 20.9% | 43.2% | 78.9% | 96.5% |
| 45% | 31.6% | 43.5% | 68.1% | 92.5% | 99.3% |
| 49% | 51.2% | 63.5% | 83.7% | 97.4% | 99.8% |

**pool of 40 (unregistered PoWit; decisions): probability that the attacker can sign without honest members** (per KWC, exact hypergeometric, 100k KWCs):

| p | 0.51 | 0.55 | 0.60 | 2/3 (SPEC default) | 0.75 |
|---|---|---|---|---|---|
| 5% | 2.47 × 10⁻¹⁷ | 1.12 × 10⁻¹⁸ | 1.70 × 10⁻²¹ | 4.69 × 10⁻²⁶ | 4.77 × 10⁻³¹ |
| 10% | 1.96 × 10⁻¹¹ | 1.86 × 10⁻¹² | 1.25 × 10⁻¹⁴ | 3.21 × 10⁻¹⁸ | 3.05 × 10⁻²² |
| 20% | 5.02 × 10⁻⁶ | 1.06 × 10⁻⁶ | 3.52 × 10⁻⁸ | 1.00 × 10⁻¹⁰ | 1.06 × 10⁻¹³ |
| 25% | 1.75 × 10⁻⁴ | 4.86 × 10⁻⁵ | 2.82 × 10⁻⁶ | 1.87 × 10⁻⁸ | 4.63 × 10⁻¹¹ |
| 30% | 2.42 × 10⁻³ | 8.54 × 10⁻⁴ | 8.03 × 10⁻⁵ | 1.10 × 10⁻⁶ | 5.70 × 10⁻⁹ |
| 33% | 8.42 × 10⁻³ | 3.38 × 10⁻³ | 4.13 × 10⁻⁴ | 8.47 × 10⁻⁶ | 6.57 × 10⁻⁸ |
| 40% | 7.43% | 3.92% | 8.34 × 10⁻³ | 4.02 × 10⁻⁴ | 7.46 × 10⁻⁶ |
| 45% | 21.3% | 13.3% | 4.05% | 3.43 × 10⁻³ | 1.13 × 10⁻⁴ |
| 49% | 38.8% | 27.4% | 10.9% | 1.40% | 7.27 × 10⁻⁴ |

**pool of 40 (unregistered PoWit; decisions): probability that the attacker can get two conflicting decisions approved** (per KWC, exact hypergeometric, 100k KWCs):

| p | 0.51 | 0.55 | 0.60 | 2/3 (SPEC default) | 0.75 |
|---|---|---|---|---|---|
| 5% | 60.1% | 13.8% | 7.11 × 10⁻⁴ | 4.10 × 10⁻⁹ | 4.94 × 10⁻¹⁶ |
| 10% | 92.0% | 57.7% | 4.19% | 1.85 × 10⁻⁵ | 1.87 × 10⁻¹⁰ |
| 20% | 99.9% | 97.2% | 56.3% | 1.94% | 2.17 × 10⁻⁵ |
| 25% | > 99.9% | 99.5% | 81.8% | 10.3% | 5.72 × 10⁻⁴ |
| 30% | > 99.9% | 99.9% | 94.5% | 29.7% | 6.25 × 10⁻³ |
| 33% | > 99.9% | > 99.9% | 97.7% | 45.2% | 1.92% |
| 40% | > 99.9% | > 99.9% | 99.8% | 78.9% | 13.0% |
| 45% | > 99.9% | > 99.9% | > 99.9% | 92.5% | 31.6% |
| 49% | > 99.9% | > 99.9% | > 99.9% | 97.4% | 51.2% |

**registered PoWit (leader 10 + subordinates 30): probability that the attacker can stall** (per KWC, exact hypergeometric, 100k KWCs):

| p | 0.51 | 0.55 | 0.60 | 2/3 rounded up per group (comparison) | SPEC default 7 + 21 | 0.75 |
|---|---|---|---|---|---|---|
| 5% | 6.37 × 10⁻⁵ | 6.37 × 10⁻⁵ | 6.37 × 10⁻⁵ | 1.03 × 10⁻³ | 1.03 × 10⁻³ | 1.16% |
| 10% | 1.63 × 10⁻³ | 1.64 × 10⁻³ | 1.64 × 10⁻³ | 1.29% | 1.32% | 7.74% |
| 20% | 3.30% | 3.37% | 3.58% | 14.3% | 17.5% | 48.4% |
| 25% | 8.07% | 8.57% | 9.80% | 30.6% | 37.7% | 73.0% |
| 30% | 16.5% | 18.4% | 22.2% | 52.6% | 61.8% | 89.2% |
| 33% | 23.8% | 27.3% | 33.0% | 65.9% | 74.6% | 94.6% |
| 40% | 47.8% | 54.8% | 63.4% | 88.9% | 93.3% | 99.3% |
| 45% | 67.5% | 74.7% | 81.9% | 96.4% | 98.2% | 99.9% |
| 49% | 81.1% | 86.7% | 91.5% | 98.8% | 99.5% | > 99.9% |

**registered PoWit (leader 10 + subordinates 30): probability that the attacker can sign without honest members** (per KWC, exact hypergeometric, 100k KWCs):

| p | 0.51 | 0.55 | 0.60 | 2/3 rounded up per group (comparison) | SPEC default 7 + 21 | 0.75 |
|---|---|---|---|---|---|---|
| 5% | 3.10 × 10⁻¹⁹ | 1.34 × 10⁻²⁰ | 5.05 × 10⁻²² | 1.43 × 10⁻²⁶ | 3.58 × 10⁻²⁸ | 2.74 × 10⁻³³ |
| 10% | 5.36 × 10⁻¹³ | 4.85 × 10⁻¹⁴ | 3.85 × 10⁻¹⁵ | 1.01 × 10⁻¹⁸ | 5.28 × 10⁻²⁰ | 3.74 × 10⁻²⁴ |
| 20% | 3.33 × 10⁻⁷ | 6.67 × 10⁻⁸ | 1.17 × 10⁻⁸ | 3.31 × 10⁻¹¹ | 3.87 × 10⁻¹² | 3.00 × 10⁻¹⁵ |
| 25% | 1.62 × 10⁻⁵ | 4.25 × 10⁻⁶ | 9.88 × 10⁻⁷ | 6.38 × 10⁻⁹ | 9.87 × 10⁻¹⁰ | 1.77 × 10⁻¹² |
| 30% | 3.02 × 10⁻⁴ | 1.01 × 10⁻⁴ | 2.96 × 10⁻⁵ | 3.90 × 10⁻⁷ | 7.70 × 10⁻⁸ | 2.86 × 10⁻¹⁰ |
| 33% | 1.25 × 10⁻³ | 4.72 × 10⁻⁴ | 1.58 × 10⁻⁴ | 3.08 × 10⁻⁶ | 6.94 × 10⁻⁷ | 3.83 × 10⁻⁹ |
| 40% | 1.61% | 8.00 × 10⁻³ | 3.53 × 10⁻³ | 1.56 × 10⁻⁴ | 4.69 × 10⁻⁵ | 6.06 × 10⁻⁷ |
| 45% | 6.04% | 3.55% | 1.87% | 1.41 × 10⁻³ | 5.11 × 10⁻⁴ | 1.16 × 10⁻⁵ |
| 49% | 13.6% | 9.01% | 5.40% | 6.10 × 10⁻³ | 2.55 × 10⁻³ | 8.92 × 10⁻⁵ |

**registered PoWit (leader 10 + subordinates 30): probability that the attacker can get two conflicting decisions approved** (per KWC, exact hypergeometric, 100k KWCs):

| p | 0.51 | 0.55 | 0.60 | 2/3 rounded up per group (comparison) | SPEC default 7 + 21 | 0.75 |
|---|---|---|---|---|---|---|
| 5% | 3.85% | 5.23 × 10⁻³ | 2.83 × 10⁻⁴ | 1.19 × 10⁻⁹ | 9.28 × 10⁻¹² | 3.10 × 10⁻¹⁹ |
| 10% | 21.5% | 9.30% | 1.93% | 5.81 × 10⁻⁶ | 1.95 × 10⁻⁷ | 5.36 × 10⁻¹³ |
| 20% | 61.8% | 54.8% | 35.7% | 7.38 × 10⁻³ | 1.15 × 10⁻³ | 3.33 × 10⁻⁷ |
| 25% | 75.4% | 72.8% | 60.3% | 4.41% | 1.14% | 1.62 × 10⁻⁵ |
| 30% | 85.0% | 84.3% | 78.6% | 14.4% | 5.58% | 3.02 × 10⁻⁴ |
| 33% | 89.2% | 88.9% | 85.8% | 23.9% | 11.4% | 1.25 × 10⁻³ |
| 40% | 95.4% | 95.3% | 94.8% | 50.9% | 35.1% | 1.61% |
| 45% | 97.7% | 97.7% | 97.6% | 68.3% | 56.3% | 6.04% |
| 49% | 98.7% | 98.7% | 98.7% | 78.9% | 71.3% | 13.6% |

**Expected counts at p = 25%, 100k KWCs.** "Now" is the expected number of KWCs in the state at one moment. "Over 10 years" is the expected number of distinct episodes in the state (SPEC v0.4 §10 H6), with the composition count, the upper bound, in brackets; adopted allocation, 49,506,400 compositions, binomial, no bans or absences:

| layout | quorum | stall, now | sign alone, now | conflict, now | sign alone, over 10 years: episodes (compositions) | conflict, over 10 years: episodes (compositions) |
|---|---|---|---|---|---|---|
| pool of 40 (unregistered PoWit; decisions) | 0.51 | 57.2 | 17.5 | 99,986 | 3,317 (8,656) | 1,153,276 (49,499,264) |
| pool of 40 (unregistered PoWit; decisions) | 0.55 | 171 | 4.86 | 99,531 | 977 (2,408) | 1,207,373 (49,273,934) |
| pool of 40 (unregistered PoWit; decisions) | 0.60 | 1,156 | 0.282 | 81,805 | 62.9 (140) | 2,313,974 (40,498,505) |
| pool of 40 (unregistered PoWit; decisions) | 2/3 (SPEC default) | 10,323 | 1.87 × 10⁻³ | 10,323 | 0.476 (0.926) | 1,062,094 (5,110,631) |
| pool of 40 (unregistered PoWit; decisions) | 0.75 | 41,610 | 4.63 × 10⁻⁶ | 57.2 | 1.32 × 10⁻³ (2.29 × 10⁻³) | 10,208 (28,339) |
| registered PoWit (leader 10 + subordinates 30) | 0.51 | 8,066 | 1.62 | 75,449 | 328 (800) | 1,330,834 (37,352,070) |
| registered PoWit (leader 10 + subordinates 30) | 0.55 | 8,567 | 0.425 | 72,767 | 91.1 (211) | 1,556,264 (36,024,026) |
| registered PoWit (leader 10 + subordinates 30) | 0.60 | 9,803 | 0.0988 | 60,282 | 22.2 (48.9) | 2,158,964 (29,843,237) |
| registered PoWit (leader 10 + subordinates 30) | 2/3 rounded up per group (comparison) | 30,615 | 6.38 × 10⁻⁴ | 4,406 | 0.163 (0.316) | 471,148 (2,181,325) |
| registered PoWit (leader 10 + subordinates 30) | SPEC default 7 + 21 | 37,666 | 9.87 × 10⁻⁵ | 1,135 | 0.0263 (0.0489) | 154,079 (562,085) |
| registered PoWit (leader 10 + subordinates 30) | 0.75 | 72,970 | 1.77 × 10⁻⁷ | 1.62 | 5.27 × 10⁻⁵ (8.79 × 10⁻⁵) | 328 (800) |

**Ten-year episodes under each seat rule** (`G4_quorum_10y_by_seat_rule.csv`): SPEC default quorums, p = 25%, 100k KWCs at the start, 4 absences per ID per year with Lomax durations. Expected distinct episodes:

| seat rule | 27 of 40: stall | 27 of 40: sign alone | 27 of 40: conflict | 7 of 10 and 21 of 30: stall | 7 of 10 and 21 of 30: sign alone | 7 of 10 and 21 of 30: conflict |
|---|---|---|---|---|---|---|
| v0.3: every absence vacates the seat | 48,554,011 | 22.6 | 48,554,011 | 83,357,024 | 1.25 | 7,151,640 |
| v0.4: L = 3 days | 13,076,704 | 6.07 | 13,076,704 | 22,541,234 | 0.336 | 1,924,337 |
| v0.4: L = 7 days | 6,037,184 | 2.79 | 6,037,184 | 10,473,971 | 0.154 | 887,119 |
| v0.4: L = 30 days | 1,804,155 | 0.821 | 1,804,155 | 3,217,643 | 0.0454 | 263,415 |
| v0.4: L = 90 days | 1,214,318 | 0.547 | 1,214,318 | 2,206,534 | 0.0302 | 176,508 |
| v0.4: L = 365 days | 1,081,200 | 0.485 | 1,081,200 | 1,978,340 | 0.0268 | 156,894 |

**Split rule** (`G2_split_rule.csv`): a lower quorum for PoWit only, while decisions that global validation cannot re-check (bans, MOBu/MOBr, offline requests, committee blocks) keep two-thirds, 27 of 40 voted by the full KWC. PoWit at the lower quorum (100k KWCs):

| PoWit quorum (unregistered; registered) | p | unregistered PoWit: stall | unregistered PoWit: sign alone | registered PoWit: stall | registered PoWit: sign alone |
|---|---|---|---|---|---|
| 0.51 (21 of 40; 6 of 10 and 16 of 30) | 5% | 4.94 × 10⁻¹⁶ | 2.47 × 10⁻¹⁷ | 6.37 × 10⁻⁵ | 3.10 × 10⁻¹⁹ |
| 0.55 (22 of 40; 6 of 10 and 17 of 30) | 5% | 9.00 × 10⁻¹⁵ | 1.12 × 10⁻¹⁸ | 6.37 × 10⁻⁵ | 1.34 × 10⁻²⁰ |
| 0.60 (24 of 40; 6 of 10 and 18 of 30) | 5% | 2.22 × 10⁻¹² | 1.70 × 10⁻²¹ | 6.37 × 10⁻⁵ | 5.05 × 10⁻²² |
| 0.51 (21 of 40; 6 of 10 and 16 of 30) | 10% | 1.87 × 10⁻¹⁰ | 1.96 × 10⁻¹¹ | 1.63 × 10⁻³ | 5.36 × 10⁻¹³ |
| 0.55 (22 of 40; 6 of 10 and 17 of 30) | 10% | 1.62 × 10⁻⁹ | 1.86 × 10⁻¹² | 1.64 × 10⁻³ | 4.85 × 10⁻¹⁴ |
| 0.60 (24 of 40; 6 of 10 and 18 of 30) | 10% | 9.14 × 10⁻⁸ | 1.25 × 10⁻¹⁴ | 1.64 × 10⁻³ | 3.85 × 10⁻¹⁵ |
| 0.51 (21 of 40; 6 of 10 and 16 of 30) | 20% | 2.17 × 10⁻⁵ | 5.02 × 10⁻⁶ | 3.30% | 3.33 × 10⁻⁷ |
| 0.55 (22 of 40; 6 of 10 and 17 of 30) | 20% | 8.51 × 10⁻⁵ | 1.06 × 10⁻⁶ | 3.37% | 6.67 × 10⁻⁸ |
| 0.60 (24 of 40; 6 of 10 and 18 of 30) | 20% | 9.91 × 10⁻⁴ | 3.52 × 10⁻⁸ | 3.58% | 1.17 × 10⁻⁸ |
| 0.51 (21 of 40; 6 of 10 and 16 of 30) | 25% | 5.72 × 10⁻⁴ | 1.75 × 10⁻⁴ | 8.07% | 1.62 × 10⁻⁵ |
| 0.55 (22 of 40; 6 of 10 and 17 of 30) | 25% | 1.71 × 10⁻³ | 4.86 × 10⁻⁵ | 8.57% | 4.25 × 10⁻⁶ |
| 0.60 (24 of 40; 6 of 10 and 18 of 30) | 25% | 1.16% | 2.82 × 10⁻⁶ | 9.80% | 9.88 × 10⁻⁷ |
| 0.51 (21 of 40; 6 of 10 and 16 of 30) | 30% | 6.25 × 10⁻³ | 2.42 × 10⁻³ | 16.5% | 3.02 × 10⁻⁴ |
| 0.55 (22 of 40; 6 of 10 and 17 of 30) | 30% | 1.48% | 8.54 × 10⁻⁴ | 18.4% | 1.01 × 10⁻⁴ |
| 0.60 (24 of 40; 6 of 10 and 18 of 30) | 30% | 6.33% | 8.03 × 10⁻⁵ | 22.2% | 2.96 × 10⁻⁵ |
| 0.51 (21 of 40; 6 of 10 and 16 of 30) | 33% | 1.92% | 8.42 × 10⁻³ | 23.8% | 1.25 × 10⁻³ |
| 0.55 (22 of 40; 6 of 10 and 17 of 30) | 33% | 3.99% | 3.38 × 10⁻³ | 27.3% | 4.72 × 10⁻⁴ |
| 0.60 (24 of 40; 6 of 10 and 18 of 30) | 33% | 13.4% | 4.13 × 10⁻⁴ | 33.0% | 1.58 × 10⁻⁴ |
| 0.51 (21 of 40; 6 of 10 and 16 of 30) | 40% | 13.0% | 7.43% | 47.8% | 1.61% |
| 0.55 (22 of 40; 6 of 10 and 17 of 30) | 40% | 20.9% | 3.92% | 54.8% | 8.00 × 10⁻³ |
| 0.60 (24 of 40; 6 of 10 and 18 of 30) | 40% | 43.2% | 8.34 × 10⁻³ | 63.4% | 3.53 × 10⁻³ |
| 0.51 (21 of 40; 6 of 10 and 16 of 30) | 45% | 31.6% | 21.3% | 67.5% | 6.04% |
| 0.55 (22 of 40; 6 of 10 and 17 of 30) | 45% | 43.5% | 13.3% | 74.7% | 3.55% |
| 0.60 (24 of 40; 6 of 10 and 18 of 30) | 45% | 68.1% | 4.05% | 81.9% | 1.87% |
| 0.51 (21 of 40; 6 of 10 and 16 of 30) | 49% | 51.2% | 38.8% | 81.1% | 13.6% |
| 0.55 (22 of 40; 6 of 10 and 17 of 30) | 49% | 63.5% | 27.4% | 86.7% | 9.01% |
| 0.60 (24 of 40; 6 of 10 and 18 of 30) | 49% | 83.7% | 10.9% | 91.5% | 5.40% |

**Decisions at two-thirds (27 of 40), unchanged by the split:**

| p | stall | approve alone | two conflicting approvals |
|---|---|---|---|
| 5% | 4.10 × 10⁻⁹ | 4.69 × 10⁻²⁶ | 4.10 × 10⁻⁹ |
| 10% | 1.85 × 10⁻⁵ | 3.21 × 10⁻¹⁸ | 1.85 × 10⁻⁵ |
| 20% | 1.94% | 1.00 × 10⁻¹⁰ | 1.94% |
| 25% | 10.3% | 1.87 × 10⁻⁸ | 10.3% |
| 30% | 29.7% | 1.10 × 10⁻⁶ | 29.7% |
| 33% | 45.2% | 8.47 × 10⁻⁶ | 45.2% |
| 40% | 78.9% | 4.02 × 10⁻⁴ | 78.9% |
| 45% | 92.5% | 3.43 × 10⁻³ | 92.5% |
| 49% | 97.4% | 1.40% | 97.4% |

**Which harms each threshold controls:**

| threshold | harms it controls | already neutralised elsewhere |
|---|---|---|
| PoWit quorum | stalling PoWits in a KWC (its miners must move to another KWC after the grace epoch); signing valid PoWits without honest members, and so censoring | invalid or early-signed blocks: every validator recomputes the hash chain and rejects a block received before its own timestamp (§3.7); two blocks at one height: the lower-hash tie-break (§3.7); two headers from one miner in a round: equivocation evidence (§3.4) |
| decision quorum (two-thirds) | false bans, MOBu/MOBr, offline requests and committee records, which rest on witnesses' observations rather than on data validators can recompute; and cancelling a decision by getting a conflicting one approved | committee placements, joins and leaves: every node recomputes them and rejects a mismatch, and placement no longer waits for the committee (§4.2, §4.3); two conflicting approved decisions or committee blocks: both rejected, and those who signed both are exposed (§4.3, §4.6) |

**Committee (`G3_cac_quorum.csv`)**: n = 600 under the seat lottery, 2.9M active IDs. Seats needed:

| quorum | approvals needed | seats to stall | seats to approve alone | seats for conflicting blocks |
|---|---|---|---|---|
| 0.51 | 306 | 295 | 306 | 12 |
| 2/3 (SPEC default) | 400 | 201 | 400 | 200 |

| p | 0.51: stall | 0.51: approve alone | 0.51: conflict | 2/3: stall | 2/3: approve alone | 2/3: conflict |
|---|---|---|---|---|---|---|
| 5% | 2.57 × 10⁻²¹² | 2.07 × 10⁻²²⁶ | > 99.9% | 2.01 × 10⁻¹⁰⁶ | 2.13 × 10⁻³⁶¹ | 1.93 × 10⁻¹⁰⁵ |
| 10% | 1.40 × 10⁻¹³⁰ | 4.21 × 10⁻¹⁴¹ | > 99.9% | 3.40 × 10⁻⁵⁵ | 1.50 × 10⁻²⁴⁵ | 1.54 × 10⁻⁵⁴ |
| 20% | 2.85 × 10⁻⁵⁷ | 6.38 × 10⁻⁶⁴ | > 99.9% | 6.72 × 10⁻¹⁵ | 2.82 × 10⁻¹³⁵ | 1.36 × 10⁻¹⁴ |
| 25% | 3.58 × 10⁻³⁷ | 1.87 × 10⁻⁴² | > 99.9% | 1.94 × 10⁻⁶ | 4.38 × 10⁻¹⁰² | 2.96 × 10⁻⁶ |
| 30% | 7.03 × 10⁻²³ | 5.74 × 10⁻²⁷ | > 99.9% | 3.49% | 2.26 × 10⁻⁷⁶ | 4.22% |
| 33% | 2.04 × 10⁻¹⁶ | 7.60 × 10⁻²⁰ | > 99.9% | 41.2% | 1.34 × 10⁻⁶³ | 44.6% |
| 40% | 3.38 × 10⁻⁶ | 3.29 × 10⁻⁸ | > 99.9% | > 99.9% | 1.05 × 10⁻³⁹ | > 99.9% |
| 45% | 2.24% | 1.83 × 10⁻³ | > 99.9% | > 99.9% | 9.50 × 10⁻²⁷ | > 99.9% |
| 49% | 48.4% | 17.4% | > 99.9% | > 99.9% | 1.86 × 10⁻¹⁸ | > 99.9% |

**In plain English.** This section does not choose a quorum.

- **A lower quorum makes stalling harder.** In a pool of 40, stalling needs 20 attacker seats at q = 0.51 against 14 at 2/3. At p = 25% the chance that a KWC can be stalled falls from 10.3% to 5.72 × 10⁻⁴.
- **It makes signing without honest members easier.** That needs 21 seats at q = 0.51 against 27 at 2/3; at p = 25% the chance rises from 1.87 × 10⁻⁸ to 1.75 × 10⁻⁴.
- **It makes conflicting approvals much easier.** Two conflicting decisions need 2 attacker seats at q = 0.51 against 14 at 2/3. At p = 10% that is possible in 92.0% of KWCs, against 1.85 × 10⁻⁵. Under SPEC v0.4 both are then rejected, so the harm is a cancelled decision, and every member who signed both is exposed.
- **What global validation neutralises.** Every validator recomputes a PoWit's hash chain and checks its timing (§3.7), so a lower PoWit quorum cannot make an invalid or early block valid. It changes who can stall, censor or sign valid blocks. Decisions about bans, online status, offline requests and committee blocks rest on witnesses' observations, which validators cannot recompute; for those the quorum is the protection.
- **The committee.** At q = 0.51 a conflict needs 12 of 600 seats, and an attacker with 5% of active IDs holds that many with probability > 99.9%. Placement conflicts are neutralised, because every node recomputes placement and it takes effect without the committee (§4.2), and a leader with two conflicting approved blocks has both rejected (§4.3). The committee's remaining power is over compiling bans that KWCs already approved: it can delay or omit them.
- **Not considered.** A quorum at or below 50%: two disjoint groups of honest members could then approve conflicting decisions with no attacker at all. The single-member entropy stall, where one online member withholds its entropy signature, does not depend on the quorum; One Chance (§4.5) handles it, and threshold BLS entropy (SPEC §12 [P]) would remove it.

## 11. Quorum feasibility under honest downtime (section H)

Tables `H1_quorum_feasibility.csv`, `H2_minimum_uptime.csv`, `H3_absent_seat_share.csv`; chart `H1_quorum_feasibility.png`. A KWC can approve only when enough members sign. Each honest member is online, and signs, with probability f; the attacker holds a fraction p of the seats and its members withhold, so each seat signs with probability (1 − p)·f. Three layouts: the unregistered PoWit (any 27 of 40); the SPEC registered PoWit (7 of the leader WC's 10 and 21 of the 30 subordinates); and, for comparison, a registered PoWit valid with any 27 of 40, the validity rule of the [P] proposal to separate validity from payment (SPEC §12). The comparison's numbers equal the unregistered ones, so the gap between the two registered rules is the cost of the leader requirement.

**A KWC that cannot meet quorum is a local liveness problem.** Its miners move to another KWC after the grace epoch plus admission, about 450 s at the §2 defaults (SPEC §3.2), and the rest of the network continues. Miners are spread evenly over KWCs, so at any moment the share of miners affected equals the failure probability.

**Withholding is assumed to cost the attacker nothing.** Every row with an attacker, including H2's "not reachable" entries, assumes its withholding members suffer no penalty. Under SPEC §4.5–§4.6 an online member that refuses to sign after One Chance is banned; M4 models that.

**Share of KWCs that cannot meet quorum, every member honest** (exact; expected failing KWCs at a network of 100k KWCs):

| f | 27 of 40 | 7 of 10 and 21 of 30 | leader WC below its quorum | subordinates below theirs | failing KWCs, 27 of 40 | failing KWCs, 7 of 10 and 21 of 30 |
|---|---|---|---|---|---|---|
| 50% | 98.1% | 99.6% | 82.8% | 97.9% | 98,076 | 99,632 |
| 60% | 78.9% | 93.3% | 61.8% | 82.4% | 78,884 | 93,261 |
| 70% | 29.7% | 61.8% | 35.0% | 41.1% | 29,675 | 61,750 |
| 80% | 1.94% | 17.5% | 12.1% | 6.11% | 1,941 | 17,458 |
| 90% | 1.85 × 10⁻⁵ | 1.32% | 1.28% | 4.54 × 10⁻⁴ | 1.85 | 1,324 |
| 95% | 4.10 × 10⁻⁹ | 1.03 × 10⁻³ | 1.03 × 10⁻³ | 1.16 × 10⁻⁶ | 4.10 × 10⁻⁴ | 103 |
| 99% | 1.82 × 10⁻¹⁸ | 2.00 × 10⁻⁶ | 2.00 × 10⁻⁶ | 2.50 × 10⁻¹³ | 1.82 × 10⁻¹³ | 0.200 |

**With attacker members withholding** (share of KWCs that cannot meet quorum):

| p | 27 of 40, f = 90% | 27 of 40, f = 95% | 27 of 40, f = 99% | 7 of 10 and 21 of 30, f = 90% | 7 of 10 and 21 of 30, f = 95% | 7 of 10 and 21 of 30, f = 99% |
|---|---|---|---|---|---|---|
| 10% | 1.26% | 1.00 × 10⁻³ | 4.86 × 10⁻⁵ | 14.4% | 5.21% | 1.81% |
| 20% | 20.6% | 7.82% | 2.67% | 52.2% | 33.1% | 20.1% |
| 25% | 42.6% | 23.9% | 12.5% | 72.6% | 55.8% | 41.2% |
| 33% | 77.8% | 62.8% | 48.8% | 92.8% | 85.6% | 77.1% |

**Minimum honest uptime f for fewer than the target share of KWCs to fail** (`H2_minimum_uptime.csv`; exact bisection on a 10⁻⁴ grid, verified on both sides):

| p | 27 of 40, under 1% | 27 of 40, under 0.1% | 7 of 10 and 21 of 30, under 1% | 7 of 10 and 21 of 30, under 0.1% |
|---|---|---|---|---|
| 0% | 0.8150 | 0.8551 | 0.9075 | 0.9504 |
| 10% | 0.9055 | 0.9501 | not reachable (1.32% fail at f = 1) | not reachable (1.32% fail at f = 1) |
| 20% | not reachable (1.94% fail at f = 1) | not reachable (1.94% fail at f = 1) | not reachable (17.5% fail at f = 1) | not reachable (17.5% fail at f = 1) |
| 25% | not reachable (10.3% fail at f = 1) | not reachable (10.3% fail at f = 1) | not reachable (37.7% fail at f = 1) | not reachable (37.7% fail at f = 1) |
| 33% | not reachable (45.2% fail at f = 1) | not reachable (45.2% fail at f = 1) | not reachable (74.6% fail at f = 1) | not reachable (74.6% fail at f = 1) |

**Absent IDs keep their seats (SPEC v0.4 §4.7)** (`H3_absent_seat_share.csv`). By Little's law, honest seat-holders are absent a share (c·E[min(D, L)] + a·L)/365 of the time, for c absences and a permanent departures per ID per year: a departed ID holds its seat as an offline member until L passes. The uptime needed among present members is the H2 minimum (before rounding to the grid) divided by (1 − that share). At 4 absences per ID per year with Lomax durations, no attacker, under 1% failing:

| L | departures per ID per year | seats held by absent IDs | uptime needed, 27 of 40 | uptime needed, 7 of 10 and 21 of 30 |
|---|---|---|---|---|
| 3 d (8,640 blocks) | 0% | 1.61% | 0.8283 | 0.9223 |
| 3 d (8,640 blocks) | 10% | 1.69% | 0.8290 | 0.9231 |
| 3 d (8,640 blocks) | 25% | 1.82% | 0.8301 | 0.9243 |
| 7 d (20,160 blocks) | 0% | 2.32% | 0.8343 | 0.9290 |
| 7 d (20,160 blocks) | 10% | 2.51% | 0.8360 | 0.9308 |
| 7 d (20,160 blocks) | 25% | 2.80% | 0.8384 | 0.9336 |
| 30 d (86,400 blocks) | 0% | 3.29% | 0.8427 | 0.9383 |
| 30 d (86,400 blocks) | 10% | 4.11% | 0.8499 | 0.9464 |
| 30 d (86,400 blocks) | 25% | 5.34% | 0.8610 | 0.9587 |
| 90 d (259,200 blocks) | 0% | 3.74% | 0.8466 | 0.9427 |
| 90 d (259,200 blocks) | 10% | 6.20% | 0.8689 | 0.9675 |
| 90 d (259,200 blocks) | 25% | 9.90% | 0.9046 | not reachable |
| 365 d (1,051,200 blocks) | 0% | 4.06% | 0.8495 | 0.9459 |
| 365 d (1,051,200 blocks) | 10% | 14.1% | 0.9483 | not reachable |
| 365 d (1,051,200 blocks) | 25% | 29.1% | not reachable | not reachable |

**What this implies for L and for honest uptime.**

- **Without an attacker**, keeping failing KWCs under 1% needs honest members online 0.8150 of the time for 27 of 40, but 0.9075 for 7 of 10 and 21 of 30; under 0.1%, 0.8551 against 0.9504. The leader requirement costs 9.25 points of uptime at the 1% target. The [P] single 27-of-40 rule would give registered KWCs the unregistered figures.
- **With attacker members withholding**, 7 of 10 and 21 of 30 cannot keep failures under 1% at any uptime from p = 10% (1.32% of KWCs fail even at f = 1), and 27 of 40 from p = 20% (1.94%). These rows assume withholding is free (see above).
- **Temporary absences hold few seats; permanent departures dominate.** With 4 absences per ID per year and no departures, absent IDs hold 1.61% of seats at L = 3 days and 4.06% at L = 365 days. A departed ID holds its seat for all of L, so with 10% departures per ID per year they hold 4.11% at L = 30 days and 14.1% at L = 365 days.
- **At the default L = 30 days** with 10% departures per ID per year, the ordinary uptime needed for under 1% failing is 0.8499 for 27 of 40 and 0.9464 for 7 of 10 and 21 of 30. From L = 365 days, 7 of 10 and 21 of 30 cannot stay under 1% at any uptime.
- **So L is a trade-off.** A shorter L vacates and re-inserts more absent IDs, which adds compositions (section 5, table B5); a longer L leaves more seats with absent IDs, which needs more honest uptime (table H3). Household profiles from M3 will replace the illustrative absence inputs.

## 12. KWC size trade-off (section I)

Tables `I1_kwc_size_security.csv`, `I2_kwc_size_liveness.csv`, `I3_kwc_size_load.csv`, `I4_on_demand_connections.csv`. A KWC of k WCs of 10 members has 10·k members. Each size uses an optimal Golomb ruler as its ring (k = 3: {1, 3}; k = 4: {1, 4, 6}; k = 5: {1, 4, 9, 11}; k = 6: {1, 4, 10, 12, 17}; k = 8: {1, 4, 9, 15, 22, 32, 34}; k = 10: {1, 6, 10, 23, 26, 34, 41, 53, 55}); k = 4 is the protocol's ring. Two single quorums over the whole KWC are compared: two-thirds, ⌈2n/3⌉ (27 of 40 at k = 4), and the split rule's PoWit quorum, ⌈0.51·n⌉ (SPEC §12 [P]). Probabilities are exact, hypergeometric at 100k KWCs. This section does not pick a size.

**Probability that the attacker can stall a KWC, quorum 2/3** (the column header gives the attacker seats that stall):

| p | k = 3 (11 of 30) | k = 4 (14 of 40) | k = 5 (17 of 50) | k = 6 (21 of 60) | k = 8 (27 of 80) | k = 10 (34 of 100) |
|---|---|---|---|---|---|---|
| 10% | 8.90 × 10⁻⁵ | 1.85 × 10⁻⁵ | 3.80 × 10⁻⁶ | 1.62 × 10⁻⁷ | 7.28 × 10⁻⁹ | 6.97 × 10⁻¹¹ |
| 20% | 2.56% | 1.94% | 1.44% | 4.82 × 10⁻³ | 2.76 × 10⁻³ | 7.36 × 10⁻⁴ |
| 25% | 10.6% | 10.3% | 9.83% | 5.41% | 4.99% | 2.76% |
| 30% | 27.0% | 29.7% | 31.6% | 23.8% | 26.8% | 22.1% |
| 33% | 40.0% | 45.2% | 49.3% | 41.8% | 48.5% | 45.3% |
| 40% | 70.9% | 78.9% | 84.4% | 82.1% | 89.6% | 90.9% |
| 45% | 86.5% | 92.5% | 95.7% | 95.5% | 98.5% | 99.0% |

**Probability that the attacker can stall a KWC, quorum 0.51** (the column header gives the attacker seats that stall):

| p | k = 3 (15 of 30) | k = 4 (20 of 40) | k = 5 (25 of 50) | k = 6 (30 of 60) | k = 8 (40 of 80) | k = 10 (50 of 100) |
|---|---|---|---|---|---|---|
| 10% | 3.56 × 10⁻⁸ | 1.87 × 10⁻¹⁰ | 1.01 × 10⁻¹² | 5.59 × 10⁻¹⁵ | 1.77 × 10⁻¹⁹ | 5.78 × 10⁻²⁴ |
| 20% | 2.31 × 10⁻⁴ | 2.17 × 10⁻⁵ | 2.09 × 10⁻⁶ | 2.06 × 10⁻⁷ | 2.06 × 10⁻⁹ | 2.13 × 10⁻¹¹ |
| 25% | 2.75 × 10⁻³ | 5.72 × 10⁻⁴ | 1.22 × 10⁻⁴ | 2.67 × 10⁻⁵ | 1.31 × 10⁻⁶ | 6.63 × 10⁻⁸ |
| 30% | 1.69% | 6.25 × 10⁻³ | 2.37 × 10⁻³ | 9.13 × 10⁻⁴ | 1.40 × 10⁻⁴ | 2.20 × 10⁻⁵ |
| 33% | 3.99% | 1.92% | 9.43 × 10⁻³ | 4.71 × 10⁻³ | 1.21 × 10⁻³ | 3.21 × 10⁻⁴ |
| 40% | 17.5% | 13.0% | 9.78% | 7.46% | 4.45% | 2.71% |
| 45% | 35.5% | 31.6% | 28.4% | 25.8% | 21.5% | 18.3% |

**Signing without honest members at two-thirds, p = 25%, and its ten-year episodes** (from 100,000 KWCs, no bans or absences; compositions, the upper bound, in brackets):

| k | members | compositions per new ID | P(sign alone) | episodes over 10 years (compositions) |
|---|---|---|---|---|
| 3 | 30 | 3.40 | 1.82 × 10⁻⁶ | 32.0 (65.3) |
| 4 | 40 | 4.70 | 1.87 × 10⁻⁸ | 0.476 (0.926) |
| 5 | 50 | 6.20 | 1.96 × 10⁻¹⁰ | 6.97 × 10⁻³ (0.0128) |
| 6 | 60 | 7.80 | 1.31 × 10⁻¹¹ | 5.93 × 10⁻⁴ (1.08 × 10⁻³) |
| 8 | 80 | 11.5 | 1.58 × 10⁻¹⁵ | 1.15 × 10⁻⁷ (1.92 × 10⁻⁷) |
| 10 | 100 | 15.6 | 1.21 × 10⁻¹⁸ | 1.25 × 10⁻¹⁰ (1.99 × 10⁻¹⁰) |

**Minimum honest uptime for under 1% of KWCs failing** (`I2_kwc_size_liveness.csv`; attacker members withhold, as in section 11):

| quorum | p | k = 3 | k = 4 | k = 5 | k = 6 | k = 8 | k = 10 |
|---|---|---|---|---|---|---|---|
| 2/3 | 0% | 0.8245 | 0.8150 | 0.8074 | 0.7873 | 0.7809 | 0.7669 |
| 2/3 | 10% | 0.9161 | 0.9055 | 0.8971 | 0.8748 | 0.8676 | 0.8521 |
| 2/3 | 20% | not reachable | not reachable | not reachable | 0.9841 | 0.9761 | 0.9586 |
| 2/3 | 25% | not reachable | not reachable | not reachable | not reachable | not reachable | not reachable |
| 2/3 | 33% | not reachable | not reachable | not reachable | not reachable | not reachable | not reachable |
| 0.51 | 0% | 0.7161 | 0.6881 | 0.6686 | 0.6541 | 0.6335 | 0.6193 |
| 0.51 | 10% | 0.7957 | 0.7646 | 0.7429 | 0.7268 | 0.7039 | 0.6881 |
| 0.51 | 20% | 0.8952 | 0.8602 | 0.8358 | 0.8176 | 0.7918 | 0.7742 |
| 0.51 | 25% | 0.9548 | 0.9175 | 0.8915 | 0.8721 | 0.8446 | 0.8258 |
| 0.51 | 33% | not reachable | not reachable | 0.9980 | 0.9762 | 0.9455 | 0.9244 |

**Load per node** (`I3_kwc_size_load.csv`): miners watched per node, which is also its open miner connections and its hash recomputations per second, and its steady bandwidth with registered miners exchanging every 1 s, unregistered every 30 s, 295 bytes per exchange, no transport overhead. Policies: A, every WC hosts the SPEC capacity; B, every node watches as many miners as at the protocol size; C, the architect's rule, 14 registered miners per WC (10 IDs plus the 33% spare-capacity target) plus u unregistered.

| policy | k = 3 | k = 4 | k = 5 | k = 6 | k = 8 | k = 10 |
|---|---|---|---|---|---|---|
| A: 250 miners per WC | 750 miners, 178 kB/s | 1,000 miners, 238 kB/s | 1,250 miners, 297 kB/s | 1,500 miners, 357 kB/s | 2,000 miners, 476 kB/s | 2,500 miners, 595 kB/s |
| B: each node watches 1,000 miners | 1,000 miners, 238 kB/s | 1,000 miners, 238 kB/s | 1,000 miners, 238 kB/s | 1,000 miners, 238 kB/s | 1,000 miners, 238 kB/s | 1,000 miners, 238 kB/s |
| C: 14 registered + 50 unregistered per WC | 192 miners, 13.9 kB/s | 256 miners, 18.5 kB/s | 320 miners, 23.1 kB/s | 384 miners, 27.7 kB/s | 512 miners, 37.0 kB/s | 640 miners, 46.2 kB/s |
| C: 14 registered + 100 unregistered per WC | 342 miners, 15.3 kB/s | 456 miners, 20.5 kB/s | 570 miners, 25.6 kB/s | 684 miners, 30.7 kB/s | 912 miners, 40.9 kB/s | 1,140 miners, 51.1 kB/s |
| C: 14 registered + 235 unregistered per WC | 747 miners, 19.3 kB/s | 996 miners, 25.8 kB/s | 1,245 miners, 32.2 kB/s | 1,494 miners, 38.6 kB/s | 1,992 miners, 51.5 kB/s | 2,490 miners, 64.4 kB/s |

**Connections and spare registered capacity:**

|  | k = 3 | k = 4 | k = 5 | k = 6 | k = 8 | k = 10 |
|---|---|---|---|---|---|---|
| connections per miner (KWC size) | 30 | 40 | 50 | 60 | 80 | 100 |
| standing witness-peer connections per node, option 1 | 69 | 129 | 209 | 309 | 569 | 909 |
| registered capacity ÷ registered IDs, A: 250 miners per WC | 20.0 | 20.0 | 20.0 | 20.0 | 20.0 | 20.0 |
| registered capacity ÷ registered IDs, B: each node watches 1,000 miners | 26.7 | 20.0 | 16.0 | 13.3 | 10.0 | 8.00 |
| registered capacity ÷ registered IDs, C: 14 registered + 50 unregistered per WC | 1.40 | 1.40 | 1.40 | 1.40 | 1.40 | 1.40 |
| registered capacity ÷ registered IDs, C: 14 registered + 100 unregistered per WC | 1.40 | 1.40 | 1.40 | 1.40 | 1.40 | 1.40 |
| registered capacity ÷ registered IDs, C: 14 registered + 235 unregistered per WC | 1.40 | 1.40 | 1.40 | 1.40 | 1.40 | 1.40 |

**Witness peer topology.** Option 1 keeps a standing connection to every member of a node's k KWCs (table above). Option 2, the architect's design [P] (SPEC §12), keeps none: the miner relays routine messages, and members connect on demand through the global directory only for One Chance, decisions, proposer duties and catch-up. Estimated on-demand connections per node per hour (opened plus accepted; `I4_on_demand_connections.csv`), policy A: 250 miners per WC, 4 absences per member per year all treated as unannounced (the worst case for One Chance), no bans; a decision costs each member 2(n − 1)/n connections on average, averaging out the two proposers:

| k | One Chance | catch-up | decisions, 2 session changes per miner per day | total, 2 changes per day | decisions, 8 session changes per miner per day | total, 8 changes per day |
|---|---|---|---|---|---|---|
| 3 | 0.0315 | 0.00731 | 121 | 121 | 483 | 483 |
| 4 | 0.0589 | 0.00731 | 162 | 163 | 650 | 650 |
| 5 | 0.0954 | 0.00731 | 204 | 204 | 817 | 817 |
| 6 | 0.141 | 0.00731 | 246 | 246 | 983 | 983 |
| 8 | 0.260 | 0.00731 | 329 | 329 | 1,317 | 1,317 |
| 10 | 0.415 | 0.00731 | 412 | 413 | 1,650 | 1,650 |

**What size buys and costs.**

- **Bigger groups make the one-third line sharper but do not move it.** At two-thirds, the chance an attacker can stall a KWC falls with size well below one third (p = 25%: 10.6% at k = 3, 2.76% at k = 10) and rises towards 1 well above it (p = 40%: 70.9% at k = 3, 90.9% at k = 10). Neither trend is smooth near the line, because ⌈2n/3⌉ rounds differently at each size: stalling needs 11 of 30 (36.7%), 14 of 40 (35.0%), 17 of 50 (34.0%), 21 of 60 (35.0%), 27 of 80 (33.8%), 34 of 100 (34.0%), so at p = 30% and 33% the odds move up and down with size.
- **A lower PoWit quorum moves the line.** At 0.51, stalling a 40-member KWC needs 20 seats instead of 14, so at p = 40% the stall chance is 13.0% instead of 78.9%. It also allows two conflicting approvals from 2 attacker seats at every size, which is why it suits PoWits only: validators recompute every PoWit, while decisions keep two-thirds (section 10).
- **Liveness.** Without an attacker, two-thirds needs honest uptime 0.8245 at k = 3 and 0.7669 at k = 10 for under 1% of KWCs failing. With attacker members withholding (and no penalty), staying under 1% is possible for two-thirds at p = 10% at every size, at p = 20% only from k = 6, at p = 25% and 33% at no size; for the 0.51 quorum at p = 10%, 20% and 25% at every size, at p = 33% only from k = 5.
- **Load.** Under policy A a node watches 750 miners at k = 3 and 2,500 at k = 10; policy B holds it at 1,000; policy C keeps registered witness capacity at least 1.33 times registered IDs at every size. Standing witness-peer connections under option 1 grow from 69 to 909; option 2 has none, at the cost of the on-demand connections above, which are mostly for miner session decisions.
- **Household limits**, such as router connection tables and upload bandwidth, are to be measured in M5. This section does not pick a size.

## 13. Cross-checks

Table `validation.csv` lists every check with its reference, tolerance and verdict. Each check compares a result with something independent: exact substitution into the formula, a different algorithm (dynamic programming, log-space arithmetic, dense grids), or a seeded Monte Carlo simulation (agreement within the stated number of standard errors).

| section | checks passed |
|---|---|
| A | 20 of 20 |
| B | 16 of 16 |
| C | 38 of 38 |
| D | 5 of 5 |
| E | 15 of 15 |
| F | 2 of 2 |
| G | 8 of 8 |
| H | 17 of 17 |
| I | 9 of 9 |

All 130 checks passed.

**Sanity values required by the M1 brief:**

| check | what is checked | value | verdict |
|---|---|---|---|
| A-sanity-s052 | G=2M, R=1.05M/yr, s=0.52, T=0.51: closed form equals 680/7 years exactly | 97.1 years | pass |
| A-sanity-s100 | G=2M, R=1.05M/yr, s=1, T=0.51: closed form equals 680/343 years exactly | 1.98 years | pass |
| A-sanity-s051 | G=2M, R=1.05M/yr, s=0.51, T=0.51: no finite solution | no finite solution | pass |
| D-sanity-5m-600s-1day | N=5M, C=600 s, W=1 day: advantage is of order 100 (in [100, 200]) and matches W/(C + qW²/2) within 0.1% | 138.2× | pass |

## What this summary does not show

- No network behaviour: messages, latency, churn and adversarial timing come with the M3/M4 simulators, which must reproduce these tables first.
- No verdicts on the pre-registered hypotheses of SPEC §10; their thresholds are confirmed by the architect before simulation results are generated.
- No incentives: M1 models no rewards, payments or penalties. Sections 11 and 12 assume withholding costs the attacker nothing; M4 adds the ban rules and the [P] rule separating validity from payment.
- Absence rates and durations are illustrative until M3 supplies household downtime profiles.
- The modelling assumptions behind every number are in `docs/ASSUMPTIONS.md`; charts are in `charts/`.
- A short brief for a general technical audience is in `M1_PUBLIC_BRIEF.md`.
