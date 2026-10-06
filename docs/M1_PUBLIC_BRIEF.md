# GrahamBell Stage 1 — M1 analytical baseline: public brief

GrahamBell is a proposed Layer 1 blockchain. New identities (IDs) are issued one at a time at a fixed global rate, one every 30 s (1,051,200 a year), through Proof of Work capped at one hash per second per participant; Witness Chains of other participants enforce the cap. Its claim is that taking control requires sustained participation over years, not a burst of hardware or capital. Stage 1 tests that claim and publishes the results whether they support it or not.

## What M1 tested

M1 computes exact formulas and exact probabilities for the rules in SPEC v0.3: how long an attacker needs to reach a share of active IDs, how likely a randomly composed Witness Chain group is to fall under its control, how often the allocation committee can be stalled or captured, and whether restarting or hopping difficulty helps. Independent methods (exhaustive enumeration, dynamic programming, log-space arithmetic, seeded Monte Carlo) cross-check the results. The default genesis distribution is 2.9M IDs.

> All M1 results assume the attacker's IDs are online 100% of the time while honest IDs are online a fraction f of the time. This is a deliberate worst case; M3 adds realistic outages for both sides.

## Headline: attackers below half of new issuance

An attacker that wins a share s of new IDs approaches a long-run share of active IDs and never exceeds it. If a fraction f of honest IDs is online, that share is s / (s + f(1 − s)); with every honest ID online it is s.

Long-run attacker share of active IDs:

| s | f = 100% | f = 70% | f = 50% |
|---|---|---|---|
| 5% | 5.0% | 7.0% | 9.5% |
| 10% | 10.0% | 13.7% | 18.2% |
| 20% | 20.0% | 26.3% | 33.3% |
| 25% | 25.0% | 32.3% | 40.0% |
| 30% | 30.0% | 38.0% | 46.2% |
| 34% | 34.0% | 42.4% | 50.7% |
| 40% | 40.0% | 48.8% | 57.1% |

While every honest ID is online, no attacker below half of new issuance ever reaches 51% of active IDs. Offline honest IDs change this: with only 50% of honest IDs online, an attacker winning 40% of new IDs eventually passes 51%, after 16.4 years from 2.9M genesis IDs. Honest uptime is therefore part of the security model.

## Worst-case bounds: an attacker that wins every new ID

If the attacker wins 100% of new IDs and every honest ID stays online, reaching 51% of active IDs takes (0.51/0.49) × G/R years for an existing active base G: 0.990 years from 1M IDs, 2.08 years from 2.1M IDs, 2.87 years from 2.9M IDs, 4.95 years from 5M IDs, 9.90 years from 10M IDs.

A 2-year floor at the fixed rate needs 2.02M active IDs. With 2.9M genesis IDs it holds while at least 69.7% of them stay active.

An optional adaptive rate is capped by registered IDs, recalculated at checkpoints every T_min. Without a safety factor, an attacker that times its start against the public checkpoint schedule reaches 51% in 0.857 T_min. The safety factor k = 7/6 adopted in SPEC v0.3 restores the floor: the worst-start time becomes 1.000 T_min.

## Restart attack, before and after per-round entropy

In an earlier design a miner's entropy stayed fixed for its whole connection, so it could compute its winning steps at once and reconnect until one fell soon. At the realistic restart cost of 450 s (grace epoch, convergence interval and post-admission wait) and a one-day keep window, that gave 150.3× the honest rate with 1M competing miners and 181.9× with 5M (up to 182.4× and 408.1× with the best keep window). The current design draws fresh entropy every round, a miner may use one header per round, and abandoning it means waiting for the next block. Every connected miner then wins each round with the same probability, so no restart policy beats staying connected: the best advantage is exactly 1.

## Witness Chains: capture odds and what each state enables

Each group of witnesses (a KWC) has 40 seats drawn uniformly at random from registered IDs. An attacker holding enough seats can block the group (stall it and censor its miners, who can move elsewhere), sign without honest members (the same powers, because every validator recomputes each block and rejects an early or invalid one), or hold every seat (which would also let it bias the group's entropy).

Probability per group, exact, at 100,000 groups (p = attacker share of registered IDs):

| p | block (ID issuance) | sign without honest members (ID issuance) | sign without honest members (transactions) | every seat |
|---|---|---|---|---|
| 10% | 1.85 × 10⁻⁵ | 3.21 × 10⁻¹⁸ | 5.28 × 10⁻²⁰ | 9.93 × 10⁻⁴¹ |
| 25% | 10.3% | 1.87 × 10⁻⁸ | 9.87 × 10⁻¹⁰ | 8.25 × 10⁻²⁵ |
| 33% | 45.2% | 8.47 × 10⁻⁶ | 6.94 × 10⁻⁷ | 5.49 × 10⁻²⁰ |

Group membership changes as IDs join and leave. Counting every group composition formed over 10 years from 100,000 groups (49,506,400 compositions) as an independent draw, the expected number able to sign without honest members at p = 25% is 0.926 for ID issuance. Most consecutive compositions differ by one seat, so this counts one long episode several times; household downtime, which now changes seats, raises the count.

## Design changes made because of M1 (SPEC v0.3)

- **Genesis size.** Raised from 2.1M to 2.9M IDs. With 2.1M the 2-year floor held only while 96.2% of genesis IDs stayed active; with 2.9M it tolerates 30.3% inactive.
- **Difficulty.** Count-based difficulty, from the exact number of admitted online miners, is now the default. Under a Bitcoin-style retarget every 144 blocks, an attacker that doubles the miners for one window earns 100% more IDs per miner-second; count-based difficulty, which follows the exact count, gives no first-order gain.
- **Committee seats by lottery.** Seats on the 600-member allocation committee now go by lottery over active IDs instead of to block miners. Under the old rule an attacker with 25% of active IDs, mining with all of them while half of honest IDs mine, held 40.0% of mining IDs and could stall the committee with probability > 99.9%; under the lottery that probability is 1.94 × 10⁻⁶.
- **Allocation.** Seats are assigned by a deterministic shuffle that every node recomputes from chain data, so the committee announces placements but cannot choose them. Every group's composition then tracks the attacker's share of all IDs, not its share of recent issuance.
- **Deactivation instead of bans.** An ID offline beyond the allowance is deactivated and can return; bans are reserved for proven misbehaviour.
- **Adaptive cap.** The optional adaptive rate gains the safety factor k = 7/6 described above.

## Limitations

- **Analytical only.** These are formulas and exact probabilities. There is no network simulation yet: no latency, message loss, churn or adversarial timing (milestones M3 and M4).
- **The attacker is always online.** Honest IDs are online a fraction f of the time; outages for both sides come in M3.
- **Idealised assignment.** Witness seats and committee draws are modelled as uniformly random, and group compositions are counted as independent draws. Simulations must confirm both.
- **No money costs yet.** The cost of sustaining an attacker share comes in M5.
- **Open parameters.** Several SPEC values (for example offline durations and the transaction-block interval) are still open and are swept.

All tables, the full summary, the cross-check verdicts and the code that produces them are in the repository.
