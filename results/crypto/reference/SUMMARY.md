# M2 cryptography measurements — summary

- Git commit: `2b0cb00189a7666a476a4fa4d8984f838f4b2f15` (clean working tree)
- Seed: 20261005
- Configuration SHA-256: `5f72b6093efc327cc75d6ae9557140e1cae54e2e61849de610e5404298deacf5`
- Protocol version: 1

Real SHA-256 and BLS12-381 (blst, min-pk, Ethereum PoP ciphersuite) throughout. Monte Carlo trials are seeded, so these tables are reproducible; timings are machine-dependent and are in `bench/BENCH.md`.

## C1 — Entropy grinding (S11, H3)

Each trial builds a fresh header and its entropy, and counts attempts to the first winning step at a test difficulty of 1 in 64. An attacker with budget G keeps the best of G candidate entropies. Advantage = honest ÷ attacker mean attempts, 95% CI by batch means; the last column is the advantage if the candidates were independent.

| experiment | G | advantage | 95% CI | independent tries | distinct entropies |
|---|---|---|---|---|---|
| a (old flow: miner signs last with a non-unique signature (free nonce)) | 1 | 1.000 | 1.000 – 1.000 | 1.000 | 1.000 |
| a (old flow: miner signs last with a non-unique signature (free nonce)) | 4 | 3.702 | 3.417 – 3.986 | 3.907 | 4.000 |
| a (old flow: miner signs last with a non-unique signature (free nonce)) | 16 | 14.045 | 13.016 – 15.075 | 14.255 | 16.000 |
| a (old flow: miner signs last with a non-unique signature (free nonce)) | 64 | 38.978 | 36.555 – 41.402 | 40.641 | 64.000 |
| b (miner aggregates any member subset meeting the quorum) | 1 | 1.000 | 1.000 – 1.000 | 1.000 | 1.000 |
| b (miner aggregates any member subset meeting the quorum) | 4 | 3.807 | 3.480 – 4.133 | 3.907 | 4.000 |
| b (miner aggregates any member subset meeting the quorum) | 16 | 13.977 | 12.748 – 15.206 | 14.255 | 16.000 |
| b (miner aggregates any member subset meeting the quorum) | 64 | 40.083 | 36.989 – 43.178 | 40.641 | 64.000 |
| c (old flow: colluding last witness signs with a free nonce) | 1 | 1.000 | 1.000 – 1.000 | 1.000 | 1.000 |
| c (old flow: colluding last witness signs with a free nonce) | 4 | 3.974 | 3.638 – 4.310 | 3.907 | 4.000 |
| c (old flow: colluding last witness signs with a free nonce) | 16 | 14.728 | 13.420 – 16.036 | 14.255 | 16.000 |
| c (old flow: colluding last witness signs with a free nonce) | 64 | 40.692 | 37.695 – 43.690 | 40.641 | 64.000 |
| c′ (current flow: colluding last witness signs or withholds (withholding triggers One Chance)) | 1 | 1.000 | 1.000 – 1.000 | 1.000 | 1.000 |
| c′ (current flow: colluding last witness signs or withholds (withholding triggers One Chance)) | 2 | 1.876 | 1.776 – 1.977 | 1.984 | 2.000 |
| e (current flow: BLS signatures are unique; re-signing changes nothing) | 1 | 1.012 | 0.9326 – 1.091 | 1.000 | 1.000 |
| e (current flow: BLS signatures are unique; re-signing changes nothing) | 4 | 1.012 | 0.9326 – 1.091 | 1.000 | 1.000 |
| e (current flow: BLS signatures are unique; re-signing changes nothing) | 16 | 1.012 | 0.9326 – 1.091 | 1.000 | 1.000 |
| e (current flow: BLS signatures are unique; re-signing changes nothing) | 64 | 1.012 | 0.9326 – 1.091 | 1.000 | 1.000 |

**Equivocation (d):**

| case | pairs | flagged | expected |
|---|---|---|---|
| two different headers, same height, same key | 500 | 500 | 500 |
| the same header twice | 500 | 0 | 0 |
| different heights (next round) | 500 | 0 | 0 |
| different candidate keys | 500 | 0 | 0 |

## C2 — Sorted-hex rule (S14)

| experiment | pairs | sorted-hex collisions | fixed-order collisions |
|---|---|---|---|
| header: previous hash and reward wallet swapped (32 bytes each) | 10000 | 10000 | 0 |
| header: height and KWC ID swapped (8 bytes each) | 10000 | 10000 | 0 |
| chain step: height and nonce swapped, timestamps matched | 10000 | 10000 | 0 |
| random distinct headers | 10000 | 0 | 0 |

Under the sorted-hex rule, 36 different headers share each header's hash (values exchanged among fields of equal width); under fixed order, 1.

## C3 — Beacon withholding and placement grinding (ARCHITECTURE §8.6)

The attacker mines each candidate beacon block with probability s and withholds it, giving up that block, when the outcome is unfavourable. Formula: q / (1 − s(1 − q)).

| beacon | k | s | q | without | with withholding (± SE) | formula | gain | blocks given up per beacon |
|---|---|---|---|---|---|---|---|---|
| allocation (§4.2) | — | 0.1 | 0.0100 | 0.0102 | 0.0111 ± 0.0003 | 0.0111 | 1.110× | 0.1085 |
| allocation (§4.2) | — | 0.1 | 0.1000 | 0.1027 | 0.1124 ± 0.0010 | 0.1099 | 1.099× | 0.0999 |
| committee lottery (§4.3) | 1 | 0.1 | 0.1000 | 0.0998 | 0.1102 ± 0.0010 | 0.1099 | 1.099× | 0.1007 |
| committee lottery (§4.3) | 3 | 0.1 | 0.1000 | 0.1011 | 0.1111 ± 0.0010 | 0.1099 | 1.099× | 0.0995 |
| committee lottery (§4.3) | 6 | 0.1 | 0.1000 | 0.0989 | 0.1086 ± 0.0010 | 0.1099 | 1.099× | 0.0996 |
| committee lottery (§4.3) | 12 | 0.1 | 0.1000 | 0.1000 | 0.1098 ± 0.0010 | 0.1099 | 1.099× | 0.0984 |
| allocation (§4.2) | — | 0.25 | 0.0100 | 0.0101 | 0.0133 ± 0.0004 | 0.0133 | 1.329× | 0.3256 |
| allocation (§4.2) | — | 0.25 | 0.1000 | 0.0987 | 0.1276 ± 0.0011 | 0.1290 | 1.290× | 0.2911 |
| committee lottery (§4.3) | 1 | 0.25 | 0.2500 | 0.2498 | 0.3080 ± 0.0015 | 0.3077 | 1.231× | 0.2324 |
| committee lottery (§4.3) | 3 | 0.25 | 0.2500 | 0.2497 | 0.3078 ± 0.0015 | 0.3077 | 1.231× | 0.2320 |
| committee lottery (§4.3) | 6 | 0.25 | 0.2500 | 0.2483 | 0.3075 ± 0.0015 | 0.3077 | 1.231× | 0.2313 |
| committee lottery (§4.3) | 12 | 0.25 | 0.2500 | 0.2492 | 0.3073 ± 0.0015 | 0.3077 | 1.231× | 0.2332 |

**Placement grinding:** an ID is the hash of its winning block, fixed before its allocation beacon exists, so a rule applied when minting cannot steer the seat:

| IDs | trials | share in target seats (± SE) | target share |
|---|---|---|---|
| all minted IDs | 100000 | 0.0099 ± 0.0003 | 0.0100 |
| IDs kept by a minting-time rule (hash starts below 0x40) | 25194 | 0.0092 ± 0.0006 | 0.0100 |

## C5 — Threshold BLS key setup (SPEC §12 [P]; benchmark only, not audited, not used by gb-protocol)

Joint-Feldman DKG with t = ⌈2n/3⌉. Per member:

| n | t | messages sent | messages received | bytes sent | bytes received | G1 multiplications | threshold signature verifies |
|---|---|---|---|---|---|---|---|
| 30 | 20 | 30 | 58 | 1888 | 28768 | 629 | true |
| 40 | 27 | 40 | 78 | 2544 | 51792 | 1119 | true |
| 60 | 40 | 60 | 118 | 3808 | 115168 | 2459 | true |
| 100 | 67 | 100 | 198 | 6384 | 321552 | 6799 | true |

Times are in `bench/BENCH.md`.

## C6 — Simulator entropy stand-in

| test | trials | statistic | p-value | passes (p ≥ 0.001) |
|---|---|---|---|---|
| winning-step distribution, real entropy vs stand-in (two-sample χ², 10 bins) | 4000 | 9.776 | 0.3689 | true |
| real entropy uniform (KS on the top 53 bits) | 4000 | 0.0144 | 0.3728 | true |
| stand-in entropy uniform (KS on the top 53 bits) | 4000 | 0.0145 | 0.3663 | true |

## Cross-checks

35 of 35 checks passed (`validation.csv`).
