# M2 timings (machine-dependent)

Machine: Intel(R) Core(TM) i5-8257U CPU @ 1.40GHz (macos x86_64), 8 logical cores, rustc 1.97.1 (8bab26f4f 2026-07-14). Single-threaded, so ops/s are per core. Release build recommended.

## C4 — Operations

| operation | signers | ops/s per core | µs per op |
|---|---|---|---|
| BLS sign | 1 | 2639 | 379 |
| BLS verify | 1 | 998 | 1002 |
| SHA-256 chain step | 1 | 1032075 | 0.9689 |
| aggregate signatures (with subgroup checks) | 3 | 5920 | 169 |
| aggregate-verify, one message (PoWit) | 3 | 1082 | 925 |
| entropy verify (miner + members, SPEC §3.4) | 3 | 452 | 2215 |
| aggregate signatures (with subgroup checks) | 10 | 1755 | 570 |
| aggregate-verify, one message (PoWit) | 10 | 1074 | 931 |
| entropy verify (miner + members, SPEC §3.4) | 10 | 379 | 2641 |
| aggregate signatures (with subgroup checks) | 27 | 659 | 1517 |
| aggregate-verify, one message (PoWit) | 27 | 1082 | 924 |
| entropy verify (miner + members, SPEC §3.4) | 27 | 278 | 3595 |
| aggregate signatures (with subgroup checks) | 40 | 435 | 2297 |
| aggregate-verify, one message (PoWit) | 40 | 1073 | 932 |
| entropy verify (miner + members, SPEC §3.4) | 40 | 227 | 4397 |
| aggregate signatures (with subgroup checks) | 60 | 294 | 3406 |
| aggregate-verify, one message (PoWit) | 60 | 1051 | 952 |
| entropy verify (miner + members, SPEC §3.4) | 60 | 178 | 5604 |
| aggregate signatures (with subgroup checks) | 100 | 175 | 5701 |
| aggregate-verify, one message (PoWit) | 100 | 1025 | 976 |
| entropy verify (miner + members, SPEC §3.4) | 100 | 128 | 7795 |

## C4 — §13 testnet witness server

Assumptions: one server runs 3 witness nodes as one WC; every miner gets fresh entropy every 30.000 s round; per miner and witness each round: one miner-signature verify, one entropy signature, one entropy-aggregate verify and one SHA-256 chain step per second of the round. PoWit signing (one block per round network-wide), networking, serialisation and disk are not counted.

| miners | CPU-seconds per round | cores busy | logical cores here |
|---|---|---|---|
| 5000 | 54.374 | 1.812 | 8 |
| 10000 | 109 | 3.625 | 8 |
| 30000 | 326 | 10.875 | 8 |

## C5 — Threshold BLS (benchmark only, not audited, not used by gb-protocol)

| n | t | deal (s) | check shares (s) | setup per member (s) | partial sign (s) | combine (s) | verify (s) |
|---|---|---|---|---|---|---|---|
| 30 | 20 | 0.0081 | 0.2511 | 0.2592 | 0.0004 | 0.0370 | 0.0010 |
| 40 | 27 | 0.0112 | 0.4602 | 0.4715 | 0.0004 | 0.0504 | 0.0010 |
| 60 | 40 | 0.0167 | 1.004 | 1.021 | 0.0004 | 0.0757 | 0.0010 |
| 100 | 67 | 0.0274 | 2.982 | 3.010 | 0.0004 | 0.1305 | 0.0012 |
