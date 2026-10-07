# GrahamBell — Stage 1 simulation

GrahamBell is a proposed Layer 1 blockchain whose Sybil resistance comes from time rather than hardware or capital. Identities (IDs) are issued one at a time at a fixed global rate through capped Proof of Work. Each miner is limited to one hash per second, and a Witness Chain of other participants enforces the limit. An attacker can still create identities, but only as fast as the shared issuance schedule allows, so taking control of the network takes years of sustained participation. The architecture calls this **Proof of Infrastructure Endurance (PoIE)** and **Proof of Time (PoT)** (A new Time-based Sybil-resistance model).

**Stage 1** tests whether PoIE's claims hold under realistic and adversarial conditions, and publishes the results whether they confirm or refute the model. The rules under test are in [`docs/SPEC.md`](docs/SPEC.md), the single source of truth.

## What is in this repository

| Milestone | Status | Contents |
|---|---|---|
| M0 | done | Rust workspace, typed configuration of every SPEC parameter, run provenance, CI |
| M1 | done | **Analytical baseline**: exact formulas and exact probabilities for issuance, witness capture, the allocation committee, the restart attack, difficulty hopping and same-step ties |
| M1.1 | done | The architect's decisions on M1 (SPEC v0.3): 2.9M genesis IDs, adaptive-cap safety factor, count-based difficulty, committee seat lottery, adopted allocation algorithm, deactivation instead of bans. Adds the quorum trade-off (section G) and a [public brief](docs/M1_PUBLIC_BRIEF.md) |
| M1.2 | done | The architect's decisions on M1.1 (SPEC v0.4): seats survive downtime (only bans and absences longer than L vacate them), distinct episodes as the H6 measure, placement without the committee, committee departures, conflicting decisions and proposer rights. Adds quorum feasibility under honest downtime (section H), the KWC size trade-off (section I) and the Apache 2.0 licence |
| M2–M6 | planned | Cryptographic core, simulators, cost model, full-scale runs; see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) |

M1 results are the ground truth that later simulators must reproduce before their own results are trusted. Every modelling assumption behind them is listed in [`docs/ASSUMPTIONS.md`](docs/ASSUMPTIONS.md).

All M1 results assume the attacker's IDs are online 100% of the time while honest IDs are online a fraction f of the time. This is a deliberate worst case; M3 adds realistic outages for both sides.

For a short overview of what M1 found, written for a general technical audience, read [`docs/M1_PUBLIC_BRIEF.md`](docs/M1_PUBLIC_BRIEF.md).

## Build and test

You need a stable Rust toolchain, 1.85 or newer; `rustup` picks it up from `rust-toolchain.toml`.

```sh
cargo build --release
cargo test --workspace
```

The same checks run in CI on every push and pull request:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
```

## Run the analysis

```sh
cargo run --release -p gb-cli -- analytic
```

This takes about fifteen seconds after compilation. It writes a new directory `results/analytic/<run-id>/` and copies its `SUMMARY.md` to `results/analytic/SUMMARY.md`. The run id is `<UTC time>_<git commit>_s<seed>`.

The command refuses to run from a working tree with uncommitted changes, so that every result can be traced to a commit. Pass `--allow-dirty` to override; the run log records that you did. It exits with a non-zero status if any cross-check fails, after writing all outputs.

Options:

| Option | Meaning |
|---|---|
| `--config FILE` | TOML file with the values you want to change, merged over the defaults |
| `--seed N` | Master seed for the Monte Carlo cross-checks (default 20261005) |
| `--out DIR` | Where run directories go (default `results/analytic`) |
| `--allow-dirty` | Allow uncommitted changes (recorded in `run.json`) |

## Where each output lives

Inside `results/analytic/<run-id>/`:

| File | What it holds |
|---|---|
| `SUMMARY.md` | Plain-English summary of every table, written for non-experts |
| `M1_PUBLIC_BRIEF.md` | Short brief for a general technical audience, from exact tables only; a test keeps `docs/M1_PUBLIC_BRIEF.md` identical to it |
| `A1_…` to `A7_….csv` | Section A: time for an attacker to reach 33%, 51% or 67% of active IDs; online fraction; honest growth; adaptive cap with its safety factor; genesis size needed; long-run shares |
| `B1_…` to `B5_….csv` | Section B: probability that an attacker can block, sign alone, or hold every seat of a Witness Chain group; network-level counts; binomial vs hypergeometric; 10-year episode and composition counts under the adopted allocation (B4) and under each seat rule with illustrative absences (B5) |
| `C1_…` to `C3_….csv` | Section C: Chain Allocation Committee stalling and capture under the seat lottery, with episode lengths and entries per year; the v0.2 rule as a comparison; the effect of honest members leaving the committee when deactivated (C3) |
| `D1_…`, `D2_….csv` | Section D: restart attack under the old and current entropy designs, including the realistic restart cost (450 s) |
| `E1_….csv` | Section E: difficulty hopping against the Variant A comparison |
| `F1_….csv` | Section F: same-step ties between identity blocks |
| `G1_…` to `G4_….csv` | Section G: quorum trade-off — stalling, signing alone and conflicting approvals for each quorum option; the split rule; committee quorums; 10-year episodes under each seat rule (G4) |
| `H1_…` to `H3_….csv` | Section H: how often a group cannot meet its quorum when honest members are offline and attacker members withhold; the minimum honest uptime; absent IDs holding seats under each long-absence threshold L |
| `I1_…` to `I4_….csv` | Section I: KWC size trade-off — security, liveness, load per node under three capacity policies, and on-demand witness connections under the proposed peer topology |
| `validation.csv` | Every cross-check: reference value, tolerance, verdict |
| `parameters.csv` | Every SPEC §2 parameter with its value, status tag and sweep |
| `charts/*.png` | Charts drawn from the tables |
| `config.resolved.toml` | The exact configuration used |
| `run.json` | Run id, time, git commit, dirty flag, seed, config hash, toolchain, and a SHA-256 of every file above |

Probabilities can be far smaller than a floating-point number can hold (some committee tails are near 10⁻⁴⁰⁰). The CSV files therefore give them as exact scientific-notation strings, with a `log10` column alongside.

## Reproduce a result

Every run is determined by three things: the git commit, the seed and the configuration. To reproduce one:

1. Check out the commit recorded in its `run.json`.
2. Run `cargo run --release -p gb-cli -- analytic --seed <seed> --config <file>` with the same seed and configuration (`config.resolved.toml` from the run directory works as the configuration file).
3. Compare the `outputs` list in the two `run.json` files.

CSV and Markdown outputs are designed to be byte-identical across machines: exact arithmetic, a pure-Rust maths library and in-repo random samplers remove the usual platform differences. A test checks byte-identity of reruns on the same machine; cross-machine identity has not yet been tested. PNG charts are byte-identical on the same platform.

## Configuration

Every parameter in SPEC section 2 is a typed parameter with its value, its SPEC status tag (`D` decided, `P` proposed, `O` open) and its sweep range. The defaults live in [`configs/default.toml`](configs/default.toml); a test fails if that file and the built-in defaults ever disagree, and another test fails if a SPEC §2 row has no matching parameter.

```sh
cargo run --release -p gb-cli -- params             # every parameter, as a Markdown table
cargo run --release -p gb-cli -- params --format csv
cargo run --release -p gb-cli -- config dump        # the resolved configuration as TOML
```

To change values, write a small TOML file with only the keys you change and pass it with `--config`. For example:

```toml
[genesis]
ids.value = 5000000

[analytic.cac]
committee_sizes = [600]
```

Unknown keys are rejected. A file cannot change a status tag, because status tags belong to the SPEC.

## Repository layout

| Path | Contents |
|---|---|
| `docs/SPEC.md` | Stage 1 specification (source of truth), with its changelog |
| `docs/ARCHITECTURE.md` | Two-tier design, planned crates, validation ladder, rationale of the adopted allocation |
| `docs/ASSUMPTIONS.md` | Every M1 modelling assumption, and open questions |
| `LICENSE` | Apache License 2.0 |
| `docs/M1_PUBLIC_BRIEF.md` | Public brief on the M1 results (generated; see above) |
| `configs/default.toml` | Default configuration |
| `crates/gb-config` | Typed configuration and the SPEC §2 parameter registry |
| `crates/gb-runlog` | Run provenance: run ids, git commit, seed, output checksums, seeded random streams |
| `crates/gb-analytic` | M1 analytical baseline: exact formulas, exact probabilities, cross-checks |
| `crates/gb-cli` | The `gb` command-line tool: tables, charts, summary |
| `results/` | Generated outputs (not committed) |

## Licence

Licensed under the Apache License 2.0; see [`LICENSE`](LICENSE). The bundled DejaVu Sans font (`crates/gb-cli/assets/fonts/`) keeps its own licence, included next to it.
