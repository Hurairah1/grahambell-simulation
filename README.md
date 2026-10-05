# GrahamBell — Stage 1 simulation

GrahamBell is a proposed Layer 1 blockchain whose Sybil resistance comes from time rather than hardware or capital. Identities (IDs) are issued one at a time at a fixed global rate through capped Proof of Work. Each miner is limited to one hash per second, and a Witness Chain of other participants enforces the limit. An attacker can still create identities, but only as fast as the shared issuance schedule allows, so taking control of the network takes years of sustained participation. The architecture calls this **Proof of Infrastructure Endurance (PoIE)**.

**Stage 1** tests whether PoIE's claims hold under realistic and adversarial conditions, and publishes the results whether they confirm or refute the model. The rules under test are in [`docs/SPEC.md`](docs/SPEC.md), the single source of truth.

## What is in this repository

| Milestone | Status | Contents |
|---|---|---|
| M0 | done | Rust workspace, typed configuration of every SPEC parameter, run provenance, CI |
| M1 | done | **Analytical baseline**: exact formulas and exact probabilities for issuance, witness capture, the allocation committee, the restart attack, difficulty hopping and same-step ties |
| M2–M6 | planned | Cryptographic core, simulators, cost model, full-scale runs; see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) |

M1 results are the ground truth that later simulators must reproduce before their own results are trusted. Every modelling assumption behind them is listed in [`docs/ASSUMPTIONS.md`](docs/ASSUMPTIONS.md).

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

This takes about ten seconds after compilation. It writes a new directory `results/analytic/<run-id>/` and copies its `SUMMARY.md` to `results/analytic/SUMMARY.md`. The run id is `<UTC time>_<git commit>_s<seed>`.

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
| `A1_…` to `A7_….csv` | Section A: time for an attacker to reach 33%, 51% or 67% of active IDs; online fraction; honest growth; adaptive cap and safety factors; genesis size needed; long-run shares |
| `B1_…` to `B4_….csv` | Section B: probability that an attacker can block, sign alone, or hold every seat of a Witness Chain group; network-level counts; binomial vs hypergeometric; 10-year counts |
| `C1_…`, `C2_….csv` | Section C: Chain Allocation Committee stalling and capture; events per year |
| `D1_…`, `D2_….csv` | Section D: restart attack under the old and current entropy designs |
| `E1_….csv` | Section E: difficulty hopping |
| `F1_….csv` | Section F: same-step ties between identity blocks |
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
ids.value = 3000000

[analytic.cac]
committee_sizes = [600]
```

Unknown keys are rejected. A file cannot change a status tag, because status tags belong to the SPEC.

## Repository layout

| Path | Contents |
|---|---|
| `docs/SPEC.md` | Stage 1 specification (source of truth), with its changelog |
| `docs/ARCHITECTURE.md` | Two-tier design, planned crates, validation ladder, allocation proposal |
| `docs/ASSUMPTIONS.md` | Every M1 modelling assumption, and open questions |
| `configs/default.toml` | Default configuration |
| `crates/gb-config` | Typed configuration and the SPEC §2 parameter registry |
| `crates/gb-runlog` | Run provenance: run ids, git commit, seed, output checksums, seeded random streams |
| `crates/gb-analytic` | M1 analytical baseline: exact formulas, exact probabilities, cross-checks |
| `crates/gb-cli` | The `gb` command-line tool: tables, charts, summary |
| `results/` | Generated outputs (not committed) |

## Licence

No licence has been chosen yet. The bundled DejaVu Sans font (`crates/gb-cli/assets/fonts/`) is distributed under its own licence, included next to it.
