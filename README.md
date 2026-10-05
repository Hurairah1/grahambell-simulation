# GrahamBell — Stage 1 simulation

GrahamBell is a proposed Layer 1 blockchain whose Sybil resistance comes from time rather than hardware or capital. Identities (IDs) are issued one at a time at a fixed global rate through capped Proof of Work. Each miner is limited to one hash per second, and a Witness Chain of other participants enforces the limit. The architecture calls this **Proof of Infrastructure Endurance (PoIE)**.

Stage 1 tests whether PoIE's claims hold under realistic and adversarial conditions, and publishes the results whether they confirm or refute the model. The rules under test are in [`docs/SPEC.md`](docs/SPEC.md), the single source of truth.

This repository currently contains milestone **M0**: a reproducible Rust foundation. Later milestones are described in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Build and test

You need a stable Rust toolchain (1.85 or newer); `rustup` picks it up from `rust-toolchain.toml`.

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

## Configuration

Every parameter in SPEC section 2 is a typed parameter with its value, its SPEC status tag (`D` decided, `P` proposed, `O` open) and its sweep range. The defaults live in [`configs/default.toml`](configs/default.toml). A test fails if that file and the built-in defaults ever disagree.

```sh
cargo run --release -p gb-cli -- params            # every parameter, as a Markdown table
cargo run --release -p gb-cli -- params --format csv
cargo run --release -p gb-cli -- config dump        # the resolved configuration as TOML
```

To change values, write a small TOML file with only the keys you change and pass it with `--config`. For example:

```toml
[genesis]
ids.value = 3000000
```

Unknown keys are rejected. A file cannot change a status tag, because status tags belong to the SPEC.

## Repository layout

| Path | Contents |
|---|---|
| `docs/SPEC.md` | Stage 1 specification (source of truth) |
| `docs/ARCHITECTURE.md` | Two-tier design, planned crates, validation ladder, allocation proposal |
| `configs/default.toml` | Default configuration |
| `crates/gb-config` | Typed configuration and the SPEC §2 parameter registry |
| `crates/gb-runlog` | Run provenance: run ids, git commit, seed, output checksums, seeded random streams |
| `crates/gb-cli` | The `gb` command-line tool |
| `results/` | Generated outputs (not committed) |

## Reproducibility

`gb-runlog` provides the run provenance that the analyses (from M1) record: a run id, the resolved configuration, the seed, the git commit with a dirty flag, and a SHA-256 of every output file. Every random number comes from a ChaCha20 stream derived from one master seed.
