# results/

Generated outputs. Everything in this folder is ignored by git except this README and the **reference run** in [`analytic/reference/`](analytic/reference/). The reference run is committed so that the repository contains the tables, charts, summary and cross-check verdicts behind the public brief; start with its [`SUMMARY.md`](analytic/reference/SUMMARY.md). Its `run.json` records the commit it was produced from and a SHA-256 of every file. New runs stay ignored. Regenerate outputs with the `gb` tool rather than editing them.

Each analysis writes one directory per run, `results/<analysis>/<run-id>/`. The run id is `YYYYMMDDTHHMMSSZ_<commit>_s<seed>`. Each run directory contains:

| File | Contents |
|---|---|
| `*.csv` | Tables, one per analysis output |
| `charts/*.png` | Charts drawn from those tables |
| `SUMMARY.md` | Plain-English summary of the tables |
| `validation.csv` | Every cross-check, with its reference value, tolerance and verdict |
| `parameters.csv` | Every SPEC §2 parameter with its value, status and sweep |
| `config.resolved.toml` | The exact configuration used |
| `run.json` | Run id, time, git commit, dirty flag, seed, config hash, toolchain, and a SHA-256 for every file above |

The M2 **crypto reference run** in [`crypto/reference/`](crypto/reference/) is committed the same way. Its `bench/` timings were measured on the machine named in `crypto/reference/bench/BENCH.md` (CPU, logical cores and rustc version) and will differ elsewhere; everything outside `bench/` reproduces from the commit in its `run.json`. New crypto runs stay ignored.

To check that a rerun reproduces a run, compare the `sha256` fields in the two `run.json` files. To check the reference run, check out the commit in `analytic/reference/run.json`, run `cargo run --release -p gb-cli -- analytic`, and compare the new run's `run.json` with the reference one.
