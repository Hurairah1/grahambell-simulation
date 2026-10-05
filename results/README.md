# results/

Generated outputs. Everything in this folder except this README is ignored by git. Regenerate it with the `gb` tool rather than editing it.

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

To check that a rerun reproduces a run, compare the `sha256` fields in the two `run.json` files.
