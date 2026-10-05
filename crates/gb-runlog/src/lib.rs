//! Run provenance for GrahamBell Stage 1.
//!
//! SPEC §11.4 requires every run to be seeded and to record its configuration, seed and git
//! commit. This crate provides:
//!
//! - [`RunIdentity`]: run id from start time, commit and seed;
//! - [`GitInfo`]: the commit and whether the working tree was clean;
//! - [`finish_run`]: writes `run.json` with a SHA-256 manifest of every output, so a rerun can
//!   be checked byte for byte;
//! - [`rng_stream`]: independent ChaCha20 streams derived from one master seed.

mod error;
mod git;
mod manifest;
mod rng;
mod runlog;
mod time;

pub use error::RunLogError;
pub use git::{GitInfo, porcelain_reports_changes};
pub use manifest::{OutputFile, build_manifest, sha256_hex};
pub use rng::rng_stream;
pub use runlog::{
    RESOLVED_CONFIG_FILE, RUN_LOG_FILE, RUSTC_VERSION, RunDetails, RunIdentity, RunLog, finish_run,
    read_run_log, write_resolved_config,
};
pub use time::UtcTimestamp;
