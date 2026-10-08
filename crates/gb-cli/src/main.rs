//! `gb`: command-line front end for GrahamBell Stage 1.
//!
//! Run `gb --help` for the list of commands.

use clap::{Parser, Subcommand};
use gb_cli::analytic::{AnalyticOptions, run_analytic};
use gb_cli::load_config;
use gb_cli::params::{ListingFormat, render_listing};
use gb_config::registry::parameter_listing;
use std::path::PathBuf;
use std::process::ExitCode;

/// GrahamBell Stage 1 simulation and analysis tool.
#[derive(Debug, Parser)]
#[command(name = "gb", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the M1 analytical baseline and write tables, charts, SUMMARY.md and run.json.
    Analytic {
        /// Configuration file to merge over the defaults.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Seed overriding the configuration's.
        #[arg(long)]
        seed: Option<u64>,
        /// Directory that receives one sub-directory per run.
        #[arg(long, default_value = "results/analytic")]
        out: PathBuf,
        /// Allow a working tree with uncommitted changes (recorded in run.json).
        #[arg(long)]
        allow_dirty: bool,
    },
    /// Write the gb-protocol test vectors (SPEC Appendix A) to a directory.
    Vectors {
        /// Directory that receives protocol_v1.json.
        #[arg(long, default_value = "crates/gb-protocol/vectors")]
        out: PathBuf,
    },
    /// Print every SPEC §2 parameter with its value, status tag and sweep.
    Params {
        /// Configuration file to merge over the defaults.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Output format.
        #[arg(long, value_enum, default_value_t = ListingFormat::Markdown)]
        format: ListingFormat,
    },
    /// Inspect the resolved configuration.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigAction {
    /// Print the resolved configuration as TOML.
    Dump {
        /// Configuration file to merge over the defaults.
        #[arg(long)]
        config: Option<PathBuf>,
    },
}

fn main() -> anyhow::Result<ExitCode> {
    match Cli::parse().command {
        Command::Analytic {
            config,
            seed,
            out,
            allow_dirty,
        } => {
            let options = AnalyticOptions {
                config_path: config,
                seed,
                out_root: out,
                allow_dirty,
                repo_dir: std::env::current_dir()?,
                command_line: std::env::args().collect(),
            };
            let outcome = run_analytic(&options)?;
            println!("Wrote {}", outcome.run_dir.display());
            println!(
                "Cross-checks passed: {} of {}",
                outcome.checks - outcome.failed.len(),
                outcome.checks
            );
            if !outcome.failed.is_empty() {
                eprintln!("Failed checks: {}", outcome.failed.join(", "));
                return Ok(ExitCode::FAILURE);
            }
        }
        Command::Vectors { out } => {
            std::fs::create_dir_all(&out)?;
            let path = out.join(gb_protocol::vectors::VECTOR_FILE);
            std::fs::write(&path, gb_protocol::vectors::render()?)?;
            println!("Wrote {}", path.display());
        }
        Command::Params { config, format } => {
            let config = load_config(config.as_deref())?;
            print!("{}", render_listing(&parameter_listing(&config)?, format)?);
        }
        Command::Config {
            action: ConfigAction::Dump { config },
        } => {
            print!("{}", load_config(config.as_deref())?.to_toml_string()?);
        }
    }
    Ok(ExitCode::SUCCESS)
}
