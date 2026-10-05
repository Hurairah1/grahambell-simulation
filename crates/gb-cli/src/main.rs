//! `gb`: command-line front end for GrahamBell Stage 1.
//!
//! Run `gb --help` for the list of commands.

use clap::{Parser, Subcommand};
use gb_cli::load_config;
use gb_cli::params::{ListingFormat, render_listing};
use gb_config::registry::parameter_listing;
use std::path::PathBuf;

/// GrahamBell Stage 1 simulation and analysis tool.
#[derive(Debug, Parser)]
#[command(name = "gb", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
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

fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
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
    Ok(())
}
