//! # lancer-agentic-radar
//!
//! Security scanner for agentic AI workflows — a Rust clone of
//! `splx-ai/agentic-radar` with a native egui GUI. This crate is the
//! application layer: it wires the `ar-*` library crates together behind both a
//! CLI ([`cli`]) and a GUI ([`gui`]), sharing one orchestration path
//! ([`pipeline`]).
//!
//! Two binaries are produced from this package:
//! * `lancer-agentic-radar` — opens the GUI by default ([`run_default`]).
//! * `lancer-agentic-radar-cli` — always the CLI ([`run_cli_forced`]).

pub mod cli;
pub mod config_load;
pub mod gui;
pub mod pipeline;
pub mod selftest;
pub mod server;

use clap::Parser;

/// Initialise tracing from `-v` count + `RUST_LOG`.
fn init_logging(verbose: u8) {
    let default = match verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| default.to_string());
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}

/// Default binary entry point: GUI unless a subcommand or `--cli` is given.
pub fn run_default() -> anyhow::Result<()> {
    let cli = cli::Cli::parse();
    init_logging(cli.global.verbose);

    if cli.global.self_test {
        std::process::exit(selftest::run()?);
    }

    match &cli.command {
        None if !cli.global.cli => {
            gui::launch()?;
            Ok(())
        }
        None => {
            cli::print_help();
            std::process::exit(2);
        }
        Some(_) => {
            let code = cli::run(cli)?;
            std::process::exit(code);
        }
    }
}

/// Companion-binary entry point: always the CLI surface.
pub fn run_cli_forced() -> anyhow::Result<()> {
    let mut cli = cli::Cli::parse();
    cli.global.cli = true;
    init_logging(cli.global.verbose);

    if cli.global.self_test {
        std::process::exit(selftest::run()?);
    }
    match &cli.command {
        None => {
            cli::print_help();
            std::process::exit(2);
        }
        Some(_) => {
            let code = cli::run(cli)?;
            std::process::exit(code);
        }
    }
}
