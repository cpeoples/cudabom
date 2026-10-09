//! cudabom command-line entry point.
//!
//! Responsibilities kept here are deliberately thin: parse arguments, dispatch
//! to a command module, and map the resulting [`exit::ExitStatus`] onto the
//! process exit code. All real work lives in the workspace library crates so
//! it is unit-testable without spawning a process.

mod cli;
mod commands;
mod datadir;
mod exit;
mod verbosity;

use std::process::ExitCode;

use clap::Parser;

use crate::cli::{Cli, Command};
use crate::exit::ExitStatus;

fn main() -> ExitCode {
    // clap handles `--help`/`--version` and exits with code 2 on usage errors,
    // which matches our documented Usage exit code.
    let cli = Cli::parse();
    // Establish the single global verbosity level before any command runs, so
    // every subcommand's diagnostics honor the same -v/-q flags.
    verbosity::set(cli.verbose, cli.quiet);
    dispatch(cli).into()
}

fn dispatch(cli: Cli) -> ExitStatus {
    match cli.command {
        Command::Version(args) => commands::version::run(&args),
        Command::Schema => commands::schema::run(),
        Command::Scan(args) => commands::scan::run(&args),
        Command::Gate(args) => commands::gate::run(&args),
        Command::Vex(args) => commands::vex::run(&args),
        Command::Reconcile(args) => commands::reconcile::run(&args),
        Command::Enrich(args) => commands::enrich::run(&args),
        Command::Explain(args) => commands::explain::run(&args),
        Command::Db(args) => commands::db::run(&args),
        Command::Update(args) => commands::update::run(&args),
    }
}
