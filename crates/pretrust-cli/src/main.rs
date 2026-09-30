mod cli;
mod commands;
mod ui;

use clap::Parser;
use cli::{Cli, Commands};

/// `pretrust rules | head` closes stdout while we are still writing to it.
/// Rust ignores SIGPIPE by default, so the failing `println!` panics, and the
/// release profile sets `panic = "abort"`, which turns that into SIGABRT (exit
/// 134). Restoring the default disposition makes the process die quietly with
/// SIGPIPE instead, which is what every other CLI does and what a shell
/// pipeline expects.
#[cfg(unix)]
fn restore_default_sigpipe() {
    unsafe extern "C" {
        fn signal(signum: core::ffi::c_int, handler: usize) -> usize;
    }
    const SIGPIPE: core::ffi::c_int = 13;
    const SIG_DFL: usize = 0;
    // SAFETY: resetting a signal to its default disposition is async-signal-safe.
    unsafe {
        signal(SIGPIPE, SIG_DFL);
    }
}

fn main() {
    #[cfg(unix)]
    restore_default_sigpipe();

    let cli = Cli::parse();

    let exit_code = match cli.command {
        Commands::Scan(args) => commands::scan::execute_scan(args),
        Commands::Run(args) => commands::run::execute_run(args),
        Commands::Hook(args) => commands::hook::execute_hook(args),
        Commands::Lock(args) => commands::lock::execute_lock(args),
        Commands::Rules(args) => commands::rules::execute_rules(args),
    };

    std::process::exit(exit_code);
}
