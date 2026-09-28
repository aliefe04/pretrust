mod cli;
mod commands;
mod ui;

use clap::Parser;
use cli::{Cli, Commands};

fn main() {
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
