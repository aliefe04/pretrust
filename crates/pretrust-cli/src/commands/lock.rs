use crate::cli::LockArgs;
use crate::ui::{BOLD, DIM, GREEN, print_lock_drift};

pub fn execute_lock(args: LockArgs) -> i32 {
    let repo_root = &args.path;
    if !repo_root.exists() {
        anstream::eprintln!("Error: Target path does not exist: {}", repo_root.display());
        return 2;
    }

    if args.check {
        match pretrust_core::verify_lockfile(repo_root) {
            Some(verification) => {
                print_lock_drift(&verification);
                if verification.is_clean() { 0 } else { 1 }
            }
            None => {
                anstream::eprintln!(
                    "Error: pretrust.lock not found in '{}'. Run 'pretrust lock' to generate it.",
                    repo_root.display()
                );
                1
            }
        }
    } else {
        let lockfile = pretrust_core::generate_lockfile(repo_root);
        let count = lockfile.files.len();

        match pretrust_core::write_lockfile(repo_root, &lockfile) {
            Ok(()) => {
                anstream::println!(
                    "{GREEN}✓ Successfully generated {BOLD}pretrust.lock{BOLD:#} with {count} locked file(s){GREEN:#}"
                );
                for file_path in lockfile.files.keys() {
                    anstream::println!("  {DIM}•{DIM:#} {file_path}");
                }
                0
            }
            Err(e) => {
                anstream::eprintln!("Failed to write pretrust.lock: {e}");
                2
            }
        }
    }
}
