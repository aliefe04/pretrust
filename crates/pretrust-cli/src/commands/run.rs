use std::path::Path;
use std::process::Command;
use crate::cli::RunArgs;
use crate::ui::{print_finding_to, RED, YELLOW, BOLD};

pub fn execute_run(args: RunArgs) -> i32 {
    let repo_root = Path::new(".");
    let findings = pretrust_core::scan_workspace(repo_root);

    let blocking_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.is_blocking_for_run())
        .collect();

    if !blocking_findings.is_empty() && !args.allow_sinks {
        anstream::eprintln!(
            "\n{RED}PRETRUST SAFETY REFUSAL:{RED:#} Detected {} unneutralizable execution sink(s):\n",
            blocking_findings.len()
        );

        for f in &blocking_findings {
            print_finding_to(f, true);
        }

        anstream::eprintln!(
            "{RED}Refusing to launch agent in hostile environment.{RED:#}"
        );
        anstream::eprintln!(
            "{YELLOW}Hint:{YELLOW:#} Remediation required, or pass '{BOLD}--allow-sinks{BOLD:#}' to bypass at your own risk.\n"
        );
        return 2;
    }

    if args.command.is_empty() {
        anstream::eprintln!("Error: No command specified to run.");
        return 2;
    }

    let program = &args.command[0];
    let program_args = &args.command[1..];

    let hardened_env = pretrust_core::build_hardened_env(repo_root);

    let mut cmd = Command::new(program);
    cmd.args(program_args);
    hardened_env.apply_to_command(&mut cmd);

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = cmd.exec();
        anstream::eprintln!("Failed to execute process '{program}': {err}");
        2
    }

    #[cfg(not(unix))]
    {
        match cmd.spawn().and_then(|mut child| child.wait()) {
            Ok(status) => status.code().unwrap_or(1),
            Err(e) => {
                anstream::eprintln!("Failed to spawn process '{program}': {e}");
                2
            }
        }
    }
}
