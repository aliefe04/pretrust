use crate::cli::{AgentHarness, HookArgs};
use pretrust_core::report::model::Severity;
use serde_json::Value;
use std::io::{self, Read};
use std::path::Path;

pub fn execute_hook(args: HookArgs) -> i32 {
    let mut stdin_buffer = String::new();
    if io::stdin().read_to_string(&mut stdin_buffer).is_err() {
        if args.harness == AgentHarness::Cursor {
            let response = serde_json::json!({
                "permission": "deny",
                "user_message": "Pretrust blocked execution: failed to read stdin payload"
            });
            println!("{response}");
        } else {
            anstream::eprintln!("Pretrust Hook: Failed to read stdin payload");
        }
        return 2;
    }

    let _parsed_payload: Option<Value> = if stdin_buffer.trim().is_empty() {
        None
    } else {
        match serde_json::from_str(&stdin_buffer) {
            Ok(v) => Some(v),
            Err(e) => {
                if args.harness == AgentHarness::Cursor {
                    let response = serde_json::json!({
                        "permission": "deny",
                        "user_message": format!("Pretrust blocked execution: invalid JSON payload on stdin: {e}")
                    });
                    println!("{response}");
                } else {
                    anstream::eprintln!("Pretrust Hook: Invalid JSON payload on stdin: {e}");
                }
                return 2;
            }
        }
    };

    let repo_root = Path::new(".");
    let findings = pretrust_core::scan_workspace(repo_root);

    let has_critical = findings.iter().any(|f| f.severity == Severity::Critical);
    let has_blocking = findings.iter().any(|f| f.is_blocking_for_run());
    let has_high = findings.iter().any(|f| f.severity >= Severity::High);

    let should_block = if args.strict {
        has_high || has_critical || has_blocking
    } else {
        has_critical || has_blocking
    };

    match args.harness {
        AgentHarness::Claude => {
            // Claude Code PreToolUse hook convention
            if should_block {
                anstream::eprintln!(
                    "Pretrust Hook [Claude]: Blocked execution due to {} detected sink(s) in repository.",
                    findings.len()
                );
                for f in findings.iter().filter(|f| f.severity >= Severity::High) {
                    anstream::eprintln!(" - [{}]: {} ({})", f.severity, f.rule_name, f.message);
                }
                anstream::eprintln!(
                    "Run via 'pretrust run -- claude' to neutralize or remediate the findings."
                );
                2
            } else {
                0
            }
        }
        AgentHarness::Cursor => {
            // Cursor beforeShellExecution hook convention
            if should_block {
                let response = serde_json::json!({
                    "permission": "deny",
                    "user_message": format!(
                        "Pretrust blocked execution: detected {} active execution sink(s) in repository.",
                        findings.len()
                    )
                });
                println!("{response}");
                2
            } else {
                let response = serde_json::json!({
                    "permission": "allow"
                });
                println!("{response}");
                0
            }
        }
        AgentHarness::Codex | AgentHarness::Copilot => {
            if should_block {
                anstream::eprintln!(
                    "Pretrust Hook [{}]: Refusing execution in unsafe repository environment.",
                    match args.harness {
                        AgentHarness::Codex => "Codex",
                        _ => "Copilot",
                    }
                );
                2
            } else {
                0
            }
        }
    }
}
