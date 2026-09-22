use std::io::{self, Read};
use std::path::Path;
use serde_json::Value;
use pretrust_core::report::model::Severity;
use crate::cli::{AgentHarness, HookArgs};

pub fn execute_hook(args: HookArgs) -> i32 {
    let mut stdin_buffer = String::new();
    let _ = io::stdin().read_to_string(&mut stdin_buffer);

    let parsed_payload: Option<Value> = if stdin_buffer.trim().is_empty() {
        None
    } else {
        serde_json::from_str(&stdin_buffer).ok()
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
            let mut command_to_check = None;
            if let Some(payload) = &parsed_payload {
                if let Some(tool_input) = payload.get("tool_input") {
                    if let Some(cmd) = tool_input.get("command").and_then(|v| v.as_str()) {
                        command_to_check = Some(cmd.to_string());
                    }
                }
            }

            let is_git_command = command_to_check
                .as_deref()
                .map(|cmd| cmd.contains("git ") || cmd.starts_with("git"))
                .unwrap_or(true);

            if should_block && is_git_command {
                anstream::eprintln!(
                    "Pretrust Hook [Claude]: Blocked git execution due to {} detected sink(s) in repository.",
                    findings.len()
                );
                for f in findings.iter().filter(|f| f.severity >= Severity::High) {
                    anstream::eprintln!(" - [{}]: {} ({})", f.severity, f.rule_name, f.message);
                }
                anstream::eprintln!("Run via 'pretrust run -- claude' to neutralize or remediate the findings.");
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
