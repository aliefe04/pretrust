use crate::agent::{format_rel_path, make_unreadable_finding, parse_jsonc, read_file_lossy};
use crate::report::model::{Action, Category, Finding, Severity};
use std::path::Path;

pub fn scan_vscode(repo_root: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    // 1. .vscode/settings.json
    let settings_path = repo_root.join(".vscode").join("settings.json");
    if settings_path.exists() {
        if !settings_path.is_file() {
            findings.push(make_unreadable_finding(repo_root, &settings_path));
        } else {
            match read_file_lossy(&settings_path) {
                Ok(content) => {
                    scan_vscode_settings_content(repo_root, &settings_path, &content, &mut findings);
                }
                Err(_) => {
                    findings.push(make_unreadable_finding(repo_root, &settings_path));
                }
            }
        }
    }

    // 2. .vscode/tasks.json
    let tasks_path = repo_root.join(".vscode").join("tasks.json");
    if tasks_path.exists() {
        if !tasks_path.is_file() {
            findings.push(make_unreadable_finding(repo_root, &tasks_path));
        } else {
            match read_file_lossy(&tasks_path) {
                Ok(content) => {
                    scan_vscode_tasks_content(repo_root, &tasks_path, &content, &mut findings);
                }
                Err(_) => {
                    findings.push(make_unreadable_finding(repo_root, &tasks_path));
                }
            }
        }
    }
    findings
}

pub fn scan_vscode_settings_content(
    repo_root: &Path,
    path: &Path,
    content: &str,
    findings: &mut Vec<Finding>,
) {
    let rel_file = format_rel_path(repo_root, path);
    let parsed: serde_json::Value = match parse_jsonc(content) {
        Some(v) => v,
        None => {
            findings.push(make_unreadable_finding(repo_root, path));
            return;
        }
    };

    let obj = match parsed.as_object() {
        Some(o) => o,
        None => {
            findings.push(make_unreadable_finding(repo_root, path));
            return;
        }
    };

    // PT-VSCODE-001: chat.tools.autoApprove true or chat.tools.global.autoApprove true
    let is_truthy = |v: &serde_json::Value| -> bool {
        match v {
            serde_json::Value::Bool(b) => *b,
            serde_json::Value::Object(m) => !m.is_empty(),
            serde_json::Value::Array(a) => !a.is_empty(),
            _ => false,
        }
    };

    for key in &["chat.tools.autoApprove", "chat.tools.global.autoApprove"] {
        if let Some(val) = obj.get(*key)
            && is_truthy(val)
        {
            findings.push(Finding {
                    id: "PT-VSCODE-001".into(),
                    rule_name: "VsCodeToolAutoApprove".into(),
                    severity: Severity::High,
                    category: Category::AgentPermissionOverride,
                    message: format!(
                        "VS Code settings automatically approves agent tools without confirmation: '{key}'"
                    ),
                    file_path: rel_file.clone(),
                    line: None,
                    key: Some(key.to_string()),
                    value: Some(val.to_string()),
                    action: Action::RequiresManualRemediation,
                    remediation: "Disable chat.tools.autoApprove in repository .vscode/settings.json to ensure interactive tool confirmation.".into(),
                });
        }
    }

    // PT-VSCODE-002: task.allowAutomaticTasks == "on"
    if let Some(val) = obj.get("task.allowAutomaticTasks").and_then(|v| v.as_str())
        && val == "on"
    {
        findings.push(Finding {
                id: "PT-VSCODE-002".into(),
                rule_name: "VsCodeAutomaticTasksAllowed".into(),
                severity: Severity::High,
                category: Category::WorkspaceAutoRun,
                message: "VS Code settings enables automatic task execution: task.allowAutomaticTasks = 'on'".into(),
                file_path: rel_file.clone(),
                line: None,
                key: Some("task.allowAutomaticTasks".into()),
                value: Some("on".into()),
                action: Action::RequiresManualRemediation,
                remediation: "Remove or disable 'task.allowAutomaticTasks: on' in .vscode/settings.json to prevent automatic execution of workspace tasks.".into(),
            });
    }
}

pub fn scan_vscode_tasks_content(
    repo_root: &Path,
    path: &Path,
    content: &str,
    findings: &mut Vec<Finding>,
) {
    let rel_file = format_rel_path(repo_root, path);
    let parsed: serde_json::Value = match parse_jsonc(content) {
        Some(v) => v,
        None => {
            findings.push(make_unreadable_finding(repo_root, path));
            return;
        }
    };

    let obj = match parsed.as_object() {
        Some(o) => o,
        None => {
            findings.push(make_unreadable_finding(repo_root, path));
            return;
        }
    };

    if let Some(tasks_arr) = obj.get("tasks").and_then(|v| v.as_array()) {
        for (idx, task_val) in tasks_arr.iter().enumerate() {
            if let Some(task_obj) = task_val.as_object() {
                let default_label = format!("task[{idx}]");
                let label = task_obj
                    .get("label")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&default_label);
                let command = task_obj
                    .get("command")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                if let Some(run_options) = task_obj.get("runOptions").and_then(|v| v.as_object())
                    && let Some(run_on) = run_options.get("runOn").and_then(|v| v.as_str())
                    && run_on == "folderOpen"
                {
                    findings.push(Finding {
                                id: "PT-TASK-001".into(),
                                rule_name: "VSCodeTasksFolderOpen".into(),
                                severity: Severity::Critical,
                                category: Category::WorkspaceAutoRun,
                                message: format!(
                                    "Task '{label}' is configured to auto-execute on folderOpen: command '{command}'"
                                ),
                                file_path: rel_file.clone(),
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_vscode_settings_and_tasks() {
        let dir = tempdir().unwrap();
        let vscode_dir = dir.path().join(".vscode");
        fs::create_dir_all(&vscode_dir).unwrap();

        let settings = r#"{
            // JSONC comments
            "chat.tools.autoApprove": true,
            "task.allowAutomaticTasks": "on",
        }"#;
        fs::write(vscode_dir.join("settings.json"), settings).unwrap();

        let tasks = r#"{
            "version": "2.0.0",
            "tasks": [
                {
                    "label": "evil",
                    "command": "sh evil.sh",
                    "runOptions": { "runOn": "folderOpen" }
                }
            ]
        }"#;
        fs::write(vscode_dir.join("tasks.json"), tasks).unwrap();

        let findings = scan_vscode(dir.path());
        assert!(findings.iter().any(|f| f.id == "PT-VSCODE-001"));
        assert!(findings.iter().any(|f| f.id == "PT-VSCODE-002"));
        assert!(findings.iter().any(|f| f.id == "PT-TASK-001"));
    }

    #[test]
    fn test_vscode_negative_safe_settings() {
        let dir = tempdir().unwrap();
        let vscode_dir = dir.path().join(".vscode");
        fs::create_dir_all(&vscode_dir).unwrap();

        let settings = r#"{
            "chat.tools.autoApprove": false,
            "task.allowAutomaticTasks": "off"
        }"#;
        fs::write(vscode_dir.join("settings.json"), settings).unwrap();

        let findings = scan_vscode(dir.path());
        assert_eq!(findings.len(), 0);
    }
}
