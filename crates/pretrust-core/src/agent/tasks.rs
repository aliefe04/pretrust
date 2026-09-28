use crate::agent::format_rel_path;
use crate::report::model::{Action, Category, Finding, Severity};
use std::fs;
use std::path::Path;

pub fn scan_tasks(repo_root: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    // .cargo/config.toml and .cargo/config
    let cargo_toml = repo_root.join(".cargo").join("config.toml");
    let cargo_bare = repo_root.join(".cargo").join("config");
    if cargo_toml.is_file() {
        if let Ok(content) = fs::read_to_string(&cargo_toml) {
            scan_cargo_config_content(repo_root, &cargo_toml, &content, &mut findings);
        }
    } else if cargo_bare.is_file()
        && let Ok(content) = fs::read_to_string(&cargo_bare)
    {
        scan_cargo_config_content(repo_root, &cargo_bare, &content, &mut findings);
    }

    findings
}

pub fn scan_cargo_config_content(
    repo_root: &Path,
    file_path: &Path,
    content: &str,
    findings: &mut Vec<Finding>,
) {
    let rel_file = format_rel_path(repo_root, file_path);

    let parsed: toml::Table = match toml::from_str(content) {
        Ok(t) => t,
        Err(_) => return,
    };

    // 1. [build] rustc-wrapper
    if let Some(build_tbl) = parsed.get("build").and_then(|v| v.as_table())
        && let Some(wrapper) = build_tbl.get("rustc-wrapper").and_then(|v| v.as_str())
    {
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

    // 2. [target.*] runner
    if let Some(target_tbl) = parsed.get("target").and_then(|v| v.as_table()) {
        for (target_name, target_val) in target_tbl {
            if let Some(target_obj) = target_val.as_table()
                && let Some(runner) = target_obj.get("runner")
            {
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_cargo_config_detection() {
        let dir = tempdir().unwrap();
        let cargo_dir = dir.path().join(".cargo");
        fs::create_dir_all(&cargo_dir).unwrap();

        let cargo_config = r#"
[build]
rustc-wrapper = "/tmp/evil_rustc.sh"

[target.x86_64-unknown-linux-gnu]
runner = "wine"
"#;
        fs::write(cargo_dir.join("config.toml"), cargo_config).unwrap();

        let findings = scan_tasks(dir.path());
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().any(|f| f.rule_name == "CargoRustcWrapper"));
        assert!(findings.iter().any(|f| f.rule_name == "CargoTargetRunner"));
    }
}
