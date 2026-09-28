use crate::git::config::resolve_git_dirs;
use crate::report::model::{Action, Category, Finding, Severity};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Default, Clone)]
pub struct BoundDrivers {
    pub filters: HashSet<String>,
    pub diffs: HashSet<String>,
    pub merges: HashSet<String>,
}

pub fn parse_attributes_file(path: &Path) -> BoundDrivers {
    let mut drivers = BoundDrivers::default();
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return drivers,
    };

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        // parts[0] is pattern, remaining parts are attributes
        for attr in &parts[1..] {
            if let Some((k, v)) = attr.split_once('=') {
                match k.to_ascii_lowercase().as_str() {
                    "filter" => {
                        drivers.filters.insert(v.to_ascii_lowercase());
                    }
                    "diff" => {
                        drivers.diffs.insert(v.to_ascii_lowercase());
                    }
                    "merge" => {
                        drivers.merges.insert(v.to_ascii_lowercase());
                    }
                    _ => {}
                }
            }
        }
    }

    drivers
}

pub fn collect_repo_attributes(repo_root: &Path) -> (BoundDrivers, Vec<PathBuf>) {
    let mut combined = BoundDrivers::default();
    let mut attribute_files = Vec::new();

    // 1. Root .gitattributes
    let root_attr = repo_root.join(".gitattributes");
    if root_attr.is_file() {
        let d = parse_attributes_file(&root_attr);
        combined.filters.extend(d.filters);
        combined.diffs.extend(d.diffs);
        combined.merges.extend(d.merges);
        attribute_files.push(root_attr);
    }

    // 2. .git/info/attributes
    if let Some(git_dirs) = resolve_git_dirs(repo_root) {
        let info_attr = git_dirs.git_dir.join("info").join("attributes");
        if info_attr.is_file() {
            let d = parse_attributes_file(&info_attr);
            combined.filters.extend(d.filters);
            combined.diffs.extend(d.diffs);
            combined.merges.extend(d.merges);
            attribute_files.push(info_attr);
        }
    }

    (combined, attribute_files)
}

#[derive(Debug, Clone)]
pub struct DefinedDriver {
    pub kind: DriverKind,
    pub name: String,
    pub key: String,
    pub command: String,
    pub config_file: PathBuf,
    pub line: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverKind {
    Filter,
    Diff,
    Merge,
}

pub fn extract_defined_drivers(repo_root: &Path) -> Vec<DefinedDriver> {
    let mut defined = Vec::new();
    let git_dirs = match resolve_git_dirs(repo_root) {
        Some(d) => d,
        None => return defined,
    };

    for config_path in &git_dirs.config_paths {
        let raw = match fs::read_to_string(config_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let mut current_section = String::new();
        let mut current_subsection: Option<String> = None;

        for (idx, raw_line) in raw.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }

            if line.starts_with('[') && line.ends_with(']') {
                let inside = &line[1..line.len() - 1].trim();
                if let Some((sec, sub)) = inside.split_once(' ') {
                    current_section = sec.trim().to_ascii_lowercase();
                    current_subsection = Some(sub.trim().trim_matches('"').to_ascii_lowercase());
                } else {
                    current_section = inside.to_ascii_lowercase();
                    current_subsection = None;
                }
                continue;
            }

            if let Some((k, v)) = line.split_once('=') {
                let key = k.trim().to_ascii_lowercase();
                let val = v.trim().trim_matches('"').to_string();

                if let Some(sub) = &current_subsection {
                    let kind = match current_section.as_str() {
                        "filter" => Some(DriverKind::Filter),
                        "diff" => Some(DriverKind::Diff),
                        "merge" => Some(DriverKind::Merge),
                        _ => None,
                    };

                    if let Some(k_kind) = kind {
                        defined.push(DefinedDriver {
                            kind: k_kind,
                            name: sub.clone(),
                            key: format!("{}.{}.{}", current_section, sub, key),
                            command: val,
                            config_file: config_path.clone(),
                            line: Some(idx + 1),
                        });
                    }
                }
            }
        }
    }

    defined
}

fn is_allowlisted_driver(name: &str, cmd: &str) -> bool {
    let trimmed_cmd = cmd.trim();
    if name == "lfs" {
        return trimmed_cmd.starts_with("git-lfs") || trimmed_cmd.contains("git-lfs ");
    }
    false
}

pub fn scan_attributes_and_drivers(repo_root: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let (bound, _attr_files) = collect_repo_attributes(repo_root);
    let defined = extract_defined_drivers(repo_root);

    for driver in defined {
        if is_allowlisted_driver(&driver.name, &driver.command) {
            continue;
        }

        let is_bound = match driver.kind {
            DriverKind::Filter => bound.filters.contains(&driver.name),
            DriverKind::Diff => bound.diffs.contains(&driver.name),
            DriverKind::Merge => bound.merges.contains(&driver.name),
        };

        let rel_file = if let Ok(rel) = driver.config_file.strip_prefix(repo_root) {
            rel.to_string_lossy().to_string()
        } else {
            driver.config_file.to_string_lossy().to_string()
        };

        if is_bound {
            findings.push(Finding {
                id: "PT-GIT-020".into(),
                rule_name: "GitActiveAttributeDriverJoin".into(),
                severity: Severity::High,
                category: Category::GitExecutionSink,
                message: format!(
                    "Active driver '{}' bound in .gitattributes executes custom command: '{}'",
                    driver.name, driver.command
                ),
                file_path: rel_file,
                line: driver.line,
                key: Some(driver.key),
                value: Some(driver.command),
                action: Action::NeutralizableViaEnv,
                remediation: "Verify driver command trustworthiness or use 'pretrust run'.".into(),
            });
        } else {
            findings.push(Finding {
                id: "PT-GIT-021".into(),
                rule_name: "GitDormantAttributeDriver".into(),
                severity: Severity::Low,
                category: Category::GitExecutionSink,
                message: format!(
                    "Dormant driver '{}' defined in git config but not currently bound in .gitattributes",
                    driver.name
                ),
                file_path: rel_file,
                line: driver.line,
                key: Some(driver.key),
                value: Some(driver.command),
                action: Action::NeutralizableViaEnv,
                remediation: "Remove unused driver configurations to reduce attack surface.".into(),
            });
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_attributes_selector_executor_join() {
        let dir = tempdir().unwrap();
        let dot_git = dir.path().join(".git");
        fs::create_dir_all(&dot_git).unwrap();

        fs::write(
            dir.path().join(".gitattributes"),
            "*.secret filter=crypto diff=custom\n",
        )
        .unwrap();

        fs::write(
            dot_git.join("config"),
            r#"
[filter "crypto"]
    clean = "encrypt.sh"
[filter "dormant"]
    clean = "dormant.sh"
[filter "lfs"]
    clean = "git-lfs clean -- %f"
"#,
        )
        .unwrap();

        let findings = scan_attributes_and_drivers(dir.path());

        let active = findings
            .iter()
            .find(|f| f.rule_name == "GitActiveAttributeDriverJoin")
            .expect("active driver");
        assert_eq!(active.severity, Severity::High);
        assert!(active.message.contains("crypto"));

        let dormant = findings
            .iter()
            .find(|f| f.rule_name == "GitDormantAttributeDriver")
            .expect("dormant driver");
        assert_eq!(dormant.severity, Severity::Low);
        assert!(dormant.message.contains("dormant"));

        // git-lfs allowlisted
        assert!(findings.iter().all(|f| !f.message.contains("lfs")));
    }
}
