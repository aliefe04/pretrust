use crate::agent::{format_rel_path, make_unreadable_finding};
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

pub fn collect_repo_attributes(repo_root: &Path) -> (BoundDrivers, Vec<PathBuf>) {
    collect_repo_attributes_with_findings(repo_root, &mut Vec::new())
}

fn collect_repo_attributes_with_findings(
    repo_root: &Path,
    findings: &mut Vec<Finding>,
) -> (BoundDrivers, Vec<PathBuf>) {
    let mut combined = BoundDrivers::default();
    let mut attribute_files = Vec::new();
    let mut inspected = HashSet::new();

    let root_attr = repo_root.join(".gitattributes");
    collect_attribute_file(
        repo_root,
        &root_attr,
        &mut inspected,
        &mut combined,
        &mut attribute_files,
        findings,
    );

    if let Some(git_dirs) = resolve_git_dirs(repo_root) {
        let info_attr = git_dirs.git_dir.join("info").join("attributes");
        collect_attribute_file(
            repo_root,
            &info_attr,
            &mut inspected,
            &mut combined,
            &mut attribute_files,
            findings,
        );
    }

    (combined, attribute_files)
}

fn collect_attribute_file(
    repo_root: &Path,
    path: &Path,
    inspected: &mut HashSet<PathBuf>,
    combined: &mut BoundDrivers,
    attribute_files: &mut Vec<PathBuf>,
    findings: &mut Vec<Finding>,
) {
    if fs::symlink_metadata(path).is_err() {
        return;
    }
    let identity = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    if !inspected.insert(identity) {
        return;
    }
    let content = match fs::read(path) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(content) => content,
            Err(_) => {
                findings.push(make_unreadable_finding(repo_root, path));
                return;
            }
        },
        Err(_) => {
            findings.push(make_unreadable_finding(repo_root, path));
            return;
        }
    };
    let d = parse_attributes_content(&content);
    combined.filters.extend(d.filters);
    combined.diffs.extend(d.diffs);
    combined.merges.extend(d.merges);
    attribute_files.push(path.to_path_buf());
}

pub fn parse_attributes_file(path: &Path) -> BoundDrivers {
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(_) => return BoundDrivers::default(),
    };
    parse_attributes_content(&content)
}

fn parse_attributes_content(content: &str) -> BoundDrivers {
    let mut drivers = BoundDrivers::default();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

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
    extract_defined_drivers_with_findings(repo_root, &mut Vec::new())
}

fn extract_defined_drivers_with_findings(
    repo_root: &Path,
    findings: &mut Vec<Finding>,
) -> Vec<DefinedDriver> {
    let mut defined = Vec::new();
    let git_dirs = match resolve_git_dirs(repo_root) {
        Some(d) => d,
        None => return defined,
    };

    for config_path in &git_dirs.config_paths {
        let raw = match fs::read_to_string(config_path) {
            Ok(c) => c,
            Err(_) => {
                findings.push(make_unreadable_finding(repo_root, config_path));
                continue;
            }
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
                    current_subsection = Some(sub.trim().trim_matches('"').to_string());
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
    if name.eq_ignore_ascii_case("lfs") {
        return trimmed_cmd.starts_with("git-lfs") || trimmed_cmd.contains("git-lfs ");
    }
    false
}

pub fn scan_attributes_and_drivers(repo_root: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let (bound, _attr_files) = collect_repo_attributes_with_findings(repo_root, &mut findings);
    let defined = extract_defined_drivers_with_findings(repo_root, &mut findings);

    for driver in defined {
        if is_allowlisted_driver(&driver.name, &driver.command) {
            continue;
        }

        let is_bound = match driver.kind {
            DriverKind::Filter => {
                bound.filters.contains(&driver.name)
                    || bound.filters.contains(&driver.name.to_ascii_lowercase())
            }
            DriverKind::Diff => {
                bound.diffs.contains(&driver.name)
                    || bound.diffs.contains(&driver.name.to_ascii_lowercase())
            }
            DriverKind::Merge => {
                bound.merges.contains(&driver.name)
                    || bound.merges.contains(&driver.name.to_ascii_lowercase())
            }
        };

        let rel_file = format_rel_path(repo_root, &driver.config_file);

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
