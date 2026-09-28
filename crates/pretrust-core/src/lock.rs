use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use crate::report::model::{Action, Category, Finding, Severity};

pub const LOCKFILE_NAME: &str = "pretrust.lock";
pub const LOCKFILE_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Lockfile {
    pub version: u32,
    pub files: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockDrift {
    pub file_path: String,
    pub expected_sha256: String,
    pub actual_sha256: String,
}

#[derive(Debug, Clone, Default)]
pub struct LockVerification {
    pub matched: Vec<String>,
    pub modified: Vec<LockDrift>,
    pub missing: Vec<String>,
    pub untracked_new: Vec<String>,
}

impl LockVerification {
    pub fn is_clean(&self) -> bool {
        self.modified.is_empty() && self.missing.is_empty() && self.untracked_new.is_empty()
    }

    pub fn to_findings(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        for modif in &self.modified {
            findings.push(Finding {
                id: "PT-LOCK-001".into(),
                rule_name: "LockfileHashMismatch".into(),
                severity: Severity::Critical,
                category: Category::PromptInjection,
                message: format!(
                    "File '{}' has been modified since pretrust.lock was generated (drift detected)",
                    modif.file_path
                ),
                file_path: modif.file_path.clone(),
                line: None,
                key: None,
                value: Some(format!("expected: {}, actual: {}", modif.expected_sha256, modif.actual_sha256)),
                action: Action::RequiresManualRemediation,
                remediation: "Review file changes for unauthorized tampering and run 'pretrust lock' to update.".into(),
            });
        }

        for missing in &self.missing {
            findings.push(Finding {
                id: "PT-LOCK-002".into(),
                rule_name: "LockfileMissingFile".into(),
                severity: Severity::High,
                category: Category::PromptInjection,
                message: format!(
                    "Locked file '{}' was deleted from repository",
                    missing
                ),
                file_path: missing.clone(),
                line: None,
                key: None,
                value: None,
                action: Action::WarnOnly,
                remediation: "Re-add missing file or run 'pretrust lock' to update fingerprint.".into(),
            });
        }

        for new_file in &self.untracked_new {
            findings.push(Finding {
                id: "PT-LOCK-003".into(),
                rule_name: "LockfileUntrackedNewFile".into(),
                severity: Severity::High,
                category: Category::PromptInjection,
                message: format!(
                    "New unrecorded agent instruction/hook file introduced: '{}'",
                    new_file
                ),
                file_path: new_file.clone(),
                line: None,
                key: None,
                value: None,
                action: Action::RequiresManualRemediation,
                remediation: "Verify newly added agent instructions and run 'pretrust lock' to lock them.".into(),
            });
        }

        findings
    }
}

pub fn compute_file_sha256(path: &Path) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Some(format!("{:x}", hasher.finalize()))
}

pub fn collect_lockable_files(repo_root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();

    for rel in crate::agent::AGENT_CONFIG_RELATIVE_PATHS {
        let p = repo_root.join(rel);
        if p.is_file() {
            files.push(p);
        }
    }

    let cursor_rules_dir = repo_root.join(".cursor").join("rules");
    if cursor_rules_dir.is_dir() {
        if let Ok(entries) = fs::read_dir(&cursor_rules_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    files.push(path);
                }
            }
        }
    }

    files.sort();
    files
}

pub fn generate_lockfile(repo_root: &Path) -> Lockfile {
    let mut files_map = BTreeMap::new();
    let lockables = collect_lockable_files(repo_root);

    for path in lockables {
        if let Some(hash) = compute_file_sha256(&path) {
            let rel = if let Ok(r) = path.strip_prefix(repo_root) {
                r.to_string_lossy().to_string()
            } else {
                path.to_string_lossy().to_string()
            };
            files_map.insert(rel, hash);
        }
    }

    Lockfile {
        version: LOCKFILE_VERSION,
        files: files_map,
    }
}

pub fn write_lockfile(repo_root: &Path, lockfile: &Lockfile) -> std::io::Result<()> {
    let path = repo_root.join(LOCKFILE_NAME);
    let json = serde_json::to_string_pretty(lockfile)?;
    fs::write(path, format!("{json}\n"))
}

pub fn read_lockfile(repo_root: &Path) -> Option<Lockfile> {
    let path = repo_root.join(LOCKFILE_NAME);
    let content = fs::read_to_string(path).ok()?;
    serde_json::from_str(&content).ok()
}

pub fn verify_lockfile(repo_root: &Path) -> Option<LockVerification> {
    let lockfile = match read_lockfile(repo_root) {
        Some(l) => l,
        None => return None,
    };

    let current_lockables = collect_lockable_files(repo_root);
    let mut current_map = BTreeMap::new();
    for path in current_lockables {
        if let Some(hash) = compute_file_sha256(&path) {
            let rel = if let Ok(r) = path.strip_prefix(repo_root) {
                r.to_string_lossy().to_string()
            } else {
                path.to_string_lossy().to_string()
            };
            current_map.insert(rel, hash);
        }
    }

    let mut result = LockVerification::default();

    // Check locked files
    for (rel_path, expected_hash) in &lockfile.files {
        match current_map.get(rel_path) {
            Some(actual_hash) => {
                if actual_hash == expected_hash {
                    result.matched.push(rel_path.clone());
                } else {
                    result.modified.push(LockDrift {
                        file_path: rel_path.clone(),
                        expected_sha256: expected_hash.clone(),
                        actual_sha256: actual_hash.clone(),
                    });
                }
            }
            None => {
                result.missing.push(rel_path.clone());
            }
        }
    }

    // Check for untracked new files
    for rel_path in current_map.keys() {
        if !lockfile.files.contains_key(rel_path) {
            result.untracked_new.push(rel_path.clone());
        }
    }

    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_lockfile_generation_and_drift_verification() {
        let dir = tempdir().unwrap();

        fs::write(dir.path().join("AGENTS.md"), "Version 1 instructions\n").unwrap();
        fs::write(dir.path().join(".cursorrules"), "Rules v1\n").unwrap();

        let lock = generate_lockfile(dir.path());
        assert_eq!(lock.files.len(), 2);
        assert!(lock.files.contains_key("AGENTS.md"));
        assert!(lock.files.contains_key(".cursorrules"));

        write_lockfile(dir.path(), &lock).unwrap();

        // 1. Clean verification
        let check = verify_lockfile(dir.path()).unwrap();
        assert!(check.is_clean());
        assert_eq!(check.matched.len(), 2);

        // 2. Tampering / drift
        fs::write(dir.path().join(".cursorrules"), "Rules v1 modified with prompt injection\n").unwrap();

        let check2 = verify_lockfile(dir.path()).unwrap();
        assert!(!check2.is_clean());
        assert_eq!(check2.modified.len(), 1);
        assert_eq!(check2.modified[0].file_path, ".cursorrules");

        let findings = check2.to_findings();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_name, "LockfileHashMismatch");
        assert_eq!(findings[0].severity, Severity::Critical);
    }
}
