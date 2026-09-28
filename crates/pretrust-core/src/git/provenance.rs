use crate::git::config::resolve_git_dirs;
use crate::report::model::{Action, Category, Finding, Severity};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvenanceKind {
    NormalClone,
    AssembledArchive,
    ShallowOrPartial,
}

#[derive(Debug, Clone)]
pub struct ProvenanceReport {
    pub kind: ProvenanceKind,
    pub has_reflog: bool,
    pub has_remotes: bool,
    pub has_packfiles: bool,
    pub findings: Vec<Finding>,
}

pub fn check_provenance(repo_root: &Path) -> ProvenanceReport {
    let git_dirs = match resolve_git_dirs(repo_root) {
        Some(d) => d,
        None => {
            return ProvenanceReport {
                kind: ProvenanceKind::NormalClone,
                has_reflog: false,
                has_remotes: false,
                has_packfiles: false,
                findings: Vec::new(),
            };
        }
    };

    let logs_head = git_dirs.git_dir.join("logs").join("HEAD");
    let has_reflog = logs_head.is_file()
        && fs::metadata(&logs_head)
            .map(|m| m.len() > 0)
            .unwrap_or(false);

    let remotes_dir = git_dirs.git_dir.join("refs").join("remotes");
    let has_remotes = if remotes_dir.is_dir() {
        fs::read_dir(&remotes_dir)
            .map(|mut it| it.next().is_some())
            .unwrap_or(false)
    } else {
        false
    };

    let pack_dir = git_dirs.git_dir.join("objects").join("pack");
    let has_packfiles = if pack_dir.is_dir() {
        if let Ok(entries) = fs::read_dir(&pack_dir) {
            entries.filter_map(|e| e.ok()).any(|e| {
                e.path()
                    .extension()
                    .map(|ext| ext == "pack")
                    .unwrap_or(false)
            })
        } else {
            false
        }
    } else {
        false
    };

    let mut findings = Vec::new();
    let kind = if !has_reflog && !has_remotes {
        findings.push(Finding {
            id: "PT-PROV-001".into(),
            rule_name: "GitProvenanceAssembledArchive".into(),
            severity: Severity::Medium,
            category: Category::RepositoryProvenance,
            message: "Repository lacks reflog history and remote tracking branches; likely an assembled archive or zip extraction".into(),
            file_path: ".git".into(),
            line: None,
            key: None,
            value: None,
            action: Action::WarnOnly,
            remediation: "Verify repository origin and provenance before allowing automated agent execution.".into(),
        });
        ProvenanceKind::AssembledArchive
    } else {
        ProvenanceKind::NormalClone
    };

    ProvenanceReport {
        kind,
        has_reflog,
        has_remotes,
        has_packfiles,
        findings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_assembled_archive_detected() {
        let dir = tempdir().unwrap();
        let dot_git = dir.path().join(".git");
        fs::create_dir_all(&dot_git).unwrap();
        fs::write(dot_git.join("config"), "[core]\nbare = false\n").unwrap();

        let report = check_provenance(dir.path());
        assert_eq!(report.kind, ProvenanceKind::AssembledArchive);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(
            report.findings[0].rule_name,
            "GitProvenanceAssembledArchive"
        );
    }

    #[test]
    fn test_normal_clone_detected() {
        let dir = tempdir().unwrap();
        let dot_git = dir.path().join(".git");
        let logs_dir = dot_git.join("logs");
        fs::create_dir_all(&logs_dir).unwrap();
        fs::write(
            logs_dir.join("HEAD"),
            "00000000 11111111 User <user@example.com> clone\n",
        )
        .unwrap();

        let remotes_dir = dot_git.join("refs").join("remotes").join("origin");
        fs::create_dir_all(&remotes_dir).unwrap();
        fs::write(remotes_dir.join("main"), "11111111\n").unwrap();

        let report = check_provenance(dir.path());
        assert_eq!(report.kind, ProvenanceKind::NormalClone);
        assert!(report.findings.is_empty());
    }
}
