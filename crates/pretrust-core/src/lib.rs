pub mod agent;
pub mod git;
pub mod lock;
pub mod report;

use std::collections::HashSet;
use std::path::Path;

pub use report::model::{Action, Category, Finding, Severity};
pub use report::json::{JsonReport, ReportSummary};
pub use report::sarif::{generate_sarif, to_sarif_string, SarifReport};
pub use report::rules::{all_rules, get_rule, RuleInfo, RulesCatalog, RULES};
pub use git::harden::{build_hardened_env, HardenedEnvironment};
pub use lock::{generate_lockfile, read_lockfile, verify_lockfile, write_lockfile, LockVerification};

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

pub fn scan_workspace(repo_root: &Path) -> Vec<Finding> {
    let mut all_findings = Vec::new();

    // 1. Git config sinks & inclusions
    all_findings.extend(git::config::scan_git_config(repo_root));

    // 2. Gitattributes selector-executor join
    all_findings.extend(git::attributes::scan_attributes_and_drivers(repo_root));

    // 3. Provenance detection
    let prov = git::provenance::check_provenance(repo_root);
    all_findings.extend(prov.findings);

    // 4. Agent vector analysis (tasks, hooks, instructions, mcp)
    all_findings.extend(agent::scan_agent_vectors(repo_root));

    // Deduplicate findings
    let mut seen = HashSet::new();
    let mut deduped = Vec::new();

    for f in all_findings {
        let key = (f.rule_name.clone(), f.file_path.clone(), f.line, f.key.clone());
        if seen.insert(key) {
            deduped.push(f);
        }
    }

    // Sort findings by severity (Critical first) then file path
    deduped.sort_by(|a, b| {
        b.severity.cmp(&a.severity)
            .then_with(|| a.file_path.cmp(&b.file_path))
            .then_with(|| a.line.cmp(&b.line))
    });

    deduped
}
