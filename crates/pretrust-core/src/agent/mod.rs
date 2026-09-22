pub mod hooks;
pub mod instructions;
pub mod tasks;

use std::path::Path;
use crate::report::model::Finding;

pub fn scan_agent_vectors(repo_root: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(tasks::scan_tasks(repo_root));
    findings.extend(hooks::scan_hooks(repo_root));
    findings.extend(instructions::scan_instructions(repo_root));
    findings
}
