use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for Severity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "info" => Ok(Severity::Info),
            "low" => Ok(Severity::Low),
            "medium" | "med" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" | "crit" => Ok(Severity::Critical),
            other => Err(format!("Unknown severity level: {other}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    GitExecutionSink,
    ConfigurationSmuggling,
    RepositoryProvenance,
    AgentLifecycleHook,
    PromptInjection,
    UnpinnedDependency,
    WorkspaceAutoRun,
}

impl Category {
    pub fn as_str(&self) -> &'static str {
        match self {
            Category::GitExecutionSink => "git_execution_sink",
            Category::ConfigurationSmuggling => "configuration_smuggling",
            Category::RepositoryProvenance => "repository_provenance",
            Category::AgentLifecycleHook => "agent_lifecycle_hook",
            Category::PromptInjection => "prompt_injection",
            Category::UnpinnedDependency => "unpinned_dependency",
            Category::WorkspaceAutoRun => "workspace_auto_run",
        }
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    NeutralizableViaEnv,
    RequiresManualRemediation,
    WarnOnly,
}

impl Action {
    pub fn as_str(&self) -> &'static str {
        match self {
            Action::NeutralizableViaEnv => "neutralizable_via_env",
            Action::RequiresManualRemediation => "requires_manual_remediation",
            Action::WarnOnly => "warn_only",
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub rule_name: String,
    pub severity: Severity,
    pub category: Category,
    pub message: String,
    pub file_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    pub action: Action,
    pub remediation: String,
}

impl Finding {
    pub fn is_blocking_for_run(&self) -> bool {
        self.action == Action::RequiresManualRemediation
    }
}
