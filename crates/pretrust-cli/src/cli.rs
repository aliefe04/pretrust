use std::path::PathBuf;
use clap::{Args, Parser, Subcommand, ValueEnum};
use pretrust_core::report::model::Severity;

#[derive(Parser, Debug)]
#[command(
    name = "pretrust",
    author = "Ali Efe Çakıcı <efe@aecapi.com>",
    version,
    about = "Zero-dependency pre-trust execution guard for AI coding agents",
    long_about = "Pretrust inspects repositories for pre-trust execution sinks (GitSpawn, Plugin4Shell, task auto-runs) and provides an execution-time runtime wrapper that neutralizes hostile configurations."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Static pre-trust vulnerability and provenance scanner
    Scan(ScanArgs),

    /// Process-level execution wrapper with environment hardening
    Run(RunArgs),

    /// Native JSON hook adapter for coding agents (Claude Code, Cursor, Codex, Copilot)
    Hook(HookArgs),

    /// Generate or verify pretrust.lock fingerprint of agent instructions & hooks
    Lock(LockArgs),

    /// List detection rules catalog
    Rules(RulesArgs),
}

#[derive(Args, Debug)]
pub struct RulesArgs {
    /// Output machine-readable JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct ScanArgs {
    /// Path to repository or workspace to scan (defaults to current directory)
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Output machine-readable JSON format
    #[arg(long, conflicts_with = "sarif")]
    pub json: bool,

    /// Output OASIS SARIF 2.1.0 format for GitHub Code Scanning
    #[arg(long, conflicts_with = "json")]
    pub sarif: bool,

    /// Minimum severity level that triggers exit code 1 (info, low, medium, high, critical)
    #[arg(long, default_value = "high")]
    pub fail_on: SeverityLevel,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeverityLevel {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl From<SeverityLevel> for Severity {
    fn from(lvl: SeverityLevel) -> Self {
        match lvl {
            SeverityLevel::Info => Severity::Info,
            SeverityLevel::Low => Severity::Low,
            SeverityLevel::Medium => Severity::Medium,
            SeverityLevel::High => Severity::High,
            SeverityLevel::Critical => Severity::Critical,
        }
    }
}

#[derive(Args, Debug)]
pub struct RunArgs {
    /// Allow execution even if unneutralizable sinks (such as url.*.insteadOf) are detected
    #[arg(long)]
    pub allow_sinks: bool,

    /// Target agent command to execute inside the hardened environment
    #[arg(required = true, last = true)]
    pub command: Vec<String>,
}

#[derive(Args, Debug)]
pub struct HookArgs {
    /// Agent harness to adapt hook for
    #[arg(value_enum)]
    pub harness: AgentHarness,

    /// Fail closed on any detected finding, blocking execution
    #[arg(long)]
    pub strict: bool,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentHarness {
    Claude,
    Cursor,
    Codex,
    Copilot,
}

#[derive(Args, Debug)]
pub struct LockArgs {
    /// Verify current workspace files against existing pretrust.lock without modifying it
    #[arg(long)]
    pub check: bool,

    /// Path to repository root (defaults to current directory)
    #[arg(default_value = ".")]
    pub path: PathBuf,
}
