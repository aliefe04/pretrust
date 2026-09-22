use anstream::{eprintln, println};
use anstyle::{AnsiColor, Color, Style};
use pretrust_core::report::model::{Action, Finding, Severity};
use pretrust_core::report::json::ReportSummary;
use pretrust_core::lock::LockVerification;

pub const BOLD: Style = Style::new().bold();
pub const DIM: Style = Style::new().dimmed();
pub const RED: Style = Style::new().fg_color(Some(Color::Ansi(AnsiColor::Red))).bold();
pub const YELLOW: Style = Style::new().fg_color(Some(Color::Ansi(AnsiColor::Yellow))).bold();
pub const GREEN: Style = Style::new().fg_color(Some(Color::Ansi(AnsiColor::Green))).bold();
pub const CYAN: Style = Style::new().fg_color(Some(Color::Ansi(AnsiColor::Cyan)));
pub const MAGENTA: Style = Style::new().fg_color(Some(Color::Ansi(AnsiColor::Magenta))).bold();

pub fn severity_badge(severity: Severity) -> String {
    match severity {
        Severity::Critical => format!("{RED}[CRITICAL]{RED:#}"),
        Severity::High => format!("{RED}[HIGH]{RED:#}"),
        Severity::Medium => format!("{YELLOW}[MEDIUM]{YELLOW:#}"),
        Severity::Low => format!("{CYAN}[LOW]{CYAN:#}"),
        Severity::Info => format!("{DIM}[INFO]{DIM:#}"),
    }
}

pub fn print_finding(f: &Finding) {
    print_finding_to(f, false);
}

pub fn print_finding_to(f: &Finding, to_stderr: bool) {
    let badge = severity_badge(f.severity);
    let loc = match f.line {
        Some(line) => format!("{}:{}", f.file_path, line),
        None => f.file_path.clone(),
    };

    let line1 = format!("{badge} {BOLD}{}{BOLD:#} {DIM}({}){DIM:#}", f.rule_name, f.id);
    let line2 = format!("  {DIM}Location:{DIM:#} {CYAN}{loc}{CYAN:#}");
    let line3 = format!("  {DIM}Message:{DIM:#}  {}", f.message);

    let action_line = match f.action {
        Action::NeutralizableViaEnv => {
            format!("  {DIM}Action:{DIM:#}   {GREEN}Neutralizable via 'pretrust run'{GREEN:#}")
        }
        Action::RequiresManualRemediation => {
            format!("  {DIM}Action:{DIM:#}   {RED}BLOCKING: Requires manual remediation{RED:#}")
        }
        Action::WarnOnly => {
            format!("  {DIM}Action:{DIM:#}   {DIM}Advisory warning{DIM:#}")
        }
    };
    let fix_line = format!("  {DIM}Fix:{DIM:#}      {DIM}{}{DIM:#}\n", f.remediation);

    if to_stderr {
        eprintln!("{line1}");
        eprintln!("{line2}");
        eprintln!("{line3}");
        if let Some(val) = &f.value {
            eprintln!("  {DIM}Payload:{DIM:#}  {YELLOW}{val}{YELLOW:#}");
        }
        eprintln!("{action_line}");
        eprintln!("{fix_line}");
    } else {
        println!("{line1}");
        println!("{line2}");
        println!("{line3}");
        if let Some(val) = &f.value {
            println!("  {DIM}Payload:{DIM:#}  {YELLOW}{val}{YELLOW:#}");
        }
        println!("{action_line}");
        println!("{fix_line}");
    }
}
pub fn print_summary(summary: &ReportSummary, elapsed_ms: u128) {
    println!("{BOLD}Scan Summary ({elapsed_ms}ms):{BOLD:#}");
    if summary.total == 0 {
        println!("  {GREEN}✓ No pre-trust vulnerabilities detected{GREEN:#}\n");
        return;
    }

    println!(
        "  Findings: {} total ({} critical, {} high, {} medium, {} low)",
        summary.total,
        if summary.critical > 0 { format!("{RED}{}{RED:#}", summary.critical) } else { "0".into() },
        if summary.high > 0 { format!("{RED}{}{RED:#}", summary.high) } else { "0".into() },
        if summary.medium > 0 { format!("{YELLOW}{}{YELLOW:#}", summary.medium) } else { "0".into() },
        summary.low,
    );

    if summary.blocking_run > 0 {
        println!(
            "  {RED}⚠ {} finding(s) require manual remediation before running agents{RED:#}",
            summary.blocking_run
        );
    } else {
        println!(
            "  {GREEN}✓ All detected sinks can be neutralized automatically via 'pretrust run'{GREEN:#}"
        );
    }
    println!();
}

pub fn print_lock_drift(verification: &LockVerification) {
    if verification.is_clean() {
        println!("{GREEN}✓ pretrust.lock verification passed: all files intact and matching{GREEN:#}");
        return;
    }

    eprintln!("{RED}✗ Drift detected against pretrust.lock:{RED:#}");

    for modif in &verification.modified {
        eprintln!(
            "  {RED}[MODIFIED]{RED:#} {} (hash changed)",
            modif.file_path
        );
    }

    for missing in &verification.missing {
        eprintln!(
            "  {YELLOW}[DELETED]{YELLOW:#}  {} (file removed)",
            missing
        );
    }

    for untracked in &verification.untracked_new {
        eprintln!(
            "  {MAGENTA}[NEW]{MAGENTA:#}      {} (unrecorded agent instruction file)",
            untracked
        );
    }

    eprintln!("\n{DIM}Run 'pretrust lock' to update fingerprints if changes were intentional.{DIM:#}");
}
