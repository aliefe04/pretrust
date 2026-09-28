use crate::cli::ScanArgs;
use crate::ui::{print_finding, print_summary};
use pretrust_core::report::json::JsonReport;
use pretrust_core::report::model::Severity;
use pretrust_core::report::sarif::to_sarif_string;
use std::time::Instant;

pub fn execute_scan(args: ScanArgs) -> i32 {
    let target_path = &args.path;
    if !target_path.exists() {
        anstream::eprintln!(
            "Error: Target path does not exist: {}",
            target_path.display()
        );
        return 2;
    }

    let start = Instant::now();
    let findings = pretrust_core::scan_workspace(target_path);
    let elapsed = start.elapsed().as_millis();

    if args.json {
        let abs_path = target_path
            .canonicalize()
            .unwrap_or_else(|_| target_path.to_path_buf())
            .to_string_lossy()
            .to_string();

        let report = JsonReport::new(abs_path, findings.clone());
        match report.to_json_string(true) {
            Ok(json) => println!("{json}"),
            Err(e) => {
                anstream::eprintln!("Failed to serialize JSON report: {e}");
                return 2;
            }
        }
    } else if args.sarif {
        match to_sarif_string(&findings, true) {
            Ok(sarif) => println!("{sarif}"),
            Err(e) => {
                anstream::eprintln!("Failed to serialize SARIF report: {e}");
                return 2;
            }
        }
    } else {
        anstream::println!("Scanning workspace at '{}'...\n", target_path.display());
        for f in &findings {
            print_finding(f);
        }

        let summary = pretrust_core::report::json::ReportSummary::from_findings(&findings);
        print_summary(&summary, elapsed);
    }

    let threshold: Severity = args.fail_on.into();
    let should_fail = findings.iter().any(|f| f.severity >= threshold);

    if should_fail { 1 } else { 0 }
}
