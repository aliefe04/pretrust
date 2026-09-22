use serde::{Deserialize, Serialize};
use crate::report::model::{Finding, Severity};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub blocking_run: usize,
}

impl ReportSummary {
    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut summary = ReportSummary {
            total: findings.len(),
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
            blocking_run: 0,
        };

        for f in findings {
            match f.severity {
                Severity::Critical => summary.critical += 1,
                Severity::High => summary.high += 1,
                Severity::Medium => summary.medium += 1,
                Severity::Low => summary.low += 1,
                Severity::Info => summary.info += 1,
            }

            if f.is_blocking_for_run() {
                summary.blocking_run += 1;
            }
        }

        summary
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonReport {
    pub version: String,
    pub target_path: String,
    pub summary: ReportSummary,
    pub findings: Vec<Finding>,
}

impl JsonReport {
    pub fn new(target_path: String, findings: Vec<Finding>) -> Self {
        let summary = ReportSummary::from_findings(&findings);
        JsonReport {
            version: env!("CARGO_PKG_VERSION").to_string(),
            target_path,
            summary,
            findings,
        }
    }

    pub fn to_json_string(&self, pretty: bool) -> Result<String, serde_json::Error> {
        if pretty {
            serde_json::to_string_pretty(self)
        } else {
            serde_json::to_string(self)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::model::{Action, Category};

    #[test]
    fn test_json_report_generation() {
        let findings = vec![Finding {
            id: "PT-TEST-001".into(),
            rule_name: "TestRule".into(),
            severity: Severity::Critical,
            category: Category::GitExecutionSink,
            message: "Test sink".into(),
            file_path: ".git/config".into(),
            line: Some(12),
            key: Some("core.fsmonitor".into()),
            value: Some("evil.sh".into()),
            action: Action::NeutralizableViaEnv,
            remediation: "Fix it".into(),
        }];

        let report = JsonReport::new("/path/to/repo".into(), findings);
        assert_eq!(report.summary.total, 1);
        assert_eq!(report.summary.critical, 1);
        assert_eq!(report.summary.blocking_run, 0);

        let json_str = report.to_json_string(true).unwrap();
        assert!(json_str.contains("PT-TEST-001"));
        assert!(json_str.contains("TestRule"));
    }
}
