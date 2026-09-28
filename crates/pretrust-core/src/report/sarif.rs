use crate::report::model::{Finding, Severity};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifReport {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<SarifRun>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifDriver {
    pub name: String,
    pub version: String,
    #[serde(rename = "informationUri")]
    pub information_uri: String,
    pub rules: Vec<SarifRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRule {
    pub id: String,
    pub name: String,
    #[serde(rename = "shortDescription")]
    pub short_description: SarifMessage,
    #[serde(rename = "defaultConfiguration")]
    pub default_configuration: SarifRuleConfiguration,
    pub help: SarifMessage,
    #[serde(rename = "helpUri", skip_serializing_if = "Option::is_none")]
    pub help_uri: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRuleConfiguration {
    pub level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifResult {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    pub level: String,
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifMessage {
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    pub physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<SarifRegion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifArtifactLocation {
    pub uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRegion {
    #[serde(rename = "startLine")]
    pub start_line: usize,
}

fn severity_to_sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

pub fn generate_sarif(findings: &[Finding]) -> SarifReport {
    let mut rules_map: BTreeMap<String, SarifRule> = BTreeMap::new();
    let mut results: Vec<SarifResult> = Vec::new();

    for f in findings {
        let level = severity_to_sarif_level(f.severity).to_string();

        rules_map.entry(f.rule_name.clone()).or_insert_with(|| {
            let rule_meta = crate::report::rules::get_rule(&f.id)
                .or_else(|| crate::report::rules::get_rule(&f.rule_name));
            let title = rule_meta
                .map(|r| r.title.to_string())
                .unwrap_or_else(|| format!("Pretrust rule {}", f.rule_name));
            let help_uri = rule_meta.and_then(|r| r.references.first().map(|s| s.to_string()));
            let help_text = if let Some(meta) = rule_meta {
                format!("{}\n\nRemediation: {}", meta.description, f.remediation)
            } else {
                f.remediation.clone()
            };
            SarifRule {
                id: f.rule_name.clone(),
                name: f.rule_name.clone(),
                short_description: SarifMessage { text: title },
                default_configuration: SarifRuleConfiguration {
                    level: level.clone(),
                },
                help: SarifMessage { text: help_text },
                help_uri,
            }
        });

        let region = f.line.map(|line| SarifRegion { start_line: line });

        results.push(SarifResult {
            rule_id: f.rule_name.clone(),
            level,
            message: SarifMessage {
                text: f.message.clone(),
            },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: f.file_path.clone(),
                    },
                    region,
                },
            }],
        });
    }

    let rules: Vec<SarifRule> = rules_map.into_values().collect();

    SarifReport {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
        version: "2.1.0".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "pretrust".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    information_uri: "https://github.com/aliefe04/pretrust".to_string(),
                    rules,
                },
            },
            results,
        }],
    }
}

pub fn to_sarif_string(findings: &[Finding], pretty: bool) -> Result<String, serde_json::Error> {
    let report = generate_sarif(findings);
    if pretty {
        serde_json::to_string_pretty(&report)
    } else {
        serde_json::to_string(&report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::model::{Action, Category};

    #[test]
    fn test_sarif_generation() {
        let findings = vec![
            Finding {
                id: "PT-GIT-001".into(),
                rule_name: "GitFsMonitor".into(),
                severity: Severity::Critical,
                category: Category::GitExecutionSink,
                message: "Malicious fsmonitor".into(),
                file_path: ".git/config".into(),
                line: Some(4),
                key: Some("core.fsmonitor".into()),
                value: Some("evil.sh".into()),
                action: Action::NeutralizableViaEnv,
                remediation: "Remove fsmonitor".into(),
            },
            Finding {
                id: "PT-TASK-001".into(),
                rule_name: "VSCodeTasksFolderOpen".into(),
                severity: Severity::Critical,
                category: Category::WorkspaceAutoRun,
                message: "FolderOpen task".into(),
                file_path: ".vscode/tasks.json".into(),
                line: None,
                key: None,
                value: None,
                action: Action::RequiresManualRemediation,
                remediation: "Remove task".into(),
            },
        ];

        let sarif = generate_sarif(&findings);
        assert_eq!(sarif.version, "2.1.0");
        assert_eq!(sarif.runs.len(), 1);
        assert_eq!(sarif.runs[0].tool.driver.name, "pretrust");
        assert_eq!(sarif.runs[0].results.len(), 2);
        assert_eq!(sarif.runs[0].results[0].level, "error");

        let sarif_json = to_sarif_string(&findings, true).unwrap();
        assert!(sarif_json.contains("GitFsMonitor"));
        assert!(sarif_json.contains("VSCodeTasksFolderOpen"));
    }
}
