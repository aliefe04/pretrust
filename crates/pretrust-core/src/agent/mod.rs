pub mod claude;
pub mod cursor;
pub mod instructions;
pub mod mcp;
pub mod tasks;
pub mod vscode;

use crate::report::model::Finding;
use std::path::Path;

pub const AGENT_CONFIG_RELATIVE_PATHS: &[&str] = &[
    "AGENTS.md",
    "CLAUDE.md",
    ".cursorrules",
    ".copilot-instructions.md",
    ".mcp.json",
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".cursor/hooks.json",
    ".cursor/mcp.json",
    ".cursor/cli.json",
    ".vscode/tasks.json",
    ".vscode/mcp.json",
    ".vscode/settings.json",
    ".gemini/settings.json",
    ".zed/settings.json",
    ".amazonq/mcp.json",
    ".cargo/config.toml",
    ".cargo/config",
    ".github/copilot-instructions.md",
];

const ZERO_WIDTH_CHARS: &[char] = &[
    '\u{200B}', // zero-width space
    '\u{200C}', // zero-width non-joiner
    '\u{200D}', // zero-width joiner
    '\u{FEFF}', // zero-width no-break space (BOM)
    '\u{2060}', // word joiner
];

const INJECTION_PHRASES: &[&str] = &[
    "<system>",
    "</system>",
    "ignore previous instructions",
    "ignore all instructions",
    "disregard all previous",
    "exfiltrate",
];

pub fn has_zero_width_chars(s: &str) -> bool {
    s.chars().any(|c| ZERO_WIDTH_CHARS.contains(&c))
}

pub fn has_injection_phrases(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    INJECTION_PHRASES
        .iter()
        .any(|phrase| lower.contains(phrase))
}

pub fn format_rel_path(repo_root: &Path, target: &Path) -> String {
    if let Ok(rel) = target.strip_prefix(repo_root) {
        rel.to_string_lossy().to_string()
    } else {
        target.to_string_lossy().to_string()
    }
}

pub fn redact_secret(val: &str) -> String {
    let char_count = val.chars().count();
    if char_count <= 4 {
        "***".to_string()
    } else {
        let prefix: String = val.chars().take(4).collect();
        format!("{prefix}…")
    }
}

pub fn parse_jsonc(content: &str) -> Option<serde_json::Value> {
    let parse_opts = jsonc_parser::ParseOptions {
        allow_comments: true,
        allow_trailing_commas: true,
        ..Default::default()
    };
    match jsonc_parser::parse_to_value(content, &parse_opts) {
        Ok(Some(v)) => Some(jsonc_to_serde(v)),
        _ => None,
    }
}

fn jsonc_to_serde(v: jsonc_parser::JsonValue) -> serde_json::Value {
    match v {
        jsonc_parser::JsonValue::Null => serde_json::Value::Null,
        jsonc_parser::JsonValue::Boolean(b) => serde_json::Value::Bool(b),
        jsonc_parser::JsonValue::Number(n) => {
            if let Ok(num) = n.parse::<i64>() {
                serde_json::Value::Number(num.into())
            } else if let Ok(num) = n.parse::<u64>() {
                serde_json::Value::Number(num.into())
            } else if let Ok(num) = n.parse::<f64>() {
                serde_json::Number::from_f64(num)
                    .map(serde_json::Value::Number)
                    .unwrap_or(serde_json::Value::Null)
            } else {
                serde_json::Value::Null
            }
        }
        jsonc_parser::JsonValue::String(s) => serde_json::Value::String(s.into_owned()),
        jsonc_parser::JsonValue::Array(arr) => {
            serde_json::Value::Array(arr.into_iter().map(jsonc_to_serde).collect())
        }
        jsonc_parser::JsonValue::Object(obj) => {
            let mut map = serde_json::Map::new();
            for (k, val) in obj {
                map.insert(k.into_owned(), jsonc_to_serde(val));
            }
            serde_json::Value::Object(map)
        }
    }
}

pub fn scan_agent_vectors(repo_root: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(mcp::scan_mcp(repo_root));
    findings.extend(claude::scan_claude(repo_root));
    findings.extend(cursor::scan_cursor(repo_root));
    findings.extend(vscode::scan_vscode(repo_root));
    findings.extend(tasks::scan_tasks(repo_root));
    findings.extend(instructions::scan_instructions(repo_root));
    findings
}
