use crate::cli::RulesArgs;
use pretrust_core::report::rules::{RulesCatalog, all_rules};

pub fn execute_rules(args: RulesArgs) -> i32 {
    let rules = all_rules().to_vec();
    if args.json {
        let catalog = RulesCatalog {
            version: env!("CARGO_PKG_VERSION").to_string(),
            rules,
        };
        match serde_json::to_string_pretty(&catalog) {
            Ok(json_str) => {
                println!("{json_str}");
                0
            }
            Err(e) => {
                eprintln!("Error serializing rules catalog: {e}");
                2
            }
        }
    } else {
        println!(
            "{:<14} {:<10} {:<27} TITLE",
            "RULE ID", "SEVERITY", "CATEGORY"
        );
        println!("{}", "-".repeat(96));
        for rule in rules {
            println!(
                "{:<14} {:<10} {:<27} {}",
                rule.id,
                rule.severity.as_str(),
                rule.category.as_str(),
                rule.title
            );
        }
        0
    }
}
