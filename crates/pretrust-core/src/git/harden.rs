use crate::git::attributes::extract_defined_drivers;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct HardenedEnvironment {
    pub env_vars: HashMap<String, String>,
    pub temp_hooks_dir: Option<PathBuf>,
}

impl HardenedEnvironment {
    pub fn apply_to_command(&self, cmd: &mut std::process::Command) {
        for (k, v) in &self.env_vars {
            cmd.env(k, v);
        }
    }
}

pub fn get_safe_hooks_path() -> (String, Option<PathBuf>) {
    #[cfg(unix)]
    {
        ("/dev/null".to_string(), None)
    }

    #[cfg(not(unix))]
    {
        let temp_dir = std::env::temp_dir().join("pretrust-empty-hooks");
        let _ = std::fs::create_dir_all(&temp_dir);
        (temp_dir.to_string_lossy().to_string(), Some(temp_dir))
    }
}

pub fn build_hardened_env(repo_root: &Path) -> HardenedEnvironment {
    let mut env = HashMap::new();
    let (hooks_path, temp_hooks_dir) = get_safe_hooks_path();

    // Standard static Git config overrides
    let git_config_pairs: Vec<(&str, &str)> = vec![
        ("core.fsmonitor", "false"),
        ("core.hooksPath", &hooks_path),
        ("core.sshCommand", "ssh"),
        ("core.askPass", "true"),
        ("core.pager", "cat"),
        ("core.editor", "true"),
        ("protocol.ext.allow", "never"),
        ("credential.helper", ""),
    ];

    // Dynamic driver overrides
    let defined_drivers = extract_defined_drivers(repo_root);
    let mut dynamic_keys: Vec<String> = Vec::new();
    for driver in &defined_drivers {
        if driver.name.eq_ignore_ascii_case("lfs") {
            continue;
        }
        dynamic_keys.push(driver.key.clone());
    }

    let mut count = 0;
    for (k, v) in git_config_pairs {
        env.insert(format!("GIT_CONFIG_KEY_{count}"), k.to_string());
        env.insert(format!("GIT_CONFIG_VALUE_{count}"), v.to_string());
        count += 1;
    }

    for key in &dynamic_keys {
        env.insert(format!("GIT_CONFIG_KEY_{count}"), key.clone());
        env.insert(format!("GIT_CONFIG_VALUE_{count}"), "".to_string());
        count += 1;
    }

    env.insert("GIT_CONFIG_COUNT".to_string(), count.to_string());

    // Additional process-level environment hardening
    env.insert("GIT_TERMINAL_PROMPT".to_string(), "0".to_string());
    env.insert("GIT_PROTOCOL_FROM_USER".to_string(), "0".to_string());
    env.insert("GIT_PAGER".to_string(), "cat".to_string());
    env.insert("PAGER".to_string(), "cat".to_string());
    env.insert("GIT_EXTERNAL_DIFF".to_string(), "true".to_string());
    env.insert(
        "GIT_SSH_COMMAND".to_string(),
        "ssh -o BatchMode=yes".to_string(),
    );

    HardenedEnvironment {
        env_vars: env,
        temp_hooks_dir,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_hardened_env_generation() {
        let dir = tempdir().unwrap();
        let dot_git = dir.path().join(".git");
        fs::create_dir_all(&dot_git).unwrap();

        fs::write(
            dot_git.join("config"),
            r#"
[filter "evil"]
    clean = "evil_clean.sh"
"#,
        )
        .unwrap();

        let hardened = build_hardened_env(dir.path());
        assert!(hardened.env_vars.contains_key("GIT_CONFIG_COUNT"));

        let count: usize = hardened.env_vars["GIT_CONFIG_COUNT"].parse().unwrap();
        assert!(count >= 9); // 8 base + 1 evil driver override

        assert_eq!(hardened.env_vars["GIT_CONFIG_KEY_0"], "core.fsmonitor");
        assert_eq!(hardened.env_vars["GIT_CONFIG_VALUE_0"], "false");

        assert_eq!(hardened.env_vars["GIT_TERMINAL_PROMPT"], "0");
        assert_eq!(hardened.env_vars["GIT_EXTERNAL_DIFF"], "true");
        assert_eq!(hardened.env_vars["GIT_SSH_COMMAND"], "ssh -o BatchMode=yes");

        // Verify driver override exists with empty value
        let has_driver_override = (0..count).any(|i| {
            let key = format!("GIT_CONFIG_KEY_{i}");
            let val = format!("GIT_CONFIG_VALUE_{i}");
            hardened.env_vars.get(&key).map(|s| s.as_str()) == Some("filter.evil.clean")
                && hardened.env_vars.get(&val).map(|s| s.as_str()) == Some("")
        });
        assert!(has_driver_override);
    }
}
