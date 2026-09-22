# Pretrust

[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![CI](https://github.com/aliefe04/pretrust/actions/workflows/test.yml/badge.svg)](https://github.com/aliefe04/pretrust/actions)

Zero-dependency pre-trust execution guard for AI coding agents.

AI coding agents (Claude Code, Cursor, Codex, OpenCode, OMP, Pi) routinely execute background commands (such as `git status`, `git diff`, or task discovery) upon opening a repository, **before** any user consent or workspace-trust dialog appears. Attackers exploit this window via:
- **GitSpawn**: `core.fsmonitor`, `core.sshCommand`, malicious hooks in `.git/config`
- **Plugin4Shell**: SHA-pinning verification bypasses
- **Workspace task auto-runs**: `.vscode/tasks.json` with `runOptions.runOn: "folderOpen"`

`pretrust` is a single-binary Rust CLI that inspects repositories before an agent touches them and provides an execution-time runtime wrapper that neutralizes hostile configurations.

---

## Features

- **`pretrust scan [path]`**: Static pre-trust vulnerability and provenance scanner (<10ms) covering `.git/config`, `.gitmodules`, `.gitattributes`, `.vscode/tasks.json`, `.cargo/config.toml`, and agent instruction/hook files.
- **`pretrust run -- <agent-cmd> [args...]`**: Execution-time process wrapper that sanitizes the environment and injects targeted `GIT_CONFIG_*` command-scope overrides before invoking the agent, neutralizing sinks in child processes without modifying files on disk.
- **`pretrust hook <harness>`**: Native stdin/stdout JSON hook adapter for Claude Code, Cursor, Codex, and Copilot CLI (`PreToolUse`, `SessionStart`, `beforeShellExecution`).
- **`pretrust lock [--check]`**: Generates and verifies `pretrust.lock` SHA-256 fingerprints of in-tree agent instructions (`AGENTS.md`, `CLAUDE.md`, `.cursorrules`), hook configs, and tool manifests to detect post-approval rug-pulls in CI/CD.

---

## Installation

```bash
# Install via Cargo
cargo install --git https://github.com/aliefe04/pretrust pretrust-cli --bin pretrust

# Or via install script
curl -fsSL https://raw.githubusercontent.com/aliefe04/pretrust/main/install.sh | sh

# Or build from source
git clone https://github.com/aliefe04/pretrust
cd pretrust
cargo build --release
```

---

## Usage

### 1. Static Scan
```bash
# Scan current repository
pretrust scan

# Output machine-readable JSON or SARIF for GitHub Code Scanning
pretrust scan --json
pretrust scan --sarif

# Fail CI only on Critical findings
pretrust scan --fail-on critical
```

### 2. Guarded Agent Execution
```bash
# Launch Claude Code inside pretrust wrapper
pretrust run -- claude

# Launch Cursor or any agent command
pretrust run -- cursor .
```

### 3. Native Agent Hooks
Configure pretrust as an automated gate in `.claude/settings.json` or `.cursor/hooks.json`:
```json
{
  "hooks": {
    "PreToolUse": "pretrust hook claude"
  }
}
```

### 4. Instruction Lockfile
```bash
# Generate pretrust.lock fingerprint
pretrust lock

# Verify against lockfile in CI
pretrust lock --check
```

---

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT) at your option.
