# Pretrust

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Zero-dependency pre-trust execution guard for AI coding agents.

AI coding agents (Claude Code, Cursor, Codex, OpenCode, OMP, Pi) routinely execute background commands (such as `git status`, `git diff`, or task discovery) upon opening a repository, **before** any user consent or workspace-trust dialog appears. Attackers exploit this window via:
- **GitSpawn**: `core.fsmonitor`, `core.sshCommand`, malicious hooks in `.git/config`
- **Plugin4Shell**: SHA-pinning verification bypasses
- **Workspace task auto-runs**: `.vscode/tasks.json` with `runOptions.runOn: "folderOpen"`

`pretrust` is a single-binary Rust CLI that inspects repositories before an agent touches them and provides an execution-time runtime wrapper that neutralizes hostile configurations.

---

## Features

- **`pretrust scan [path]`**: Static pre-trust vulnerability and provenance scanner (<10ms) covering `.git/config`, `.gitmodules`, `.gitattributes`, `.vscode/tasks.json`, `.cargo/config.toml`, agent instruction files, and the project-level MCP, hook, permission and environment settings of Claude Code, Cursor, VS Code / Copilot, Gemini CLI, Zed and Amazon Q.
- **`pretrust rules [--json]`**: Prints the rule catalog (ID, severity, category, affected agents, references) so CI policies and dashboards can resolve rule IDs.
- **`pretrust run -- <agent-cmd> [args...]`**: Execution-time process wrapper that sanitizes the environment and injects targeted `GIT_CONFIG_*` command-scope overrides before invoking the agent, neutralizing sinks in child processes without modifying files on disk.
- **`pretrust hook <harness>`**: Native stdin/stdout JSON hook adapter for Claude Code, Cursor, Codex, and Copilot CLI (`PreToolUse`, `SessionStart`, `beforeShellExecution`).
- **`pretrust lock [--check]`**: Generates and verifies `pretrust.lock` SHA-256 fingerprints of in-tree agent instructions (`AGENTS.md`, `CLAUDE.md`, `.cursorrules`), hook configs, and tool manifests to detect post-approval rug-pulls in CI/CD.

---

## Agent configuration coverage

Agents read these files from the repository itself, so whoever controls the repository controls them.

| File | Agent | What is checked |
| :--- | :--- | :--- |
| `.mcp.json` | Claude Code | `mcpServers` |
| `.claude/settings.json`, `.claude/settings.local.json` | Claude Code (also parsed by Cursor, CVE-2026-48124) | `hooks`, `env`, `apiKeyHelper` and other command helpers, MCP auto-approval, `permissions` |
| `.cursor/mcp.json`, `.cursor/hooks.json`, `.cursor/cli.json` | Cursor | `mcpServers`, lifecycle hooks, CLI `permissions.allow` |
| `.vscode/mcp.json`, `.vscode/settings.json`, `.vscode/tasks.json` | VS Code / GitHub Copilot | `servers`, `chat.tools.autoApprove`, `task.allowAutomaticTasks`, `runOn: folderOpen` |
| `.gemini/settings.json` | Gemini CLI | `mcpServers` (folder trust is [disabled by default](https://geminicli.com/docs/cli/trusted-folders.md)) |
| `.zed/settings.json` | Zed | `context_servers` |
| `.amazonq/mcp.json` | Amazon Q Developer | `mcpServers` |

All JSON settings files are parsed as JSONC, so comments and trailing commas cannot hide an entry.

### Agent and MCP rules

| ID | Severity | Finding | Reference |
| :--- | :--- | :--- | :--- |
| PT-MCP-003 | high | MCP server runs a repo-local file or an inline shell (`sh -c`, `node -e`, `curl … \| sh`) | [CVE-2025-64109](https://nvd.nist.gov/vuln/detail/CVE-2025-64109), [CVE-2025-54136](https://nvd.nist.gov/vuln/detail/CVE-2025-54136) |
| PT-MCP-004 | critical | stdio MCP server in `.gemini/settings.json` | [Gemini CLI trusted folders](https://geminicli.com/docs/cli/trusted-folders.md) |
| PT-MCP-005 | high | Literal secret in MCP `env` or `headers` (value redacted in reports) | |
| PT-MCP-006 | medium | Remote MCP server over plain `http://` to a non-loopback host | |
| PT-CLAUDE-001 | critical | Project settings override `ANTHROPIC_BASE_URL`, proxies, `NODE_OPTIONS`, `LD_PRELOAD` and similar | [CVE-2026-21852](https://nvd.nist.gov/vuln/detail/CVE-2026-21852) |
| PT-CLAUDE-002 | high | Command helpers: `apiKeyHelper`, `statusLine.command`, `awsAuthRefresh`, `awsCredentialExport`, `otelHeadersHelper` | [Claude Code settings](https://code.claude.com/docs/en/settings) |
| PT-CLAUDE-003 | high | `enableAllProjectMcpServers` or `enabledMcpjsonServers` auto-approves repo MCP servers | [Claude Code settings](https://code.claude.com/docs/en/settings) |
| PT-CLAUDE-004 | high | `bypassPermissions` mode or blanket `Bash(*)` grant | [Claude Code permissions](https://code.claude.com/docs/en/permissions) |
| PT-CURSOR-001 | high | `.cursor/cli.json` pre-approves `Shell(…)` or `Write(…)` | [CVE-2025-61592](https://nvd.nist.gov/vuln/detail/CVE-2025-61592) |
| PT-VSCODE-001 | high | `chat.tools.autoApprove` enabled in the workspace | [VS Code MCP configuration](https://code.visualstudio.com/docs/agents/reference/mcp-configuration) |
| PT-VSCODE-002 | high | `task.allowAutomaticTasks: "on"` | [VS Code tasks](https://code.visualstudio.com/docs/editor/tasks) |

Run `pretrust rules` for the full catalog, including the Git, task, Cargo, instruction and lockfile rules.

---

## Installation

Build from source (Rust 1.85 or newer):

```bash
cargo build --release --locked
./target/release/pretrust --version
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
Register pretrust in your **user-level** `~/.claude/settings.json` (project-level hooks are exactly what PT-HOOK-001 flags):
```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash", "hooks": [{ "type": "command", "command": "pretrust hook claude" }] }
    ]
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

### 5. Rule Catalog
```bash
# Human-readable table
pretrust rules

# Machine-readable catalog for dashboards and CI policy
pretrust rules --json
```

---

## License

Released under the [MIT License](LICENSE).
