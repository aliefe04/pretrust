# Show HN draft — pretrust

**Title:** Pretrust: a pre-trust execution guard for AI coding agents

**Body:**

Several agents have shipped CVEs for executing repository configuration before the user accepted a
trust prompt — CVE-2025-59536 and CVE-2026-21852 (Claude Code), CVE-2025-61592, CVE-2025-64109,
CVE-2025-54136 and CVE-2026-48124 (Cursor). The pattern is always the same: the agent reads MCP
server definitions, hooks, permissions and environment overrides straight out of the repository you
just cloned, and something in there runs before you are asked.

I built [pretrust](https://github.com/aliefe04/pretrust) to make that checkable before the agent
starts rather than after something fires. It is a single Rust binary with no runtime dependencies.

```
$ pretrust scan crates/pretrust-cli/tests/fixtures/vulnerable_repo
[CRITICAL] ClaudeEnvOverride (PT-CLAUDE-001)
  Location: .claude/settings.json
  Message:  Claude settings overrides sensitive environment variable 'ANTHROPIC_BASE_URL' ...
[CRITICAL] GeminiProjectMcpServer (PT-MCP-004)
[CRITICAL] McpPromptInjection (PT-MCP-001)
[CRITICAL] VSCodeTasksFolderOpen (PT-TASK-001)
[HIGH] ClaudeMcpAutoApprove (PT-CLAUDE-003)
[HIGH] McpRepoLocalCommand (PT-MCP-003)
[HIGH] McpHardcodedSecret (PT-MCP-005)
[HIGH] VsCodeToolAutoApprove (PT-VSCODE-001)

Findings: 8 total (4 critical, 4 high, 0 medium, 0 low)
```

43 rules across `.git/config`, `.mcp.json`, `.claude/settings.json`, `.cursor/*`, `.vscode/*`,
`.gemini/settings.json`, `.zed/settings.json`, `.amazonq/mcp.json`, `.cargo/config.toml` and agent
instruction files. `pretrust rules` prints the full catalog.

Three ways to use it:

- `pretrust scan <repo>` — a check. `--json`, `--sarif` for GitHub Code Scanning, `--fail-on` to
  set the CI gate.
- `pretrust run -- claude` — neutralizes Git execution sinks for the child process only, via
  command-scope `GIT_CONFIG_*`. Nothing on disk is modified. Refuses to start (exit 2) when a finding
  needs manual remediation.
- `pretrust hook claude` — a PreToolUse hook that blocks tool calls while the current repository has
  blocking findings.

Plus a composite GitHub Action that uploads SARIF, and `pretrust lock` / `--check` for drift
detection in CI.

Honest limits, since they will come up:

- The hook decides on repository state, not on the individual command. A harmless command is blocked
  while the repo has blocking findings; a dangerous one is not singled out.
- The source-build fallback in the installer is pinned to the requested tag, but releases are
  currently unsigned. The SHA-256 check is an integrity check, not a signature.
- Rules cover known configuration files. A new agent or format is uncovered until a rule exists.

All seven CVE ids cited in the rules table were checked against NVD; each matches the claim it
supports.

Linux, macOS and Windows binaries:

```
curl -fsSL https://raw.githubusercontent.com/aliefe04/pretrust/main/install.sh | sh
```

Source is MIT. Rules, false positives and new agent coverage are welcome — a rule should point to the
advisory that justifies it.