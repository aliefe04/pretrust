# Rules and agent configuration coverage

Agents read these files from the repository itself, so whoever controls the repository controls them. Run `pretrust rules` for the full catalog, or `pretrust rules --json` for a machine-readable version.

## Files checked

| File | Agent | What is checked |
| :--- | :--- | :--- |
| `.git/config`, `.gitmodules`, `.gitattributes` | Git (every agent that runs `git status` or `git diff`) | execution sinks such as `core.fsmonitor`, `core.sshCommand`, `core.hooksPath`, `diff.external`, filter and diff drivers, aliases, `url.insteadOf`, include smuggling |
| `.mcp.json` | Claude Code | `mcpServers` |
| `.claude/settings.json`, `.claude/settings.local.json` | Claude Code (also parsed by Cursor, CVE-2026-48124) | `hooks`, `env`, `apiKeyHelper` and other command helpers, MCP auto-approval, `permissions` |
| `.cursor/mcp.json`, `.cursor/hooks.json`, `.cursor/cli.json` | Cursor | `mcpServers`, lifecycle hooks, CLI `permissions.allow` |
| `.vscode/mcp.json`, `.vscode/settings.json`, `.vscode/tasks.json` | VS Code / GitHub Copilot | `servers`, `chat.tools.autoApprove`, `task.allowAutomaticTasks`, `runOn: folderOpen` |
| `.gemini/settings.json` | Gemini CLI | `mcpServers` (folder trust is [disabled by default](https://geminicli.com/docs/cli/trusted-folders.md)) |
| `.zed/settings.json` | Zed | `context_servers` |
| `.amazonq/mcp.json` | Amazon Q Developer | `mcpServers` |
| `.cargo/config.toml` | Cargo | `rustc-wrapper`, target runners |
| `AGENTS.md`, `CLAUDE.md`, `.cursorrules` and similar | any | zero-width characters, ANSI escapes, injection phrases |

All JSON settings files are parsed as JSONC, so comments and trailing commas cannot hide an entry.

## Agent and MCP rules

| ID | Severity | Finding | Reference |
| :--- | :--- | :--- | :--- |
| PT-MCP-001 | critical | Prompt injection or zero-width characters in an MCP server description | |
| PT-MCP-002 | medium | MCP server uses an unpinned package (`@latest`) | |
| PT-MCP-003 | high | MCP server runs a repo-local file or an inline shell (`sh -c`, `node -e`, `curl … \| sh`) | [CVE-2025-64109](https://nvd.nist.gov/vuln/detail/CVE-2025-64109), [CVE-2025-54136](https://nvd.nist.gov/vuln/detail/CVE-2025-54136) |
| PT-MCP-004 | critical | stdio MCP server in `.gemini/settings.json` | [Gemini CLI trusted folders](https://geminicli.com/docs/cli/trusted-folders.md) |
| PT-MCP-005 | high | Literal secret in MCP `env` or `headers` (value redacted in reports) | |
| PT-MCP-006 | medium | Remote MCP server over plain `http://` to a non-loopback host | |
| PT-CLAUDE-001 | critical | Project settings override `ANTHROPIC_BASE_URL`, proxies, `NODE_OPTIONS`, `LD_PRELOAD` and similar | [CVE-2026-21852](https://nvd.nist.gov/vuln/detail/CVE-2026-21852) |
| PT-CLAUDE-002 | high | Command helpers: `apiKeyHelper`, `statusLine.command`, `awsAuthRefresh`, `awsCredentialExport`, `otelHeadersHelper` | [Claude Code settings](https://code.claude.com/docs/en/settings) |
| PT-CLAUDE-003 | high | `enableAllProjectMcpServers` or `enabledMcpjsonServers` auto-approves repo MCP servers | [Claude Code settings](https://code.claude.com/docs/en/settings) |
| PT-CLAUDE-004 | high | `bypassPermissions` mode or blanket `Bash(*)` grant | [Claude Code permissions](https://code.claude.com/docs/en/permissions) |
| PT-HOOK-001 | high | Claude project lifecycle hook | |
| PT-HOOK-002 | high | Cursor project lifecycle hook | |
| PT-CURSOR-001 | high | `.cursor/cli.json` pre-approves `Shell(…)` or `Write(…)` | [CVE-2025-61592](https://nvd.nist.gov/vuln/detail/CVE-2025-61592) |
| PT-VSCODE-001 | high | `chat.tools.autoApprove` enabled in the workspace | [VS Code MCP configuration](https://code.visualstudio.com/docs/agents/reference/mcp-configuration) |
| PT-VSCODE-002 | high | `task.allowAutomaticTasks: "on"` | [VS Code tasks](https://code.visualstudio.com/docs/editor/tasks) |
| PT-CFG-001 | high | Unreadable or malformed agent configuration file | |

## Exit codes

`pretrust scan` exits `0` when nothing at or above `--fail-on` is found, `1` when something is, and `2` on error.
