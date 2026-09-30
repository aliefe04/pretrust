# r/LocalLLaMA draft

**Title:** I built a scanner for the config your AI coding agent executes before it asks you

**Body:**

Short version: if you `git clone` a repo and open it in Claude Code or Cursor, MCP servers, hooks,
permissions and env overrides come out of that repo. Several agents have shipped CVEs for running
something from there before the trust prompt — CVE-2025-59536 and CVE-2026-21852 for Claude Code,
CVE-2025-61592 / 64109 / 54136 / 48124 for Cursor.

I wanted to check that before the agent starts, so I wrote [pretrust](https://github.com/aliefe04/pretrust)
— a single Rust binary, no runtime deps, 43 rules.

```
$ pretrust scan path/to/repo
[CRITICAL] ClaudeEnvOverride (PT-CLAUDE-001)
[CRITICAL] GeminiProjectMcpServer (PT-MCP-004)
[CRITICAL] McpPromptInjection (PT-MCP-001)
[CRITICAL] VSCodeTasksFolderOpen (PT-TASK-001)
Findings: 8 total (4 critical, 4 high)
```

Covers `.git/config` sinks (`core.fsmonitor`, `core.hooksPath`, filter/diff drivers, `url.insteadOf`,
aliases), MCP definitions for Claude/Cursor/VS Code/Gemini/Zed/Amazon Q, Claude hooks and permission
overrides, VS Code `runOn: folderOpen` tasks, Cargo hooks, and prompt-injection smuggled into
AGENTS.md / CLAUDE.md via zero-width characters or ANSI escapes.

Three modes:

- `pretrust scan <repo>` — check it, `--sarif` into GitHub Code Scanning
- `pretrust run -- claude` — runs the agent with Git's execution sinks neutralized for that child
  process only, nothing written to disk; refuses to start (exit 2) if a finding needs fixing
- `pretrust hook claude` — PreToolUse hook

There is a GitHub Action too. Install:

```
curl -fsSL https://raw.githubusercontent.com/aliefe04/pretrust/main/install.sh | sh
```

Worth knowing: the hook gates on repo state, not on the command being run. Releases are unsigned, so
the installer's SHA-256 check is integrity only. Both are in the README under Limits.

If you have run into a real repo that got you, I would like to hear about it — new rules are the part
I am least sure about.