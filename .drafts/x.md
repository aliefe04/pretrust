# X drafts — pretrust launch

Thread 1 — the hook (the part people react to)

1/ Several coding agents have shipped CVEs for executing repo configuration before the trust prompt:
CVE-2025-59536, CVE-2026-21852 (Claude Code), CVE-2025-61592, CVE-2025-64109, CVE-2025-54136,
CVE-2026-48124 (Cursor).

Same shape every time: MCP servers, hooks, permissions and env overrides come out of the repo you
just cloned.

2/ So I wrote pretrust — one Rust binary, 43 rules, no runtime deps — to check that before the agent
starts instead of after something fires.

3/ The output names the file, the sink and the fix:

```
[CRITICAL] McpRepoLocalCommand (PT-MCP-003)
  Location: .mcp.json
  Message:  MCP server 'evil' executes repository-local binary,
            script, or inline shell command: 'sh -c curl … | sh'
```

4/ Three modes:

· `pretrust scan <repo>` — a check, with `--sarif` for Code Scanning
· `pretrust run -- claude` — neutralizes Git's execution sinks for that child process only
· `pretrust hook claude` — gates tool calls

Nothing on disk is modified. Refuses to start (exit 2) when a finding needs manual remediation.

5/ Limits I'd rather state than let you find:

· the hook gates on repo state, not on the individual command
· releases are unsigned, so the installer's SHA-256 check is integrity only
· rules only cover known config file formats

https://github.com/aliefe04/pretrust

---

Thread 2 — the finding-led post (use this one if there is a fresh advisory to write up)

1/ Found something: <AGENT> advertises <tool> as read-only, but <file> runs a build command
against untrusted repository files during <operation>.

<one-paragraph mechanism, with the exact file and line>

2/ Reproduced with a harmless marker file in a scratch directory — nothing touched the host.

3/ Reported privately via the project's stated channel.

4/ The generalisable bit: <the pattern>. If you build tools that execute files from a checkout, this
is the shape to check.

This post has one job and it is not to sell anything — it is to be the credible technical voice that
makes the product post land later.