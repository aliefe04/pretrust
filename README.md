<p align="center">
  <picture>
    <source srcset="https://raw.githubusercontent.com/aliefe04/pretrust/main/docs/assets/logo-dark.svg" media="(prefers-color-scheme: dark)">
    <source srcset="https://raw.githubusercontent.com/aliefe04/pretrust/main/docs/assets/logo-light.svg" media="(prefers-color-scheme: light)">
    <img src="https://raw.githubusercontent.com/aliefe04/pretrust/main/docs/assets/logo-light.svg" alt="Pretrust logo" width="300">
  </picture>
</p>
<p align="center">The pre-trust guard for AI coding agents.</p>
<p align="center">
  <a href="https://github.com/aliefe04/pretrust/actions/workflows/test.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/aliefe04/pretrust/test.yml?style=flat-square&branch=main&label=ci" /></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" /></a>
</p>

[![Pretrust scanning a hostile repository](https://raw.githubusercontent.com/aliefe04/pretrust/main/docs/assets/screenshot.png)](https://github.com/aliefe04/pretrust/blob/main/docs/RULES.md)

---

AI coding agents read configuration straight out of the repository you open: MCP servers, hooks, permissions, environment variables, Git settings. Claude Code executed project content before the user accepted its trust dialog ([CVE-2025-59536](https://nvd.nist.gov/vuln/detail/CVE-2025-59536), [CVE-2026-21852](https://nvd.nist.gov/vuln/detail/CVE-2026-21852)). Cursor has shipped remote code execution and sandbox escape driven by the same class of files ([CVE-2025-64109](https://nvd.nist.gov/vuln/detail/CVE-2025-64109), [CVE-2025-54136](https://nvd.nist.gov/vuln/detail/CVE-2025-54136), [CVE-2026-26268](https://nvd.nist.gov/vuln/detail/CVE-2026-26268)).

Pretrust is a single Rust binary with no runtime dependencies. It checks a repository before an agent touches it, and it can start an agent with Git's execution sinks switched off.

### Installation

**macOS and Linux:**

```bash
curl -fsSL https://raw.githubusercontent.com/aliefe04/pretrust/main/install.sh | sh
```

That URL tracks `main`, which is mutable. Pin both the installer and the version it installs:

```bash
curl -fsSL https://raw.githubusercontent.com/aliefe04/pretrust/v0.1.3/install.sh \
  | PRETRUST_VERSION=v0.1.3 sh
```

Fetching `install.sh` from a tag only pins the script; without `PRETRUST_VERSION` it still installs
the newest release.

The installer downloads the binary for your platform and its published `.sha256` sidecar, compares
them, and aborts if they differ or the sidecar is missing. That is an **integrity** check: it catches
corruption, truncated uploads and mismatched assets. It is not a signature — both files come from the
same release, so it cannot defend against someone able to replace the release itself. Releases are
currently unsigned; verify the commit SHA out of band if you need more than integrity.

If the download is unavailable the installer falls back to `cargo install`, pinned to the requested
tag with `--locked`; for `latest` it resolves the actual release tag first and refuses rather than
building an unpinned default branch. Set `PRETRUST_NO_CARGO_FALLBACK=1` to disable the fallback
entirely. Other overrides: `PRETRUST_INSTALL_DIR` (default `/usr/local/bin`, else `~/.local/bin`),
`PRETRUST_VERBOSE=1`.

**Windows (x86_64):** download `pretrust-x86_64-pc-windows-msvc.zip` and its `.sha256` sidecar from
the [releases page](https://github.com/aliefe04/pretrust/releases), compare the checksums, and extract
`pretrust.exe`.

Releases are built for Linux (x86_64, aarch64), macOS (x86_64, aarch64) and Windows (x86_64). Linux
binaries are built against Ubuntu 22.04's glibc 2.35; on older distributions, build from source:

```bash
cargo install --git https://github.com/aliefe04/pretrust pretrust --bin pretrust

# or from a clone
git clone https://github.com/aliefe04/pretrust && cd pretrust
cargo build --release --locked
./target/release/pretrust --version
```

### Usage

**Scan** a repository before you open it in an agent:

```bash
pretrust scan path/to/repo
pretrust scan --json          # machine-readable
pretrust scan --sarif         # GitHub Code Scanning
pretrust scan --fail-on high  # exit 1 on high or critical findings (default)
```

**Run** an agent with Git execution sinks neutralized. Pretrust sets command-scope `GIT_CONFIG_*` overrides for the child process only, so files on disk are never modified. If a finding needs manual remediation, it refuses to start and exits with code 2 (`--allow-sinks` overrides this):

```bash
pretrust run -- claude
pretrust run -- cursor .
```

**Hook** it into an agent so tool calls are gated. The hook re-scans the repository you are working in
and blocks every tool call while that repository has blocking findings; it does not inspect the
individual command. Put this in your user-level `~/.claude/settings.json`; project-level hooks are
exactly what rule PT-HOOK-001 flags:

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash", "hooks": [{ "type": "command", "command": "pretrust hook claude" }] }
    ]
  }
}
```

**Lock** instruction and config files and detect drift in CI:

```bash
pretrust lock          # writes pretrust.lock (SHA-256 per file)
pretrust lock --check  # exits non-zero if a locked file changed, was removed, or a new one appeared
```

`pretrust.lock` lives inside the repository, so it detects drift against a baseline you trust. Review changes to the lockfile itself, and pin it from outside the repo if the repo accepts untrusted pull requests.

**Rules** lists everything the scanner can report:

```bash
pretrust rules
pretrust rules --json
```

### GitHub Action

Scan repositories in CI and upload findings directly to GitHub Code Scanning via SARIF:

```yaml
name: Pretrust Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

permissions:
  contents: read
  security-events: write   # Required for SARIF upload to GitHub Code Scanning
  pull-requests: write     # Optional: only needed if 'comment: true' is enabled

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
        with:
          persist-credentials: false

      - name: Run Pretrust Security Scan
        uses: aliefe04/pretrust@main # Pin to a full 40-character commit SHA in production
        with:
          path: '.'                  # Workspace directory to scan (default: '.')
          fail-on: 'high'            # info | low | medium | high | critical (default: 'high')
          comment: 'false'           # Optional idempotent PR comment (default: 'false')
```

#### Action Notes & Permissions
- **Production Pinning**: In production workflows, pin the action to a full 40-character commit SHA (e.g. `uses: aliefe04/pretrust@<commit-sha>`) rather than a mutable branch or tag. This protects against supply chain drift and tag tampering. Use `@main` only for evaluation or tracking active development.
- **Runtime Environment**: The composite Action requires a GitHub-hosted `ubuntu-latest` (Ubuntu Linux) runner with `bash` and the GitHub CLI (`gh`).
- **Trusted Source**: The action builds the CLI binary strictly from its pinned action repository (`GITHUB_ACTION_PATH`), never executing or building cargo from the untrusted scanned checkout. Overriding the binary via environment is disabled to maintain trust boundaries.
- **Code Scanning Permissions**: SARIF upload requires `security-events: write`. Private repositories require GitHub Advanced Security or GitHub Team/Enterprise Code Security enabled.
- **Fork Pull Requests**: On public fork pull requests, `GITHUB_TOKEN` is read-only by default. SARIF upload and PR comments require write permissions (`security-events: write` and `pull-requests: write`). If PR comments are enabled on a fork without write permission, the action will report a clear permission error and fail closed.
- **Reject `pull_request_target`**: Do not invoke this action from a `pull_request_target` workflow. The action explicitly rejects `pull_request_target` events because running scans or posting comments under `pull_request_target` risks evaluating untrusted code while operating with elevated repository write permissions and access to secrets. Always trigger scans using standard `pull_request` events.
- **Credential Protection**: Always set `persist-credentials: false` in `actions/checkout`. GitHub tokens are accessed exclusively through environment variables (`GH_TOKEN`), never passed as command-line arguments or echoed in logs.
- **Exit Status**: Exit code 0 indicates no findings meeting or exceeding the configured threshold (findings below threshold may still be recorded in SARIF), exit code 1 indicates findings meeting or exceeding threshold, and exit code 2 indicates scanner invocation or execution error.

### What it checks

Git config execution sinks, VS Code tasks, Cargo hooks, agent instruction files, and the project-level MCP, hook, permission and environment settings of Claude Code, Cursor, VS Code / Copilot, Gemini CLI, Zed and Amazon Q. See [docs/RULES.md](https://github.com/aliefe04/pretrust/blob/main/docs/RULES.md) for every file and rule with its reference.

### Limits

- `pretrust scan` and `pretrust lock` are checks. Nothing protects an agent that you launch without `pretrust run` or `pretrust hook`.
- `pretrust run` neutralizes Git execution sinks. MCP, hook and permission findings are reported and block the launch; they are not rewritten.
- `pretrust hook` decides on repository state, not on the command being run. A harmless command is blocked while the repository has blocking findings, and a dangerous one is not singled out.
- Rules cover known configuration files. A new agent or file format is not covered until a rule exists for it.

### Contributing

Bug reports, false positives and new rules are welcome. Run the tests with `cargo test --all-targets --locked`. A rule should point to the advisory or documentation that justifies it.

---

Released under the [MIT License](https://github.com/aliefe04/pretrust/blob/main/LICENSE).
