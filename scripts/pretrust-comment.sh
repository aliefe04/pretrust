#!/usr/bin/env bash
set -euo pipefail

find_existing_comment_id_from_file() {
  local marker="$1"
  local comments_file="$2"

  python3 -c '
import json, sys

marker = sys.argv[1]
comments_file = sys.argv[2]

def parse_comments(path):
    with open(path, "r", encoding="utf-8") as f:
        content = f.read().strip()
    if not content:
        return []
    decoder = json.JSONDecoder()
    pos = 0
    length = len(content)
    comments = []
    while pos < length:
        while pos < length and content[pos].isspace():
            pos += 1
        if pos >= length:
            break
        doc, end = decoder.raw_decode(content, idx=pos)
        if isinstance(doc, list):
            comments.extend(doc)
        elif isinstance(doc, dict):
            comments.append(doc)
        pos = end
    return comments

try:
    comments = parse_comments(comments_file)
except Exception:
    sys.stderr.write("::error::Failed to parse comments from GitHub API response (category: JSON parse error).\n")
    sys.exit(1)

target_id = None
for c in comments:
    if not isinstance(c, dict):
        continue
    body = c.get("body") or ""
    if marker not in body:
        continue
    user = c.get("user") or {}
    login = user.get("login") or ""
    # Restrict strictly to github-actions[bot] comments
    if login == "github-actions[bot]":
        target_id = c.get("id")
        break

if target_id is not None:
    print(target_id)
' "$marker" "$comments_file"
}

if [ "${1:-}" = "--select-comment-id" ]; then
  find_existing_comment_id_from_file "${2:-}" "${3:-}"
  exit $?
fi

is_agent_config_file() {
  local f="$1"
  case "$f" in
    AGENTS.md|*/AGENTS.md) return 0 ;;
    CLAUDE.md|*/CLAUDE.md) return 0 ;;
    .cursorrules|*/.cursorrules) return 0 ;;
    .cursor/rules/*|*/.cursor/rules/*) return 0 ;;
    .copilot-instructions.md|*/.copilot-instructions.md) return 0 ;;
    .github/copilot-instructions.md|*/.github/copilot-instructions.md) return 0 ;;
    .mcp.json|*/.mcp.json) return 0 ;;
    .claude/settings.json|*/.claude/settings.json) return 0 ;;
    .claude/settings.local.json|*/.claude/settings.local.json) return 0 ;;
    .cursor/hooks.json|*/.cursor/hooks.json) return 0 ;;
    .cursor/mcp.json|*/.cursor/mcp.json) return 0 ;;
    .cursor/cli.json|*/.cursor/cli.json) return 0 ;;
    .vscode/tasks.json|*/.vscode/tasks.json) return 0 ;;
    .vscode/mcp.json|*/.vscode/mcp.json) return 0 ;;
    .vscode/settings.json|*/.vscode/settings.json) return 0 ;;
    .gemini/settings.json|*/.gemini/settings.json) return 0 ;;
    .zed/settings.json|*/.zed/settings.json) return 0 ;;
    .amazonq/mcp.json|*/.amazonq/mcp.json) return 0 ;;
    .cargo/config.toml|*/.cargo/config.toml) return 0 ;;
    .cargo/config|*/.cargo/config) return 0 ;;
    .gitmodules|*/.gitmodules) return 0 ;;
    .gitattributes|*/.gitattributes) return 0 ;;
    *) return 1 ;;
  esac
}

get_pr_changed_files() {
  local pr_num="$1"
  local files_tmp="$2"
  local repo="$3"

  local err_tmp
  err_tmp="$(mktemp "${RUNNER_TEMP:-/tmp}/pretrust-gh-err.XXXXXX")"
  if ! gh api --paginate "repos/$repo/pulls/$pr_num/files" --jq '.[].filename' > "$files_tmp" 2> "$err_tmp"; then
    local is_perm_err=0
    if grep -iqE "forbidden|resource not accessible|permission|403|bad credentials" "$err_tmp" 2>/dev/null; then
      is_perm_err=1
    fi
    rm -f "$err_tmp"
    echo "::error::GitHub API query for PR #$pr_num changed files failed (category: API request error)." >&2
    if [ "$is_perm_err" -eq 1 ]; then
      echo "::error::GitHub token lacks 'pull-requests: read' permission. On pull requests from forks, the default token has read-only access." >&2
    fi
    return 1
  fi
  rm -f "$err_tmp"
  return 0
}

find_existing_comment_id() {
  local pr_num="$1"
  local marker="$2"
  local repo="$3"

  local comments_tmp
  comments_tmp="$(mktemp "${RUNNER_TEMP:-/tmp}/pretrust-comments.XXXXXX")"
  local err_tmp
  err_tmp="$(mktemp "${RUNNER_TEMP:-/tmp}/pretrust-gh-err.XXXXXX")"

  if ! gh api --paginate "repos/$repo/issues/$pr_num/comments" > "$comments_tmp" 2> "$err_tmp"; then
    local is_perm_err=0
    if grep -iqE "forbidden|resource not accessible|permission|403|bad credentials" "$err_tmp" 2>/dev/null; then
      is_perm_err=1
    fi
    rm -f "$err_tmp" "$comments_tmp"
    echo "::error::GitHub API query for PR #$pr_num comments failed (category: API request error)." >&2
    if [ "$is_perm_err" -eq 1 ]; then
      echo "::error::GitHub token lacks 'pull-requests: write' or 'issues: write' permission. Pull requests from forks cannot post comments with the default read-only token." >&2
    fi
    exit 1
  fi
  rm -f "$err_tmp"

  local existing_id
  if ! existing_id="$(find_existing_comment_id_from_file "$marker" "$comments_tmp")"; then
    rm -f "$comments_tmp"
    echo "::error::Failed to parse comments from GitHub API response (category: JSON parse error)." >&2
    exit 1
  fi
  rm -f "$comments_tmp"
  echo "$existing_id"
}

post_or_update_comment() {
  local pr_num="$1"
  local comment_body="$2"
  local existing_id="$3"
  local repo="$4"
  local is_fork="${5:-0}"
  local err_tmp
  err_tmp="$(mktemp "${RUNNER_TEMP:-/tmp}/pretrust-gh-err.XXXXXX")"

  if [ -n "$existing_id" ]; then
    echo "Pretrust: Updating existing bot comment on PR #$pr_num..."
    if ! gh api --method PATCH "repos/$repo/issues/$pr_num/comments/$existing_id" -f body="$comment_body" >/dev/null 2> "$err_tmp"; then
      local is_perm_err=0
      if grep -iqE "forbidden|resource not accessible|permission|403|bad credentials" "$err_tmp" 2>/dev/null; then
        is_perm_err=1
      fi
      rm -f "$err_tmp"
      echo "::error::Failed to update PR comment (category: GitHub API update failure)." >&2
      if [ "$is_fork" = "1" ] || [ "$is_perm_err" -eq 1 ]; then
        echo "::error::GitHub token lacks 'pull-requests: write' permission to update comment. Pull requests from forks cannot post comments with the default read-only token." >&2
      fi
      exit 1
    fi
  else
    echo "Pretrust: Creating new bot comment on PR #$pr_num..."
    if ! gh api --method POST "repos/$repo/issues/$pr_num/comments" -f body="$comment_body" >/dev/null 2> "$err_tmp"; then
      local is_perm_err=0
      if grep -iqE "forbidden|resource not accessible|permission|403|bad credentials" "$err_tmp" 2>/dev/null; then
        is_perm_err=1
      fi
      rm -f "$err_tmp"
      echo "::error::Failed to create PR comment (category: GitHub API post failure)." >&2
      if [ "$is_fork" = "1" ] || [ "$is_perm_err" -eq 1 ]; then
        echo "::error::GitHub token lacks 'pull-requests: write' permission to create comment. Pull requests from forks cannot post comments with the default read-only token." >&2
      fi
      exit 1
    fi
  fi
  rm -f "$err_tmp"
  echo "Pretrust: PR comment successfully posted/updated on PR #$pr_num."
}

main() {
  local sarif_file="${SARIF_FILE:-}"
  local fail_on="${FAIL_ON:-high}"
  local scan_exit_code="${SCAN_EXIT_CODE:-0}"
  local token="${GH_TOKEN:-${GITHUB_TOKEN:-${INPUT_TOKEN:-}}}"
  local event_name="${GITHUB_EVENT_NAME:-}"
  local event_path="${GITHUB_EVENT_PATH:-}"
  local repo="${GITHUB_REPOSITORY:-}"

  # 1. Reject pull_request_target explicitly
  if [ "$event_name" = "pull_request_target" ]; then
    echo "::error::Pretrust comment rejects 'pull_request_target' events. Running scans or comments under pull_request_target is unsafe because checked-out code may diverge from the PR head while executing with elevated write permissions. Use 'pull_request' instead." >&2
    exit 2
  fi

  # Check if running in a pull request context
  if [ "$event_name" != "pull_request" ]; then
    echo "Pretrust: Event '$event_name' is not a pull request. Skipping PR comment."
    exit 0
  fi

  # Ensure gh CLI is installed
  if ! command -v gh >/dev/null 2>&1; then
    echo "::error::GitHub CLI (gh) is required on the runner for PR comments. Ubuntu runners include gh by default." >&2
    exit 2
  fi

  if [ -z "$event_path" ] || [ ! -f "$event_path" ]; then
    echo "Pretrust: GITHUB_EVENT_PATH not available. Skipping PR comment."
    exit 0
  fi

  local pr_info
  pr_info="$(python3 -c '
import json, sys
try:
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        data = json.load(f)
    pr = data.get("pull_request", {})
    pr_num = pr.get("number", "")
    head_repo = pr.get("head", {}).get("repo", {}).get("full_name", "")
    base_repo = pr.get("base", {}).get("repo", {}).get("full_name", "")
    is_fork = "1" if (head_repo and base_repo and head_repo != base_repo) or pr.get("head", {}).get("repo", {}).get("fork", False) else "0"
    print(f"{pr_num}\t{is_fork}")
except Exception:
    pass
' "$event_path" 2>/dev/null || true)"

  local pr_num
  pr_num="$(echo "$pr_info" | cut -f1)"
  local is_fork
  is_fork="$(echo "$pr_info" | cut -f2)"

  if [ -z "$pr_num" ]; then
    echo "Pretrust: Could not identify pull request number. Skipping PR comment."
    exit 0
  fi

  # 2. Check GitHub token
  if [ -z "$token" ]; then
    echo "::error::Pretrust PR comment is enabled, but no GitHub token was provided. Pass 'token: \${{ github.token }}'." >&2
    exit 1
  fi
  export GH_TOKEN="$token"

  if [ -z "$repo" ]; then
    echo "::error::GITHUB_REPOSITORY is not set. Cannot post PR comment." >&2
    exit 1
  fi

  # 3. Check changed files in the pull request
  local files_tmp
  files_tmp="$(mktemp "${RUNNER_TEMP:-/tmp}/pretrust-pr-files.XXXXXX")"
  if ! get_pr_changed_files "$pr_num" "$files_tmp" "$repo"; then
    rm -f "$files_tmp"
    exit 1
  fi

  local agent_files_modified=0
  while IFS= read -r changed_file || [ -n "$changed_file" ]; do
    [ -z "$changed_file" ] && continue
    if is_agent_config_file "$changed_file"; then
      agent_files_modified=1
      break
    fi
  done < "$files_tmp"
  rm -f "$files_tmp"

  if [ "$agent_files_modified" -eq 0 ]; then
    echo "Pretrust: No agent configuration or instruction files were modified in PR #$pr_num. Skipping PR comment."
    exit 0
  fi

  echo "Pretrust: Agent configuration or instruction changes detected in PR #$pr_num."

  # 4. Parse SARIF for findings metadata (counts, severity, rule IDs only - never content or paths)
  if [ -z "$sarif_file" ] || [ ! -f "$sarif_file" ]; then
    echo "::error::SARIF file not found at '$sarif_file'. Cannot generate PR comment." >&2
    exit 1
  fi

  local marker="<!-- pretrust-agent-guard-comment -->"
  local comment_body
  comment_body="$(python3 -c '
import json, sys

sarif_path = sys.argv[1]
fail_on = sys.argv[2]
marker = sys.argv[3]
scan_exit_code = sys.argv[4] if len(sys.argv) > 4 else "0"

try:
    with open(sarif_path, "r", encoding="utf-8") as f:
        data = json.load(f)
except Exception:
    sys.stderr.write("::error::Failed to parse SARIF file (category: JSON parse error).\n")
    sys.exit(2)

runs = data.get("runs", [])
results = []
if runs and isinstance(runs, list):
    results = runs[0].get("results", [])

total_count = len(results)
error_count = sum(1 for r in results if r.get("level") == "error")
warning_count = sum(1 for r in results if r.get("level") == "warning")
note_count = sum(1 for r in results if r.get("level") == "note")

rule_ids = sorted(list({str(r.get("ruleId", "")).strip() for r in results if r.get("ruleId")}))

lines = [
    marker,
    "### 🛡️ Pretrust Agent Configuration Scan",
    "",
    "Agent configuration or instruction files were modified in this pull request.",
    "",
]

if total_count == 0:
    lines.extend([
        "- **Status**: ✅ No security findings detected",
        "- **Findings count**: 0",
        "",
        "No execution sinks, unverified lifecycle hooks, or unsafe agent settings were detected in the modified configuration files.",
    ])
elif scan_exit_code == "0":
    lines.extend([
        f"- **Status**: ℹ️ No findings above threshold (`{fail_on}`)",
        f"- **Total findings count**: {total_count} (below threshold)",
        f"  - **Error (High / Critical)**: {error_count}",
        f"  - **Warning (Medium)**: {warning_count}",
        f"  - **Note (Low / Info)**: {note_count}",
        "",
        "- **Triggered Rule IDs**: " + (", ".join(f"`{rid}`" for rid in rule_ids) if rule_ids else "None"),
        "",
        "> Findings were detected below the configured failure threshold. Review finding details in the repository **GitHub Code Scanning** tab (SARIF upload).",
    ])
else:
    status_label = f"⚠️ Findings meeting or exceeding threshold (`{fail_on}`)"
    lines.extend([
        f"- **Status**: {status_label}",
        f"- **Total findings count**: {total_count}",
        f"  - **Error (High / Critical)**: {error_count}",
        f"  - **Warning (Medium)**: {warning_count}",
        f"  - **Note (Low / Info)**: {note_count}",
        "",
        "- **Triggered Rule IDs**: " + (", ".join(f"`{rid}`" for rid in rule_ids) if rule_ids else "None"),
        "",
        "> Full finding details, locations, and remediation steps are recorded in the repository **GitHub Code Scanning** tab (SARIF upload).",
    ])

print("\n".join(lines))
' "$sarif_file" "$fail_on" "$marker" "$scan_exit_code")"

  # 5. Idempotent comment: find existing comment ID
  local existing_id
  existing_id="$(find_existing_comment_id "$pr_num" "$marker" "$repo")" || exit 1

  # 6. Post or update comment
  post_or_update_comment "$pr_num" "$comment_body" "$existing_id" "$repo" "$is_fork"
}

main "$@"
