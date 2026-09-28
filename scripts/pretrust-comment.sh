#!/usr/bin/env bash
set -euo pipefail

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
  local token="$3"
  local repo="$4"

  if command -v gh >/dev/null 2>&1; then
    local err_tmp
    err_tmp="$(mktemp "${RUNNER_TEMP:-/tmp}/pretrust-gh-err.XXXXXX")"
    if ! gh api --paginate "repos/$repo/pulls/$pr_num/files" --jq '.[].filename' > "$files_tmp" 2> "$err_tmp"; then
      local err_content
      err_content="$(cat "$err_tmp")"
      rm -f "$err_tmp"
      echo "::error::GitHub API query for PR #$pr_num files failed: $err_content" >&2
      if echo "$err_content" | grep -iqE "forbidden|resource not accessible|permission|403|bad credentials"; then
        echo "::error::GitHub token lacks 'pull-requests: read' permission. On pull requests from forks, the default token has read-only access." >&2
      fi
      return 1
    fi
    rm -f "$err_tmp"
  else
    local api_url="${GITHUB_API_URL:-https://api.github.com}"
    local http_code
    http_code="$(curl -s -S -w "%{http_code}" \
      -H "Authorization: Bearer $token" \
      -H "Accept: application/vnd.github+json" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      "$api_url/repos/$repo/pulls/$pr_num/files" \
      -o "$files_tmp")"

    if [ "$http_code" -lt 200 ] || [ "$http_code" -ge 300 ]; then
      echo "::error::GitHub API returned HTTP $http_code when querying files for PR #$pr_num." >&2
      if [ "$http_code" -eq 403 ] || [ "$http_code" -eq 401 ]; then
        echo "::error::GitHub token lacks required permissions (pull-requests: read) or was forbidden." >&2
      fi
      return 1
    fi
    local parsed
    parsed="$(jq -r '.[].filename // empty' "$files_tmp" 2>/dev/null || true)"
    echo "$parsed" > "$files_tmp"
  fi
  return 0
}

find_existing_comment_id() {
  local pr_num="$1"
  local marker="$2"
  local repo="$3"

  if command -v gh >/dev/null 2>&1; then
    local comments_tmp
    comments_tmp="$(mktemp "${RUNNER_TEMP:-/tmp}/pretrust-comments.XXXXXX")"
    local err_tmp
    err_tmp="$(mktemp "${RUNNER_TEMP:-/tmp}/pretrust-gh-err.XXXXXX")"

    if ! gh api --paginate "repos/$repo/issues/$pr_num/comments" > "$comments_tmp" 2> "$err_tmp"; then
      local err_content
      err_content="$(cat "$err_tmp")"
      rm -f "$err_tmp" "$comments_tmp"
      echo "::error::GitHub API query for PR #$pr_num comments failed: $err_content" >&2
      if echo "$err_content" | grep -iqE "forbidden|resource not accessible|permission|403"; then
        echo "::error::GitHub token lacks 'pull-requests: write' or 'issues: write' permission. Pull requests from forks cannot post comments with the default read-only token." >&2
      fi
      exit 1
    fi
    rm -f "$err_tmp"

    local existing_id
    existing_id="$(python3 -c '
import json, sys
marker = sys.argv[1]
with open(sys.argv[2], "r", encoding="utf-8") as f:
    comments = json.load(f)
for c in comments:
    if marker in c.get("body", ""):
        print(c.get("id", ""))
        break
' "$marker" "$comments_tmp" 2>/dev/null || true)"
    rm -f "$comments_tmp"
    echo "$existing_id"
  fi
  return 0
}

post_or_update_comment() {
  local pr_num="$1"
  local comment_body="$2"
  local existing_id="$3"
  local repo="$4"
  local err_tmp
  err_tmp="$(mktemp "${RUNNER_TEMP:-/tmp}/pretrust-gh-err.XXXXXX")"

  if [ -n "$existing_id" ]; then
    echo "Pretrust: Updating existing comment ID $existing_id on PR #$pr_num..."
    if ! gh api --method PATCH "repos/$repo/issues/$pr_num/comments/$existing_id" -f body="$comment_body" >/dev/null 2> "$err_tmp"; then
      local err_content
      err_content="$(cat "$err_tmp")"
      rm -f "$err_tmp"
      echo "::error::Failed to update PR comment #$existing_id: $err_content" >&2
      if echo "$err_content" | grep -iqE "forbidden|resource not accessible|permission|403"; then
        echo "::error::GitHub token lacks 'pull-requests: write' permission to update comment. Pull requests from forks cannot post comments with the default read-only token." >&2
      fi
      exit 1
    fi
  else
    echo "Pretrust: Creating new comment on PR #$pr_num..."
    if ! gh api --method POST "repos/$repo/issues/$pr_num/comments" -f body="$comment_body" >/dev/null 2> "$err_tmp"; then
      local err_content
      err_content="$(cat "$err_tmp")"
      rm -f "$err_tmp"
      echo "::error::Failed to create PR comment on PR #$pr_num: $err_content" >&2
      if echo "$err_content" | grep -iqE "forbidden|resource not accessible|permission|403"; then
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
  local token="${GITHUB_TOKEN:-${INPUT_TOKEN:-}}"
  local event_name="${GITHUB_EVENT_NAME:-}"
  local event_path="${GITHUB_EVENT_PATH:-}"
  local repo="${GITHUB_REPOSITORY:-}"

  # 1. Check if running in a pull request context
  if [ "$event_name" != "pull_request" ] && [ "$event_name" != "pull_request_target" ]; then
    echo "Pretrust: Event '$event_name' is not a pull request. Skipping PR comment."
    exit 0
  fi

  if [ -z "$event_path" ] || [ ! -f "$event_path" ]; then
    echo "Pretrust: GITHUB_EVENT_PATH not available. Skipping PR comment."
    exit 0
  fi

  local pr_num
  pr_num="$(python3 -c '
import json, sys
try:
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        data = json.load(f)
    print(data.get("pull_request", {}).get("number", ""))
except Exception:
    pass
' "$event_path" 2>/dev/null || true)"

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
  if ! get_pr_changed_files "$pr_num" "$files_tmp" "$token" "$repo"; then
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

try:
    with open(sarif_path, "r", encoding="utf-8") as f:
        data = json.load(f)
except Exception as e:
    sys.stderr.write(f"::error::Failed to parse SARIF file: {e}\n")
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
        "- **Status**: ✅ Clean (no pre-trust security findings detected)",
        "- **Findings count**: 0",
        "",
        "No execution sinks, unverified lifecycle hooks, or unsafe agent settings were detected in the modified configuration files.",
    ])
else:
    status_label = "⚠️ Findings detected (Threshold: `" + fail_on + "`)"
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
' "$sarif_file" "$fail_on" "$marker")"

  # 5. Idempotent comment: find existing comment ID
  local existing_id
  existing_id="$(find_existing_comment_id "$pr_num" "$marker" "$repo")" || exit 1

  # 6. Post or update comment
  post_or_update_comment "$pr_num" "$comment_body" "$existing_id" "$repo"
}

main "$@"
