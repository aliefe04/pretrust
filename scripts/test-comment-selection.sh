#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
COMMENT_SCRIPT="$SCRIPT_DIR/pretrust-comment.sh"

if [ ! -f "$COMMENT_SCRIPT" ]; then
  echo "Error: Comment script not found at $COMMENT_SCRIPT" >&2
  exit 1
fi

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/pretrust-test.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

MARKER="<!-- pretrust-agent-guard-comment -->"

# Test 1: Realistic paginated JSON across 3 pages concatenated ([...][...][...])
# Page 1 contains an attacker comment planting the exact marker
# Page 2 contains the genuine github-actions[bot] comment
# Page 3 contains another bot comment without the marker
PAGE_FILE="$TMP_DIR/paginated_comments.json"
cat > "$PAGE_FILE" << 'EOF'
[
  {
    "id": 101,
    "user": {
      "login": "octocat",
      "type": "User"
    },
    "body": "LGTM! Approved."
  },
  {
    "id": 102,
    "user": {
      "login": "attacker-user",
      "type": "User"
    },
    "body": "<!-- pretrust-agent-guard-comment -->\nAttacker trying to trick the bot into editing their comment."
  }
][
  {
    "id": 201,
    "user": {
      "login": "reviewer",
      "type": "User"
    },
    "body": "Needs minor fix."
  },
  {
    "id": 202,
    "user": {
      "login": "github-actions[bot]",
      "type": "Bot"
    },
    "body": "<!-- pretrust-agent-guard-comment -->\n### 🛡️ Pretrust Agent Configuration Scan\n- **Status**: ℹ️ No findings above threshold (`high`)"
  }
][
  {
    "id": 301,
    "user": {
      "login": "github-actions[bot]",
      "type": "Bot"
    },
    "body": "CodeQL scan succeeded."
  }
]
EOF

RESULT_1="$(bash "$COMMENT_SCRIPT" --select-comment-id "$MARKER" "$PAGE_FILE")"
if [ "$RESULT_1" = "102" ]; then
  echo "FAILED: Selected attacker comment ID 102 instead of bot comment!" >&2
  exit 1
fi
if [ "$RESULT_1" != "202" ]; then
  echo "FAILED: Expected bot comment ID 202, got '$RESULT_1'" >&2
  exit 1
fi
echo "PASS: Correctly selected github-actions[bot] ID 202 over attacker marker 102 across paginated JSON."

# Test 2: Attacker comment exists with marker, but no bot comment exists
ATTACKER_ONLY_FILE="$TMP_DIR/attacker_only.json"
cat > "$ATTACKER_ONLY_FILE" << 'EOF'
[
  {
    "id": 555,
    "user": {
      "login": "malicious-user",
      "type": "User"
    },
    "body": "<!-- pretrust-agent-guard-comment --> plant"
  }
]
EOF

RESULT_2="$(bash "$COMMENT_SCRIPT" --select-comment-id "$MARKER" "$ATTACKER_ONLY_FILE")"
if [ -n "$RESULT_2" ]; then
  echo "FAILED: Expected empty comment ID when only attacker comment exists, got '$RESULT_2'" >&2
  exit 1
fi
echo "PASS: Ignored attacker comment when no bot comment exists (returns empty ID)."

# Test 3: Multiple pages with newline separation
NEWLINE_PAGE_FILE="$TMP_DIR/newline_pages.json"
cat > "$NEWLINE_PAGE_FILE" << 'EOF'
[{"id": 601, "user": {"login": "alice", "type": "User"}, "body": "first page"}]
[{"id": 602, "user": {"login": "github-actions[bot]", "type": "Bot"}, "body": "<!-- pretrust-agent-guard-comment --> second page bot"}]
EOF

RESULT_3="$(bash "$COMMENT_SCRIPT" --select-comment-id "$MARKER" "$NEWLINE_PAGE_FILE")"
if [ "$RESULT_3" != "602" ]; then
  echo "FAILED: Expected comment ID 602 from newline-separated pages, got '$RESULT_3'" >&2
  exit 1
fi
echo "PASS: Correctly parsed newline-separated paginated JSON and extracted bot comment ID 602."

# Test 4: Malformed JSON must fail closed (exit non-zero)
MALFORMED_FILE="$TMP_DIR/malformed.json"
cat > "$MALFORMED_FILE" << 'EOF'
[{"id": 700, "user":
EOF

set +e
RESULT_4="$(bash "$COMMENT_SCRIPT" --select-comment-id "$MARKER" "$MALFORMED_FILE" 2>/dev/null)"
STATUS_4=$?
set -e

if [ "$STATUS_4" -eq 0 ]; then
  echo "FAILED: Malformed JSON should exit non-zero (fail closed), but exited with code 0" >&2
  exit 1
fi
echo "PASS: Malformed JSON fails closed with non-zero exit code."

# Test 5: Empty comments file returns empty ID
EMPTY_FILE="$TMP_DIR/empty.json"
: > "$EMPTY_FILE"

RESULT_5="$(bash "$COMMENT_SCRIPT" --select-comment-id "$MARKER" "$EMPTY_FILE")"
if [ -n "$RESULT_5" ]; then
  echo "FAILED: Expected empty string on empty comments file, got '$RESULT_5'" >&2
  exit 1
fi
echo "PASS: Empty comments file returns empty ID without error."

echo "All comment identity and pagination tests passed successfully."
