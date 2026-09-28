#!/usr/bin/env bash
set -euo pipefail

# Determine action directory (trusted action source)
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ACTION_PATH="${GITHUB_ACTION_PATH:-"$(cd -- "$SCRIPT_DIR/.." && pwd)"}"

ensure_rust() {
  if ! command -v cargo >/dev/null 2>&1 || ! command -v rustc >/dev/null 2>&1; then
    if command -v rustup >/dev/null 2>&1; then
      echo "Pretrust: cargo or rustc not found on PATH. Configuring stable toolchain via host rustup..." >&2
      rustup default stable
    else
      echo "::error::Neither cargo nor rustc found on PATH, and host rustup is not available." >&2
      exit 2
    fi
  fi

  local rust_ver
  rust_ver="$(rustc --version 2>/dev/null | awk '{print $2}')"
  local rust_major
  rust_major="$(echo "$rust_ver" | cut -d. -f1)"
  local rust_minor
  rust_minor="$(echo "$rust_ver" | cut -d. -f2)"

  if [ "${rust_major:-0}" -lt 1 ] || { [ "${rust_major:-0}" -eq 1 ] && [ "${rust_minor:-0}" -lt 88 ]; }; then
    if command -v rustup >/dev/null 2>&1; then
      echo "Pretrust: Installed rustc ($rust_ver) is older than 1.88. Updating via host rustup..." >&2
      rustup update stable
      rustup default stable
    else
      echo "::error::Pretrust requires Rust >= 1.88, but found $rust_ver and rustup is not available." >&2
      exit 2
    fi
  fi
}

build_cli() {

  ensure_rust

  local target_dir="${CARGO_TARGET_DIR:-"${RUNNER_TEMP:-/tmp}/pretrust-cargo-target"}"
  mkdir -p "$target_dir"

  echo "Pretrust: Building CLI binary from trusted action source at $ACTION_PATH..."
  (
    cd "$ACTION_PATH"
    CARGO_TARGET_DIR="$target_dir" cargo build --release --locked --manifest-path "$ACTION_PATH/crates/pretrust-cli/Cargo.toml" --bin pretrust
  )

  PRETRUST_BIN="$target_dir/release/pretrust"
  if [ ! -x "$PRETRUST_BIN" ]; then
    echo "::error::Failed to locate built Pretrust binary at $PRETRUST_BIN" >&2
    exit 2
  fi
}

main() {
  local scan_target="${INPUT_PATH:-"${1:-.}"}"
  local fail_on="${INPUT_FAIL_ON:-"${2:-high}"}"

  # Normalize fail_on to lower case
  fail_on="$(echo "$fail_on" | tr '[:upper:]' '[:lower:]' | xargs)"
  case "$fail_on" in
    info|low|medium|high|critical) ;;
    *)
      echo "::error::Invalid fail-on threshold '$fail_on'. Allowed: info, low, medium, high, critical." >&2
      exit 2
      ;;
  esac

  build_cli

  local sarif_dir
  sarif_dir="$(mktemp -d "${RUNNER_TEMP:-/tmp}/pretrust-sarif.XXXXXX")"
  local sarif_file="$sarif_dir/results.sarif"
  local scan_err_file="$sarif_dir/scan.err"

  echo "Pretrust: Scanning workspace (fail-on: $fail_on)..."

  local scan_exit_code=0
  set +e
  "$PRETRUST_BIN" scan "$scan_target" --sarif --fail-on "$fail_on" > "$sarif_file" 2> "$scan_err_file"
  scan_exit_code=$?
  set -e

  # Handle exit status and SARIF validity
  if [ "$scan_exit_code" -ge 2 ]; then
    echo "::error::Pretrust scan failed with invocation or execution error (category: scanner runtime failure, exit code $scan_exit_code)." >&2
    rm -f "$sarif_file" "$scan_err_file"
    if [ -n "${GITHUB_OUTPUT:-}" ]; then
      echo "sarif-file=" >> "$GITHUB_OUTPUT"
      echo "scan-exit-code=$scan_exit_code" >> "$GITHUB_OUTPUT"
    fi
    exit "$scan_exit_code"
  fi

  # Check that SARIF file was generated and non-empty
  if [ ! -s "$sarif_file" ]; then
    echo "::error::Pretrust scan exited with $scan_exit_code but generated an empty SARIF report (category: empty output)." >&2
    rm -f "$scan_err_file"
    rm -f "$sarif_file"
    if [ -n "${GITHUB_OUTPUT:-}" ]; then
      echo "sarif-file=" >> "$GITHUB_OUTPUT"
      echo "scan-exit-code=2" >> "$GITHUB_OUTPUT"
    fi
    exit 2
  fi
  rm -f "$scan_err_file"

  echo "Pretrust: SARIF report generated at $sarif_file"
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    echo "sarif-file=$sarif_file" >> "$GITHUB_OUTPUT"
    echo "scan-exit-code=$scan_exit_code" >> "$GITHUB_OUTPUT"
  fi

  if [ "$scan_exit_code" -eq 1 ]; then
    echo "Pretrust: Security findings met or exceeded threshold '$fail_on'." >&2
  else
    echo "Pretrust: Scan complete. No findings above threshold '$fail_on'."
  fi

  exit "$scan_exit_code"
}

main "$@"
