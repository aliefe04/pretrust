#!/bin/sh
# Pretrust one-line installer
# Usage: curl -fsSL https://raw.githubusercontent.com/aliefe04/pretrust/main/install.sh | sh

set -e

REPO="aliefe04/pretrust"
VERSION="v0.1.0"

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Darwin)
        TARGET_OS="apple-darwin"
        ;;
    Linux)
        TARGET_OS="unknown-linux-musl"
        ;;
    *)
        echo "Unsupported operating system: $OS" >&2
        exit 1
        ;;
esac

case "$ARCH" in
    arm64|aarch64)
        TARGET_ARCH="aarch64"
        ;;
    x86_64|amd64)
        TARGET_ARCH="x86_64"
        ;;
    *)
        echo "Unsupported architecture: $ARCH" >&2
        exit 1
        ;;
esac

TARGET="${TARGET_ARCH}-${TARGET_OS}"
ARCHIVE_NAME="pretrust-${TARGET}.tar.gz"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${ARCHIVE_NAME}"

# Determine install directory
if [ -w "/usr/local/bin" ]; then
    INSTALL_DIR="/usr/local/bin"
else
    INSTALL_DIR="${HOME}/.local/bin"
    mkdir -p "$INSTALL_DIR"
fi

echo "==> Downloading pretrust (${TARGET})..."
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

if curl -fsSL "$DOWNLOAD_URL" -o "$TMP_DIR/$ARCHIVE_NAME" 2>/dev/null; then
    tar -xzf "$TMP_DIR/$ARCHIVE_NAME" -C "$TMP_DIR"
    cp "$TMP_DIR/pretrust" "$INSTALL_DIR/pretrust"
    chmod +x "$INSTALL_DIR/pretrust"
else
    # Fallback: if release tarball not yet built on GitHub, check if local cargo exists
    echo "Notice: Release asset not reachable via direct URL, checking cargo..."
    if command -v cargo >/dev/null 2>&1; then
        echo "==> Installing via cargo..."
        cargo install --git "https://github.com/${REPO}" pretrust-cli --bin pretrust --root "${HOME}/.local"
        INSTALL_DIR="${HOME}/.local/bin"
    else
        echo "Error: Could not download prebuilt binary and cargo is not installed." >&2
        exit 1
    fi
fi

echo "==> Successfully installed pretrust to ${INSTALL_DIR}/pretrust"

# Check if INSTALL_DIR is in PATH
case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *)
        echo "Note: Add $INSTALL_DIR to your PATH in your shell config:"
        echo "  export PATH=\"\$PATH:$INSTALL_DIR\""
        ;;
esac

"${INSTALL_DIR}/pretrust" --version
