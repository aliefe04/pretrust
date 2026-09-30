#!/bin/sh
# Pretrust one-line installer
# Usage: curl -fsSL https://raw.githubusercontent.com/aliefe04/pretrust/main/install.sh | sh
#
# Environment overrides:
#   PRETRUST_VERSION      release tag to install (default: latest)
#   PRETRUST_BASE_URL     releases base URL (default: GitHub releases for this repo)
#   PRETRUST_INSTALL_DIR  install directory (default: /usr/local/bin, else ~/.local/bin)

set -eu

REPO="aliefe04/pretrust"
REQ_VERSION="${PRETRUST_VERSION:-latest}"
VERSION="$REQ_VERSION"
BASE_URL="${PRETRUST_BASE_URL:-https://github.com/${REPO}/releases}"

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Darwin)
        TARGET_OS="apple-darwin"
        ;;
    Linux)
        TARGET_OS="unknown-linux-gnu"
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

# Portable SHA-256: GNU coreutils on Linux, shasum on macOS.
if command -v sha256sum >/dev/null 2>&1; then
    sha256_of() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
    sha256_of() { shasum -a 256 "$1" | awk '{print $1}'; }
else
    echo "Error: need sha256sum or shasum to verify the download." >&2
    exit 1
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

release_url() {
    # GitHub serves a pinned release at /releases/download/<tag>/<asset> but the
    # newest one at /releases/latest/download/<asset>. They are not
    # interchangeable, and /releases/download/latest/... is a 404.
    if [ "$1" = "latest" ]; then
        printf '%s/latest/download/%s' "$BASE_URL" "$2"
    else
        printf '%s/download/%s/%s' "$BASE_URL" "$1" "$2"
    fi
}

DOWNLOAD_URL="$(release_url "$VERSION" "$ARCHIVE_NAME")"
CHECKSUM_URL="${DOWNLOAD_URL}.sha256"

fetch() {
    # $1 = url, $2 = destination.
    # curl's own error text ("curl: (22) The requested URL returned error: 404") is
    # noise for someone who just wants to install a tool, so it is captured and
    # only shown when PRETRUST_VERBOSE=1.
    if curl -fsSL "$1" -o "$2" 2>"$TMP_DIR/curl.log"; then
        return 0
    fi
    if [ "${PRETRUST_VERBOSE:-0}" = "1" ] && [ -s "$TMP_DIR/curl.log" ]; then
        echo "curl: $(cat "$TMP_DIR/curl.log")" >&2
    fi
    return 1
}

install_dir="${PRETRUST_INSTALL_DIR:-}"

if [ -z "$install_dir" ]; then
    if [ -w "/usr/local/bin" ]; then
        install_dir="/usr/local/bin"
    else
        install_dir="${HOME}/.local/bin"
    fi
fi
mkdir -p "$install_dir"

download_ok=0
if fetch "$DOWNLOAD_URL" "$TMP_DIR/$ARCHIVE_NAME"; then
    download_ok=1
elif [ "$VERSION" != "latest" ]; then
    # A pinned tag may not have assets yet; fall back to the newest published one.
    echo "Notice: no assets for ${VERSION}, retrying against the latest release..." >&2
    VERSION="latest"
    DOWNLOAD_URL="$(release_url "$VERSION" "$ARCHIVE_NAME")"
    CHECKSUM_URL="${DOWNLOAD_URL}.sha256"
    if fetch "$DOWNLOAD_URL" "$TMP_DIR/$ARCHIVE_NAME"; then
        download_ok=1
    fi
fi

if [ "$download_ok" -eq 0 ]; then
    echo "Notice: could not download ${ARCHIVE_NAME} from ${DOWNLOAD_URL}" >&2
    if [ "${PRETRUST_NO_CARGO_FALLBACK:-0}" = "1" ]; then
        echo "Error: download failed and PRETRUST_NO_CARGO_FALLBACK=1 is set." >&2
        exit 1
    fi
    if ! command -v cargo >/dev/null 2>&1; then
        echo "Error: download failed and cargo is not installed." >&2
        echo "Build from source instead:" >&2
        echo "  git clone https://github.com/${REPO} && cd ${REPO} && cargo build --release --locked" >&2
        exit 1
    fi

    # `cargo install --git` with neither --tag nor --rev builds whatever the
    # default branch points at today, which is not the release this installer
    # was asked for. Pin it. When the caller asked for "latest" there is no tag
    # to pin to, so resolve the actual latest release rather than guessing.
    build_tag="$REQ_VERSION"
    if [ "$build_tag" = "latest" ]; then
        latest_url="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "${BASE_URL}/latest" 2>/dev/null || true)"
        case "$latest_url" in
            */tag/*) build_tag="${latest_url##*/tag/}" ;;
            *)
                echo "Error: could not resolve which release is latest, so the source build" >&2
                echo "would not be pinned to any known version. Refusing to guess." >&2
                echo "Re-run with PRETRUST_VERSION set to the tag you want." >&2
                exit 1
                ;;
        esac
        echo "==> Resolved latest release to ${build_tag}" >&2
    fi

    echo "==> Falling back to building ${build_tag} from source with cargo..." >&2
    # Build into a scratch root and copy from there. Deriving a cargo root from
    # install_dir would only work when the caller happened to name it "bin".
    cargo_root="$TMP_DIR/cargo-root"
    mkdir -p "$cargo_root"
    # Positional arguments rather than an expanded string: paths may contain spaces.
    set -- install --git "https://github.com/${REPO}" pretrust --bin pretrust \
        --locked --root "$cargo_root" --tag "$build_tag"
    cargo "$@"
    mkdir -p "$install_dir"
    cp "$cargo_root/bin/pretrust" "$install_dir/pretrust"
    chmod +x "$install_dir/pretrust"
else
    # Verification is mandatory: this installer is the first thing a security tool
    # asks people to pipe into a shell, so an unverified download is not installable.
    if ! fetch "$CHECKSUM_URL" "$TMP_DIR/$ARCHIVE_NAME.sha256"; then
        echo "Error: could not fetch the SHA-256 sidecar for ${ARCHIVE_NAME}; refusing to install unverified." >&2
        exit 1
    fi

    expected="$(awk '{print $1; exit}' "$TMP_DIR/$ARCHIVE_NAME.sha256")"
    actual="$(sha256_of "$TMP_DIR/$ARCHIVE_NAME")"

    if [ -z "$expected" ]; then
        echo "Error: empty SHA-256 sidecar; refusing to install unverified." >&2
        exit 1
    fi

    if [ "$expected" != "$actual" ]; then
        echo "Error: SHA-256 mismatch for ${ARCHIVE_NAME}." >&2
        echo "  expected ${expected}" >&2
        echo "  actual   ${actual}" >&2
        echo "Refusing to install. If you just rebuilt a local release, this is expected." >&2
        exit 1
    fi

    echo "==> SHA-256 verified: ${actual}"
    tar -xzf "$TMP_DIR/$ARCHIVE_NAME" -C "$TMP_DIR"
    cp "$TMP_DIR/pretrust" "$install_dir/pretrust"
    chmod +x "$install_dir/pretrust"
fi

echo "==> Installed pretrust to ${install_dir}/pretrust"

case ":$PATH:" in
    *":$install_dir:"*) ;;
    *)
        echo "Note: add the install directory to your PATH:"
        echo "  export PATH=\"\$PATH:${install_dir}\""
        ;;
esac

"${install_dir}/pretrust" --version