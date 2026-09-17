#!/usr/bin/env bash
set -euo pipefail

# Plexar installer — downloads the latest release from GitHub.
#
# Usage:
#   curl -sL https://raw.githubusercontent.com/plexar-io/plexar/main/install.sh | sh
#
# Options (env vars):
#   PLEXAR_VERSION=0.5.0   Install a specific version (default: latest)
#   PLEXAR_DIR=/usr/local/bin  Install directory (default: /usr/local/bin or ~/.plexar/bin)
#   PLEXAR_BUNDLE=1        Also download trivy + offline vuln DB for air-gapped use

REPO="plexar-io/plexar"
BINARY="plexar"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${BLUE}=>${NC} $*"; }
ok()    { echo -e "${GREEN}✓${NC}  $*"; }
warn()  { echo -e "${YELLOW}!${NC}  $*"; }
fail()  { echo -e "${RED}✗${NC}  $*" >&2; exit 1; }

# ── Detect OS and architecture ──
detect_platform() {
  OS=$(uname -s | tr '[:upper:]' '[:lower:]')
  ARCH=$(uname -m)

  case "$OS" in
    linux)  OS="linux" ;;
    darwin) OS="darwin" ;;
    *)      fail "Unsupported OS: $OS" ;;
  esac

  case "$ARCH" in
    x86_64|amd64)  ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *)             fail "Unsupported architecture: $ARCH" ;;
  esac
}

# ── Find the install directory ──
detect_install_dir() {
  if [ -n "${PLEXAR_DIR:-}" ]; then
    INSTALL_DIR="$PLEXAR_DIR"
  elif [ -w /usr/local/bin ]; then
    INSTALL_DIR="/usr/local/bin"
  else
    INSTALL_DIR="$HOME/.plexar/bin"
  fi
  mkdir -p "$INSTALL_DIR"
}

# ── Resolve version ──
resolve_version() {
  if [ -n "${PLEXAR_VERSION:-}" ]; then
    VERSION="$PLEXAR_VERSION"
    return
  fi

  info "Fetching latest release..."
  if command -v curl >/dev/null 2>&1; then
    VERSION=$(curl -sI "https://github.com/${REPO}/releases/latest" 2>/dev/null \
      | grep -i '^location:' | sed 's|.*/v||' | tr -d '\r\n')
  elif command -v wget >/dev/null 2>&1; then
    VERSION=$(wget -q --spider --server-response "https://github.com/${REPO}/releases/latest" 2>&1 \
      | grep -i 'Location:' | tail -1 | sed 's|.*/v||' | tr -d '\r\n')
  fi

  if [ -z "${VERSION:-}" ]; then
    fail "Could not determine latest version. Set PLEXAR_VERSION=x.y.z manually."
  fi
}

# ── Download and install ──
download() {
  local url="https://github.com/${REPO}/releases/download/v${VERSION}/${BINARY}_${VERSION}_${OS}_${ARCH}.tar.gz"
  local tmp
  tmp=$(mktemp -d)
  trap "rm -rf $tmp" EXIT

  info "Downloading plexar v${VERSION} (${OS}/${ARCH})..."

  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$tmp/plexar.tar.gz" || fail "Download failed. Check version exists: $url"
  elif command -v wget >/dev/null 2>&1; then
    wget -q "$url" -O "$tmp/plexar.tar.gz" || fail "Download failed. Check version exists: $url"
  else
    fail "Neither curl nor wget found. Install one and retry."
  fi

  tar -xzf "$tmp/plexar.tar.gz" -C "$tmp"

  # Find the binary (may be in root or a subdirectory)
  local bin
  bin=$(find "$tmp" -name "plexar" -type f | head -1)
  if [ -z "$bin" ]; then
    fail "Binary not found in archive"
  fi

  chmod +x "$bin"
  mv "$bin" "${INSTALL_DIR}/${BINARY}"
  ok "Installed plexar v${VERSION} to ${INSTALL_DIR}/${BINARY}"
}

# ── Verify ──
verify() {
  if ! "${INSTALL_DIR}/${BINARY}" version >/dev/null 2>&1; then
    warn "Binary installed but 'plexar version' failed — may need exec permissions"
  fi

  # Check if install dir is in PATH
  case ":$PATH:" in
    *":${INSTALL_DIR}:"*) ;;
    *)
      echo ""
      warn "${INSTALL_DIR} is not in your PATH. Add it:"
      echo ""
      echo "    export PATH=\"${INSTALL_DIR}:\$PATH\""
      echo ""
      echo "  Or add to your shell profile:"
      echo "    echo 'export PATH=\"${INSTALL_DIR}:\$PATH\"' >> ~/.bashrc"
      ;;
  esac
}

# ── Main ──
main() {
  echo ""
  echo -e "${BOLD}Plexar Installer${NC}"
  echo ""

  detect_platform
  detect_install_dir
  resolve_version
  download
  verify

  echo ""
  echo -e "${BOLD}Quick start:${NC}"
  echo ""
  echo "  # Scan the current cluster"
  echo "  plexar scan -A"
  echo ""
  echo "  # Scan a specific namespace"
  echo "  plexar scan -n my-namespace"
  echo ""
  echo "  # Start the dashboard"
  echo "  plexar serve"
  echo ""
}

main
