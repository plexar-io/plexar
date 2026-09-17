#!/usr/bin/env bash
set -euo pipefail

# Build an air-gap bundle: plexar + trivy + vuln DB in one tarball.
# Run this on a machine with internet. Transfer the tarball to the target node.
#
# Usage:
#   ./scripts/bundle-airgap.sh                  # linux/amd64 (default)
#   ./scripts/bundle-airgap.sh linux arm64      # linux/arm64
#
# On the air-gapped node:
#   tar xzf plexar-airgap-linux-amd64.tar.gz
#   cd plexar/
#   ./install.sh        # copies to /usr/local/bin or ~/bin

TARGET_OS="${1:-linux}"
TARGET_ARCH="${2:-amd64}"
TRIVY_VERSION="0.73.0"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUNDLE_DIR="$(mktemp -d)/plexar"
OUTFILE="plexar-airgap-${TARGET_OS}-${TARGET_ARCH}.tar.gz"

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${BLUE}=>${NC} $*"; }
ok()    { echo -e "${GREEN}✓${NC}  $*"; }
warn()  { echo -e "${RED}!${NC}  $*"; }
fail()  { echo -e "${RED}✗${NC}  $*" >&2; exit 1; }

mkdir -p "$BUNDLE_DIR"

# ── Step 1: Build plexar binary ──
info "Building plexar for ${TARGET_OS}/${TARGET_ARCH}..."
cd "$PROJECT_DIR"
GOOS="$TARGET_OS" GOARCH="$TARGET_ARCH" CGO_ENABLED=0 go build -ldflags="-s -w" -o "$BUNDLE_DIR/plexar" .
ok "plexar binary built ($(du -h "$BUNDLE_DIR/plexar" | cut -f1))"

# ── Step 2: Download Trivy ──
info "Downloading trivy v${TRIVY_VERSION} for ${TARGET_OS}/${TARGET_ARCH}..."

# Map arch names for Trivy's release naming
TRIVY_ARCH="$TARGET_ARCH"
case "$TARGET_ARCH" in
  amd64) TRIVY_ARCH="64bit" ;;
  arm64) TRIVY_ARCH="ARM64" ;;
esac
TRIVY_OS="$(echo "$TARGET_OS" | sed 's/linux/Linux/;s/darwin/macOS/')"

TRIVY_URL="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${TRIVY_OS}-${TRIVY_ARCH}.tar.gz"
curl -fsSL "$TRIVY_URL" | tar -xz -C "$BUNDLE_DIR" trivy 2>/dev/null || {
  # Some releases use different naming
  TRIVY_URL="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${TRIVY_OS}_${TRIVY_ARCH}.tar.gz"
  curl -fsSL "$TRIVY_URL" | tar -xz -C "$BUNDLE_DIR" trivy
}
ok "trivy binary downloaded ($(du -h "$BUNDLE_DIR/trivy" | cut -f1))"

# ── Step 3: Download Trivy vulnerability DB ──
# Use host trivy if available (needed when cross-building, e.g. macOS -> Linux)
TRIVY_CMD="$BUNDLE_DIR/trivy"
HOST_OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
if [ "$HOST_OS" != "$TARGET_OS" ]; then
  if command -v trivy >/dev/null 2>&1; then
    TRIVY_CMD="trivy"
    info "Cross-building: using host trivy for DB download"
  else
    warn "Cross-building without host trivy — downloading DBs with oras..."
  fi
fi

info "Downloading trivy vulnerability DB (this takes a minute)..."
TRIVY_CACHE="$BUNDLE_DIR/trivy-cache"
mkdir -p "$TRIVY_CACHE"
"$TRIVY_CMD" --cache-dir "$TRIVY_CACHE" image --download-db-only --db-repository ghcr.io/aquasecurity/trivy-db:2 2>/dev/null || {
  warn "DB download failed — bundle will work but first scan on target will need DB"
}
if [ -d "$TRIVY_CACHE/db" ]; then
  ok "Vulnerability DB downloaded ($(du -sh "$TRIVY_CACHE/db" | cut -f1))"
fi

# ── Step 4: Download Java DB (for JAR scanning) ──
info "Downloading trivy Java DB..."
"$TRIVY_CMD" --cache-dir "$TRIVY_CACHE" image --download-java-db-only --java-db-repository ghcr.io/aquasecurity/trivy-java-db:1 2>/dev/null || {
  warn "Java DB download failed — Java JAR scanning may be limited"
}
if [ -d "$TRIVY_CACHE/java-db" ]; then
  ok "Java DB downloaded ($(du -sh "$TRIVY_CACHE/java-db" | cut -f1))"
fi

# ── Step 5: Write the on-node install script ──
cat > "$BUNDLE_DIR/install.sh" << 'INSTALL_EOF'
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Determine install location
if [ -w /usr/local/bin ]; then
  BIN_DIR="/usr/local/bin"
else
  BIN_DIR="$HOME/.local/bin"
  mkdir -p "$BIN_DIR"
fi

# Determine cache location (use /data if /home is full, common on NDFC)
HOME_FREE=$(df "$HOME" 2>/dev/null | tail -1 | awk '{print $4}')
if [ -n "$HOME_FREE" ] && [ "$HOME_FREE" -lt 2000000 ] 2>/dev/null; then
  # Less than 2GB free on /home — look for a bigger partition
  for dir in /data/services/atx_ctx /data /opt /var/lib; do
    if [ -d "$dir" ] && [ -w "$dir" ]; then
      CACHE_DIR="$dir/plexar/trivy-cache"
      break
    fi
  done
fi
CACHE_DIR="${CACHE_DIR:-$HOME/.plexar/trivy-cache}"
mkdir -p "$CACHE_DIR"

# Copy binaries
cp "$SCRIPT_DIR/plexar" "$BIN_DIR/plexar"
chmod +x "$BIN_DIR/plexar"
cp "$SCRIPT_DIR/trivy" "$BIN_DIR/trivy"
chmod +x "$BIN_DIR/trivy"

# Copy vulnerability databases
if [ -d "$SCRIPT_DIR/trivy-cache/db" ]; then
  cp -r "$SCRIPT_DIR/trivy-cache/db" "$CACHE_DIR/"
fi
if [ -d "$SCRIPT_DIR/trivy-cache/java-db" ]; then
  cp -r "$SCRIPT_DIR/trivy-cache/java-db" "$CACHE_DIR/"
fi

echo ""
echo "  Plexar installed successfully!"
echo ""
echo "  Binaries:  $BIN_DIR/plexar, $BIN_DIR/trivy"
echo "  Cache:     $CACHE_DIR"
echo ""

# Check PATH
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) echo "  Add to PATH:  export PATH=\"$BIN_DIR:\$PATH\""
     echo "" ;;
esac

echo "  Quick start:"
echo "    export TRIVY_CACHE_DIR=$CACHE_DIR"
echo "    plexar scan -n <namespace>"
echo "    plexar serve"
echo ""
INSTALL_EOF
chmod +x "$BUNDLE_DIR/install.sh"

# ── Step 6: Package ──
info "Packaging bundle..."
PARENT_DIR="$(dirname "$BUNDLE_DIR")"
tar czf "$PROJECT_DIR/$OUTFILE" -C "$PARENT_DIR" plexar/

FINAL_SIZE=$(du -h "$PROJECT_DIR/$OUTFILE" | cut -f1)
rm -rf "$PARENT_DIR"

echo ""
echo -e "${BOLD}Air-gap bundle ready:${NC} ${OUTFILE} (${FINAL_SIZE})"
echo ""
echo "  Transfer to the target node:"
echo "    scp ${OUTFILE} user@node:/tmp/"
echo ""
echo "  On the target node:"
echo "    tar xzf /tmp/${OUTFILE}"
echo "    cd plexar/"
echo "    ./install.sh"
echo ""
