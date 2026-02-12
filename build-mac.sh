#!/usr/bin/env bash
set -euo pipefail
# build-mac.sh -- macOS build. Produces build/lancer-agentic-radar and, when
# cargo-bundle is available, a lancer-agentic-radar.app bundle.

REPO="$(cd "$(dirname "$0")" && pwd)"
BUILD="$REPO/build"
BIN="lancer-agentic-radar"
CLI="lancer-agentic-radar-cli"

echo "================================================"
echo "  lancer-agentic-radar Build (macOS)"
echo "================================================"

echo "[1/2] Building release binary..."
cargo build --release

echo "[2/2] Copying to build/..."
mkdir -p "$BUILD"
cp "$REPO/target/release/$BIN" "$BUILD/"
[[ -f "$REPO/target/release/$CLI" ]] && cp "$REPO/target/release/$CLI" "$BUILD/" || true

if command -v cargo-bundle >/dev/null 2>&1; then
  echo "[bundle] cargo-bundle found — building .app ..."
  (cd "$REPO/lancer-agentic-radar" && cargo bundle --release) || \
    echo "  cargo-bundle failed (non-fatal); plain binary is in $BUILD/"
else
  echo "[bundle] cargo-bundle not installed; skipping .app (install with: cargo install cargo-bundle)"
fi

echo ""
echo "Done!  Binary ready: $BUILD/$BIN"
