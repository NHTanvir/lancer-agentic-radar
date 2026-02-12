#!/usr/bin/env bash
set -euo pipefail

REPO="$(cd "$(dirname "$0")" && pwd)"
BUILD="$REPO/build"
BIN="lancer-agentic-radar"
CLI="lancer-agentic-radar-cli"
INSTALL=0
[[ "${1:-}" == "--install" ]] && INSTALL=1

echo "================================================"
echo "  lancer-agentic-radar Build (Linux)"
echo "================================================"
echo ""
echo "  Repo   : $REPO"
echo "  Output : $BUILD/$BIN"
echo ""

echo "[1/2] Building release binary..."
cargo build --release

echo "[2/2] Copying to build/..."
mkdir -p "$BUILD"
cp "$REPO/target/release/$BIN" "$BUILD/"
[[ -f "$REPO/target/release/$CLI" ]] && cp "$REPO/target/release/$CLI" "$BUILD/" || true

if [[ "$INSTALL" == "1" ]]; then
  echo "[install] Installing binary + .desktop entry..."
  DEST="${PREFIX:-$HOME/.local}"
  mkdir -p "$DEST/bin" "$DEST/share/applications"
  cp "$BUILD/$BIN" "$DEST/bin/"
  [[ -f "$BUILD/$CLI" ]] && cp "$BUILD/$CLI" "$DEST/bin/" || true
  cat > "$DEST/share/applications/lancer-agentic-radar.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Lancer Agentic Radar
Comment=Security scanner for agentic AI workflows
Exec=$DEST/bin/$BIN
Terminal=false
Categories=Development;Security;
EOF
  echo "  Installed to $DEST"
fi

echo ""
echo "================================================"
echo "  Done!  Binary ready: $BUILD/$BIN"
echo "================================================"
