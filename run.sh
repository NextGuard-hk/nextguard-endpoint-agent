#!/bin/bash
#
# run.sh - Build and launch NextGuard Agent with proper .app bundle
# This wraps the SPM binary into a macOS .app so NSStatusBar works
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

APP_BUNDLE=".build/NextGuardAgent.app"
BINARY_PATH=".build/debug/NextGuardAgent"

echo "[NextGuard] Building..."
swift build 2>&1

echo "[NextGuard] Creating .app bundle..."
rm -rf "$APP_BUNDLE"
mkdir -p "$APP_BUNDLE/Contents/MacOS"
mkdir -p "$APP_BUNDLE/Contents/Resources"

cp "$BINARY_PATH" "$APP_BUNDLE/Contents/MacOS/NextGuardAgent"
chmod +x "$APP_BUNDLE/Contents/MacOS/NextGuardAgent"
cp "Resources/Info.plist" "$APP_BUNDLE/Contents/Info.plist"

# Kill any existing instance
pkill -f "NextGuardAgent" 2>/dev/null || true
sleep 0.5

echo "[NextGuard] Launching agent..."
open "$APP_BUNDLE"

echo "[NextGuard] Done! Green shield should appear in menubar."
