#!/bin/bash
#
# run.sh - Build and launch NextGuard Agent
# Launches the binary directly (NOT via .app bundle / open command)
# to ensure single-instance flock guard works correctly.
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

BINARY_PATH=".build/debug/NextGuardAgent"

echo "[NextGuard] Building..."
swift build 2>&1

# Kill any existing instance and wait for it to fully exit
echo "[NextGuard] Stopping any existing instance..."
pkill -f "NextGuardAgent" 2>/dev/null || true
sleep 1

# Remove stale lock file (only needed if previous run crashed without releasing lock)
rm -f /tmp/com.nextguard.agent.lock

echo "[NextGuard] Launching agent..."
exec "$BINARY_PATH"
