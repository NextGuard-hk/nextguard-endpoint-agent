#!/bin/bash
#
# build-dmg.sh
# NextGuard Endpoint DLP Agent - macOS DMG Installer Builder
#
# Copyright (c) 2026 NextGuard Technology Limited. All rights reserved.
#
# Usage: ./Scripts/build-dmg.sh [--sign IDENTITY] [--notarize]
#
set -euo pipefail

APP_NAME="NextGuard DLP Agent"
BUNDLE_ID="com.nextguard.agent"
VERSION="2.3.0"
BUILD_NUMBER="1"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_ROOT/.build"
RELEASE_DIR="$BUILD_DIR/release"
APP_BUNDLE="$BUILD_DIR/$APP_NAME.app"
DMG_NAME="NextGuardDLPAgent-${VERSION}.dmg"
DMG_PATH="$BUILD_DIR/$DMG_NAME"

SIGN_IDENTITY=""
DO_NOTARIZE=false

while [[ $# -gt 0 ]]; do
  case $1 in
    --sign) SIGN_IDENTITY="$2"; shift 2 ;;
    --notarize) DO_NOTARIZE=true; shift ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
error() { echo "[ERROR] $*" >&2; exit 1; }

log "=========================================="
log "NextGuard DLP Agent - DMG Build Pipeline"
log "Version: $VERSION (Build $BUILD_NUMBER)"
log "=========================================="

# Prerequisites
log "Checking prerequisites..."
command -v swift >/dev/null 2>&1 || error "Swift not found. Install Xcode."
command -v hdiutil >/dev/null 2>&1 || error "hdiutil not found."
log "Swift: $(swift --version 2>&1 | head -1)"
log "macOS: $(sw_vers -productVersion)"
log "Arch: $(uname -m)"

# Step 1: Build for native architecture only (no --arch flag to avoid SPM bug)
log "Building NextGuard Agent for $(uname -m)..."
cd "$PROJECT_ROOT"
swift package clean
swift build -c release 2>&1 | tail -20

# Find the built binary
BINARY_PATH=$(swift build -c release --show-bin-path)/NextGuardAgent
if [[ ! -f "$BINARY_PATH" ]]; then
  error "Build failed: binary not found at $BINARY_PATH"
fi
log "Binary built: $(file "$BINARY_PATH")"
mkdir -p "$RELEASE_DIR"
cp "$BINARY_PATH" "$RELEASE_DIR/NextGuardAgent"

# Step 2: Create .app bundle
log "Creating application bundle..."
rm -rf "$APP_BUNDLE"
mkdir -p "$APP_BUNDLE/Contents/MacOS"
mkdir -p "$APP_BUNDLE/Contents/Resources/Config"
mkdir -p "$APP_BUNDLE/Contents/Library/LaunchDaemons"

cp "$RELEASE_DIR/NextGuardAgent" "$APP_BUNDLE/Contents/MacOS/"
chmod +x "$APP_BUNDLE/Contents/MacOS/NextGuardAgent"
cp "$PROJECT_ROOT/Resources/Info.plist" "$APP_BUNDLE/Contents/"
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $VERSION" "$APP_BUNDLE/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $BUILD_NUMBER" "$APP_BUNDLE/Contents/Info.plist"
cp "$PROJECT_ROOT/Resources/NextGuardAgent.entitlements" "$BUILD_DIR/"
log "App bundle created: $APP_BUNDLE"

# Step 3: Code signing (optional)
if [[ -n "$SIGN_IDENTITY" ]]; then
  log "Signing with: $SIGN_IDENTITY"
  codesign --force --deep --sign "$SIGN_IDENTITY" \
    --entitlements "$BUILD_DIR/NextGuardAgent.entitlements" \
    --options runtime --timestamp "$APP_BUNDLE"
  codesign --verify --deep --strict "$APP_BUNDLE"
  log "Signing verified"
else
  log "Skipping code signing (no identity provided)"
fi

# Step 4: Create DMG
log "Creating DMG installer..."
DMG_TEMP="$BUILD_DIR/dmg_temp"
rm -rf "$DMG_TEMP"
mkdir -p "$DMG_TEMP"
cp -R "$APP_BUNDLE" "$DMG_TEMP/"
ln -s /Applications "$DMG_TEMP/Applications"
rm -f "$DMG_PATH"
hdiutil create -volname "$APP_NAME" -srcfolder "$DMG_TEMP" \
  -ov -format UDZO -imagekey zlib-level=9 "$DMG_PATH"
if [[ -n "$SIGN_IDENTITY" ]]; then
  codesign --force --sign "$SIGN_IDENTITY" --timestamp "$DMG_PATH"
fi
rm -rf "$DMG_TEMP"
DMG_SIZE=$(du -h "$DMG_PATH" | cut -f1)
log "DMG created: $DMG_PATH ($DMG_SIZE)"

# Step 5: Notarization (optional)
if $DO_NOTARIZE && [[ -n "$SIGN_IDENTITY" ]]; then
  log "Submitting for Apple notarization..."
  xcrun notarytool submit "$DMG_PATH" --keychain-profile "NextGuardNotarize" --wait
  xcrun stapler staple "$DMG_PATH"
  log "Notarization complete"
fi

log "=========================================="
log "BUILD COMPLETE"
log "DMG: $DMG_PATH"
log "SHA256: $(shasum -a 256 "$DMG_PATH" | cut -d' ' -f1)"
log "=========================================="
echo ""
echo "To install: open $DMG_PATH"
