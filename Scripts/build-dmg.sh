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

# Configuration
APP_NAME="NextGuard DLP Agent"
BUNDLE_ID="com.nextguard.agent"
VERSION="1.0.0"
BUILD_NUMBER="1"
MIN_MACOS="14.0"

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

check_prerequisites() {
  log "Checking prerequisites..."
  command -v swift >/dev/null 2>&1 || error "Swift not found. Install Xcode."
  command -v hdiutil >/dev/null 2>&1 || error "hdiutil not found."
  SWIFT_VERSION=$(swift --version 2>&1 | head -1)
  log "Swift: $SWIFT_VERSION"
  MACOS_VERSION=$(sw_vers -productVersion)
  log "macOS: $MACOS_VERSION"
}

# Step 1: Build Swift Package (Universal Binary)
build_agent() {
  log "Building NextGuard Agent (universal binary)..."
  cd "$PROJECT_ROOT"

  # Clean previous build artifacts to avoid 'multiple producers' error
  rm -rf "$BUILD_DIR/arm64" "$BUILD_DIR/x86_64"

  log "Building for production..."
  # Build for arm64 (Apple Silicon) - sequential jobs to avoid conflicts
  log "Building arm64..."
  swift build \
    -c release \
    --arch arm64 \
    --build-path "$BUILD_DIR/arm64" \
    -j 1 \
    2>&1 | tail -5

  # Build for x86_64 (Intel)
  log "Building x86_64..."
  swift build \
    -c release \
    --arch x86_64 \
    --build-path "$BUILD_DIR/x86_64" \
    -j 1 \
    2>&1 | tail -5

  # Create universal binary with lipo
  mkdir -p "$RELEASE_DIR"
  lipo -create \
    "$BUILD_DIR/arm64/release/NextGuardAgent" \
    "$BUILD_DIR/x86_64/release/NextGuardAgent" \
    -output "$RELEASE_DIR/NextGuardAgent"

  log "Universal binary created: $(file "$RELEASE_DIR/NextGuardAgent")"
}

# Step 2: Create .app Bundle
create_app_bundle() {
  log "Creating application bundle..."
  rm -rf "$APP_BUNDLE"
  mkdir -p "$APP_BUNDLE/Contents/MacOS"
  mkdir -p "$APP_BUNDLE/Contents/Resources"
  mkdir -p "$APP_BUNDLE/Contents/Library/SystemExtensions"
  mkdir -p "$APP_BUNDLE/Contents/Library/LaunchDaemons"

  cp "$RELEASE_DIR/NextGuardAgent" "$APP_BUNDLE/Contents/MacOS/"
  chmod +x "$APP_BUNDLE/Contents/MacOS/NextGuardAgent"
  cp "$PROJECT_ROOT/Resources/Info.plist" "$APP_BUNDLE/Contents/"
  /usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $VERSION" "$APP_BUNDLE/Contents/Info.plist"
  /usr/libexec/PlistBuddy -c "Set :CFBundleVersion $BUILD_NUMBER" "$APP_BUNDLE/Contents/Info.plist"
  cp "$PROJECT_ROOT/Resources/NextGuardAgent.entitlements" "$BUILD_DIR/"

  cat > "$APP_BUNDLE/Contents/Library/LaunchDaemons/com.nextguard.agent.plist" << 'LAUNCHDAEMON'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.nextguard.agent</string>
<key>ProgramArguments</key><array><string>/Applications/NextGuard DLP Agent.app/Contents/MacOS/NextGuardAgent</string><string>--daemon</string></array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><true/>
</dict></plist>
LAUNCHDAEMON

  mkdir -p "$APP_BUNDLE/Contents/Resources/Config"
  cat > "$APP_BUNDLE/Contents/Resources/Config/default-policy.json" << 'POLICY'
{"version":"1.0.0","rules":[{"id":"pii-credit-card","name":"Credit Card Numbers","patterns":["\\b\\d{4}[- ]?\\d{4}[- ]?\\d{4}[- ]?\\d{4}\\b"],"severity":"critical","action":"block","channels":["network","clipboard","file","email","usb"]},{"id":"pii-hkid","name":"Hong Kong ID","patterns":["[A-Z]{1,2}\\d{6}\\([0-9A]\\)"],"severity":"critical","action":"block","channels":["network","clipboard","file","email"]}]}
POLICY

  log "App bundle created: $APP_BUNDLE"
}

# Step 3: Code Signing
sign_app() {
  if [[ -z "$SIGN_IDENTITY" ]]; then
    log "Skipping code signing (no identity provided)"
    return
  fi
  log "Signing application with: $SIGN_IDENTITY"
  codesign --force --deep --sign "$SIGN_IDENTITY" \
    --entitlements "$BUILD_DIR/NextGuardAgent.entitlements" \
    --options runtime --timestamp "$APP_BUNDLE"
  codesign --verify --deep --strict "$APP_BUNDLE"
  log "Code signing verified"
}

# Step 4: Create DMG Installer
create_dmg() {
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
}

# Step 5: Notarization (optional)
notarize_dmg() {
  if ! $DO_NOTARIZE; then log "Skipping notarization"; return; fi
  if [[ -z "$SIGN_IDENTITY" ]]; then error "Notarization requires signing identity"; fi
  log "Submitting for Apple notarization..."
  xcrun notarytool submit "$DMG_PATH" --keychain-profile "NextGuardNotarize" --wait
  xcrun stapler staple "$DMG_PATH"
  log "Notarization complete"
}

# Main
main() {
  log "=========================================="
  log "NextGuard DLP Agent - DMG Build Pipeline"
  log "Version: $VERSION (Build $BUILD_NUMBER)"
  log "=========================================="
  check_prerequisites
  build_agent
  create_app_bundle
  sign_app
  create_dmg
  notarize_dmg
  log "=========================================="
  log "BUILD COMPLETE"
  log "DMG: $DMG_PATH"
  log "SHA256: $(shasum -a 256 "$DMG_PATH" | cut -d' ' -f1)"
  log "=========================================="
  echo ""
  echo "To install: open $DMG_PATH"
}

main "$@"
