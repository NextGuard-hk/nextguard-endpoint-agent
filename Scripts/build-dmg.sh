#!/bin/bash
#
# build-dmg.sh
# NextGuard Endpoint DLP Agent - macOS DMG Installer Builder
#
# Copyright (c) 2026 NextGuard Technology Limited. All rights reserved.
#
# Usage: ./Scripts/build-dmg.sh [--sign IDENTITY] [--notarize]
#
# Prerequisites:
#   - Xcode 15+ with Command Line Tools
#   - macOS 14+ SDK
#   - Apple Developer ID (for signing/notarization)
#
# Standards: ISO 27001:2022, NIST SP 800-171, CIS Controls v8
#

set -euo pipefail

# ============================================================
# Configuration
# ============================================================
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

# Parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --sign)
      SIGN_IDENTITY="$2"
      shift 2
      ;;
    --notarize)
      DO_NOTARIZE=true
      shift
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

# ============================================================
# Helper Functions
# ============================================================
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
error() { echo "[ERROR] $*" >&2; exit 1; }

check_prerequisites() {
  log "Checking prerequisites..."
  
  command -v swift >/dev/null 2>&1 || error "Swift not found. Install Xcode."
  command -v xcodebuild >/dev/null 2>&1 || error "xcodebuild not found."
  command -v hdiutil >/dev/null 2>&1 || error "hdiutil not found."
  
  SWIFT_VERSION=$(swift --version 2>&1 | head -1)
  log "Swift: $SWIFT_VERSION"
  
  MACOS_VERSION=$(sw_vers -productVersion)
  log "macOS: $MACOS_VERSION"
  
  if [[ -n "$SIGN_IDENTITY" ]]; then
    security find-identity -v -p codesigning | grep -q "$SIGN_IDENTITY" \
      || error "Signing identity not found: $SIGN_IDENTITY"
    log "Signing identity: $SIGN_IDENTITY"
  fi
}

# ============================================================
# Step 1: Build Swift Package (Universal Binary)
# ============================================================
build_agent() {
  log "Building NextGuard Agent (universal binary)..."
  
  cd "$PROJECT_ROOT"
  
  # Build for arm64 (Apple Silicon)
  swift build \
    -c release \
    --arch arm64 \
    --build-path "$BUILD_DIR/arm64" \
    2>&1 | tail -5
  
  # Build for x86_64 (Intel)
  swift build \
    -c release \
    --arch x86_64 \
    --build-path "$BUILD_DIR/x86_64" \
    2>&1 | tail -5
  
  # Create universal binary with lipo
  mkdir -p "$RELEASE_DIR"
  lipo -create \
    "$BUILD_DIR/arm64/release/NextGuardAgent" \
    "$BUILD_DIR/x86_64/release/NextGuardAgent" \
    -output "$RELEASE_DIR/NextGuardAgent"
  
  log "Universal binary created: $(file "$RELEASE_DIR/NextGuardAgent")"
}

# ============================================================
# Step 2: Create .app Bundle
# ============================================================
create_app_bundle() {
  log "Creating application bundle..."
  
  # Clean previous bundle
  rm -rf "$APP_BUNDLE"
  
  # Create bundle structure
  mkdir -p "$APP_BUNDLE/Contents/MacOS"
  mkdir -p "$APP_BUNDLE/Contents/Resources"
  mkdir -p "$APP_BUNDLE/Contents/Library/SystemExtensions"
  mkdir -p "$APP_BUNDLE/Contents/Library/LaunchDaemons"
  
  # Copy executable
  cp "$RELEASE_DIR/NextGuardAgent" "$APP_BUNDLE/Contents/MacOS/"
  chmod +x "$APP_BUNDLE/Contents/MacOS/NextGuardAgent"
  
  # Copy Info.plist
  cp "$PROJECT_ROOT/Resources/Info.plist" "$APP_BUNDLE/Contents/"
  
  # Update version in Info.plist
  /usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $VERSION" "$APP_BUNDLE/Contents/Info.plist"
  /usr/libexec/PlistBuddy -c "Set :CFBundleVersion $BUILD_NUMBER" "$APP_BUNDLE/Contents/Info.plist"
  
  # Copy entitlements (used during signing)
  cp "$PROJECT_ROOT/Resources/NextGuardAgent.entitlements" "$BUILD_DIR/"
  
  # Create LaunchDaemon plist for auto-start
  cat > "$APP_BUNDLE/Contents/Library/LaunchDaemons/com.nextguard.agent.plist" << 'LAUNCHDAEMON'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.nextguard.agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>/Applications/NextGuard DLP Agent.app/Contents/MacOS/NextGuardAgent</string>
    <string>--daemon</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>/var/log/nextguard-agent.log</string>
  <key>StandardErrorPath</key>
  <string>/var/log/nextguard-agent-error.log</string>
</dict>
</plist>
LAUNCHDAEMON
  
  # Create default configuration
  mkdir -p "$APP_BUNDLE/Contents/Resources/Config"
  cat > "$APP_BUNDLE/Contents/Resources/Config/default-policy.json" << 'POLICY'
{
  "version": "1.0.0",
  "rules": [
    {
      "id": "pii-credit-card",
      "name": "Credit Card Numbers",
      "patterns": ["\\b\\d{4}[- ]?\\d{4}[- ]?\\d{4}[- ]?\\d{4}\\b"],
      "severity": "critical",
      "action": "block",
      "channels": ["network", "clipboard", "file", "email", "usb"]
    },
    {
      "id": "pii-hkid",
      "name": "Hong Kong ID",
      "patterns": ["[A-Z]{1,2}\\d{6}\\([0-9A]\\)"],
      "severity": "critical",
      "action": "block",
      "channels": ["network", "clipboard", "file", "email"]
    },
    {
      "id": "pii-email-bulk",
      "name": "Bulk Email Addresses",
      "patterns": ["([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}.*){5,}"],
      "severity": "high",
      "action": "block",
      "channels": ["network", "clipboard", "file"]
    }
  ],
  "usb_policy": "blockMassStorage",
  "compliance_frameworks": ["ISO 27001:2022", "NIST SP 800-171", "PCI DSS 4.0"]
}
POLICY
  
  # Create uninstall script
  cat > "$APP_BUNDLE/Contents/Resources/uninstall.sh" << 'UNINSTALL'
#!/bin/bash
echo "Uninstalling NextGuard DLP Agent..."
sudo launchctl unload /Library/LaunchDaemons/com.nextguard.agent.plist 2>/dev/null
sudo rm -f /Library/LaunchDaemons/com.nextguard.agent.plist
sudo rm -rf "/Applications/NextGuard DLP Agent.app"
sudo rm -rf "/Library/Application Support/NextGuard"
sudo rm -f /var/log/nextguard-agent*.log
echo "NextGuard DLP Agent uninstalled successfully."
UNINSTALL
  chmod +x "$APP_BUNDLE/Contents/Resources/uninstall.sh"
  
  log "App bundle created: $APP_BUNDLE"
}

# ============================================================
# Step 3: Code Signing
# ============================================================
sign_app() {
  if [[ -z "$SIGN_IDENTITY" ]]; then
    log "Skipping code signing (no identity provided)"
    return
  fi
  
  log "Signing application with: $SIGN_IDENTITY"
  
  codesign --force --deep --sign "$SIGN_IDENTITY" \
    --entitlements "$BUILD_DIR/NextGuardAgent.entitlements" \
    --options runtime \
    --timestamp \
    "$APP_BUNDLE"
  
  # Verify signature
  codesign --verify --deep --strict "$APP_BUNDLE"
  log "Code signing verified successfully"
}

# ============================================================
# Step 4: Create DMG Installer
# ============================================================
create_dmg() {
  log "Creating DMG installer..."
  
  DMG_TEMP="$BUILD_DIR/dmg_temp"
  rm -rf "$DMG_TEMP"
  mkdir -p "$DMG_TEMP"
  
  # Copy app to DMG staging
  cp -R "$APP_BUNDLE" "$DMG_TEMP/"
  
  # Create Applications symlink for drag-install
  ln -s /Applications "$DMG_TEMP/Applications"
  
  # Create README
  cat > "$DMG_TEMP/README.txt" << README
NextGuard DLP Agent v${VERSION}
================================
Copyright (c) 2026 NextGuard Technology Limited

INSTALLATION:
1. Drag "NextGuard DLP Agent" to Applications folder
2. Open the app from Applications
3. Grant System Extension permission in System Settings > Privacy
4. The agent will start protecting your data automatically

REQUIREMENTS:
- macOS 14 (Sonoma) or later
- macOS 15 (Sequoia) supported
- Admin privileges for system extension approval

COMPLIANCE:
- ISO 27001:2022 (A.8.x Information Security Controls)
- NIST SP 800-171 (CUI Protection)
- CIS Controls v8
- COBIT 2019
- PCI DSS 4.0

SUPPORT:
https://www.next-guard.com/support
support@next-guard.com
README
  
  # Remove old DMG if exists
  rm -f "$DMG_PATH"
  
  # Create DMG
  hdiutil create \
    -volname "$APP_NAME" \
    -srcfolder "$DMG_TEMP" \
    -ov \
    -format UDZO \
    -imagekey zlib-level=9 \
    "$DMG_PATH"
  
  # Sign DMG if identity provided
  if [[ -n "$SIGN_IDENTITY" ]]; then
    codesign --force --sign "$SIGN_IDENTITY" --timestamp "$DMG_PATH"
    log "DMG signed"
  fi
  
  # Cleanup
  rm -rf "$DMG_TEMP"
  
  DMG_SIZE=$(du -h "$DMG_PATH" | cut -f1)
  log "DMG created: $DMG_PATH ($DMG_SIZE)"
}

# ============================================================
# Step 5: Notarization (optional)
# ============================================================
notarize_dmg() {
  if ! $DO_NOTARIZE; then
    log "Skipping notarization"
    return
  fi
  
  if [[ -z "$SIGN_IDENTITY" ]]; then
    error "Notarization requires code signing identity"
  fi
  
  log "Submitting for Apple notarization..."
  
  xcrun notarytool submit "$DMG_PATH" \
    --keychain-profile "NextGuardNotarize" \
    --wait
  
  # Staple the ticket
  xcrun stapler staple "$DMG_PATH"
  
  log "Notarization complete and stapled"
}

# ============================================================
# Main Build Pipeline
# ============================================================
main() {
  log "========================================="
  log "NextGuard DLP Agent - DMG Build Pipeline"
  log "Version: $VERSION (Build $BUILD_NUMBER)"
  log "========================================="
  
  check_prerequisites
  build_agent
  create_app_bundle
  sign_app
  create_dmg
  notarize_dmg
  
  log "========================================="
  log "BUILD COMPLETE"
  log "DMG: $DMG_PATH"
  log "SHA256: $(shasum -a 256 "$DMG_PATH" | cut -d' ' -f1)"
  log "========================================="
  
  echo ""
  echo "To install:"
  echo "  open $DMG_PATH"
  echo ""
  echo "To build signed + notarized:"
  echo "  ./Scripts/build-dmg.sh --sign 'Developer ID Application: NextGuard Technology Limited' --notarize"
}

main "$@"
