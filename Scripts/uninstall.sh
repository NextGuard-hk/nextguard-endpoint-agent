#!/bin/bash
# NextGuard Endpoint Agent - Uninstall Script
# Copyright (c) 2024 NextGuard Technology. All rights reserved.
# Usage: sudo ./uninstall.sh

set -e

APP_NAME="NextGuardAgent"
INSTALL_DIR="/Library/NextGuard"
LAUNCH_DAEMON="com.nextguard.agent"
LAUNCH_DAEMON_PLIST="/Library/LaunchDaemons/${LAUNCH_DAEMON}.plist"
SYSEXT_BUNDLE="com.nextguard.agent.endpoint-security"
LOG_DIR="${INSTALL_DIR}/Logs"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [[ $EUID -ne 0 ]]; then
  echo -e "${RED}Error: This script must be run as root (sudo)${NC}"
  exit 1
fi

echo "================================================"
echo "  NextGuard Endpoint Agent - Uninstaller"
echo "================================================"
echo ""

# Confirm uninstall
read -p "Are you sure you want to uninstall NextGuard Agent? [y/N] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
  echo "Uninstall cancelled."
  exit 0
fi

# Step 1: Stop the LaunchDaemon
echo -e "${YELLOW}[1/5] Stopping agent service...${NC}"
if launchctl list | grep -q "${LAUNCH_DAEMON}"; then
  launchctl bootout system "${LAUNCH_DAEMON_PLIST}" 2>/dev/null || true
  echo "  Agent service stopped."
else
  echo "  Agent service not running."
fi

# Step 2: Deactivate System Extension
echo -e "${YELLOW}[2/5] Deactivating system extension...${NC}"
if systemextensionsctl list 2>/dev/null | grep -q "${SYSEXT_BUNDLE}"; then
  systemextensionsctl uninstall "${SYSEXT_BUNDLE}" 2>/dev/null || true
  echo "  System extension deactivation requested."
else
  echo "  No system extension found."
fi

# Step 3: Remove LaunchDaemon plist
echo -e "${YELLOW}[3/5] Removing LaunchDaemon...${NC}"
if [ -f "${LAUNCH_DAEMON_PLIST}" ]; then
  rm -f "${LAUNCH_DAEMON_PLIST}"
  echo "  LaunchDaemon plist removed."
else
  echo "  LaunchDaemon plist not found."
fi

# Step 4: Remove application files
echo -e "${YELLOW}[4/5] Removing application files...${NC}"
if [ -d "${INSTALL_DIR}" ]; then
  rm -rf "${INSTALL_DIR}"
  echo "  Application directory removed."
else
  echo "  Application directory not found."
fi

# Step 5: Remove network extension config
echo -e "${YELLOW}[5/5] Cleaning up network configuration...${NC}"
networksetup -listallnetworkservices 2>/dev/null | grep -i "nextguard" | while read svc; do
  networksetup -removenetworkservice "$svc" 2>/dev/null || true
done
echo "  Network configuration cleaned."

echo ""
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}  NextGuard Agent has been uninstalled.${NC}"
echo -e "${GREEN}================================================${NC}"
echo ""
echo "Note: A system restart may be required to fully"
echo "remove the system extension."
exit 0
