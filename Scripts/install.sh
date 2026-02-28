#!/bin/bash
# NextGuard Endpoint Agent - Post-Install Script
# Copyright (c) 2024 NextGuard Technology. All rights reserved.
# Executed by the DMG installer after file copy

set -e

INSTALL_DIR="/Library/NextGuard"
BINARY="${INSTALL_DIR}/NextGuardAgent"
LAUNCH_DAEMON_SRC="${INSTALL_DIR}/Resources/com.nextguard.agent.plist"
LAUNCH_DAEMON_DST="/Library/LaunchDaemons/com.nextguard.agent.plist"
CONFIG_DEFAULT="${INSTALL_DIR}/Resources/config.default.json"
CONFIG_FILE="${INSTALL_DIR}/config.json"
LOG_DIR="${INSTALL_DIR}/Logs"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [[ $EUID -ne 0 ]]; then
  echo "Error: This script must be run as root (sudo)"
  exit 1
fi

echo "================================================"
echo "  NextGuard Endpoint Agent - Installer"
echo "  Version 1.0.0"
echo "================================================"
echo ""

# Step 1: Create directories
echo -e "${YELLOW}[1/6] Creating directories...${NC}"
mkdir -p "${INSTALL_DIR}"
mkdir -p "${LOG_DIR}"
mkdir -p "${INSTALL_DIR}/Data"
echo "  Directories created."

# Step 2: Set permissions
echo -e "${YELLOW}[2/6] Setting permissions...${NC}"
chmod 755 "${BINARY}"
chown -R root:wheel "${INSTALL_DIR}"
chmod 750 "${INSTALL_DIR}"
echo "  Permissions set."

# Step 3: Install config if not present
echo -e "${YELLOW}[3/6] Configuring agent...${NC}"
if [ ! -f "${CONFIG_FILE}" ]; then
  cp "${CONFIG_DEFAULT}" "${CONFIG_FILE}"
  echo "  Default configuration installed."
else
  echo "  Existing configuration preserved."
fi

# Step 4: Install LaunchDaemon
echo -e "${YELLOW}[4/6] Installing LaunchDaemon...${NC}"
cp "${LAUNCH_DAEMON_SRC}" "${LAUNCH_DAEMON_DST}"
chown root:wheel "${LAUNCH_DAEMON_DST}"
chmod 644 "${LAUNCH_DAEMON_DST}"
echo "  LaunchDaemon installed."

# Step 5: Load the daemon
echo -e "${YELLOW}[5/6] Starting agent service...${NC}"
launchctl bootstrap system "${LAUNCH_DAEMON_DST}" 2>/dev/null || true
echo "  Agent service started."

# Step 6: Verify
echo -e "${YELLOW}[6/6] Verifying installation...${NC}"
if launchctl list | grep -q "com.nextguard.agent"; then
  echo "  Agent is running."
else
  echo "  Warning: Agent may need a restart to activate."
fi

echo ""
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}  NextGuard Agent installed successfully!${NC}"
echo -e "${GREEN}================================================${NC}"
echo ""
echo "Configuration: ${CONFIG_FILE}"
echo "Logs: ${LOG_DIR}"
echo ""
echo "Note: You may need to approve the System Extension"
echo "in System Settings > Privacy & Security."
exit 0
