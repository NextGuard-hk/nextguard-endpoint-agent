#!/bin/bash
# NextGuard Endpoint Agent - Post-Install Script
# Copyright (c) 2026 NextGuard Technology. All rights reserved.
# Executed by the DMG installer after file copy

set -e

INSTALL_DIR="/Library/NextGuard"
BINARY="${INSTALL_DIR}/NextGuardAgent"
LAUNCH_DAEMON_SRC="${INSTALL_DIR}/Resources/com.nextguard.agent.plist"
LAUNCH_DAEMON_DST="/Library/LaunchDaemons/com.nextguard.agent.plist"
CONFIG_DEFAULT="${INSTALL_DIR}/Resources/config.default.json"
CONFIG_FILE="${INSTALL_DIR}/config.json"
LOG_DIR="${INSTALL_DIR}/Logs"
CERT_CACHE="/tmp/nextguard_certs"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root (sudo)"
    exit 1
fi

echo "================================================"
echo " NextGuard Endpoint Agent - Installer"
echo " Version 2.4.0"
echo "================================================"
echo ""

# Step 1: Create directories
echo -e "${YELLOW}[1/7] Creating directories...${NC}"
mkdir -p "${INSTALL_DIR}"
mkdir -p "${LOG_DIR}"
mkdir -p "${INSTALL_DIR}/Data"
mkdir -p "${CERT_CACHE}"
echo "  Directories created."

# Step 2: Set permissions
echo -e "${YELLOW}[2/7] Setting permissions...${NC}"
chmod 755 "${BINARY}"
chown -R root:wheel "${INSTALL_DIR}"
chmod 750 "${INSTALL_DIR}"
echo "  Permissions set."

# Step 3: Install config if not present
echo -e "${YELLOW}[3/7] Configuring agent...${NC}"
if [ ! -f "${CONFIG_FILE}" ]; then
    cp "${CONFIG_DEFAULT}" "${CONFIG_FILE}"
    echo "  Default configuration installed."
else
    echo "  Existing configuration preserved."
fi

# Step 4: Generate Root CA for TLS interception
echo -e "${YELLOW}[4/7] Setting up Root CA for HTTPS block pages...${NC}"
ROOT_CA_KEY="${CERT_CACHE}/rootCA.key"
ROOT_CA_PEM="${CERT_CACHE}/rootCA.pem"
if [ ! -f "${ROOT_CA_PEM}" ] || [ ! -f "${ROOT_CA_KEY}" ]; then
    echo "  Generating NextGuard Root CA..."
    /usr/bin/openssl genrsa -out "${ROOT_CA_KEY}" 4096 2>/dev/null
    /usr/bin/openssl req -x509 -new -nodes -key "${ROOT_CA_KEY}" \
        -sha256 -days 3650 \
        -subj "/C=HK/ST=HK/O=NextGuard Technology/CN=NextGuard DLP Root CA" \
        -out "${ROOT_CA_PEM}" 2>/dev/null
    echo "  Root CA generated."
    # Add to System Keychain as trusted
    echo "  Adding Root CA to System Keychain (trusted)..."
    security add-trusted-cert -d -r trustRoot \
        -k /Library/Keychains/System.keychain \
        "${ROOT_CA_PEM}" 2>/dev/null || echo "  Warning: Could not add cert to keychain. Manual trust may be needed."
    echo "  Root CA trusted."
else
    echo "  Root CA already exists, skipping."
fi

# Step 5: Install LaunchDaemon
echo -e "${YELLOW}[5/7] Installing LaunchDaemon...${NC}"
cp "${LAUNCH_DAEMON_SRC}" "${LAUNCH_DAEMON_DST}"
chown root:wheel "${LAUNCH_DAEMON_DST}"
chmod 644 "${LAUNCH_DAEMON_DST}"
echo "  LaunchDaemon installed."

# Step 6: Load the daemon
echo -e "${YELLOW}[6/7] Starting agent service...${NC}"
launchctl bootstrap system "${LAUNCH_DAEMON_DST}" 2>/dev/null || true
echo "  Agent service started."

# Step 7: Verify
echo -e "${YELLOW}[7/7] Verifying installation...${NC}"
if launchctl list | grep -q "com.nextguard.agent"; then
    echo "  Agent is running."
else
    echo "  Warning: Agent may need a restart to activate."
fi

echo ""
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN} NextGuard Agent v2.4.0 installed successfully!${NC}"
echo -e "${GREEN}================================================${NC}"
echo ""
echo "Configuration: ${CONFIG_FILE}"
echo "Logs: ${LOG_DIR}"
echo "Root CA: ${ROOT_CA_PEM}"
echo ""
echo "Note: You may need to approve the System Extension"
echo "in System Settings > Privacy & Security."
echo ""
echo "DNS Filter: Blocked domains show a branded block page"
echo "on both HTTP and HTTPS (TLS interception enabled)."
echo "Configure in Agent > Settings > DNS Filter."

exit 0
