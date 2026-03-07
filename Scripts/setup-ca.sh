#!/bin/bash
#
# setup-ca.sh
# NextGuard DLP Agent - Root CA Setup
#
# Generates a NextGuard Root CA and installs it into the macOS System Keychain.
# This enables TLS interception for blocked HTTPS sites (Method B - Forcepoint style).
# Must run as root (sudo).
#
set -e

CA_DIR="/Library/NextGuard/ca"
CA_KEY="$CA_DIR/nextguard-ca.key"
CA_CERT="$CA_DIR/nextguard-ca.crt"
CA_NAME="NextGuard DLP Root CA"

echo "[NextGuard] Setting up Root CA for HTTPS interception..."

# Create CA directory
mkdir -p "$CA_DIR"
chmod 700 "$CA_DIR"

# Generate Root CA if not already present
if [ ! -f "$CA_KEY" ] || [ ! -f "$CA_CERT" ]; then
    echo "[NextGuard] Generating Root CA keypair..."
    
    # Generate CA private key (4096-bit RSA)
    openssl genrsa -out "$CA_KEY" 4096 2>/dev/null
    chmod 600 "$CA_KEY"
    
    # Generate self-signed Root CA certificate (10 year validity)
    openssl req -new -x509 -days 3650 \
        -key "$CA_KEY" \
        -out "$CA_CERT" \
        -subj "/C=HK/O=NextGuard Technology Limited/OU=Security/CN=NextGuard DLP Root CA" \
        -extensions v3_ca \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -addext "subjectKeyIdentifier=hash" 2>/dev/null
    
    echo "[NextGuard] Root CA generated: $CA_CERT"
else
    echo "[NextGuard] Root CA already exists, skipping generation."
fi

# Install CA into macOS System Keychain
echo "[NextGuard] Installing Root CA into System Keychain..."

# Remove existing NextGuard CA first to avoid duplicates
security delete-certificate -c "$CA_NAME" /Library/Keychains/System.keychain 2>/dev/null || true

# Add to System Keychain and trust for SSL
security add-trusted-cert \
    -d \
    -r trustRoot \
    -k /Library/Keychains/System.keychain \
    "$CA_CERT"

echo "[NextGuard] Root CA installed and trusted in System Keychain."
echo "[NextGuard] CA certificate: $CA_CERT"
echo "[NextGuard] CA private key: $CA_KEY"
echo ""
echo "[NextGuard] HTTPS interception is now enabled."
echo "[NextGuard] Blocked HTTPS sites will show the NextGuard block page."
