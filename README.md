# NextGuard Endpoint DLP Agent for macOS

> Enterprise-grade Data Loss Prevention agent for macOS, built with Swift and Apple's native frameworks.

[![macOS](https://img.shields.io/badge/macOS-14%2B-blue)](https://www.apple.com/macos/)
[![Swift](https://img.shields.io/badge/Swift-5.9-orange)](https://swift.org/)
[![License](https://img.shields.io/badge/License-Proprietary-red)](LICENSE)
[![ISO 27001](https://img.shields.io/badge/ISO-27001%3A2022-green)](https://www.iso.org/isoiec-27001-information-security.html)

## Overview

NextGuard Endpoint DLP Agent is a comprehensive data loss prevention solution designed for macOS endpoints. It provides real-time monitoring and protection across multiple data channels, referencing Tier-1 security vendor architectures (Forcepoint, Symantec, McAfee, Zscaler, Netskope, Palo Alto, Fortinet, Microsoft) and aligned with international compliance frameworks.

## Features

| Channel | Description | Framework |
|---------|-------------|-----------|
| **Network DLP** | HTTP/HTTPS/SMTP/FTP traffic inspection via NetworkExtension | NEFilterProvider |
| **File System** | Real-time file monitoring with FSEvents + content scanning | CoreServices |
| **Clipboard** | Copy/paste interception with sensitive data detection | NSPasteboard |
| **USB/Removable** | Device control with whitelist/blacklist via IOKit | IOKit + DiskArbitration |
| **Email** | SMTP/IMAP traffic inspection for outbound data | NetworkExtension |
| **Cloud Upload** | Detection of uploads to Google Drive, Dropbox, OneDrive, etc. | NetworkExtension |
| **Print/AirDrop** | Print job and AirDrop transfer monitoring | CUPS + DistributedNotification |
| **Screenshot** | Screenshot detection and audit logging | NSPasteboard |

## Architecture

```
NextGuard DLP Agent
├── App (SwiftUI menu bar app)
│   └── NextGuardApp.swift          # Main entry, lifecycle management
├── DLP Engine
│   └── DLPPolicyEngine.swift       # Hybrid pattern + AI-powered scanning
├── Monitors
│   ├── NetworkMonitor.swift        # Network traffic DLP inspection
│   ├── FileSystemWatcher.swift     # FSEvents real-time file monitoring
│   ├── ClipboardMonitor.swift      # Clipboard DLP with screenshot detection
│   └── USBDeviceMonitor.swift      # IOKit USB/removable device control
├── Extensions
│   └── SystemExtensionManager.swift # macOS System Extension + Endpoint Security
├── Resources
│   ├── Info.plist                  # App bundle configuration
│   └── NextGuardAgent.entitlements # Security entitlements
├── Scripts
│   └── build-dmg.sh               # DMG installer build pipeline
└── Package.swift                   # Swift Package Manager config
```

## Compliance Standards

- **ISO 27001:2022** — A.8.x Information Security Controls
- **NIST SP 800-171** — CUI Protection (3.1, 3.8, 3.13)
- **CIS Controls v8** — Controls 3.4, 10.3
- **COBIT 2019** — Information & Technology governance
- **PCI DSS 4.0** — Cardholder data protection
- **Gartner 2025** — Endpoint DLP & SSE Market Guide alignment

## Requirements

- macOS 14 (Sonoma) or later
- macOS 15 (Sequoia) fully supported
- Xcode 15+ (for building)
- Apple Developer ID (for code signing & notarization)

## Building

```bash
# Clone the repository
git clone https://github.com/NextGuard-hk/nextguard-endpoint-agent.git
cd nextguard-endpoint-agent

# Build unsigned DMG (development)
./Scripts/build-dmg.sh

# Build signed + notarized DMG (production)
./Scripts/build-dmg.sh --sign "Developer ID Application: NextGuard Technology Limited" --notarize
```

The build script produces a universal binary (arm64 + x86_64) DMG installer at `.build/NextGuardDLPAgent-1.0.0.dmg`.

## Installation

1. Open `NextGuardDLPAgent-1.0.0.dmg`
2. Drag **NextGuard DLP Agent** to Applications
3. Launch the app — approve System Extension in **System Settings > Privacy & Security**
4. The agent runs as a menu bar app with real-time DLP protection

## Management Server

The agent connects to NextGuard Management Console at `https://console.next-guard.com` for:
- Policy distribution and updates
- Event reporting and audit logs
- Compliance dashboard
- Remote agent management

## License

Copyright (c) 2026 NextGuard Technology Limited. All rights reserved.

## Support

- Website: [https://www.next-guard.com](https://www.next-guard.com)
- Email: support@next-guard.com
