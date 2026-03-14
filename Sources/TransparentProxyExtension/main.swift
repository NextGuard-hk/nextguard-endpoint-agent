//
// main.swift
// TransparentProxyExtension
//
// Copyright (c) 2026 NextGuard Technology Limited. All rights reserved.
// Network Extension entry point for NETransparentProxyProvider
//

import Foundation
import NetworkExtension
import os.log

/// Entry point for the Network Extension process.
/// This is a separate binary that macOS launches when the proxy is activated.
/// It runs in its own sandboxed process, separate from the main NextGuard app.

let logger = Logger(subsystem: "com.nextguard.agent.transparent-proxy", category: "Extension")

logger.info("NextGuard TransparentProxy Extension starting...")

// The NEProvider subclass (TransparentProxyProvider) is declared in
// the shared module. The system automatically instantiates it based on
// the NEMachServiceName in Info.plist and the provider bundle identifier
// configured in NETunnelProviderProtocol.

// For System Extension packaging, the extension must:
// 1. Be embedded in the main app bundle under Contents/Library/SystemExtensions/
// 2. Have its own Info.plist with NEProviderClasses
// 3. Have proper entitlements for com.apple.developer.networking.networkextension
// 4. Be signed with a Developer ID certificate (for distribution)

// The extension lifecycle is managed by macOS:
// - Activated via OSSystemExtensionManager in the main app
// - Started/stopped via NETunnelProviderManager
// - Survives main app termination (runs as system extension)

authorize()

func authorize() {
    // Request Network Extension authorization
    // This triggers the system prompt for user approval
    NEProvider.startSystemExtensionMode()
}

// Keep the extension running
dispatchMain()