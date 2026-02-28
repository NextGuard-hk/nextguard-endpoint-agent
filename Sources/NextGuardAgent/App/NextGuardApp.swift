//
// NextGuardApp.swift
// NextGuard Endpoint DLP Agent
//
// Copyright (c) 2026 NextGuard Technology Limited. All rights reserved.
// Enterprise-grade Data Loss Prevention for macOS
//
// Architecture References:
//   - Apple Endpoint Security Framework (WWDC 2020)
//   - Apple Network Extension Framework
//   - ISO 27001:2022 Annex A 8.12 (Data Leakage Prevention)
//   - NIST SP 800-171 (CUI Protection)
//   - Gartner 2025 Market Guide for DLP
//   - COBIT 2019 DSS05 (Manage Security Services)
//

import SwiftUI
import ServiceManagement
import SystemExtensions
import os.log

/// NextGuard Endpoint DLP Agent - Menu Bar Application
/// Provides real-time DLP monitoring via:
///   1. Endpoint Security System Extension (file access, process exec)
///   2. Network Extension (content filtering, egress inspection)
///   3. Clipboard / Screenshot / USB / Print channel monitors
///   4. AI-powered content classification (local + cloud)
@main
struct NextGuardApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate

    var body: some Scene {
        MenuBarExtra("NextGuard DLP", systemImage: "shield.checkered") {
            NextGuardMenuBarView()
        }
        .menuBarExtraStyle(.window)

        Settings {
            NextGuardSettingsView()
        }
    }
}

// MARK: - App Delegate
class AppDelegate: NSObject, NSApplicationDelegate {
    private let logger = Logger(subsystem: "com.nextguard.agent", category: "AppDelegate")
    private let extensionManager = SystemExtensionManager.shared
    private let policyEngine = DLPPolicyEngine.shared
    private let channelCoordinator = ChannelMonitorCoordinator.shared

    func applicationDidFinishLaunching(_ notification: Notification) {
        logger.info("NextGuard Endpoint DLP Agent v1.0.0 starting...")
        logger.info("macOS \(ProcessInfo.processInfo.operatingSystemVersionString)")

        // 1. Load DLP policies from management server or local cache
        Task {
            await self.policyEngine.loadPolicies()
            self.logger.info("DLP policies loaded: \(self.policyEngine.activePolicies.count) active rules")
        }

        // 2. Install/activate System Extensions
        extensionManager.installEndpointSecurityExtension()
        extensionManager.installNetworkExtension()

        // 3. Start channel monitors
        channelCoordinator.startAll()

        // 4. Register for login item (persist across reboots)
        registerAsLoginItem()

        // 5. Start heartbeat to management console
        HeartbeatService.shared.start()

        logger.info("NextGuard Endpoint DLP Agent initialized successfully")
    }

    func applicationWillTerminate(_ notification: Notification) {
        logger.info("NextGuard Endpoint DLP Agent shutting down")
        channelCoordinator.stopAll()
        HeartbeatService.shared.stop()
    }

    private func registerAsLoginItem() {
        if #available(macOS 13.0, *) {
            do {
                try SMAppService.mainApp.register()
                logger.info("Registered as login item")
            } catch {
                logger.error("Failed to register login item: \(error.localizedDescription)")
            }
        }
    }
}
