//
//  NextGuardApp.swift
//  NextGuard Endpoint DLP Agent
//
//  Copyright (c) 2026 NextGuard Technology Limited. All rights reserved.
//  Enterprise-grade Data Loss Prevention for macOS
//

import AppKit
import os.log

@main
class AppDelegate: NSObject, NSApplicationDelegate {
    static let logger = Logger(subsystem: "com.nextguard.agent", category: "App")
    private var statusItem: NSStatusItem!
    private let policyEngine = DLPPolicyEngine.shared
    private let mgmtClient = ManagementClient.shared
    private var monitoringActive = false
    private var statusMenuItem: NSMenuItem!
    private var policiesMenuItem: NSMenuItem!
    private var connectionMenuItem: NSMenuItem!

    static func main() {
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        let delegate = AppDelegate()
        app.delegate = delegate
        app.run()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        print("[OK] Application launched successfully")
        Self.logger.info("Application launched")

        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let button = statusItem.button {
            button.image = NSImage(systemSymbolName: "shield.checkered", accessibilityDescription: "NextGuard DLP")
            button.toolTip = "NextGuard DLP Agent - Active"
        }

        let menu = NSMenu()
        let titleItem = NSMenuItem(title: "NextGuard DLP Agent v1.2.0", action: nil, keyEquivalent: "")
        titleItem.isEnabled = false
        menu.addItem(titleItem)
        menu.addItem(NSMenuItem.separator())

        connectionMenuItem = NSMenuItem(title: "Console: Connecting...", action: nil, keyEquivalent: "")
        connectionMenuItem.isEnabled = false
        menu.addItem(connectionMenuItem)

        statusMenuItem = NSMenuItem(title: "Status: Initializing...", action: nil, keyEquivalent: "")
        statusMenuItem.isEnabled = false
        menu.addItem(statusMenuItem)

        policiesMenuItem = NSMenuItem(title: "Policies: Loading...", action: nil, keyEquivalent: "")
        policiesMenuItem.isEnabled = false
        menu.addItem(policiesMenuItem)
        menu.addItem(NSMenuItem.separator())

        menu.addItem(NSMenuItem(title: "Show Dashboard", action: #selector(showDashboard), keyEquivalent: "d"))
        menu.addItem(NSMenuItem(title: "Scan Clipboard Now", action: #selector(scanClipboard), keyEquivalent: "c"))
        menu.addItem(NSMenuItem.separator())
        menu.addItem(NSMenuItem(title: "About NextGuard", action: #selector(showAbout), keyEquivalent: ""))
        menu.addItem(NSMenuItem(title: "Quit", action: #selector(quitApp), keyEquivalent: "q"))
        statusItem.menu = menu

        // Initialize: register, load policies from console, start heartbeat + policy refresh
        Task {
            if mgmtClient.tenantId == nil {
                mgmtClient.setTenantId("tenant-demo")
            }

            // Step 1: Register with management console
            await updateConnectionStatus("Console: Registering...")
            let registered = await mgmtClient.registerAgent()
            if registered {
                await updateConnectionStatus("Console: Connected (\(mgmtClient.tenantId ?? "unknown"))")
                Self.logger.info("Agent registered with management console")
                print("[OK] Agent registered with management console")
            } else {
                await updateConnectionStatus("Console: Offline (local mode)")
                Self.logger.warning("Failed to register with console, running in local mode")
                print("[WARN] Running in local mode - console unreachable")
            }

            // Step 2: Pull policies from console and load into DLP engine
            let remotePolicies = await mgmtClient.pullPolicies()
            if !remotePolicies.isEmpty {
                policyEngine.loadPoliciesFromConsole(remotePolicies)
                let count = policyEngine.activePolicies.count
                await updatePoliciesStatus("Policies: \(count) rules (remote)")
                print("[OK] \(count) policies loaded from console")
            } else {
                await policyEngine.loadPolicies()
                let count = policyEngine.activePolicies.count
                await updatePoliciesStatus("Policies: \(count) rules (local)")
                print("[OK] \(count) policies loaded locally")
            }

            // Step 3: Start heartbeat + periodic policy refresh (every 5 min)
            mgmtClient.startHeartbeat()
            print("[OK] Heartbeat started")
            policyEngine.startPolicyRefresh(interval: 300)
            print("[OK] Policy refresh started (every 5 min)")

            // Step 4: Start real-time clipboard monitoring (auto-scan every 2 seconds)
            ClipboardMonitor.shared.startMonitoring()
            print("[OK] Real-time clipboard monitoring started")

            await updateStatusMenuItem("Status: Monitoring Active")
        }

        monitoringActive = true
        print("[OK] Menu bar icon active")
        print("[OK] DLP monitoring started")
    }

    @MainActor
    private func updateConnectionStatus(_ text: String) { connectionMenuItem.title = text }
    @MainActor
    private func updateStatusMenuItem(_ text: String) { statusMenuItem.title = text }
    @MainActor
    private func updatePoliciesStatus(_ text: String) { policiesMenuItem.title = text }

    @objc func showDashboard() { MainWindowController.shared.showWindow() }

    @objc func scanClipboard() {
        let pasteboard = NSPasteboard.general
        guard let content = pasteboard.string(forType: .string) else {
            print("[INFO] Clipboard is empty or has no text")
            return
        }
        let results = policyEngine.scanContent(content, channel: .clipboard)
        if results.isEmpty {
            let alert = NSAlert()
            alert.messageText = "Clipboard Scan Complete"
            alert.informativeText = "No sensitive data detected in clipboard."
            alert.alertStyle = .informational
            alert.runModal()
        } else {
            let matchCount = results.reduce(0) { $0 + $1.matches.count }
            let alert = NSAlert()
            alert.messageText = "Sensitive Data Detected!"
            alert.informativeText = "Found \(matchCount) matches in \(results.count) rules."
            alert.alertStyle = .critical
            alert.runModal()

            Task {
                for result in results {
                    await mgmtClient.reportIncident(
                        policyId: result.ruleId, channel: "clipboard",
                        severity: result.severity.rawValue, action: result.action.rawValue,
                        matchCount: result.matches.count,
                        details: "Clipboard scan: \(result.matches.count) matches for policy \(result.ruleName)"
                    )
                }
                print("[OK] Incidents reported to management console")
            }
        }
    }

    @objc func showAbout() {
        MainWindowController.shared.showWindow()
        MainWindowController.shared.showContentForItem(.about)
    }

    @objc func quitApp() {
        print("[OK] NextGuard DLP Agent shutting down")
        ClipboardMonitor.shared.stopMonitoring()
        mgmtClient.stopHeartbeat()
        policyEngine.stopPolicyRefresh()
        NSApplication.shared.terminate(nil)
    }
}
