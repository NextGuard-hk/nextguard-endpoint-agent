//
//  NextGuardApp.swift
//  NextGuard Endpoint DLP Agent
//
//  Copyright (c) 2026 NextGuard Technology Limited. All rights reserved.
//  Enterprise-grade Data Loss Prevention for macOS
//

import AppKit
import SwiftUI
import os.log

@main
class AppDelegate: NSObject, NSApplicationDelegate {
    static let logger = Logger(subsystem: "com.nextguard.agent", category: "App")

    private var statusItem: NSStatusItem!
    private let policyEngine = DLPPolicyEngine.shared
    private let mgmtClient = ManagementClient.shared
    private var monitoringActive = false
    private var scanningTimer: Timer?

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

        setupStatusItem()
        setupMenu()

        // Start real-time clipboard monitoring
        ClipboardMonitor.shared.startMonitoring()
        print("[OK] Real-time clipboard monitoring started")

        // Async initialization
        Task {
            if mgmtClient.tenantId == nil {
                mgmtClient.setTenantId("tenant-demo")
            }

            // Scanning animation while initializing
            await startScanningAnimation()

            // Step 1: Register with console
            await updateConnectionStatus("Console: Registering...")
            let registered = await mgmtClient.registerAgent()
            if registered {
                await updateConnectionStatus("Console: Connected (\(mgmtClient.tenantId ?? "unknown"))")
                Self.logger.info("Agent registered with management console")
                print("[OK] Agent registered with management console")
                // Update GUI connection status
                GUIManager.shared.updateConnectionStatus(
                    connected: true,
                    tenantId: mgmtClient.tenantId,
                    consoleUrl: "https://next-guard.com"
                )
            } else {
                await updateConnectionStatus("Console: Offline (local mode)")
                Self.logger.warning("Failed to register with console, running in local mode")
                print("[WARN] Running in local mode - console unreachable")
                GUIManager.shared.updateConnectionStatus(
                    connected: false,
                    tenantId: mgmtClient.tenantId,
                    consoleUrl: "https://next-guard.com"
                )
            }

            // Step 2: Pull policies
            let remotePolicies = await mgmtClient.pullPolicies()
            if !remotePolicies.isEmpty {
                policyEngine.loadPoliciesFromConsole(remotePolicies)
                let count = policyEngine.activePolicies.count
                await updatePoliciesStatus("Policies: \(count) rules (remote)")
                print("[OK] \(count) policies loaded from console")
                GUIManager.shared.updatePolicyCount(count, source: "remote")
            } else {
                await policyEngine.loadPolicies()
                let count = policyEngine.activePolicies.count
                await updatePoliciesStatus("Policies: \(count) rules (local)")
                print("[OK] \(count) policies loaded locally")
                GUIManager.shared.updatePolicyCount(count, source: "local")
            }

            // Step 3: Heartbeat + refresh
            mgmtClient.startHeartbeat()
            print("[OK] Heartbeat started")
            policyEngine.startPolicyRefresh(interval: 300)
            print("[OK] Policy refresh started (every 5 min)")

            await stopScanningAnimation()
            await updateStatusMenuItem("Status: Monitoring Active")
            await updateStatusIcon(protected: true)
        }

        monitoringActive = true
        print("[OK] Menu bar icon active")
        print("[OK] DLP monitoring started")
    }

    // MARK: - Status Item Setup

    private func setupStatusItem() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        if let button = statusItem.button {
            StatusBarIconHelper.update(button: button, protected: true, scanning: true)
            button.action = #selector(statusBarButtonClicked)
            button.target = self
            button.sendAction(on: [.leftMouseUp, .rightMouseUp])
        }
    }

    private func setupMenu() {
        // Right-click context menu
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
        menu.addItem(NSMenuItem(title: "Open Dashboard", action: #selector(showDashboard), keyEquivalent: "d"))
        menu.addItem(NSMenuItem(title: "Scan Clipboard Now", action: #selector(scanClipboard), keyEquivalent: "c"))
        menu.addItem(NSMenuItem.separator())
        menu.addItem(NSMenuItem(title: "About NextGuard", action: #selector(showAbout), keyEquivalent: ""))
        menu.addItem(NSMenuItem(title: "Quit", action: #selector(quitApp), keyEquivalent: "q"))

        // Store menu for right-click; left-click shows popover
        statusItem.menu = nil  // will be set on right-click only
        statusItem.button?.sendAction(on: [.leftMouseUp, .rightMouseUp])
    }

    // MARK: - Status Bar Button Click Handler

    @objc func statusBarButtonClicked() {
        guard let event = NSApp.currentEvent else { return }
        if event.type == .rightMouseUp {
            // Show context menu
            statusItem.menu = buildContextMenu()
            statusItem.button?.performClick(nil)
            statusItem.menu = nil
        } else {
            // Left click: show SwiftUI popover
            if let button = statusItem.button {
                GUIManager.shared.togglePopover(relativeTo: button)
            }
        }
    }

    private func buildContextMenu() -> NSMenu {
        let menu = NSMenu()
        let titleItem = NSMenuItem(title: "NextGuard DLP Agent", action: nil, keyEquivalent: "")
        titleItem.isEnabled = false
        menu.addItem(titleItem)
        menu.addItem(NSMenuItem.separator())
        if let conn = connectionMenuItem { menu.addItem(conn.copy() as! NSMenuItem) }
        if let status = statusMenuItem { menu.addItem(status.copy() as! NSMenuItem) }
        if let policies = policiesMenuItem { menu.addItem(policies.copy() as! NSMenuItem) }
        menu.addItem(NSMenuItem.separator())
        menu.addItem(NSMenuItem(title: "Scan Clipboard Now", action: #selector(scanClipboard), keyEquivalent: ""))
        menu.addItem(NSMenuItem.separator())
        menu.addItem(NSMenuItem(title: "Quit", action: #selector(quitApp), keyEquivalent: ""))
        return menu
    }

    // MARK: - MainActor Helpers

    @MainActor
    private func updateConnectionStatus(_ text: String) {
        connectionMenuItem?.title = text
    }

    @MainActor
    private func updateStatusMenuItem(_ text: String) {
        statusMenuItem?.title = text
    }

    @MainActor
    private func updatePoliciesStatus(_ text: String) {
        policiesMenuItem?.title = text
    }

    @MainActor
    private func updateStatusIcon(protected: Bool, alert: Bool = false) {
        if let button = statusItem.button {
            StatusBarIconHelper.update(button: button, protected: protected, alert: alert)
        }
    }

    @MainActor
    private func startScanningAnimation() {
        if let button = statusItem.button {
            scanningTimer = StatusBarIconHelper.startScanningAnimation(button: button)
        }
    }

    @MainActor
    private func stopScanningAnimation() {
        scanningTimer?.invalidate()
        scanningTimer = nil
    }

    // MARK: - Actions

    @objc func showDashboard() {
        // Show SwiftUI popover dashboard
        if let button = statusItem.button {
            GUIManager.shared.openPopover(relativeTo: button)
        }
    }

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
                    // Notify GUI
                    let action: PolicyAction = result.action.rawValue == "block" ? .block : .audit
                    GUIManager.shared.notifyIncident(policyName: result.ruleName, action: action)
                    // Report to console
                    await mgmtClient.reportIncident(
                        policyId: result.ruleId,
                        channel: "clipboard",
                        severity: result.severity.rawValue,
                        action: result.action.rawValue,
                        matchCount: result.matches.count,
                        details: "Clipboard scan: \(result.matches.count) matches for policy \(result.ruleName)"
                    )
                }
                print("[OK] Incidents reported to management console")
            }
        }
    }

    @objc func showAbout() {
        if let button = statusItem.button {
            GUIManager.shared.openPopover(relativeTo: button)
        }
    }

    @objc func quitApp() {
        print("[OK] NextGuard DLP Agent shutting down")
        ClipboardMonitor.shared.stopMonitoring()
        mgmtClient.stopHeartbeat()
        policyEngine.stopPolicyRefresh()
        NSApplication.shared.terminate(nil)
    }
}
