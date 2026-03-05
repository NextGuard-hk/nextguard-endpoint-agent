//
//  NextGuardApp.swift
//  NextGuard Endpoint DLP Agent
//
//  Copyright (c) 2026 NextGuard Technology Limited. All rights reserved.
//  Enterprise-grade Data Loss Prevention for macOS
//
//  DESIGN REFERENCE: Forcepoint DLP Agent, Palo Alto Cortex XDR,
//  McAfee DLP Endpoint, Zscaler Client Connector
//

import AppKit
import SwiftUI
import os.log

@main
class AppDelegate: NSObject, NSApplicationDelegate {
    static let logger = Logger(subsystem: "com.nextguard.agent", category: "App")

    // Core engines
    private var statusItem: NSStatusItem!
    private let policyEngine = DLPPolicyEngine.shared
    private let localPolicyEngine = LocalPolicyEngine.shared
    private let mgmtClient = ManagementClient.shared
    private var monitoringActive = false
    private var scanningTimer: Timer?

    // Menu bar items
    private var statusMenuItem: NSMenuItem!
    private var policiesMenuItem: NSMenuItem!
    private var connectionMenuItem: NSMenuItem!

    // GUI controllers
    private var menuBarController: MenuBarController?
    private var mainWindowController: MainWindowController?

    static func main() {
        let app = NSApplication.shared
        app.setActivationPolicy(.regular)
        let delegate = AppDelegate()
        app.delegate = delegate
        app.run()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        Self.logger.info("NextGuard DLP Agent launching")
        print("[OK] Application launched")

        // Setup main window (full-featured GUI)
        mainWindowController = MainWindowController()
        mainWindowController?.showWindow(nil)
        mainWindowController?.window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        print("[OK] Main window opened")

        // Setup menu bar controller
        menuBarController = MenuBarController()
        menuBarController?.setupMenuBar()

        // Legacy status item (kept for compatibility)
        setupStatusItem()
        setupMenu()

        // Start real-time monitoring
        ClipboardMonitor.shared.startMonitoring()
        print("[OK] Clipboard monitoring started")

        // Start file system DLP monitoring
        FileSystemWatcher.shared.startWatching()
        print("[OK] File system monitoring started")

        // Async initialization
        Task {
            if mgmtClient.tenantId == nil {
                mgmtClient.setTenantId("tenant-demo")
            }

            await startScanningAnimation()
            await updateConnectionStatus("Console: Registering...")

            // Step 1: Register with console
            let registered = await mgmtClient.registerAgent()
            if registered {
                await updateConnectionStatus("Console: Connected (\(mgmtClient.tenantId ?? "unknown"))")
                Self.logger.info("Agent registered with management console")
                GUIManager.shared.updateConnectionStatus(
                    connected: true,
                    tenantId: mgmtClient.tenantId,
                    consoleUrl: "https://next-guard.com"
                )
                menuBarController?.updateConnectionStatus(.connected)
            } else {
                await updateConnectionStatus("Console: Offline (local mode)")
                Self.logger.warning("Running in local mode")
                GUIManager.shared.updateConnectionStatus(
                    connected: false,
                    tenantId: mgmtClient.tenantId,
                    consoleUrl: "https://next-guard.com"
                )
                menuBarController?.updateConnectionStatus(.disconnected)
            }

            // Step 2: Pull server policies and merge with local
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

            // Step 3: Heartbeat
            mgmtClient.startHeartbeat()
            policyEngine.startPolicyRefresh(interval: 300)

            await stopScanningAnimation()
            await updateStatusMenuItem("Status: Monitoring Active")
            await updateStatusIcon(protected: true)
        }

        monitoringActive = true
        print("[OK] DLP monitoring active")
        print("[OK] NextGuard Agent ready")
    }

    func applicationWillTerminate(_ notification: Notification) {
        print("[OK] NextGuard DLP Agent shutting down")
        ClipboardMonitor.shared.stopMonitoring()
        FileSystemWatcher.shared.stopWatching()
        mgmtClient.stopHeartbeat()
        policyEngine.stopPolicyRefresh()
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if !flag {
            mainWindowController?.showWindow(nil)
            mainWindowController?.window?.makeKeyAndOrderFront(nil)
        }
        return true
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
        let menu = NSMenu()
        let titleItem = NSMenuItem(title: "NextGuard DLP Agent v\(AgentConfig.shared.agentVersion)", action: nil, keyEquivalent: "")
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

        let dashboardItem = NSMenuItem(title: "Open Dashboard", action: #selector(showDashboard), keyEquivalent: "d")
        dashboardItem.target = self
        menu.addItem(dashboardItem)

        let scanItem = NSMenuItem(title: "Scan Clipboard Now", action: #selector(scanClipboard), keyEquivalent: "c")
        scanItem.target = self
        menu.addItem(scanItem)

        menu.addItem(NSMenuItem.separator())

        let quitItem = NSMenuItem(title: "Quit", action: #selector(quitApp), keyEquivalent: "q")
        quitItem.target = self
        menu.addItem(quitItem)

        statusItem.menu = nil
        statusItem.button?.sendAction(on: [.leftMouseUp, .rightMouseUp])
    }

    @objc func statusBarButtonClicked() {
        guard let event = NSApp.currentEvent else { return }
        if event.type == .rightMouseUp {
            statusItem.menu = buildContextMenu()
            statusItem.button?.performClick(nil)
            statusItem.menu = nil
        } else {
            mainWindowController?.showWindow(nil)
            mainWindowController?.window?.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
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
        menu.addItem(NSMenuItem(title: "Open Dashboard", action: #selector(showDashboard), keyEquivalent: ""))
        menu.addItem(NSMenuItem(title: "Scan Clipboard Now", action: #selector(scanClipboard), keyEquivalent: ""))
        menu.addItem(NSMenuItem.separator())
        menu.addItem(NSMenuItem(title: "Quit", action: #selector(quitApp), keyEquivalent: ""))
        return menu
    }

    // MARK: - MainActor Helpers
    @MainActor private func updateConnectionStatus(_ text: String) {
        connectionMenuItem?.title = text
    }

    @MainActor private func updateStatusMenuItem(_ text: String) {
        statusMenuItem?.title = text
    }

    @MainActor private func updatePoliciesStatus(_ text: String) {
        policiesMenuItem?.title = text
    }

    @MainActor private func updateStatusIcon(protected: Bool, alert: Bool = false) {
        if let button = statusItem.button {
            StatusBarIconHelper.update(button: button, protected: protected, alert: alert)
        }
    }

    @MainActor private func startScanningAnimation() {
        if let button = statusItem.button {
            scanningTimer = StatusBarIconHelper.startScanningAnimation(button: button)
        }
    }

    @MainActor private func stopScanningAnimation() {
        scanningTimer?.invalidate()
        scanningTimer = nil
    }

    // MARK: - Actions
    @objc func showDashboard() {
        mainWindowController?.showWindow(nil)
        mainWindowController?.window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    @objc func scanClipboard() {
        let pasteboard = NSPasteboard.general
        guard let content = pasteboard.string(forType: .string) else {
            print("[INFO] Clipboard is empty")
            return
        }

        let results = policyEngine.scanContent(content, channel: .clipboard)
        let localMatch = localPolicyEngine.evaluate(
            content: content,
            filePath: nil as String?,
            destination: nil as String?,
            app: "Clipboard"
        )

        let totalMatches = results.reduce(0) { $0 + $1.matches.count }
        let hasLocalMatch = localMatch != nil

        if results.isEmpty && !hasLocalMatch {
            let alert = NSAlert()
            alert.messageText = "Clipboard Scan Complete"
            alert.informativeText = "No sensitive data detected in clipboard."
            alert.alertStyle = .informational
            alert.runModal()
        } else {
            let alert = NSAlert()
            alert.messageText = "Sensitive Data Detected!"
            var info = ""
            if totalMatches > 0 {
                info += "Server policies: \(totalMatches) matches. "
            }
            if hasLocalMatch {
                info += "Local policy matched: \(localMatch!.matchedRule.name) -> \(localMatch!.action.rawValue)"
            }
            alert.informativeText = info
            alert.alertStyle = .critical
            alert.runModal()

            Task {
                for result in results {
                    let guiAction: RuleAction = result.action.rawValue == "block" ? .block : .audit
                    GUIManager.shared.notifyIncident(policyName: result.ruleName, action: guiAction)
                    await mgmtClient.reportIncident(
                        policyId: result.ruleId,
                        channel: "clipboard",
                        severity: result.severity.rawValue,
                        action: result.action.rawValue,
                        matchCount: result.matches.count,
                        details: "Clipboard scan: \(result.matches.count) matches for policy \(result.ruleName)"
                    )
                }
                let incidentCount = results.count + (hasLocalMatch ? 1 : 0)
                menuBarController?.updateIncidentCount(incidentCount)
            }
        }
    }

    @objc func quitApp() {
        NSApplication.shared.terminate(nil)
    }
}
