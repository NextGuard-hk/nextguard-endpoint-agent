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
    private var monitoringActive = false

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

        let titleItem = NSMenuItem(title: "NextGuard DLP Agent v1.0.5", action: nil, keyEquivalent: "")
        titleItem.isEnabled = false
        menu.addItem(titleItem)
        menu.addItem(NSMenuItem.separator())

        let statusItem2 = NSMenuItem(title: "Status: Monitoring Active", action: nil, keyEquivalent: "")
        statusItem2.isEnabled = false
        menu.addItem(statusItem2)

        let policiesItem = NSMenuItem(title: "Policies: Loading...", action: nil, keyEquivalent: "")
        policiesItem.isEnabled = false
        menu.addItem(policiesItem)
        menu.addItem(NSMenuItem.separator())

        menu.addItem(NSMenuItem(title: "Show Dashboard", action: #selector(showDashboard), keyEquivalent: "d"))
        menu.addItem(NSMenuItem(title: "Scan Clipboard Now", action: #selector(scanClipboard), keyEquivalent: "c"))
        menu.addItem(NSMenuItem.separator())
        menu.addItem(NSMenuItem(title: "About NextGuard", action: #selector(showAbout), keyEquivalent: ""))
        menu.addItem(NSMenuItem(title: "Quit", action: #selector(quitApp), keyEquivalent: "q"))

        statusItem.menu = menu

        Task {
            await policyEngine.loadPolicies()
            let count = policyEngine.activePolicies.count
            print("[OK] \(count) DLP policies loaded")
            await MainActor.run {
                policiesItem.title = "Policies: \(count) rules active"
            }
        }

        monitoringActive = true
        print("[OK] Menu bar icon active")
        print("[OK] DLP monitoring started")
    }

    @objc func showDashboard() {
        let alert = NSAlert()
        alert.messageText = "NextGuard DLP Dashboard"
        alert.informativeText = "Monitoring Status: Active\nPolicies Loaded: \(policyEngine.activePolicies.count)\nChannels: File, Clipboard, Network, Email, USB, Print\n\nVersion: 1.0.5\nhttps://www.next-guard.com"
        alert.alertStyle = .informational
        alert.addButton(withTitle: "OK")
        alert.runModal()
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
        }
    }

    @objc func showAbout() {
        let alert = NSAlert()
        alert.messageText = "NextGuard Endpoint DLP Agent"
        alert.informativeText = "Version 1.0.5\n\nEnterprise-grade Data Loss Prevention for macOS\n\nCopyright (c) 2026 NextGuard Technology Limited.\nhttps://www.next-guard.com"
        alert.alertStyle = .informational
        alert.runModal()
    }

    @objc func quitApp() {
        print("[OK] NextGuard DLP Agent shutting down")
        NSApplication.shared.terminate(nil)
    }
}
