//
//  ClipboardMonitor.swift
//  NextGuard Endpoint DLP Agent
//
//  Copyright (c) 2026 NextGuard Technology Limited. All rights reserved.
//
//  Real-time clipboard DLP monitoring - auto-detects and blocks sensitive data
//  Ref: ISO 27001:2022 A.8.12, NIST SP 800-171
//

import Foundation
import AppKit
import os.log

// MARK: - Clipboard Monitor
final class ClipboardMonitor {
    static let shared = ClipboardMonitor()
    private let logger = Logger(subsystem: "com.nextguard.agent", category: "ClipboardMonitor")
    private let engine = DLPPolicyEngine.shared
    private let mgmtClient = ManagementClient.shared

    private var pollTimer: Timer?
    private var lastChangeCount: Int = 0
    private(set) var isActive: Bool = false
    private var totalInspected: Int = 0
    private var totalBlocked: Int = 0

    private let pollInterval: TimeInterval = 0.5

    private init() {}

    // MARK: - Start / Stop
    func startMonitoring() {
        guard !isActive else { return }
        lastChangeCount = NSPasteboard.general.changeCount
        pollTimer = Timer.scheduledTimer(withTimeInterval: pollInterval, repeats: true) { [weak self] _ in
            self?.checkClipboard()
        }
        RunLoop.current.add(pollTimer!, forMode: .common)
        isActive = true
        logger.info("Clipboard DLP monitoring started (polling every \(self.pollInterval)s)")
        print("[OK] Clipboard monitor active - real-time scanning enabled")
    }

    func stopMonitoring() {
        pollTimer?.invalidate()
        pollTimer = nil
        isActive = false
        logger.info("Clipboard monitoring stopped")
    }

    // MARK: - Clipboard Polling
    private func checkClipboard() {
        let pasteboard = NSPasteboard.general
        let currentCount = pasteboard.changeCount

        guard currentCount != lastChangeCount else { return }
        lastChangeCount = currentCount

        // Get clipboard text content
        guard let text = pasteboard.string(forType: .string), !text.isEmpty else { return }

        totalInspected += 1
        let sourceApp = NSWorkspace.shared.frontmostApplication?.localizedName ?? "Unknown"

        // Scan with DLP engine using POLICY-DEFINED rules
        let violations = engine.scanContent(text, channel: .clipboard)
        guard !violations.isEmpty else { return }

        // Use the policy-defined action (strictest wins)
        let action = engine.determineAction(for: violations)
        let matchCount = violations.reduce(0) { $0 + $1.matches.count }
        let ruleNames = violations.map { $0.ruleName }.joined(separator: ", ")
        let severities = violations.map { $0.severity.rawValue }.joined(separator: ", ")

        print("")
        print("=== [DLP ALERT] Clipboard Violation Detected ===")
        print("  Source App: \(sourceApp)")
        print("  Matched Rules: \(ruleNames)")
        print("  Severities: \(severities)")
        print("  Total Matches: \(matchCount)")
        print("  Action: \(action.rawValue.uppercased())")

        // Execute action based on POLICY setting
        if action == .block || action == .quarantine {
            clearClipboard()
            totalBlocked += 1
            showPopup(
                title: "NextGuard DLP - Content BLOCKED",
                message: "Sensitive data detected and blocked in \(sourceApp).\n\nRules: \(ruleNames)\nSeverity: \(severities)\nMatches: \(matchCount)\n\nClipboard has been cleared.",
                critical: true
            )
            print("  Result: CLIPBOARD CLEARED - content blocked")
        } else {
            showPopup(
                title: "NextGuard DLP - Sensitive Data Detected",
                message: "Sensitive data detected in \(sourceApp) (audit mode).\n\nRules: \(ruleNames)\nSeverity: \(severities)\nMatches: \(matchCount)",
                critical: false
            )
            print("  Result: Logged (audit mode)")
        }
        print("================================================")
        print("")

        // Report all violations to Console
        Task {
            for v in violations {
                await mgmtClient.reportIncident(
                    policyId: v.ruleId,
                    channel: "clipboard",
                    severity: v.severity.rawValue,
                    action: v.action.rawValue,
                    matchCount: v.matches.count,
                    details: "Auto-scan from \(sourceApp): \(v.matches.count) matches for \(v.ruleName)"
                )
            }
            print("[NextGuard] \(violations.count) incident(s) reported to console")
        }

        logger.warning("Clipboard DLP: \(action.rawValue) | rules=\(ruleNames) | app=\(sourceApp) | matches=\(matchCount)")
    }

    // MARK: - Block Actions
    private func clearClipboard() {
        DispatchQueue.main.async {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString("[Content blocked by NextGuard DLP Policy]", forType: .string)
        }
    }

    // MARK: - Popup Alert (NSAlert - works in any macOS app)
    private func showPopup(title: String, message: String, critical: Bool) {
        DispatchQueue.main.async {
            // Bring app to front so alert is visible
            NSApp.activate(ignoringOtherApps: true)

            let alert = NSAlert()
            alert.messageText = title
            alert.informativeText = message
            alert.alertStyle = critical ? .critical : .warning
            if critical {
                alert.icon = NSImage(systemSymbolName: "xmark.shield.fill", accessibilityDescription: "Blocked")
            } else {
                alert.icon = NSImage(systemSymbolName: "exclamationmark.shield.fill", accessibilityDescription: "Warning")
            }
            alert.addButton(withTitle: "OK")
            alert.runModal()
        }
    }
}
