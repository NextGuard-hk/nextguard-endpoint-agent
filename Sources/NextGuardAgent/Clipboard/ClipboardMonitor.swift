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
import UserNotifications

// MARK: - Clipboard Monitor
final class ClipboardMonitor: NSObject, UNUserNotificationCenterDelegate {
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

    private override init() {
        super.init()
        setupNotifications()
    }

    // MARK: - Notification Setup
    private func setupNotifications() {
        let center = UNUserNotificationCenter.current()
        center.delegate = self

        // Request notification permission
        center.requestAuthorization(options: [.alert, .sound, .badge]) { granted, error in
            if granted {
                print("[OK] Notification permission granted")
            } else {
                print("[WARN] Notification permission denied: \(error?.localizedDescription ?? "unknown")")
            }
        }

        // Register custom categories for actionable notifications
        let blockCategory = UNNotificationCategory(
            identifier: "DLP_BLOCK",
            actions: [],
            intentIdentifiers: [],
            options: .customDismissAction
        )
        let auditCategory = UNNotificationCategory(
            identifier: "DLP_AUDIT",
            actions: [],
            intentIdentifiers: [],
            options: .customDismissAction
        )
        center.setNotificationCategories([blockCategory, auditCategory])
    }

    // UNUserNotificationCenterDelegate - show notification even when app is in foreground
    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                willPresent notification: UNNotification,
                                withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .sound, .badge])
    }

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
            showDLPNotification(
                title: "NextGuard DLP - Content BLOCKED",
                body: "Sensitive data detected and blocked in \(sourceApp).\nRules: \(ruleNames) | Severity: \(severities) | Matches: \(matchCount)",
                isBlock: true
            )
            print("  Result: CLIPBOARD CLEARED - content blocked")
        } else {
            showDLPNotification(
                title: "NextGuard DLP - Sensitive Data Detected",
                body: "Sensitive data detected in \(sourceApp) (audit mode).\nRules: \(ruleNames) | Severity: \(severities) | Matches: \(matchCount)",
                isBlock: false
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

    // MARK: - Modern Notification (UNUserNotificationCenter)
    private func showDLPNotification(title: String, body: String, isBlock: Bool) {
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.sound = UNNotificationSound.default
        content.categoryIdentifier = isBlock ? "DLP_BLOCK" : "DLP_AUDIT"

        // Use unique ID so notifications don't replace each other
        let requestId = "dlp-\(UUID().uuidString)"
        let request = UNNotificationRequest(identifier: requestId, content: content, trigger: nil)

        UNUserNotificationCenter.current().add(request) { error in
            if let error = error {
                print("[WARN] Notification failed: \(error.localizedDescription)")
            }
        }
    }
}
