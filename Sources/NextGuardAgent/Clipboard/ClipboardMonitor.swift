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
    private var notificationsConfigured: Bool = false

    private let pollInterval: TimeInterval = 0.5

    private override init() {
        super.init()
        // NOTE: Do NOT call setupNotifications() here.
        // static let shared init runs via dispatch_once which may not be on main thread.
        // Notification setup is deferred to startMonitoring() on main thread.
    }

    // MARK: - Notification Setup (must be called on main thread)
    private func setupNotifications() {
        guard !notificationsConfigured else { return }
        notificationsConfigured = true

        let center = UNUserNotificationCenter.current()
        center.delegate = self

        center.requestAuthorization(options: [.alert, .sound, .badge]) { granted, error in
            if granted {
                print("[OK] Notification permission granted")
            } else {
                print("[WARN] Notification permission denied: \(error?.localizedDescription ?? "unknown")")
            }
        }

        let viewAction = UNNotificationAction(identifier: "VIEW_DETAILS", title: "View Details", options: .foreground)
        let dismissAction = UNNotificationAction(identifier: "DISMISS", title: "Dismiss", options: .destructive)

        let blockCategory = UNNotificationCategory(
            identifier: "DLP_BLOCK",
            actions: [viewAction, dismissAction],
            intentIdentifiers: [],
            options: .customDismissAction
        )
        let auditCategory = UNNotificationCategory(
            identifier: "DLP_AUDIT",
            actions: [viewAction, dismissAction],
            intentIdentifiers: [],
            options: .customDismissAction
        )

        center.setNotificationCategories([blockCategory, auditCategory])
    }

    // MARK: - UNUserNotificationCenterDelegate
    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                willPresent notification: UNNotification,
                                withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .sound, .list])
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                didReceive response: UNNotificationResponse,
                                withCompletionHandler completionHandler: @escaping () -> Void) {
        if response.actionIdentifier == "VIEW_DETAILS" {
            DispatchQueue.main.async {
                MainWindowController.shared.showWindow()
            }
        }
        completionHandler()
    }

    // MARK: - Start / Stop
    func startMonitoring() {
        guard !isActive else { return }

        // Setup notifications on main thread (deferred from init)
        if Thread.isMainThread {
            setupNotifications()
        } else {
            DispatchQueue.main.sync {
                setupNotifications()
            }
        }

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

        guard let text = pasteboard.string(forType: .string), !text.isEmpty else { return }

        totalInspected += 1
        let sourceApp = NSWorkspace.shared.frontmostApplication?.localizedName ?? "Unknown"

        let violations = engine.scanContent(text, channel: .clipboard)
        guard !violations.isEmpty else { return }

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

        if action == .block || action == .quarantine {
            clearClipboard()
            totalBlocked += 1

            sendNotification(
                title: "NextGuard DLP - Content BLOCKED",
                body: "Sensitive data blocked in \(sourceApp). Rules: \(ruleNames) | Severity: \(severities) | Matches: \(matchCount). Clipboard cleared.",
                category: "DLP_BLOCK",
                critical: true
            )

            print("  Result: CLIPBOARD CLEARED - content blocked")
        } else {
            sendNotification(
                title: "NextGuard DLP - Sensitive Data Detected",
                body: "Sensitive data detected in \(sourceApp) (audit mode). Rules: \(ruleNames) | Severity: \(severities) | Matches: \(matchCount)",
                category: "DLP_AUDIT",
                critical: false
            )

            print("  Result: Logged (audit mode)")
        }
        print("================================================")
        print("")

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

    // MARK: - macOS Native Notification (Non-Blocking Push)
    private func sendNotification(title: String, body: String, category: String, critical: Bool) {
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.categoryIdentifier = category
        content.sound = critical ? .defaultCritical : .default

        content.userInfo = [
            "type": "dlp_alert",
            "critical": critical,
            "timestamp": ISO8601DateFormatter().string(from: Date())
        ]

        let request = UNNotificationRequest(
            identifier: "dlp-\(UUID().uuidString)",
            content: content,
            trigger: nil
        )

        UNUserNotificationCenter.current().add(request) { error in
            if let error = error {
                print("[WARN] Notification failed: \(error.localizedDescription)")
                self.showFallbackAlert(title: title, message: body, critical: critical)
            }
        }
    }

    // MARK: - Fallback Alert (only if UNNotification fails)
    private func showFallbackAlert(title: String, message: String, critical: Bool) {
        DispatchQueue.main.async {
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
