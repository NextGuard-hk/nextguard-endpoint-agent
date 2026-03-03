//
//  DLPNotificationHelper.swift
//  NextGuardAgent
//
//  Shows macOS User Notifications for DLP policy matches
//  Block alerts (modal) and Audit notifications (banner)
//

import AppKit
import UserNotifications

// MARK: - DLP Notification Helper
// Provides user-facing alerts and macOS notification banners
// for DLP policy enforcement events

struct DLPNotificationHelper {

    /// Request notification permission on launch (call once from AppDelegate)
    static func requestPermission() {
        UNUserNotificationCenter.current().requestAuthorization(
            options: [.alert, .sound, .badge]
        ) { granted, error in
            if let error = error {
                print("[WARN] Notification permission error: \(error.localizedDescription)")
            } else {
                print(granted ? "[OK] Notifications authorized" : "[INFO] Notifications denied by user")
            }
        }
    }

    /// Show a banner notification for BLOCK events
    static func showBlockAlert(policyName: String, channel: String) {
        let content = UNMutableNotificationContent()
        content.title = "NextGuard DLP: Transfer Blocked"
        content.body = "Policy \"\(policyName)\" blocked a \(channel) transfer."
        content.sound = .defaultCritical
        content.categoryIdentifier = "DLP_BLOCK"

        let request = UNNotificationRequest(
            identifier: UUID().uuidString,
            content: content,
            trigger: nil
        )
        UNUserNotificationCenter.current().add(request) { error in
            if let error = error {
                print("[WARN] Failed to show block notification: \(error.localizedDescription)")
            }
        }
    }

    /// Show a banner notification for AUDIT events
    static func showAuditAlert(policyName: String, channel: String) {
        let content = UNMutableNotificationContent()
        content.title = "NextGuard DLP: Activity Logged"
        content.body = "Policy \"\(policyName)\" audited a \(channel) transfer."
        content.sound = .default
        content.categoryIdentifier = "DLP_AUDIT"

        let request = UNNotificationRequest(
            identifier: UUID().uuidString,
            content: content,
            trigger: nil
        )
        UNUserNotificationCenter.current().add(request) { error in
            if let error = error {
                print("[WARN] Failed to show audit notification: \(error.localizedDescription)")
            }
        }
    }

    /// Show a timed reminder banner (e.g. scan complete summary)
    static func showScanSummary(blockedCount: Int, auditCount: Int) {
        guard blockedCount > 0 || auditCount > 0 else { return }
        let content = UNMutableNotificationContent()
        content.title = "NextGuard DLP: Scan Summary"
        var parts: [String] = []
        if blockedCount > 0 { parts.append("\(blockedCount) blocked") }
        if auditCount > 0 { parts.append("\(auditCount) audited") }
        content.body = parts.joined(separator: ", ") + " since last check."
        content.sound = blockedCount > 0 ? .defaultCritical : .default

        let request = UNNotificationRequest(
            identifier: "scan-summary-" + Date().description,
            content: content,
            trigger: nil
        )
        UNUserNotificationCenter.current().add(request, withCompletionHandler: nil)
    }
}
