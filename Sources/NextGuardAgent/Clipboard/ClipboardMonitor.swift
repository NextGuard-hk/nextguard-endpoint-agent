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

            showFloatingNotification(
                title: "NextGuard DLP - Content BLOCKED",
                message: "Sensitive data blocked in \(sourceApp).\nRules: \(ruleNames) | Matches: \(matchCount)\nClipboard has been cleared.",
                critical: true
            )

            print("  Result: CLIPBOARD CLEARED - content blocked")
        } else {
            showFloatingNotification(
                title: "NextGuard DLP - Sensitive Data Detected",
                message: "Sensitive data in \(sourceApp) (audit mode).\nRules: \(ruleNames) | Matches: \(matchCount)",
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

    // MARK: - Floating Notification Panel (Non-Blocking, no bundle required)
    private func showFloatingNotification(title: String, message: String, critical: Bool) {
        DispatchQueue.main.async {
            let panel = NSPanel(
                contentRect: NSRect(x: 0, y: 0, width: 420, height: 140),
                styleMask: [.titled, .closable, .nonactivatingPanel, .hudWindow],
                backing: .buffered,
                defer: false
            )
            panel.level = .floating
            panel.isFloatingPanel = true
            panel.hidesOnDeactivate = false
            panel.title = title

            // Position top-right of screen
            if let screen = NSScreen.main {
                let screenFrame = screen.visibleFrame
                let x = screenFrame.maxX - 440
                let y = screenFrame.maxY - 160
                panel.setFrameOrigin(NSPoint(x: x, y: y))
            }

            let contentView = NSView(frame: NSRect(x: 0, y: 0, width: 420, height: 100))

            // Icon
            let iconView = NSImageView(frame: NSRect(x: 15, y: 40, width: 40, height: 40))
            let iconName = critical ? "xmark.shield.fill" : "exclamationmark.shield.fill"
            iconView.image = NSImage(systemSymbolName: iconName, accessibilityDescription: nil)
            iconView.contentTintColor = critical ? .systemRed : .systemOrange
            contentView.addSubview(iconView)

            // Message label
            let label = NSTextField(wrappingLabelWithString: message)
            label.frame = NSRect(x: 65, y: 10, width: 340, height: 80)
            label.font = NSFont.systemFont(ofSize: 12)
            label.isEditable = false
            label.isBordered = false
            label.drawsBackground = false
            contentView.addSubview(label)

            panel.contentView = contentView
            panel.orderFrontRegardless()

            // Auto-dismiss after 6 seconds
            DispatchQueue.main.asyncAfter(deadline: .now() + 6.0) {
                panel.close()
            }
        }
    }
}
