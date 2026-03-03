//
//  StatusBarController.swift
//  NextGuardAgent
//
//  Status bar icon helper - used by NextGuardApp.swift's AppDelegate
//  to update the status icon color/symbol based on protection state.
//  NOTE: The actual NSStatusItem is owned by AppDelegate.
//

import AppKit

// MARK: - Status Bar Icon Helper
// Called by AppDelegate to update icon appearance

struct StatusBarIconHelper {
    
    /// Apply protection status styling to a status item button
    static func update(
        button: NSStatusBarButton,
        protected: Bool,
        scanning: Bool = false,
        alert: Bool = false
    ) {
        let iconName: String
        let tintColor: NSColor
        
        if alert {
            iconName = "shield.slash.fill"
            tintColor = .systemRed
        } else if scanning {
            iconName = "shield.lefthalf.filled"
            tintColor = .systemBlue
        } else if protected {
            iconName = "shield.fill"
            tintColor = .systemGreen
        } else {
            iconName = "shield.slash.fill"
            tintColor = .systemOrange
        }
        
        let config = NSImage.SymbolConfiguration(pointSize: 16, weight: .medium)
        if let image = NSImage(
            systemSymbolName: iconName,
            accessibilityDescription: "NextGuard DLP"
        )?.withSymbolConfiguration(config) {
            button.image = image
            button.contentTintColor = tintColor
        }
    }
    
    /// Start scanning animation on a status item button
    /// Returns the timer - caller must invalidate it to stop
    static func startScanningAnimation(button: NSStatusBarButton) -> Timer {
        var frame = 0
        return Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { _ in
            update(button: button, protected: true, scanning: frame % 2 == 0)
            frame += 1
        }
    }
}

// MARK: - Alert Helper
// Shows macOS system notifications for DLP incidents

struct DLPNotificationHelper {
    
    static func showBlockAlert(policyName: String, channel: String) {
        let notification = NSUserNotification()
        notification.title = "NextGuard DLP - Blocked"
        notification.informativeText = "Transfer blocked: \(policyName) violation on \(channel)"
        notification.soundName = NSUserNotificationDefaultSoundName
        NSUserNotificationCenter.default.deliver(notification)
    }
    
    static func showAuditAlert(policyName: String, channel: String) {
        let notification = NSUserNotification()
        notification.title = "NextGuard DLP - Audited"
        notification.informativeText = "Sensitive data detected: \(policyName) on \(channel)"
        NSUserNotificationCenter.default.deliver(notification)
    }
}
