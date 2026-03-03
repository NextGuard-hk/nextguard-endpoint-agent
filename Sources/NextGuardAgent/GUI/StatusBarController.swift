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

    /// Animate scanning state with alternating icons
    /// Called as: StatusBarIconHelper.startScanningAnimation(button: button)
    /// Returns the Timer so caller can invalidate it when done
    @discardableResult
    static func startScanningAnimation(button: NSStatusBarButton) -> Timer {
        var toggle = false
        let timer = Timer.scheduledTimer(withTimeInterval: 0.6, repeats: true) { _ in
            toggle.toggle()
            DispatchQueue.main.async {
                let iconName = toggle ? "shield.lefthalf.filled" : "shield.righthalf.filled"
                let config = NSImage.SymbolConfiguration(pointSize: 16, weight: .medium)
                if let image = NSImage(
                    systemSymbolName: iconName,
                    accessibilityDescription: "NextGuard DLP Scanning"
                )?.withSymbolConfiguration(config) {
                    button.image = image
                    button.contentTintColor = .systemBlue
                }
            }
        }
        return timer
    }
}
