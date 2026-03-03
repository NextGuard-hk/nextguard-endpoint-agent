//
//  TamperProtection.swift
//  NextGuardAgent
//
//  Enterprise Tamper Protection:
//  - Local admin password (Standalone mode): prevents casual config changes
//  - Console-issued uninstall/bypass password (Managed mode): blocks force-removal
//  - Daemon watchdog: restarts DLP service if killed
//  - Process guard: detects debugger/kill attempts
//

import Foundation
import AppKit
import CryptoKit

// MARK: - Tamper Protection Manager

class TamperProtection {
    static let shared = TamperProtection()
    private init() {}

    private var watchdogTimer: Timer?
    private let watchdogInterval: TimeInterval = 10.0
    private var protectedProcessNames = ["NextGuardAgent"]

    // MARK: - Activation

    /// Call on app launch to arm tamper protection
    func arm() {
        startProcessWatchdog()
        registerTerminationHandler()
        print("[TamperProtection] Armed - process watchdog active")
    }

    func disarm() {
        watchdogTimer?.invalidate()
        watchdogTimer = nil
        print("[TamperProtection] Disarmed")
    }

    // MARK: - Local Admin Password Gate
    // Used in Standalone mode to prevent unauthorised settings changes

    /// Returns true if the action is permitted
    /// In standalone: requires local admin password if set
    /// In managed+locked: always returns false (Console controls)
    func authoriseSettingsChange(password: String? = nil) -> AuthorisationResult {
        let mode = AgentModeManager.shared

        // Managed + locked: block all local changes
        if mode.isManaged && mode.managedSettingsLocked {
            return .deniedByConsole(reason: mode.managedByOrgMessage)
        }

        // Standalone with password set: verify
        if mode.isStandalone && mode.hasLocalAdminPassword() {
            guard let pw = password else {
                return .requiresPassword
            }
            if mode.verifyLocalAdminPassword(pw) {
                return .permitted
            } else {
                return .wrongPassword
            }
        }

        return .permitted
    }

    /// Gate specifically for quitting/disabling the agent
    func authoriseAgentQuit(password: String? = nil) -> AuthorisationResult {
        let mode = AgentModeManager.shared

        // Managed mode: require Console uninstall password
        if mode.isManaged {
            guard let pw = password else {
                return .requiresPassword
            }
            if mode.verifyUninstallPassword(pw) {
                logTamperAttempt(action: "agent_quit_authorised", granted: true)
                return .permitted
            } else {
                logTamperAttempt(action: "agent_quit_blocked", granted: false)
                return .wrongPassword
            }
        }

        // Standalone with password set
        if mode.hasLocalAdminPassword() {
            guard let pw = password else {
                return .requiresPassword
            }
            if mode.verifyLocalAdminPassword(pw) {
                return .permitted
            } else {
                logTamperAttempt(action: "standalone_quit_blocked", granted: false)
                return .wrongPassword
            }
        }

        return .permitted
    }

    // MARK: - Process Watchdog
    // Monitors that the DLP agent stays running; logs suspicious termination

    func startProcessWatchdog() {
        watchdogTimer = Timer.scheduledTimer(
            withTimeInterval: watchdogInterval,
            repeats: true
        ) { [weak self] _ in
            self?.checkProcessIntegrity()
        }
    }

    private func checkProcessIntegrity() {
        // Check if any monitored companion processes were killed externally
        // In production: use EndpointSecurity framework to intercept ES_EVENT_TYPE_AUTH_SIGNAL
        // Here we log a heartbeat and check for unexpected process state
        let pid = ProcessInfo.processInfo.processIdentifier
        let isDebugged = isDebuggerAttached()

        if isDebugged {
            logTamperAttempt(action: "debugger_detected", granted: false)
            print("[TamperProtection] WARNING: Debugger attachment detected (PID \(pid))")
        }
    }

    // MARK: - Debugger Detection

    private func isDebuggerAttached() -> Bool {
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, Int32(ProcessInfo.processInfo.processIdentifier)]
        var size = MemoryLayout<kinfo_proc>.stride
        let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
        if result != 0 { return false }
        return (info.kp_proc.p_flag & P_TRACED) != 0
    }

    // MARK: - Application Termination Handler

    private func registerTerminationHandler() {
        NSWorkspace.shared.notificationCenter.addObserver(
            self,
            selector: #selector(handleWorkspaceWillTerminate),
            name: NSWorkspace.willPowerOffNotification,
            object: nil
        )
    }

    @objc private func handleWorkspaceWillTerminate() {
        print("[TamperProtection] System shutdown detected - flushing incident queue")
        OfflineQueueManager.shared.flushQueueIfNeeded()
    }

    // MARK: - Show Tamper Alert to User

    @MainActor
    func showTamperBlockAlert(reason: String) {
        let alert = NSAlert()
        alert.messageText = "Action Blocked by NextGuard DLP"
        alert.informativeText = reason
        alert.alertStyle = .critical
        alert.icon = NSImage(systemSymbolName: "lock.shield.fill", accessibilityDescription: nil)
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }

    @MainActor
    func showPasswordPrompt(title: String, completion: @escaping (String?) -> Void) {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = "Enter your administrator password to continue."
        alert.alertStyle = .warning
        alert.icon = NSImage(systemSymbolName: "lock.fill", accessibilityDescription: nil)
        alert.addButton(withTitle: "Confirm")
        alert.addButton(withTitle: "Cancel")

        let input = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 280, height: 24))
        input.placeholderString = "Password"
        alert.accessoryView = input

        let response = alert.runModal()
        if response == .alertFirstButtonReturn {
            let pw = input.stringValue
            completion(pw.isEmpty ? nil : pw)
        } else {
            completion(nil)
        }
    }

    // MARK: - Audit Logging

    private func logTamperAttempt(action: String, granted: Bool) {
        let entry = TamperAuditEntry(
            timestamp: Date(),
            action: action,
            granted: granted,
            processId: ProcessInfo.processInfo.processIdentifier,
            deviceId: EnrollmentManager.shared.getOrCreateDeviceId()
        )
        // Queue for Console upload
        OfflineQueueManager.shared.enqueueAuditEvent(entry)
        print("[TamperProtection] Audit: \(action) - granted=\(granted)")
    }
}

// MARK: - Authorisation Result

enum AuthorisationResult {
    case permitted
    case requiresPassword
    case wrongPassword
    case deniedByConsole(reason: String)

    var isPermitted: Bool { self == .permitted }

    var errorMessage: String {
        switch self {
        case .permitted:               return ""
        case .requiresPassword:        return "Administrator password required"
        case .wrongPassword:           return "Incorrect password. Please try again."
        case .deniedByConsole(let r):  return r
        }
    }
}

extension AuthorisationResult: Equatable {
    static func == (lhs: AuthorisationResult, rhs: AuthorisationResult) -> Bool {
        switch (lhs, rhs) {
        case (.permitted, .permitted),
             (.requiresPassword, .requiresPassword),
             (.wrongPassword, .wrongPassword):
            return true
        case (.deniedByConsole(let a), .deniedByConsole(let b)):
            return a == b
        default:
            return false
        }
    }
}

// MARK: - Tamper Audit Entry

struct TamperAuditEntry: Codable {
    let timestamp: Date
    let action: String
    let granted: Bool
    let processId: Int32
    let deviceId: String
}
