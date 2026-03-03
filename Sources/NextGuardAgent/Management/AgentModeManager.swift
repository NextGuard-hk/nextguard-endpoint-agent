//
//  AgentModeManager.swift
//  NextGuardAgent
//
//  Dual-State Architecture: Standalone (Unjoined) vs Managed (Tenant-Joined)
//  Inspired by Windows Domain Join / Intune Device Enrollment model
//
//  State Machine:
//    .standalone  - local admin control only, full GUI access
//    .managed     - Console has override authority, GUI settings greyed-out
//

import Foundation
import Combine
import CryptoKit

// MARK: - Agent Mode

enum AgentMode: String, Codable {
    case standalone = "standalone"   // Unjoined - local control
    case managed    = "managed"      // Tenant-joined - Console override
}

// MARK: - Enrollment State

enum EnrollmentState: String, Codable {
    case unenrolled   = "unenrolled"
    case enrolling    = "enrolling"    // token submitted, awaiting cert
    case enrolled     = "enrolled"     // mTLS cert issued, heartbeat active
    case suspended    = "suspended"    // Console suspended this device
    case unenrolling  = "unenrolling"  // Leave in progress
}

// MARK: - Enrolled Device Info

struct EnrolledDeviceInfo: Codable {
    var deviceId: String           // UUID assigned by Console on enrollment
    var tenantId: String
    var tenantName: String
    var consoleUrl: String
    var enrolledAt: Date
    var enrolledBy: String         // admin email who issued the token
    var clientCertThumbprint: String  // SHA256 of issued mTLS cert
    var lastPolicySync: Date?
    var uninstallPasswordHash: String? // SHA256 of Console-issued bypass password
    var policyLockLevel: PolicyLockLevel
}

enum PolicyLockLevel: String, Codable {
    case none      = "none"      // Level 3 (local) still active
    case override  = "override"  // Level 1 overrides but local still visible
    case locked    = "locked"    // Level 1 fully locks; local config frozen
}

// MARK: - Agent Mode Manager

class AgentModeManager: ObservableObject {
    static let shared = AgentModeManager()

    @Published var mode: AgentMode = .standalone
    @Published var enrollmentState: EnrollmentState = .unenrolled
    @Published var enrolledDevice: EnrolledDeviceInfo? = nil
    @Published var isConsoleReachable: Bool = false
    @Published var managedSettingsLocked: Bool = false

    // Local admin password hash (Standalone mode self-protection)
    private(set) var localAdminPasswordHash: String? = nil

    private let storageKey = "ng_agent_mode_state"
    private let deviceInfoKey = "ng_enrolled_device"
    private let adminPwHashKey = "ng_local_admin_pw_hash"
    private var heartbeatTimer: Timer?
    private var cancellables = Set<AnyCancellable>()

    private init() {
        loadPersistedState()
    }

    // MARK: - Persist / Load

    private func loadPersistedState() {
        if let modeRaw = UserDefaults.standard.string(forKey: storageKey),
           let savedMode = AgentMode(rawValue: modeRaw) {
            mode = savedMode
        }
        if let data = UserDefaults.standard.data(forKey: deviceInfoKey),
           let info = try? JSONDecoder().decode(EnrolledDeviceInfo.self, from: data) {
            enrolledDevice = info
            enrollmentState = .enrolled
            managedSettingsLocked = info.policyLockLevel == .locked
        }
        localAdminPasswordHash = UserDefaults.standard.string(forKey: adminPwHashKey)
    }

    private func persistState() {
        UserDefaults.standard.set(mode.rawValue, forKey: storageKey)
        if let info = enrolledDevice,
           let data = try? JSONEncoder().encode(info) {
            UserDefaults.standard.set(data, forKey: deviceInfoKey)
        }
    }

    // MARK: - Standalone Mode: Local Admin Password

    /// Set a local admin password (hashed with SHA256) for self-protection
    func setLocalAdminPassword(_ password: String) {
        let hash = sha256(password)
        localAdminPasswordHash = hash
        UserDefaults.standard.set(hash, forKey: adminPwHashKey)
        print("[AgentMode] Local admin password set")
    }

    /// Verify local admin password
    func verifyLocalAdminPassword(_ password: String) -> Bool {
        guard let stored = localAdminPasswordHash else { return true } // no password = open
        return sha256(password) == stored
    }

    func hasLocalAdminPassword() -> Bool {
        return localAdminPasswordHash != nil && !localAdminPasswordHash!.isEmpty
    }

    // MARK: - Managed Mode: Enrollment

    /// Begin enrollment: called after token is validated by EnrollmentManager
    func transitionToManaged(deviceInfo: EnrolledDeviceInfo) {
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            self.enrolledDevice = deviceInfo
            self.mode = .managed
            self.enrollmentState = .enrolled
            self.managedSettingsLocked = deviceInfo.policyLockLevel == .locked
            self.persistState()
            self.startHeartbeatMonitor()
            NotificationCenter.default.post(name: .agentModeChanged, object: AgentMode.managed)
            print("[AgentMode] Transitioned to MANAGED mode. Tenant: \(deviceInfo.tenantId)")
        }
    }

    /// Leave managed mode (requires Console-issued uninstall password OR Console remote command)
    func leaveManaged(bypassPassword: String, completion: @escaping (Bool) -> Void) {
        guard let info = enrolledDevice else {
            transitionToStandalone()
            completion(true)
            return
        }
        // Verify uninstall password
        if let hash = info.uninstallPasswordHash {
            guard sha256(bypassPassword) == hash else {
                print("[AgentMode] Leave rejected: invalid bypass password")
                completion(false)
                return
            }
        }
        enrollmentState = .unenrolling
        // Notify Console
        Task {
            await notifyConsoleLeave(deviceId: info.deviceId, consoleUrl: info.consoleUrl)
            await MainActor.run {
                self.transitionToStandalone()
                completion(true)
            }
        }
    }

    private func transitionToStandalone() {
        enrolledDevice = nil
        mode = .standalone
        enrollmentState = .unenrolled
        managedSettingsLocked = false
        stopHeartbeatMonitor()
        UserDefaults.standard.removeObject(forKey: deviceInfoKey)
        persistState()
        NotificationCenter.default.post(name: .agentModeChanged, object: AgentMode.standalone)
        print("[AgentMode] Transitioned to STANDALONE mode")
    }

    // MARK: - Policy Lock Level (set by Console)

    func applyPolicyLockLevel(_ level: PolicyLockLevel) {
        guard var info = enrolledDevice else { return }
        info.policyLockLevel = level
        enrolledDevice = info
        managedSettingsLocked = level == .locked
        persistState()
        print("[AgentMode] Policy lock level set to: \(level.rawValue)")
    }

    // MARK: - Uninstall/Bypass Password (set by Console)

    func setUninstallPassword(_ password: String) {
        guard var info = enrolledDevice else { return }
        info.uninstallPasswordHash = sha256(password)
        enrolledDevice = info
        persistState()
        print("[AgentMode] Uninstall password updated by Console")
    }

    func verifyUninstallPassword(_ password: String) -> Bool {
        guard let hash = enrolledDevice?.uninstallPasswordHash else { return true }
        return sha256(password) == hash
    }

    // MARK: - Console Reachability Heartbeat

    func startHeartbeatMonitor() {
        stopHeartbeatMonitor()
        heartbeatTimer = Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { [weak self] _ in
            self?.checkConsoleReachability()
        }
        checkConsoleReachability()
    }

    func stopHeartbeatMonitor() {
        heartbeatTimer?.invalidate()
        heartbeatTimer = nil
    }

    private func checkConsoleReachability() {
        guard let info = enrolledDevice,
              let url = URL(string: "\(info.consoleUrl)/api/v1/health") else { return }
        URLSession.shared.dataTask(with: url) { [weak self] _, response, _ in
            let reachable = (response as? HTTPURLResponse)?.statusCode == 200
            DispatchQueue.main.async {
                self?.isConsoleReachable = reachable
                if !reachable {
                    print("[AgentMode] Console unreachable - switching to last-known-good policy cache")
                    OfflineQueueManager.shared.enterOfflineMode()
                } else {
                    OfflineQueueManager.shared.flushQueueIfNeeded()
                }
            }
        }.resume()
    }

    // MARK: - Console Remote Commands

    /// Called when Console pushes a remote command via polling / push
    func handleRemoteCommand(_ command: ConsoleRemoteCommand) {
        print("[AgentMode] Remote command received: \(command.type.rawValue)")
        switch command.type {
        case .lockSettings:
            applyPolicyLockLevel(.locked)
        case .unlockSettings:
            applyPolicyLockLevel(.none)
        case .forceLeave:
            transitionToStandalone()
        case .suspend:
            enrollmentState = .suspended
            persistState()
        case .setUninstallPassword:
            if let pw = command.payload { setUninstallPassword(pw) }
        case .networkIsolation:
            // Placeholder: hook into NetworkExtension filter to block all except Console
            print("[AgentMode] Network isolation requested - requires NetworkExtension entitlement")
        }
    }

    // MARK: - Helpers

    private func sha256(_ input: String) -> String {
        let data = Data(input.utf8)
        let hash = SHA256.hash(data: data)
        return hash.compactMap { String(format: "%02x", $0) }.joined()
    }

    private func notifyConsoleLeave(deviceId: String, consoleUrl: String) async {
        guard let url = URL(string: "\(consoleUrl)/api/v1/agents/\(deviceId)/leave") else { return }
        var req = URLRequest(url: url)
        req.httpMethod = "DELETE"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        try? await URLSession.shared.data(for: req)
    }

    // MARK: - Computed Helpers

    var isManaged: Bool { mode == .managed }
    var isStandalone: Bool { mode == .standalone }
    var canEditLocalSettings: Bool {
        mode == .standalone || enrolledDevice?.policyLockLevel == .none
    }
    var managedByOrgMessage: String {
        if let name = enrolledDevice?.tenantName {
            return "Some settings are managed by \(name)"
        }
        return "Some settings are managed by your organisation"
    }
}

// MARK: - Console Remote Command Model

struct ConsoleRemoteCommand: Codable {
    enum CommandType: String, Codable {
        case lockSettings       = "lock_settings"
        case unlockSettings     = "unlock_settings"
        case forceLeave         = "force_leave"
        case suspend            = "suspend"
        case setUninstallPassword = "set_uninstall_password"
        case networkIsolation   = "network_isolation"
    }
    let type: CommandType
    let payload: String?
    let issuedAt: Date
    let issuedBy: String
}

// MARK: - Notification Names

extension Notification.Name {
    static let agentModeChanged = Notification.Name("com.nextguard.agent.modeChanged")
    static let consolePolicyUpdated = Notification.Name("com.nextguard.agent.policyUpdated")
    static let offlineModeEntered = Notification.Name("com.nextguard.agent.offlineMode")
    static let incidentQueueFlushed = Notification.Name("com.nextguard.agent.queueFlushed")
}
