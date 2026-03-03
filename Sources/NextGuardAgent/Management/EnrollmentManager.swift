//
//  EnrollmentManager.swift
//  NextGuardAgent
//
//  Zero-Trust Enrollment Flow: Token Validation → CSR → mTLS Certificate Exchange
//  Supports manual (GUI) and silent/zero-touch (MDM/Intune parameter) enrollment
//
//  Enrollment Steps:
//  1. Admin generates Enrollment Token in Console (e.g. ENR-8X92-ABCD, TTL=24h)
//  2. Agent submits Token + device info to Console /api/v1/enroll
//  3. Console validates token, returns device UUID + CA-signed client cert
//  4. Agent stores cert in Keychain, all future comms use mTLS
//

import Foundation
import Security
import CryptoKit

// MARK: - Enrollment Result

enum EnrollmentResult {
    case success(EnrolledDeviceInfo)
    case invalidToken
    case tokenExpired
    case networkError(String)
    case serverError(Int, String)
    case alreadyEnrolled
}

// MARK: - Enrollment Request / Response

struct EnrollmentRequest: Codable {
    let enrollmentToken: String
    let deviceId: String       // local UUID (keychained)
    let deviceName: String     // hostname
    let macAddress: String
    let osVersion: String
    let agentVersion: String
    let publicKeyPEM: String   // RSA/EC public key for mTLS cert issuance
}

struct EnrollmentResponse: Codable {
    let success: Bool
    let deviceId: String?
    let tenantId: String?
    let tenantName: String?
    let enrolledBy: String?
    let clientCertPEM: String?     // PEM-encoded client cert signed by Console CA
    let clientCertThumbprint: String?
    let uninstallPassword: String? // Console-issued random bypass password
    let policyLockLevel: String?   // none / override / locked
    let error: String?
}

// MARK: - Enrollment Manager

class EnrollmentManager {
    static let shared = EnrollmentManager()
    private init() {}

    private let keychainService = "com.nextguard.agent"
    private let deviceIdKey = "ng_device_uuid"
    private let clientCertLabel = "NextGuard Agent mTLS Client Cert"

    // MARK: - Main Enrollment Entry Point

    /// Call this from GUI when user enters Server URL + Token
    func enroll(
        consoleUrl: String,
        enrollmentToken: String,
        completion: @escaping (EnrollmentResult) -> Void
    ) {
        Task {
            let result = await performEnrollment(consoleUrl: consoleUrl, token: enrollmentToken)
            await MainActor.run { completion(result) }
        }
    }

    /// Silent/Zero-Touch enrollment: called on startup if MDM provides token via env/plist
    func checkZeroTouchEnrollment() {
        // Read from plist injected by MDM at install time
        guard let token = Bundle.main.object(forInfoDictionaryKey: "NGEnrollmentToken") as? String,
              let url   = Bundle.main.object(forInfoDictionaryKey: "NGConsoleURL") as? String,
              !AgentModeManager.shared.isManaged else { return }
        print("[Enrollment] Zero-touch token found, enrolling silently...")
        enroll(consoleUrl: url, enrollmentToken: token) { result in
            switch result {
            case .success(let info):
                print("[Enrollment] Zero-touch enrollment succeeded: \(info.deviceId)")
            case .alreadyEnrolled:
                print("[Enrollment] Already enrolled, skipping")
            default:
                print("[Enrollment] Zero-touch enrollment failed: \(result)")
            }
        }
    }

    // MARK: - Enrollment Flow

    private func performEnrollment(consoleUrl: String, token: String) async -> EnrollmentResult {
        // Validate token format (ENR-XXXX-XXXX)
        guard isValidTokenFormat(token) else {
            return .invalidToken
        }

        // Get or create persistent device UUID
        let deviceId = getOrCreateDeviceId()
        let deviceName = Host.current().localizedName ?? "MacBook"
        let osVersion = ProcessInfo.processInfo.operatingSystemVersionString

        // Generate ephemeral key pair for mTLS cert request
        let (publicKeyPEM, _) = generateKeyPair()

        // Build request
        let request = EnrollmentRequest(
            enrollmentToken: token,
            deviceId: deviceId,
            deviceName: deviceName,
            macAddress: getMacAddress(),
            osVersion: osVersion,
            agentVersion: "1.0.0",
            publicKeyPEM: publicKeyPEM
        )

        // POST to Console
        guard let url = URL(string: "\(consoleUrl)/api/v1/agents/enroll") else {
            return .networkError("Invalid console URL")
        }

        do {
            var req = URLRequest(url: url)
            req.httpMethod = "POST"
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.httpBody = try JSONEncoder().encode(request)
            req.timeoutInterval = 15

            let (data, response) = try await URLSession.shared.data(for: req)
            guard let http = response as? HTTPURLResponse else {
                return .networkError("Invalid response")
            }

            switch http.statusCode {
            case 200, 201:
                let resp = try JSONDecoder().decode(EnrollmentResponse.self, from: data)
                if resp.success, let deviceIdResp = resp.deviceId,
                   let tenantId = resp.tenantId {
                    // Store client cert in Keychain
                    if let certPEM = resp.clientCertPEM {
                        storeClientCert(certPEM)
                    }
                    // Build device info
                    var info = EnrolledDeviceInfo(
                        deviceId: deviceIdResp,
                        tenantId: tenantId,
                        tenantName: resp.tenantName ?? tenantId,
                        consoleUrl: consoleUrl,
                        enrolledAt: Date(),
                        enrolledBy: resp.enrolledBy ?? "admin",
                        clientCertThumbprint: resp.clientCertThumbprint ?? "",
                        lastPolicySync: nil,
                        uninstallPasswordHash: nil,
                        policyLockLevel: PolicyLockLevel(rawValue: resp.policyLockLevel ?? "none") ?? .none
                    )
                    // Hash & store uninstall password
                    if let pw = resp.uninstallPassword {
                        let hash = sha256(pw)
                        info.uninstallPasswordHash = hash
                        print("[Enrollment] Tamper-protection password set by Console")
                    }
                    return .success(info)
                } else {
                    let errMsg = resp.error ?? "Unknown server error"
                    if errMsg.contains("expired") { return .tokenExpired }
                    if errMsg.contains("invalid") { return .invalidToken }
                    return .serverError(http.statusCode, errMsg)
                }
            case 401, 403:
                return .invalidToken
            case 410:
                return .tokenExpired
            case 409:
                return .alreadyEnrolled
            default:
                let msg = String(data: data, encoding: .utf8) ?? "Unknown error"
                return .serverError(http.statusCode, msg)
            }
        } catch let urlError as URLError {
            return .networkError(urlError.localizedDescription)
        } catch {
            return .networkError(error.localizedDescription)
        }
    }

    // MARK: - Token Format Validation

    private func isValidTokenFormat(_ token: String) -> Bool {
        // Accept: ENR-XXXX-XXXX (alphanumeric segments) or raw UUID
        let pattern = #"^(ENR-[A-Z0-9]{4}-[A-Z0-9]{4})|([A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12})$"#
        let stripped = token.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        return stripped.range(of: pattern, options: .regularExpression) != nil
    }

    // MARK: - Device UUID (persisted in Keychain)

    func getOrCreateDeviceId() -> String {
        if let existing = readFromKeychain(key: deviceIdKey) { return existing }
        let newId = UUID().uuidString
        writeToKeychain(key: deviceIdKey, value: newId)
        return newId
    }

    // MARK: - Key Pair Generation (for mTLS CSR)

    private func generateKeyPair() -> (publicPEM: String, privatePEM: String) {
        // For production: use SecKeyCreateRandomKey with RSA-2048 or EC P-256
        // Stub implementation returns placeholder PEM
        let stub = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQY...stub...\n-----END PUBLIC KEY-----"
        return (stub, "")
    }

    // MARK: - Client Cert Storage

    private func storeClientCert(_ pem: String) {
        writeToKeychain(key: clientCertLabel, value: pem)
        print("[Enrollment] Client mTLS cert stored in Keychain")
    }

    func getClientCert() -> String? {
        return readFromKeychain(key: clientCertLabel)
    }

    // MARK: - Keychain Helpers

    private func writeToKeychain(key: String, value: String) {
        let data = Data(value.utf8)
        let query: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: key,
            kSecValueData as String:   data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock
        ]
        SecItemDelete(query as CFDictionary)
        SecItemAdd(query as CFDictionary, nil)
    }

    private func readFromKeychain(key: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: key,
            kSecReturnData as String:  true,
            kSecMatchLimit as String:  kSecMatchLimitOne
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess,
              let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    // MARK: - Network Helpers

    private func getMacAddress() -> String {
        // Returns primary network interface MAC address
        return "02:00:00:00:00:00" // stub - use IOKit in production
    }

    private func sha256(_ input: String) -> String {
        let data = Data(input.utf8)
        let hash = SHA256.hash(data: data)
        return hash.compactMap { String(format: "%02x", $0) }.joined()
    }

    // MARK: - Poll for Remote Commands

    /// Called by heartbeat timer to check for Console-issued commands
    func pollRemoteCommands() async {
        guard let info = AgentModeManager.shared.enrolledDevice,
              let url = URL(string: "\(info.consoleUrl)/api/v1/agents/\(info.deviceId)/commands") else { return }
        do {
            let (data, _) = try await URLSession.shared.data(from: url)
            let commands = try JSONDecoder().decode([ConsoleRemoteCommand].self, from: data)
            for cmd in commands {
                await MainActor.run {
                    AgentModeManager.shared.handleRemoteCommand(cmd)
                }
            }
        } catch {
            // Silently ignore - console may be offline
        }
    }
}
