//
//  ManagementClient.swift
//  NextGuard Endpoint DLP Agent
//
//  Copyright (c) 2026 NextGuard Technology Limited. All rights reserved.
//

import Foundation

/// ManagementClient handles all communication between the DLP Agent and
/// the NextGuard Management Console (next-guard.com).
/// Implements: Agent Registration, Heartbeat, Policy Pull, Incident Reporting
class ManagementClient {
    static let shared = ManagementClient()

    private let baseURL = "https://www.next-guard.com/api/v1"
    private let session = URLSession.shared
    private(set) var agentId: String?
    private(set) var tenantId: String?
    private var heartbeatTimer: Timer?

    private init() {
        agentId = UserDefaults.standard.string(forKey: "nextguard_agent_id")
        tenantId = UserDefaults.standard.string(forKey: "nextguard_tenant_id")
    }

    /// Configure the tenant ID for this agent. Call before registration.
    func setTenantId(_ id: String) {
        tenantId = id
        UserDefaults.standard.set(id, forKey: "nextguard_tenant_id")
        print("[NextGuard] Tenant ID set: \(id)")
    }

    // MARK: - Agent Registration (async)

    func registerAgent() async -> Bool {
        let hostname = Host.current().localizedName ?? "unknown"
        let username = NSUserName()
        let osVersion = ProcessInfo.processInfo.operatingSystemVersionString
        let agentVersion = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.2.0"

        var body: [String: Any] = [
            "hostname": hostname,
            "username": username,
            "os": "macOS \(osVersion)",
            "agentVersion": agentVersion,
            "capabilities": ["file", "clipboard", "email", "browser", "network", "usb", "print"]
        ]
        if let tenantId = tenantId {
            body["tenantId"] = tenantId
        }

        do {
            let data = try await postJSON(endpoint: "/agents/register", body: body)
            if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let id = json["agentId"] as? String {
                self.agentId = id
                UserDefaults.standard.set(id, forKey: "nextguard_agent_id")
                // Server may assign tenantId during registration
                if let serverTenantId = json["tenantId"] as? String {
                    setTenantId(serverTenantId)
                }
                print("[NextGuard] Registered with ID: \(id), tenant: \(tenantId ?? "none")")
                return true
            }
            return false
        } catch {
            print("[NextGuard] Registration failed: \(error.localizedDescription)")
            return false
        }
    }

    // MARK: - Heartbeat

    func startHeartbeat(interval: TimeInterval = 60) {
        heartbeatTimer?.invalidate()
        sendHeartbeat()
        heartbeatTimer = Timer.scheduledTimer(withTimeInterval: interval, repeats: true) { [weak self] _ in
            self?.sendHeartbeat()
        }
    }

    func stopHeartbeat() {
        heartbeatTimer?.invalidate()
        heartbeatTimer = nil
    }

    private func sendHeartbeat() {
        guard let agentId = agentId else { return }
        var body: [String: Any] = [
            "agentId": agentId,
            "status": "online",
            "hostname": Host.current().localizedName ?? "unknown",
            "username": NSUserName(),
            "agentVersion": Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.2.0",
            "os": "macOS \(ProcessInfo.processInfo.operatingSystemVersionString)",
            "uptime": ProcessInfo.processInfo.systemUptime
        ]
        if let tenantId = tenantId {
            body["tenantId"] = tenantId
        }
        Task {
            do {
                _ = try await postJSON(endpoint: "/agents/heartbeat", body: body)
                print("[NextGuard] Heartbeat sent (tenant: \(tenantId ?? "none"))")
            } catch {
                print("[NextGuard] Heartbeat failed: \(error.localizedDescription)")
            }
        }
    }

    // MARK: - Policy Pull (async)

    func pullPolicies() async -> [[String: Any]] {
        guard let agentId = agentId else { return [] }
        var urlString = "\(baseURL)/policies/bundle?agentId=\(agentId)"
        if let tenantId = tenantId {
            urlString += "&tenantId=\(tenantId)"
        }
        guard let url = URL(string: urlString) else { return [] }

        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.timeoutInterval = 15

        do {
            let (data, _) = try await session.data(for: request)
            if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let bundle = json["bundle"] as? [String: Any],
               let policies = bundle["policies"] as? [[String: Any]] {
                print("[NextGuard] Pulled \(policies.count) policies (tenant: \(tenantId ?? "none"))")
                return policies
            }
        } catch {
            print("[NextGuard] Policy pull failed: \(error.localizedDescription)")
        }
        return []
    }

    // MARK: - Incident Reporting (async)

    func reportIncident(
        policyId: String,
        channel: String,
        severity: String,
        action: String,
        matchCount: Int,
        details: String
    ) async {
        guard let agentId = agentId else { return }
        var body: [String: Any] = [
            "agentId": agentId,
            "hostname": Host.current().localizedName ?? "unknown",
            "username": NSUserName(),
            "policyId": policyId,
            "severity": severity,
            "action": action,
            "channel": channel,
            "matchCount": matchCount,
            "details": details,
            "timestamp": ISO8601DateFormatter().string(from: Date())
        ]
        if let tenantId = tenantId {
            body["tenantId"] = tenantId
        }

        do {
            let data = try await postJSON(endpoint: "/incidents", body: body)
            if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let incidentId = json["incidentId"] as? String {
                print("[NextGuard] Incident reported: \(incidentId)")
            }
        } catch {
            print("[NextGuard] Incident report failed: \(error.localizedDescription)")
        }
    }

    // MARK: - HTTP Helper (async)

    private func postJSON(endpoint: String, body: [String: Any]) async throws -> Data {
        guard let url = URL(string: "\(baseURL)\(endpoint)") else {
            throw NSError(domain: "ManagementClient", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid URL"])
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try? JSONSerialization.data(withJSONObject: body)
        request.timeoutInterval = 15
        let (data, _) = try await session.data(for: request)
        return data

            // MARK: - Log Upload (for ForensicCollector)
    func uploadLogs(events: [[String: Any]], completion: @escaping (Bool) -> Void) {
        guard let url = URL(string: "\(baseURL)/logs/upload") else {
            completion(false); return
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try? JSONSerialization.data(withJSONObject: ["events": events])
        request.timeoutInterval = 15
        session.dataTask(with: request) { _, response, error in
            let success = (response as? HTTPURLResponse)?.statusCode == 200
            completion(success)
        }.resume()
    }
}
