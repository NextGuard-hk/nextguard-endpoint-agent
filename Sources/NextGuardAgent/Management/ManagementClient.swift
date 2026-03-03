//
//  ManagementClient.swift
//  NextGuard Endpoint DLP Agent
//
//  Copyright (c) 2026 NextGuard Technology Limited. All rights reserved.
//

import Foundation
import os.log

/// ManagementClient handles all communication between the DLP Agent and
/// the NextGuard Management Console (next-guard.com).
class ManagementClient {
    static let shared = ManagementClient()

    private let baseURL = "https://www.next-guard.com/api/v1"
    private let session = URLSession.shared
    private let syslogger = Logger(subsystem: "com.nextguard.agent", category: "Syslog")

    private(set) var agentId: String?
    private(set) var tenantId: String?
    private var heartbeatTimer: Timer?

    private init() {
        agentId = UserDefaults.standard.string(forKey: "nextguard_agent_id")
        tenantId = UserDefaults.standard.string(forKey: "nextguard_tenant_id")
    }

    func setTenantId(_ id: String) {
        tenantId = id
        UserDefaults.standard.set(id, forKey: "nextguard_tenant_id")
        print("[NextGuard] Tenant ID set: \(id)")
    }

    // MARK: - Agent Registration
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
        if let tenantId = tenantId { body["tenantId"] = tenantId }

        do {
            let data = try await postJSON(endpoint: "/agents/register", body: body)
            if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let id = json["agentId"] as? String {
                self.agentId = id
                UserDefaults.standard.set(id, forKey: "nextguard_agent_id")
                if let serverTenantId = json["tenantId"] as? String {
                    setTenantId(serverTenantId)
                }
                writeSyslog(level: .info, message: "Agent registered: \(id), tenant: \(tenantId ?? "none")")
                return true
            }
            return false
        } catch {
            writeSyslog(level: .error, message: "Registration failed: \(error.localizedDescription)")
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

    func sendHeartbeat() {
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
        if let tenantId = tenantId { body["tenantId"] = tenantId }

        Task {
            do {
                _ = try await postJSON(endpoint: "/agents/heartbeat", body: body)
                print("[NextGuard] Heartbeat sent (tenant: \(tenantId ?? "none"))")
            } catch {
                print("[NextGuard] Heartbeat failed: \(error.localizedDescription)")
            }
        }
    }

    // MARK: - Policy Pull
    func pullPolicies() async -> [[String: Any]] {
        guard let agentId = agentId else { return [] }
        var urlString = "\(baseURL)/policies/bundle?agentId=\(agentId)"
        if let tenantId = tenantId { urlString += "&tenantId=\(tenantId)" }
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
                writeSyslog(level: .info, message: "Pulled \(policies.count) policies")
                return policies
            }
        } catch {
            writeSyslog(level: .error, message: "Policy pull failed: \(error.localizedDescription)")
        }
        return []
    }

    // MARK: - Enhanced Incident Reporting (Full Forensic Data)
    func reportIncident(
        policyId: String,
        policyName: String,
        channel: String,
        severity: String,
        action: String,
        matchCount: Int,
        matchedPatterns: [String],
        matchedContent: [String],
        sourceApp: String,
        complianceFramework: String,
        details: String
    ) async {
        guard let agentId = agentId else { return }
        let hostname = Host.current().localizedName ?? "unknown"
        let username = NSUserName()
        let osVersion = ProcessInfo.processInfo.operatingSystemVersionString
        let timestamp = ISO8601DateFormatter().string(from: Date())

        // Mask sensitive content for forensic storage (keep first/last 4 chars)
        let maskedContent = matchedContent.map { content -> String in
            if content.count > 8 {
                let prefix = String(content.prefix(4))
                let suffix = String(content.suffix(4))
                let masked = String(repeating: "*", count: min(content.count - 8, 20))
                return "\(prefix)\(masked)\(suffix)"
            }
            return String(repeating: "*", count: content.count)
        }

        // Generate content hash for forensic integrity
        let contentForHash = matchedContent.joined(separator: "|")
        let contentHash = contentForHash.data(using: .utf8)?.base64EncodedString() ?? ""

        // Risk score based on severity
        let riskScore: Int
        switch severity {
        case "critical": riskScore = 95
        case "high": riskScore = 80
        case "medium": riskScore = 60
        case "low": riskScore = 30
        default: riskScore = 50
        }

        // Build rich forensic details object
        let forensicDetails: [String: Any] = [
            "sourceApp": sourceApp,
            "matchCount": matchCount,
            "matchedPatterns": matchedPatterns,
            "maskedContent": maskedContent,
            "contentHash": contentHash,
            "complianceFramework": complianceFramework,
            "osVersion": "macOS \(osVersion)",
            "agentVersion": "1.2.0",
            "endpointHostname": hostname,
            "endpointUser": username,
            "detectionMethod": "real-time-clipboard-monitor",
            "rawDetails": details
        ]

        var body: [String: Any] = [
            "agentId": agentId,
            "hostname": hostname,
            "username": username,
            "policyId": policyId,
            "policyName": policyName,
            "severity": severity,
            "action": action,
            "channel": channel,
            "matchCount": matchCount,
            "details": forensicDetails,
            "timestamp": timestamp,
            "riskScore": riskScore
        ]
        if let tenantId = tenantId { body["tenantId"] = tenantId }

        // Write to macOS Unified Syslog
        writeSyslog(
            level: severity == "critical" ? .fault : (severity == "high" ? .error : .info),
            message: "DLP INCIDENT | policy=\(policyName) | severity=\(severity) | action=\(action) | channel=\(channel) | app=\(sourceApp) | matches=\(matchCount) | patterns=\(matchedPatterns.joined(separator: ",")) | risk=\(riskScore) | compliance=\(complianceFramework) | host=\(hostname) | user=\(username) | hash=\(contentHash)"
        )

        do {
            let data = try await postJSON(endpoint: "/incidents", body: body)
            if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let incidentId = json["incidentId"] as? String {
                print("[NextGuard] Incident reported: \(incidentId)")
                writeSyslog(level: .info, message: "Incident reported to console: \(incidentId)")
            }
        } catch {
            writeSyslog(level: .error, message: "Incident report failed: \(error.localizedDescription)")
        }
    }

    // MARK: - Legacy reportIncident (backward compatibility)
    func reportIncident(
        policyId: String,
        channel: String,
        severity: String,
        action: String,
        matchCount: Int,
        details: String
    ) async {
        await reportIncident(
            policyId: policyId,
            policyName: policyId,
            channel: channel,
            severity: severity,
            action: action,
            matchCount: matchCount,
            matchedPatterns: [],
            matchedContent: [],
            sourceApp: "Unknown",
            complianceFramework: "",
            details: details
        )
    }

    // MARK: - macOS Unified Syslog (os.log)
    func writeSyslog(level: OSLogType, message: String) {
        syslogger.log(level: level, "\(message, privacy: .public)")
        // Also print to console for visibility
        let levelStr: String
        switch level {
        case .fault: levelStr = "FAULT"
        case .error: levelStr = "ERROR"
        case .debug: levelStr = "DEBUG"
        default: levelStr = "INFO"
        }
        print("[SYSLOG/\(levelStr)] \(message)")
    }

    // MARK: - HTTP Helper
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
    }

    // MARK: - Log Upload
    func uploadLogs(events: [[String: Any]], completion: @escaping (Bool) -> Void) {
        guard let url = URL(string: "\(baseURL)/logs/upload") else { completion(false); return }
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
