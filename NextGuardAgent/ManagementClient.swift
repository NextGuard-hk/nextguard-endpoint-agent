import Foundation

/// ManagementClient handles all communication between the DLP Agent and
/// the NextGuard Management Console (next-guard.com).
/// Implements: Agent Registration, Heartbeat, Policy Pull, Incident Reporting
class ManagementClient {
    static let shared = ManagementClient()
    
    private let baseURL = "https://www.next-guard.com/api/v1"
    private let session = URLSession.shared
    private var agentId: String?
    private var heartbeatTimer: Timer?
    
    private init() {
        agentId = UserDefaults.standard.string(forKey: "nextguard_agent_id")
    }
    
    // MARK: - Agent Registration
    
    func registerAgent(completion: @escaping (Bool) -> Void) {
        let hostname = Host.current().localizedName ?? "unknown"
        let username = NSUserName()
        let osVersion = ProcessInfo.processInfo.operatingSystemVersionString
        let agentVersion = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0.0"
        
        let body: [String: Any] = [
            "hostname": hostname,
            "username": username,
            "os": "macOS \(osVersion)",
            "agentVersion": agentVersion,
            "capabilities": ["file", "clipboard", "email", "browser", "network"]
        ]
        
        postJSON(endpoint: "/agents/register", body: body) { [weak self] result in
            switch result {
            case .success(let data):
                if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                   let id = json["agentId"] as? String {
                    self?.agentId = id
                    UserDefaults.standard.set(id, forKey: "nextguard_agent_id")
                    print("[NextGuard] Registered with ID: \(id)")
                    completion(true)
                } else {
                    completion(false)
                }
            case .failure(let error):
                print("[NextGuard] Registration failed: \(error.localizedDescription)")
                completion(false)
            }
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
        guard let agentId = agentId else {
            registerAgent { [weak self] success in
                if success { self?.sendHeartbeat() }
            }
            return
        }
        
        let body: [String: Any] = [
            "agentId": agentId,
            "status": "online",
            "hostname": Host.current().localizedName ?? "unknown",
            "username": NSUserName(),
            "agentVersion": Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0.0",
            "os": "macOS \(ProcessInfo.processInfo.operatingSystemVersionString)",
            "activePolicies": PolicyManager.shared.policies.count,
            "uptime": ProcessInfo.processInfo.systemUptime
        ]
        
        postJSON(endpoint: "/agents/heartbeat", body: body) { result in
            switch result {
            case .success:
                print("[NextGuard] Heartbeat sent")
            case .failure(let error):
                print("[NextGuard] Heartbeat failed: \(error.localizedDescription)")
            }
        }
    }
    
    // MARK: - Policy Pull
    
    func pullPolicies(completion: @escaping ([[String: Any]]?) -> Void) {
        guard let agentId = agentId else {
            completion(nil)
            return
        }
        
        let urlString = "\(baseURL)/policies/bundle?agentId=\(agentId)"
        guard let url = URL(string: urlString) else {
            completion(nil)
            return
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        
        session.dataTask(with: request) { data, response, error in
            guard let data = data, error == nil,
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let bundle = json["bundle"] as? [String: Any],
                  let policies = bundle["policies"] as? [[String: Any]] else {
                print("[NextGuard] Policy pull failed: \(error?.localizedDescription ?? "unknown")")
                completion(nil)
                return
            }
            print("[NextGuard] Pulled \(policies.count) policies from management console")
            completion(policies)
        }.resume()
    }
    
    // MARK: - Incident Reporting
    
    func reportIncident(
        policyId: String,
        policyName: String,
        severity: String,
        action: String,
        channel: String,
        details: [String: Any] = [:]
    ) {
        guard let agentId = agentId else { return }
        
        let body: [String: Any] = [
            "agentId": agentId,
            "hostname": Host.current().localizedName ?? "unknown",
            "username": NSUserName(),
            "policyId": policyId,
            "policyName": policyName,
            "severity": severity,
            "action": action,
            "channel": channel,
            "details": details,
            "timestamp": ISO8601DateFormatter().string(from: Date())
        ]
        
        postJSON(endpoint: "/incidents", body: body) { result in
            switch result {
            case .success(let data):
                if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                   let incidentId = json["incidentId"] as? String {
                    print("[NextGuard] Incident reported: \(incidentId)")
                }
            case .failure(let error):
                print("[NextGuard] Incident report failed: \(error.localizedDescription)")
            }
        }
    }
    
    // MARK: - HTTP Helper
    
    private func postJSON(endpoint: String, body: [String: Any], completion: @escaping (Result<Data, Error>) -> Void) {
        guard let url = URL(string: "\(baseURL)\(endpoint)") else {
            completion(.failure(NSError(domain: "ManagementClient", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid URL"])))
            return
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try? JSONSerialization.data(withJSONObject: body)
        request.timeoutInterval = 15
        
        session.dataTask(with: request) { data, response, error in
            if let error = error {
                completion(.failure(error))
                return
            }
            guard let data = data else {
                completion(.failure(NSError(domain: "ManagementClient", code: -2, userInfo: [NSLocalizedDescriptionKey: "No data"])))
                return
            }
            completion(.success(data))
        }.resume()
    }
}
