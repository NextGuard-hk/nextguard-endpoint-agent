//
//  PolicyStore.swift
//  NextGuardAgent
//
//  Local policy data model and persistence store
//

import Foundation
import Combine

// MARK: - Policy Models

enum PolicyAction: String, Codable, CaseIterable {
    case block = "block"
    case audit = "audit"
    case allow = "allow"
    
    var displayName: String {
        switch self {
        case .block: return "Block"
        case .audit: return "Audit"
        case .allow: return "Allow"
        }
    }
    
    var color: String {
        switch self {
        case .block: return "red"
        case .audit: return "orange"
        case .allow: return "green"
        }
    }
}

struct PolicyRule: Codable, Identifiable {
    var id: UUID
    var name: String
    var description: String
    var enabled: Bool
    var action: PolicyAction
    var keywords: [String]
    var fileTypes: [String]
    var destinations: [String]
    var createdAt: Date
    var updatedAt: Date
    
    init(id: UUID = UUID(), name: String, description: String = "",
         enabled: Bool = true, action: PolicyAction = .audit,
         keywords: [String] = [], fileTypes: [String] = [],
         destinations: [String] = []) {
        self.id = id
        self.name = name
        self.description = description
        self.enabled = enabled
        self.action = action
        self.keywords = keywords
        self.fileTypes = fileTypes
        self.destinations = destinations
        self.createdAt = Date()
        self.updatedAt = Date()
    }
}

struct AgentStatus: Codable {
    var isProtected: Bool
    var isConnectedToConsole: Bool
    var lastSyncTime: Date?
    var totalIncidentsToday: Int
    var blockedToday: Int
    var auditedToday: Int
    var agentVersion: String
    var tenantId: String?
    var consoleUrl: String
    
    static var `default`: AgentStatus {
        AgentStatus(
            isProtected: true,
            isConnectedToConsole: false,
            lastSyncTime: nil,
            totalIncidentsToday: 0,
            blockedToday: 0,
            auditedToday: 0,
            agentVersion: "1.0.0",
            tenantId: nil,
            consoleUrl: "https://next-guard.com"
        )
    }
}

// MARK: - Policy Store

class PolicyStore: ObservableObject {
    static let shared = PolicyStore()
    
    @Published var policies: [PolicyRule] = []
    @Published var agentStatus: AgentStatus = .default
    @Published var isLoading = false
    @Published var lastError: String?
    
    private let policiesKey = "ng_local_policies"
    private let statusKey = "ng_agent_status"
    private var syncTimer: Timer?
    private var cancellables = Set<AnyCancellable>()
    
    private init() {
        loadLocalPolicies()
        loadDefaultPolicies()
        startPeriodicSync()
    }
    
    // MARK: - Default Policies
    
    private func loadDefaultPolicies() {
        guard policies.isEmpty else { return }
        
        policies = [
            PolicyRule(
                name: "Credit Card Data",
                description: "Detect and block credit card numbers in outbound transfers",
                enabled: true,
                action: .block,
                keywords: ["credit card", "card number", "CVV", "expiry"],
                fileTypes: [".txt", ".csv", ".xlsx", ".pdf"],
                destinations: ["email", "usb", "cloud"]
            ),
            PolicyRule(
                name: "Personal Identifiable Information",
                description: "Audit PII data movement including HKID, passport numbers",
                enabled: true,
                action: .audit,
                keywords: ["HKID", "passport", "date of birth", "address"],
                fileTypes: [".pdf", ".docx", ".xlsx"],
                destinations: ["email", "cloud", "web"]
            ),
            PolicyRule(
                name: "Confidential Documents",
                description: "Block sharing of files marked Confidential or Top Secret",
                enabled: true,
                action: .block,
                keywords: ["CONFIDENTIAL", "TOP SECRET", "RESTRICTED", "INTERNAL ONLY"],
                fileTypes: [".pdf", ".docx", ".pptx", ".xlsx"],
                destinations: ["email", "usb", "cloud", "web"]
            ),
            PolicyRule(
                name: "Source Code",
                description: "Audit source code file transfers",
                enabled: false,
                action: .audit,
                keywords: [],
                fileTypes: [".swift", ".py", ".js", ".ts", ".go", ".java"],
                destinations: ["email", "cloud", "web"]
            )
        ]
        saveLocalPolicies()
    }
    
    // MARK: - CRUD Operations
    
    func addPolicy(_ policy: PolicyRule) {
        policies.append(policy)
        saveLocalPolicies()
        syncToConsole()
    }
    
    func updatePolicy(_ policy: PolicyRule) {
        if let index = policies.firstIndex(where: { $0.id == policy.id }) {
            var updated = policy
            updated.updatedAt = Date()
            policies[index] = updated
            saveLocalPolicies()
            syncToConsole()
        }
    }
    
    func deletePolicy(_ policy: PolicyRule) {
        policies.removeAll { $0.id == policy.id }
        saveLocalPolicies()
        syncToConsole()
    }
    
    func togglePolicy(_ policy: PolicyRule) {
        var updated = policy
        updated.enabled = !policy.enabled
        updatePolicy(updated)
    }
    
    // MARK: - Persistence
    
    private func saveLocalPolicies() {
        if let data = try? JSONEncoder().encode(policies) {
            UserDefaults.standard.set(data, forKey: policiesKey)
        }
    }
    
    private func loadLocalPolicies() {
        guard let data = UserDefaults.standard.data(forKey: policiesKey),
              let decoded = try? JSONDecoder().decode([PolicyRule].self, from: data) else { return }
        policies = decoded
    }
    
    // MARK: - Console Sync
    
    private func startPeriodicSync() {
        syncTimer = Timer.scheduledTimer(withTimeInterval: 300, repeats: true) { [weak self] _ in
            self?.fetchPoliciesFromConsole()
        }
    }
    
    func fetchPoliciesFromConsole() {
        guard let tenantId = agentStatus.tenantId,
              let url = URL(string: "\(agentStatus.consoleUrl)/api/v1/policies/bundle?tenantId=\(tenantId)") else { return }
        
        isLoading = true
        
        URLSession.shared.dataTask(with: url) { [weak self] data, response, error in
            DispatchQueue.main.async {
                self?.isLoading = false
                
                if let error = error {
                    self?.lastError = error.localizedDescription
                    self?.agentStatus.isConnectedToConsole = false
                    return
                }
                
                guard let data = data,
                      let consolePolicies = try? JSONDecoder().decode([PolicyRule].self, from: data) else {
                    return
                }
                
                self?.policies = consolePolicies
                self?.saveLocalPolicies()
                self?.agentStatus.isConnectedToConsole = true
                self?.agentStatus.lastSyncTime = Date()
            }
        }.resume()
    }
    
    func syncToConsole() {
        // Push local policy changes to console
        guard let tenantId = agentStatus.tenantId,
              let url = URL(string: "\(agentStatus.consoleUrl)/api/v1/policies/sync") else { return }
        
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(tenantId, forHTTPHeaderField: "X-Tenant-ID")
        
        guard let body = try? JSONEncoder().encode(policies) else { return }
        request.httpBody = body
        
        URLSession.shared.dataTask(with: request) { [weak self] _, response, error in
            DispatchQueue.main.async {
                if error != nil {
                    self?.agentStatus.isConnectedToConsole = false
                }
            }
        }.resume()
    }
    
    func recordIncident(action: PolicyAction) {
        agentStatus.totalIncidentsToday += 1
        if action == .block {
            agentStatus.blockedToday += 1
        } else if action == .audit {
            agentStatus.auditedToday += 1
        }
    }
}
