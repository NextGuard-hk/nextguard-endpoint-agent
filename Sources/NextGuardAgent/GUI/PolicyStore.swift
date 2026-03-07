//
// PolicyStore.swift
// NextGuardAgent
//
// Local policy data model and persistence store
// NOTE: RuleAction (not PolicyAction) to avoid conflict with Policy/PolicyManager.swift
//
import Foundation
import Combine

// MARK: - Policy Models

enum RuleAction: String, Codable, CaseIterable {
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

struct GUIPolicyRule: Codable, Identifiable {
    var id: UUID
    var name: String
    var description: String
    var enabled: Bool
    var action: RuleAction
    var keywords: [String]
    var fileTypes: [String]
    var destinations: [String]
    var createdAt: Date
    var updatedAt: Date

    init(id: UUID = UUID(), name: String, description: String = "",
         enabled: Bool = true, action: RuleAction = .audit,
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

struct AgentStatusInfo: Codable {
    var isProtected: Bool
    var isConnectedToConsole: Bool
    var lastSyncTime: Date?
    var totalIncidentsToday: Int
    var blockedToday: Int
    var auditedToday: Int
    var agentVersion: String
    var tenantId: String?
    var consoleUrl: String

    static var `default`: AgentStatusInfo {
        AgentStatusInfo(
            isProtected: true,
            isConnectedToConsole: false,
            lastSyncTime: nil,
            totalIncidentsToday: 0,
            blockedToday: 0,
            auditedToday: 0,
            agentVersion: "2.4.0",  // Updated from 2.3.0
            tenantId: nil,
            consoleUrl: "https://next-guard.com"
        )
    }
}

// MARK: - StatusDashboardView Aliases
extension AgentStatusInfo {
    var protectionEnabled: Bool {
        get { isProtected }
        set { isProtected = newValue }
    }
    var isConnected: Bool { isConnectedToConsole }
    var lastPolicySync: Date? { lastSyncTime }
    var todayIncidentCount: Int { totalIncidentsToday }
    var todayBlockCount: Int { blockedToday }
    var todayAuditCount: Int { auditedToday }
    var activePolicyCount: Int { PolicyStore.shared.policies.filter { $0.enabled }.count }
    var endpointId: String { tenantId ?? "" }
    var enrollmentStatus: String {
        isConnectedToConsole ? "Managed" : "Standalone"
    }
}

// MARK: - Policy Store
class PolicyStore: ObservableObject {
    static let shared = PolicyStore()

    @Published var policies: [GUIPolicyRule] = []
    @Published var agentStatus: AgentStatusInfo = .default
    @Published var isLoading = false
    @Published var lastError: String?

    private let policiesKey = "ng_local_policies"
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
            GUIPolicyRule(
                name: "Credit Card Data",
                description: "Detect and block credit card numbers in outbound transfers",
                enabled: true,
                action: .block,
                keywords: ["credit card", "card number", "CVV", "expiry"],
                fileTypes: [".txt", ".csv", ".xlsx", ".pdf"],
                destinations: ["email", "usb", "cloud"]
            ),
            GUIPolicyRule(
                name: "Personal Identifiable Information",
                description: "Audit PII data movement including HKID, passport numbers",
                enabled: true,
                action: .audit,
                keywords: ["HKID", "passport", "date of birth", "address"],
                fileTypes: [".pdf", ".docx", ".xlsx"],
                destinations: ["email", "cloud", "web"]
            ),
            GUIPolicyRule(
                name: "Confidential Documents",
                description: "Block sharing of files marked Confidential or Top Secret",
                enabled: true,
                action: .block,
                keywords: ["CONFIDENTIAL", "TOP SECRET", "RESTRICTED", "INTERNAL ONLY"],
                fileTypes: [".pdf", ".docx", ".pptx", ".xlsx"],
                destinations: ["email", "usb", "cloud", "web"]
            ),
            GUIPolicyRule(
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

    func addPolicy(_ policy: GUIPolicyRule) {
        policies.append(policy)
        saveLocalPolicies()
    }

    func updatePolicy(_ policy: GUIPolicyRule) {
        if let index = policies.firstIndex(where: { $0.id == policy.id }) {
            var updated = policy
            updated.updatedAt = Date()
            policies[index] = updated
            saveLocalPolicies()
        }
    }

    func deletePolicy(_ policy: GUIPolicyRule) {
        policies.removeAll { $0.id == policy.id }
        saveLocalPolicies()
    }

    func togglePolicy(_ policy: GUIPolicyRule) {
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
              let decoded = try? JSONDecoder().decode([GUIPolicyRule].self, from: data) else { return }
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
                if error != nil {
                    self?.agentStatus.isConnectedToConsole = false
                    return
                }
                self?.agentStatus.isConnectedToConsole = true
                self?.agentStatus.lastSyncTime = Date()
            }
        }.resume()
    }

    func recordIncident(action: RuleAction) {
        agentStatus.totalIncidentsToday += 1
        if action == .block {
            agentStatus.blockedToday += 1
        } else if action == .audit {
            agentStatus.auditedToday += 1
        }
    }
}
