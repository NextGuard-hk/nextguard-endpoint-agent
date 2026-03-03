//
//  PolicyHierarchyEngine.swift
//  NextGuardAgent
//
//  3-Level GPO-style Policy Override Hierarchy:
//    Level 1 (Highest): Tenant Global Policy    - Console-issued, unconditional
//    Level 2 (Middle):  Group/User Policy       - Console per-group exceptions
//    Level 3 (Lowest):  Local Agent Config      - Standalone/unjoined rules
//
//  Conflict Resolution: Higher level ALWAYS wins.
//  When policyLockLevel == .locked, Level 3 is completely frozen.
//

import Foundation
import Combine

// MARK: - Policy Priority Level

enum PolicyPriorityLevel: Int, Codable, Comparable {
    case local  = 3   // Local Agent Config (lowest)
    case group  = 2   // Group/User Policy
    case tenant = 1   // Tenant Global Policy (highest)

    static func < (lhs: PolicyPriorityLevel, rhs: PolicyPriorityLevel) -> Bool {
        // Lower rawValue = higher priority
        return lhs.rawValue > rhs.rawValue
    }
}

// MARK: - Hierarchical Policy Rule

struct HierarchicalPolicyRule: Codable, Identifiable {
    var id: UUID
    var name: String
    var description: String
    var enabled: Bool
    var action: String           // "block" | "audit" | "allow"
    var keywords: [String]
    var fileTypes: [String]
    var destinations: [String]
    var priority: PolicyPriorityLevel
    var sourceGroupId: String?   // nil = global, set = group-specific
    var isLocked: Bool           // true = cannot be overridden by lower level
    var appliesTo: [String]      // device IDs, group IDs, or ["*"] for all
    var conditions: PolicyConditions
    var createdAt: Date
    var updatedAt: Date

    init(
        id: UUID = UUID(),
        name: String,
        description: String = "",
        enabled: Bool = true,
        action: String = "audit",
        keywords: [String] = [],
        fileTypes: [String] = [],
        destinations: [String] = [],
        priority: PolicyPriorityLevel = .local,
        sourceGroupId: String? = nil,
        isLocked: Bool = false,
        appliesTo: [String] = ["*"],
        conditions: PolicyConditions = PolicyConditions()
    ) {
        self.id = id
        self.name = name
        self.description = description
        self.enabled = enabled
        self.action = action
        self.keywords = keywords
        self.fileTypes = fileTypes
        self.destinations = destinations
        self.priority = priority
        self.sourceGroupId = sourceGroupId
        self.isLocked = isLocked
        self.appliesTo = appliesTo
        self.conditions = conditions
        self.createdAt = Date()
        self.updatedAt = Date()
    }
}

// MARK: - Policy Conditions (enterprise match criteria)

struct PolicyConditions: Codable {
    var minFileSizeBytes: Int?       // only trigger if file > N bytes
    var maxFileSizeBytes: Int?       // only trigger if file < N bytes
    var timeWindowStart: String?     // HH:mm - only active during work hours
    var timeWindowEnd: String?       // HH:mm
    var requiresContentScan: Bool    // must AI-scan content (not just extension)
    var sensitivityScore: Int?       // 0-100 minimum AI sensitivity to trigger
    var complianceFrameworks: [String] // ["PCI-DSS", "GDPR", "HIPAA"]

    init() {
        requiresContentScan = false
    }
}

// MARK: - Policy Hierarchy Engine

class PolicyHierarchyEngine: ObservableObject {
    static let shared = PolicyHierarchyEngine()

    // All rules across all levels
    @Published private(set) var allRules: [HierarchicalPolicyRule] = []

    // Effective (resolved) rule set - what actually gets enforced
    @Published private(set) var effectiveRules: [HierarchicalPolicyRule] = []

    private let cacheKey = "ng_policy_hierarchy_cache"
    private let lastGoodKey = "ng_last_known_good_policies"

    private init() {
        loadCachedPolicies()
    }

    // MARK: - Load Policies from Console

    /// Called when Console pushes a new policy bundle
    func applyConsolePolicy(rules: [HierarchicalPolicyRule], level: PolicyPriorityLevel) {
        // Remove existing rules at this level
        allRules.removeAll { $0.priority == level }

        // Add new rules at this level, marking them as console-sourced
        let stamped = rules.map { r -> HierarchicalPolicyRule in
            var rule = r
            rule.priority = level
            return rule
        }
        allRules.append(contentsOf: stamped)
        allRules.sort { $0.priority > $1.priority } // highest priority first

        resolveEffectivePolicies()
        persistCache()

        // Save as last-known-good if from Console
        if level == .tenant || level == .group {
            saveLastKnownGood()
        }

        NotificationCenter.default.post(name: .consolePolicyUpdated, object: effectiveRules)
        print("[PolicyHierarchy] Applied \(stamped.count) rules at level \(level.rawValue)")
    }

    /// Add/update local (Level 3) policy rule
    func setLocalRule(_ rule: HierarchicalPolicyRule) {
        guard AgentModeManager.shared.canEditLocalSettings else {
            print("[PolicyHierarchy] Local settings locked by Console - ignoring local rule change")
            return
        }
        var localRule = rule
        localRule.priority = .local
        if let idx = allRules.firstIndex(where: { $0.id == rule.id }) {
            allRules[idx] = localRule
        } else {
            allRules.append(localRule)
        }
        resolveEffectivePolicies()
        persistCache()
    }

    func removeLocalRule(id: UUID) {
        guard AgentModeManager.shared.canEditLocalSettings else { return }
        allRules.removeAll { $0.id == id && $0.priority == .local }
        resolveEffectivePolicies()
        persistCache()
    }

    // MARK: - Effective Policy Resolution

    /// Resolve conflicts: higher priority wins, locked rules block lower override
    private func resolveEffectivePolicies() {
        let lockLevel = AgentModeManager.shared.enrolledDevice?.policyLockLevel ?? .none

        var resolved: [String: HierarchicalPolicyRule] = [:] // keyed by rule name (canonical)
        let sorted = allRules.sorted { $0.priority > $1.priority } // highest first

        for rule in sorted {
            // Skip local rules if settings are locked
            if rule.priority == .local && lockLevel == .locked {
                continue
            }
            // Skip disabled rules
            guard rule.enabled else { continue }

            let key = rule.name.lowercased().trimmingCharacters(in: .whitespaces)
            if resolved[key] == nil {
                resolved[key] = rule // first (highest priority) wins
            } else if resolved[key]!.isLocked {
                continue // locked rule cannot be supplemented
            }
        }

        effectiveRules = Array(resolved.values).sorted { $0.name < $1.name }
    }

    // MARK: - Query helpers

    func tenantRules() -> [HierarchicalPolicyRule] {
        allRules.filter { $0.priority == .tenant }
    }

    func groupRules() -> [HierarchicalPolicyRule] {
        allRules.filter { $0.priority == .group }
    }

    func localRules() -> [HierarchicalPolicyRule] {
        allRules.filter { $0.priority == .local }
    }

    func effectiveAction(forName name: String) -> String? {
        effectiveRules.first { $0.name.lowercased() == name.lowercased() }?.action
    }

    var hasConsoleOverrides: Bool {
        allRules.contains { $0.priority == .tenant || $0.priority == .group }
    }

    // MARK: - Last Known Good (Offline Fallback)

    private func saveLastKnownGood() {
        if let data = try? JSONEncoder().encode(effectiveRules) {
            UserDefaults.standard.set(data, forKey: lastGoodKey)
            print("[PolicyHierarchy] Last-known-good snapshot saved (\(effectiveRules.count) rules)")
        }
    }

    func loadLastKnownGood() {
        guard let data = UserDefaults.standard.data(forKey: lastGoodKey),
              let rules = try? JSONDecoder().decode([HierarchicalPolicyRule].self, from: data),
              !rules.isEmpty else { return }
        effectiveRules = rules
        print("[PolicyHierarchy] Loaded last-known-good policy (\(rules.count) rules) - offline fallback active")
    }

    // MARK: - Persistence

    private func persistCache() {
        if let data = try? JSONEncoder().encode(allRules) {
            UserDefaults.standard.set(data, forKey: cacheKey)
        }
    }

    private func loadCachedPolicies() {
        guard let data = UserDefaults.standard.data(forKey: cacheKey),
              let rules = try? JSONDecoder().decode([HierarchicalPolicyRule].self, from: data) else { return }
        allRules = rules
        resolveEffectivePolicies()
        print("[PolicyHierarchy] Loaded \(allRules.count) cached rules from disk")
    }

    // MARK: - Console Policy Bundle Parser

    /// Parse Console API /policies/bundle response into HierarchicalPolicyRule array
    func parseBundleJSON(_ data: Data, level: PolicyPriorityLevel) {
        struct PolicyBundle: Codable {
            struct Rule: Codable {
                let id: String?
                let name: String
                let description: String?
                let enabled: Bool?
                let action: String
                let keywords: [String]?
                let fileTypes: [String]?
                let destinations: [String]?
                let isLocked: Bool?
                let complianceFrameworks: [String]?
            }
            let rules: [Rule]
        }
        guard let bundle = try? JSONDecoder().decode(PolicyBundle.self, from: data) else { return }
        let rules = bundle.rules.map { r -> HierarchicalPolicyRule in
            var conditions = PolicyConditions()
            conditions.complianceFrameworks = r.complianceFrameworks ?? []
            return HierarchicalPolicyRule(
                id: UUID(uuidString: r.id ?? "") ?? UUID(),
                name: r.name,
                description: r.description ?? "",
                enabled: r.enabled ?? true,
                action: r.action,
                keywords: r.keywords ?? [],
                fileTypes: r.fileTypes ?? [],
                destinations: r.destinations ?? [],
                priority: level,
                isLocked: r.isLocked ?? false,
                conditions: conditions
            )
        }
        applyConsolePolicy(rules: rules, level: level)
    }
}
