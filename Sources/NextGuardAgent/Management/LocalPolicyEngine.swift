//
// LocalPolicyEngine.swift
// NextGuardAgent
//
// Autonomous Local Policy Engine - allows Agent to set and enforce
// policies locally (Block/Audit/Allow) independent of server connection
//

import Foundation
import Combine

// MARK: - Enforcement Mode (renamed from AgentMode to avoid conflict)
enum EnforcementMode: String, Codable, CaseIterable {
    case enforce = "Enforce"
    case monitor = "Monitor"
    case disabled = "Disabled"

    var displayName: String { rawValue }

    var icon: String {
        switch self {
        case .enforce: return "shield.checkmark.fill"
        case .monitor: return "eye.fill"
        case .disabled: return "shield.slash"
        }
    }
}

// MARK: - Local Policy Action (prefixed to avoid conflict with DLPPolicyEngine.DLPAction)
enum LocalDLPAction: String, Codable, CaseIterable {
    case block = "Block"
    case audit = "Audit"
    case allow = "Allow"
    case encrypt = "Encrypt"
    case quarantine = "Quarantine"
}

// MARK: - Local Policy Rule (renamed from PolicyRule to avoid conflict with PolicyManager)
struct LocalPolicyRule: Codable, Identifiable {
    let id: UUID
    var name: String
    var description: String
    var isEnabled: Bool
    var action: LocalDLPAction
    var priority: Int
    var category: LocalPolicyCategory
    var conditions: [LocalPolicyCondition]
    var source: LocalPolicySource
    var createdAt: Date
    var updatedAt: Date
}

// MARK: - Local Policy Category (prefixed to avoid conflict with PolicyManager.PolicyCategory)
enum LocalPolicyCategory: String, Codable, CaseIterable {
    case pii = "PII"
    case phi = "PHI"
    case pci = "PCI-DSS"
    case financialData = "Financial Data"
    case intellectualProperty = "Intellectual Property"
    case confidential = "Confidential"
    case sourceCode = "Source Code"
    case custom = "Custom"
}

// MARK: - Local Policy Source (prefixed to avoid conflict with PolicyManager.PolicySource)
enum LocalPolicySource: String, Codable {
    case server = "Server"
    case local = "Local"
}

// MARK: - Local Policy Condition (prefixed to avoid conflict with PolicyHierarchyEngine.PolicyConditions)
struct LocalPolicyCondition: Codable, Identifiable {
    let id: UUID
    var type: ConditionType
    var pattern: String
    var isRegex: Bool
    var caseSensitive: Bool

    enum ConditionType: String, Codable, CaseIterable {
        case contentMatch = "Content Match"
        case fileExtension = "File Extension"
        case fileName = "File Name"
        case filePath = "File Path"
        case fileSize = "File Size"
        case destinationURL = "Destination URL"
        case destinationApp = "Destination App"
        case clipboardContent = "Clipboard Content"
        case emailRecipient = "Email Recipient"
        case usbDevice = "USB Device"
        case networkEndpoint = "Network Endpoint"
    }
}

// MARK: - Policy Match Result
struct PolicyMatchResult {
    let matchedRule: LocalPolicyRule
    let matchedConditions: [LocalPolicyCondition]
    let action: LocalDLPAction
    let timestamp: Date
    let context: MatchContext

    struct MatchContext {
        var filePath: String?
        var destination: String?
        var contentSnippet: String?
        var application: String?
        var userName: String?
    }
}

// MARK: - Local Policy Engine
final class LocalPolicyEngine: ObservableObject {
    static let shared = LocalPolicyEngine()

    @Published var localRules: [LocalPolicyRule] = []
    @Published var serverRules: [LocalPolicyRule] = []
    @Published var agentMode: EnforcementMode = EnforcementMode.enforce
    @Published var isEngineActive: Bool = true

    private let storageKey = "com.nextguard.localPolicies"
    private let modeKey = "com.nextguard.agentMode"
    private var cancellables = Set<AnyCancellable>()

    var allActiveRules: [LocalPolicyRule] {
        (localRules + serverRules)
            .filter { $0.isEnabled }
            .sorted { $0.priority > $1.priority }
    }

    private init() {
        loadLocalRules()
        loadAgentMode()
    }

    // MARK: - Policy Evaluation
    func evaluate(content: String, filePath: String?, destination: String?, app: String?) -> PolicyMatchResult? {
        guard isEngineActive, agentMode != EnforcementMode.disabled else { return nil }

        for rule in allActiveRules {
            if let match = evaluateRule(rule, content: content, filePath: filePath, destination: destination, app: app) {
                logMatch(match)
                return match
            }
        }
        return nil
    }

    private func evaluateRule(_ rule: LocalPolicyRule, content: String, filePath: String?, destination: String?, app: String?) -> PolicyMatchResult? {
        var matchedConditions: [LocalPolicyCondition] = []

        for condition in rule.conditions {
            let matched: Bool
            switch condition.type {
            case .contentMatch:
                matched = matchPattern(condition, against: content)
            case .fileExtension:
                matched = filePath.map { matchPattern(condition, against: URL(fileURLWithPath: $0).pathExtension) } ?? false
            case .fileName:
                matched = filePath.map { matchPattern(condition, against: URL(fileURLWithPath: $0).lastPathComponent) } ?? false
            case .filePath:
                matched = filePath.map { matchPattern(condition, against: $0) } ?? false
            case .destinationURL, .networkEndpoint:
                matched = destination.map { matchPattern(condition, against: $0) } ?? false
            case .destinationApp:
                matched = app.map { matchPattern(condition, against: $0) } ?? false
            case .clipboardContent:
                matched = matchPattern(condition, against: content)
            default:
                matched = false
            }
            if matched {
                matchedConditions.append(condition)
            }
        }

        guard !matchedConditions.isEmpty else { return nil }

        let effectiveAction: LocalDLPAction = agentMode == EnforcementMode.monitor ? LocalDLPAction.audit : rule.action

        return PolicyMatchResult(
            matchedRule: rule,
            matchedConditions: matchedConditions,
            action: effectiveAction,
            timestamp: Date(),
            context: .init(
                filePath: filePath,
                destination: destination,
                contentSnippet: String(content.prefix(200)),
                application: app,
                userName: NSUserName()
            )
        )
    }

    private func matchPattern(_ condition: LocalPolicyCondition, against text: String) -> Bool {
        if condition.isRegex {
            let options: NSRegularExpression.Options = condition.caseSensitive ? [] : [.caseInsensitive]
            guard let regex = try? NSRegularExpression(pattern: condition.pattern, options: options) else { return false }
            let range = NSRange(text.startIndex..., in: text)
            return regex.firstMatch(in: text, range: range) != nil
        } else {
            if condition.caseSensitive {
                return text.contains(condition.pattern)
            } else {
                return text.localizedCaseInsensitiveContains(condition.pattern)
            }
        }
    }

    // MARK: - Local Policy CRUD
    func addLocalRule(name: String, description: String, action: LocalDLPAction, category: LocalPolicyCategory, conditions: [LocalPolicyCondition], priority: Int = 50) {
        let rule = LocalPolicyRule(
            id: UUID(),
            name: name,
            description: description,
            isEnabled: true,
            action: action,
            priority: priority,
            category: category,
            conditions: conditions,
            source: .local,
            createdAt: Date(),
            updatedAt: Date()
        )
        localRules.append(rule)
        saveLocalRules()
    }

    func updateLocalRule(_ rule: LocalPolicyRule) {
        if let index = localRules.firstIndex(where: { $0.id == rule.id }) {
            var updated = rule
            updated.updatedAt = Date()
            localRules[index] = updated
            saveLocalRules()
        }
    }

    func deleteLocalRule(id: UUID) {
        localRules.removeAll { $0.id == id }
        saveLocalRules()
    }

    func toggleRule(id: UUID) {
        if let index = localRules.firstIndex(where: { $0.id == id }) {
            localRules[index].isEnabled.toggle()
            saveLocalRules()
        }
    }

    func setAgentMode(_ mode: EnforcementMode) {
        agentMode = mode
        UserDefaults.standard.set(mode.rawValue, forKey: modeKey)
    }

    // MARK: - Server Policy Merge
    func mergeServerPolicies(_ policies: [LocalPolicyRule]) {
        serverRules = policies
    }

    // MARK: - Built-in Default Policies
    func installDefaultPolicies() {
        let defaults: [(String, String, LocalDLPAction, LocalPolicyCategory, String, Bool)] = [
            ("Credit Card Detection", "Detects credit card numbers", .audit, .pci, "\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\\b", true),
            ("SSN Detection", "Detects US Social Security Numbers", .block, .pii, "\\b\\d{3}-\\d{2}-\\d{4}\\b", true),
            ("HKID Detection", "Detects Hong Kong ID numbers", .audit, .pii, "\\b[A-Z]{1,2}\\d{6}\\([0-9A]\\)\\b", true),
            ("Email Address Bulk", "Detects bulk email addresses", .audit, .pii, "([\\w.+-]+@[\\w-]+\\.[\\w.-]+.*){5,}", true),
            ("Source Code Files", "Blocks sharing of source code", .block, .sourceCode, "\\.(swift|py|ts|js|java|cpp|h|go|rs)$", true),
            ("Confidential Marker", "Detects confidential markings", .block, .confidential, "(?i)(confidential|internal only|do not distribute|restricted)", true),
        ]

        for (name, desc, action, category, pattern, isRegex) in defaults {
            guard !localRules.contains(where: { $0.name == name }) else { continue }
            let condition = LocalPolicyCondition(
                id: UUID(),
                type: .contentMatch,
                pattern: pattern,
                isRegex: isRegex,
                caseSensitive: false
            )
            addLocalRule(name: name, description: desc, action: action, category: category, conditions: [condition])
        }
    }

    // MARK: - Persistence
    private func saveLocalRules() {
        if let data = try? JSONEncoder().encode(localRules) {
            UserDefaults.standard.set(data, forKey: storageKey)
        }
    }

    private func loadLocalRules() {
        if let data = UserDefaults.standard.data(forKey: storageKey),
           let rules = try? JSONDecoder().decode([LocalPolicyRule].self, from: data) {
            localRules = rules
        } else {
            installDefaultPolicies()
        }
    }

    private func loadAgentMode() {
        if let raw = UserDefaults.standard.string(forKey: modeKey),
           let mode = EnforcementMode(rawValue: raw) {
            agentMode = mode
        }
    }

    // MARK: - Logging
    private func logMatch(_ match: PolicyMatchResult) {
        let entry: [String: Any] = [
            "timestamp": ISO8601DateFormatter().string(from: match.timestamp),
            "policy": match.matchedRule.name,
            "action": match.action.rawValue,
            "filePath": match.context.filePath ?? "",
            "destination": match.context.destination ?? "",
            "app": match.context.application ?? "",
        ]
        NotificationCenter.default.post(
            name: .init("NextGuardPolicyMatch"),
            object: entry
        )
    }

    // MARK: - Monitor Integration Convenience API
    // Used by BrowserMonitor, FileSystemWatcher, ClipboardMonitor, EmailMonitor

    struct MonitorEvalResult {
        let action: LocalDLPAction
        let matchedRules: [String]
        let policySource: String
    }

    func evaluate(content: String, channel: DLPChannel, metadata: [String: String]) -> MonitorEvalResult {
        let filePath = metadata["filePath"] ?? metadata["fileName"]
        let destination = metadata["url"] ?? metadata["domain"] ?? metadata["destination"]
        let app = metadata["application"] ?? metadata["browser"]

        if let match = evaluate(content: content, filePath: filePath, destination: destination, app: app) {
            return MonitorEvalResult(
                action: match.action,
                matchedRules: [match.matchedRule.id.uuidString],
                policySource: "local"
            )
        }
        return MonitorEvalResult(action: .allow, matchedRules: [], policySource: "none")
    }

    func reportIncident(ruleIds: [String], channel: DLPChannel, content: String, action: LocalDLPAction, metadata: [String: String]) {
        let entry: [String: Any] = [
            "timestamp": ISO8601DateFormatter().string(from: Date()),
            "channel": channel.rawValue,
            "action": action.rawValue,
            "ruleIds": ruleIds,
            "contentSnippet": String(content.prefix(200)),
            "metadata": metadata
        ]
        NotificationCenter.default.post(
            name: .init("NextGuardLocalPolicyIncident"),
            object: entry
        )
    }
}
