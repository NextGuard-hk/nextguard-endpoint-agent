//
//  DLPPolicyEngine.swift
//  NextGuard Endpoint DLP Agent
//
//  Copyright (c) 2026 NextGuard Technology Limited. All rights reserved.
//
//  Hybrid DLP engine: Pattern-based (Regex/Dictionary) + AI-powered analysis
//  Ref: ISO 27001:2022 A.8.12, NIST SP 800-171, Gartner 2025 DLP Market Guide
//

import Foundation
import os.log
import NaturalLanguage

// MARK: - DLP Rule Severity & Action (ISO 27001 A.8.12 classifications)
enum DLPSeverity: String, Codable, CaseIterable, Comparable {
    case critical, high, medium, low, info
}

enum DLPAction: String, Codable, CaseIterable {
    case block, quarantine, audit, encrypt, notify, allow
}

enum DLPChannel: String, Codable {
    case file, clipboard, network, usb, print, screenshot, email, cloud, airdrop
}

// MARK: - DLP Rule Definition
struct DLPRule: Codable, Identifiable {
    let id: String
    let name: String
    let description: String
    let patterns: [String]         // regex patterns
    let keywords: [String]         // dictionary keywords
    let severity: DLPSeverity
    let action: DLPAction
    let channels: [DLPChannel]
    let enabled: Bool
    let complianceFramework: String // e.g. "ISO27001", "GDPR", "PDPO"
}

// MARK: - DLP Scan Result
struct DLPScanResult {
    let ruleId: String
    let ruleName: String
    let matches: [DLPMatch]
    let severity: DLPSeverity
    let action: DLPAction
    let channel: DLPChannel
    let timestamp: Date
    let filePath: String?
    let processName: String?
}

struct DLPMatch {
    let type: String       // "regex", "keyword", "ai"
    let matchedText: String
    let decodedValue: String?
    let confidence: Int
    let evasionDetected: Bool
}

// MARK: - DLP Policy Engine (Singleton)
final class DLPPolicyEngine {
    static let shared = DLPPolicyEngine()
    private let logger = Logger(subsystem: "com.nextguard.agent", category: "DLPEngine")
    
    private(set) var activePolicies: [DLPRule] = []
    private let policyQueue = DispatchQueue(label: "com.nextguard.policy", qos: .userInitiated)
    private var cachedRegexes: [String: NSRegularExpression] = [:]
    
    // Built-in rules matching Tier-1 vendors (Forcepoint/Symantec/Microsoft Purview)
    private let builtInRules: [DLPRule] = [
        DLPRule(id: "cc-detect", name: "Credit Card Number",
                description: "Visa/MC/Amex credit card patterns",
                patterns: ["\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\\b",
                           "\\b[0-9]{4}[\\s-]?[0-9]{4}[\\s-]?[0-9]{4}[\\s-]?[0-9]{4}\\b"],
                keywords: [], severity: .critical, action: .block,
                channels: [.file, .clipboard, .network, .email, .usb, .cloud, .print],
                enabled: true, complianceFramework: "PCI-DSS"),
        
        DLPRule(id: "hkid-detect", name: "Hong Kong ID",
                description: "HKID number pattern",
                patterns: ["\\b[A-Z]{1,2}[0-9]{6}\\(?[0-9A]\\)?\\b"],
                keywords: [], severity: .critical, action: .block,
                channels: [.file, .clipboard, .network, .email, .usb, .cloud, .print],
                enabled: true, complianceFramework: "PDPO"),
        
        DLPRule(id: "email-detect", name: "Email Address",
                description: "Email address pattern",
                patterns: ["\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b"],
                keywords: [], severity: .low, action: .audit,
                channels: [.file, .clipboard, .network, .email],
                enabled: true, complianceFramework: "GDPR"),
        
        DLPRule(id: "phone-hk", name: "HK Phone Number",
                description: "Hong Kong phone number",
                patterns: ["\\b(?:\\+?852[\\s-]?)?[2-9][0-9]{3}[\\s-]?[0-9]{4}\\b"],
                keywords: [], severity: .medium, action: .audit,
                channels: [.file, .clipboard, .network, .email],
                enabled: true, complianceFramework: "PDPO"),
        
        DLPRule(id: "sensitive-keywords", name: "Sensitive Keywords",
                description: "Classification labels and sensitive terms",
                patterns: [],
                keywords: ["confidential", "secret", "classified", "internal only",
                           "do not distribute", "password", "restricted",
                           "機密", "秘密", "絕密", "內部", "限閱", "禁止分發", "密碼", "保密"],
                severity: .high, action: .quarantine,
                channels: [.file, .clipboard, .network, .email, .usb, .cloud, .print],
                enabled: true, complianceFramework: "ISO27001"),
        
        DLPRule(id: "api-key-detect", name: "API Keys & Secrets",
                description: "AWS keys, tokens, passwords in code",
                patterns: ["(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?key|auth[_-]?token)\\s*[:=]\\s*['\"][A-Za-z0-9+/=_-]{16,}['\"]",
                           "\\bAKIA[0-9A-Z]{16}\\b",
                           "(?i)password\\s*[:=]\\s*['\"][^'\"]{6,}['\"]"],
                keywords: [], severity: .critical, action: .block,
                channels: [.file, .clipboard, .network, .email, .cloud],
                enabled: true, complianceFramework: "NIST-800-171"),
        
        DLPRule(id: "iban-detect", name: "IBAN / Bank Account",
                description: "International bank account numbers",
                patterns: ["\\b[A-Z]{2}[0-9]{2}\\s?[A-Z0-9]{4}\\s?[0-9]{4}\\s?[0-9]{4}\\s?[0-9]{4}\\s?[0-9]{0,4}\\b"],
                keywords: [], severity: .high, action: .block,
                channels: [.file, .clipboard, .network, .email, .usb],
                enabled: true, complianceFramework: "GDPR"),
        
        DLPRule(id: "passport-detect", name: "Passport Number",
                description: "Common passport number formats",
                patterns: ["\\b[A-Z][0-9]{8}\\b", "\\b[A-Z]{2}[0-9]{7}\\b"],
                keywords: ["passport", "travel document"],
                severity: .high, action: .quarantine,
                channels: [.file, .clipboard, .network, .email],
                enabled: true, complianceFramework: "GDPR")
    ]
    
    private init() {}
    
    // MARK: - Policy Loading
    func loadPolicies() async {
        // 1. Load built-in rules
        activePolicies = builtInRules
        
        // 2. Attempt to fetch policies from NextGuard management console
        if let serverPolicies = await fetchServerPolicies() {
            activePolicies.append(contentsOf: serverPolicies)
        }
        
        // 3. Load local policy overrides
        if let localPolicies = loadLocalPolicies() {
            activePolicies.append(contentsOf: localPolicies)
        }
        
        // Pre-compile all regex patterns
        precompileRegexes()
        logger.info("Policy engine ready: \(self.activePolicies.count) rules loaded")
    }
    
    private func precompileRegexes() {
        for rule in activePolicies {
            for pattern in rule.patterns {
                if cachedRegexes[pattern] == nil {
                    do {
                        cachedRegexes[pattern] = try NSRegularExpression(pattern: pattern, options: [])
                    } catch {
                        logger.error("Invalid regex in rule \(rule.id): \(pattern)")
                    }
                }
            }
        }
    }
    
    // MARK: - Content Scanning (Core DLP Function)
    func scanContent(_ content: String, channel: DLPChannel, filePath: String? = nil, processName: String? = nil) -> [DLPScanResult] {
        var results: [DLPScanResult] = []
        
        policyQueue.sync {
            for rule in activePolicies where rule.enabled && rule.channels.contains(channel) {
                var matches: [DLPMatch] = []
                
                // Pattern-based scan (Traditional DLP - like Forcepoint/Symantec)
                for pattern in rule.patterns {
                    guard let regex = cachedRegexes[pattern] else { continue }
                    let nsContent = content as NSString
                    let regexMatches = regex.matches(in: content, options: [], range: NSRange(location: 0, length: nsContent.length))
                    for m in regexMatches {
                        let matchStr = nsContent.substring(with: m.range)
                        matches.append(DLPMatch(type: "regex", matchedText: matchStr, decodedValue: nil, confidence: 95, evasionDetected: false))
                    }
                }
                
                // Dictionary/keyword scan
                let lowerContent = content.lowercased()
                for keyword in rule.keywords {
                    if lowerContent.contains(keyword.lowercased()) {
                        matches.append(DLPMatch(type: "keyword", matchedText: keyword, decodedValue: nil, confidence: 90, evasionDetected: false))
                    }
                }
                
                if !matches.isEmpty {
                    results.append(DLPScanResult(
                        ruleId: rule.id, ruleName: rule.name, matches: matches,
                        severity: rule.severity, action: rule.action, channel: channel,
                        timestamp: Date(), filePath: filePath, processName: processName
                    ))
                }
            }
        }
        
        return results
    }
    
    // MARK: - File Scanning
    func scanFile(at path: String, channel: DLPChannel = .file) -> [DLPScanResult] {
        guard let data = FileManager.default.contents(atPath: path),
              let content = String(data: data, encoding: .utf8) else {
            logger.warning("Cannot read file: \(path)")
            return []
        }
        return scanContent(content, channel: channel, filePath: path)
    }
    
    // MARK: - Determine Action (strictest wins, per Gartner hybrid DLP model)
    func determineAction(for results: [DLPScanResult]) -> DLPAction {
        let priority: [DLPAction: Int] = [.block: 5, .quarantine: 4, .encrypt: 3, .notify: 2, .audit: 1, .allow: 0]
        var maxAction: DLPAction = .allow
        for r in results {
            if (priority[r.action] ?? 0) > (priority[maxAction] ?? 0) {
                maxAction = r.action
            }
        }
        return maxAction
    }
    
    // MARK: - Server Policy Fetch
    private func fetchServerPolicies() async -> [DLPRule]? {
        let serverURL = AgentConfig.shared.managementServerURL
        guard !serverURL.isEmpty else { return nil }
        
        do {
            let url = URL(string: "\(serverURL)/api/v1/policies")!
            var request = URLRequest(url: url)
            request.setValue("Bearer \(AgentConfig.shared.apiToken)", forHTTPHeaderField: "Authorization")
            request.setValue(AgentConfig.shared.deviceId, forHTTPHeaderField: "X-Device-ID")
            let (data, _) = try await URLSession.shared.data(for: request)
            return try JSONDecoder().decode([DLPRule].self, from: data)
        } catch {
            logger.error("Failed to fetch server policies: \(error.localizedDescription)")
            return nil
        }
    }
    
    private func loadLocalPolicies() -> [DLPRule]? {
        let policyPath = "/Library/Application Support/NextGuard/policies.json"
        guard let data = FileManager.default.contents(atPath: policyPath) else { return nil }
        return try? JSONDecoder().decode([DLPRule].self, from: data)
    }
}

// MARK: - Agent Configuration
final class AgentConfig {
    static let shared = AgentConfig()
    var managementServerURL: String = "https://console.next-guard.com"
    var apiToken: String = ""
    var deviceId: String = ""
    var agentVersion: String = "1.0.0"
    
    private init() {
        deviceId = getDeviceId()
        loadConfig()
    }
    
    private func getDeviceId() -> String {
        let key = "com.nextguard.device-id"
        if let existing = UserDefaults.standard.string(forKey: key) { return existing }
        let newId = UUID().uuidString
        UserDefaults.standard.set(newId, forKey: key)
        return newId
    }
    
    private func loadConfig() {
        let configPath = "/Library/Application Support/NextGuard/agent.conf"
        guard let data = FileManager.default.contents(atPath: configPath),
              let config = try? JSONDecoder().decode(AgentConfigFile.self, from: data) else { return }
        managementServerURL = config.serverURL ?? managementServerURL
        apiToken = config.apiToken ?? apiToken
    }
}

struct AgentConfigFile: Codable {
    let serverURL: String?
    let apiToken: String?
}
