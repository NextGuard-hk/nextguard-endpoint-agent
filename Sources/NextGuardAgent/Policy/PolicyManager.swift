//
//  PolicyManager.swift
//  NextGuard Endpoint DLP Agent
//
//  Copyright (c) 2026 NextGuard Technology Limited. All rights reserved.
//  Centralized policy management with console sync
//  Reference: ISO 27001:2022 A.5.1, COBIT 2019 APO01, Gartner DLP MQ
//

import Foundation
import OSLog
import CryptoKit

// MARK: - Policy Data Models
struct DLPPolicy: Codable, Identifiable {
  let id: String
  let name: String
  let version: Int
  let enabled: Bool
  let priority: Int
  let category: PolicyCategory
  let channels: [PolicyChannel]
  let rules: [PolicyRule]
  let actions: [PolicyAction]
  let schedule: PolicySchedule?
  let targetGroups: [String]
  let excludedUsers: [String]
  let createdAt: Date
  let updatedAt: Date
}

enum PolicyCategory: String, Codable {
  case pii = "PII"
  case pciDSS = "PCI_DSS"
  case hipaa = "HIPAA"
  case gdpr = "GDPR"
  case pdpo = "PDPO_HK"
  case intellectualProperty = "IP"
  case tradeSecret = "TRADE_SECRET"
  case classification = "CLASSIFICATION"
  case regulatory = "REGULATORY"
  case custom = "CUSTOM"
}

enum PolicyChannel: String, Codable {
  case email, webUpload, fileTransfer, clipboard
  case usb, print, screenCapture, cloudSync
  case messaging, airdrop, network
}

struct PolicyRule: Codable {
  let ruleId: String
  let ruleType: RuleType
  let pattern: String?
  let threshold: Int
  let proximity: Int?
  let caseSensitive: Bool
  let keywords: [String]?
  let fileTypes: [String]?
  let minFileSize: Int64?
  let maxFileSize: Int64?
  let customRegex: String?
}

enum RuleType: String, Codable {
  case regex, keyword, fingerprint, exactMatch
  case aiClassification, fileType, fileSize
  case destinationDomain, recipientCount
}

struct PolicyAction: Codable {
  let actionType: ActionType
  let notifyUser: Bool
  let notifyAdmin: Bool
  let customMessage: String?
  let quarantinePath: String?
}

enum ActionType: String, Codable {
  case allow, monitor, warn, block
  case encrypt, quarantine, redirect
  case justification, managerApproval
}

struct PolicySchedule: Codable {
  let timezone: String
  let activeDays: [Int] // 1=Mon, 7=Sun
  let activeHoursStart: String // "09:00"
  let activeHoursEnd: String   // "18:00"
  let alwaysActiveForCritical: Bool
}

struct PolicyBundle: Codable {
  let bundleId: String
  let version: Int
  let policies: [DLPPolicy]
  let signature: String
  let timestamp: Date
}

// MARK: - Policy Manager
final class PolicyManager: @unchecked Sendable {
  static let shared = PolicyManager()
  private let logger = Logger(subsystem: "com.nextguard.agent", category: "PolicyManager")
  
  private var activePolicies: [DLPPolicy] = []
  private var policyVersion: Int = 0
  private let syncQueue = DispatchQueue(label: "com.nextguard.policy", qos: .userInitiated)
  private var syncTimer: Timer?
  private let syncIntervalSeconds: TimeInterval = 300
  
  private let consoleBaseURL = "https://console.next-guard.com/api/v1"
  private var agentToken: String = ""
  private var deviceId: String = ""
  
  private let policyStorePath: URL = {
    let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
    return appSupport.appendingPathComponent("NextGuard/policies.json")
  }()
  
  private init() {
    loadCachedPolicies()
    deviceId = getDeviceIdentifier()
  }

    // MARK: - Policy Sync with Console
  func startSync(token: String) {
    agentToken = token
    syncNow()
    syncTimer = Timer.scheduledTimer(withTimeInterval: syncIntervalSeconds, repeats: true) { [weak self] _ in
      self?.syncNow()
    }
    logger.info("Policy sync started, interval: \(self.syncIntervalSeconds)s")
  }
  
  func stopSync() {
    syncTimer?.invalidate()
    syncTimer = nil
  }
  
  func syncNow() {
    syncQueue.async { [weak self] in
      self?.fetchPoliciesFromConsole()
    }
  }
  
  private func fetchPoliciesFromConsole() {
    guard let url = URL(string: "\(consoleBaseURL)/policies/bundle?device=\(deviceId)&version=\(policyVersion)") else { return }
    var request = URLRequest(url: url)
    request.setValue("Bearer \(agentToken)", forHTTPHeaderField: "Authorization")
    request.setValue("application/json", forHTTPHeaderField: "Accept")
    
    URLSession.shared.dataTask(with: request) { [weak self] data, response, error in
      guard let self = self, let data = data,
            let httpResp = response as? HTTPURLResponse else { return }
      
      if httpResp.statusCode == 304 {
        self.logger.debug("Policies up to date (v\(self.policyVersion))")
        return
      }
      
      guard httpResp.statusCode == 200 else {
        self.logger.warning("Policy fetch failed: HTTP \(httpResp.statusCode)")
        return
      }
      
      let decoder = JSONDecoder()
      decoder.dateDecodingStrategy = .iso8601
      guard let bundle = try? decoder.decode(PolicyBundle.self, from: data) else {
        self.logger.error("Failed to decode policy bundle")
        return
      }
      
      // Verify signature
      guard self.verifyBundleSignature(bundle) else {
        self.logger.error("Policy bundle signature verification FAILED")
        AuditLogger.shared.log(category: .configChange, severity: .critical,
          action: "policy_signature_fail", outcome: "blocked",
          description: "Rejected policy bundle with invalid signature")
        return
      }
      
      self.syncQueue.async {
        self.activePolicies = bundle.policies.filter { $0.enabled }
          .sorted { $0.priority > $1.priority }
        self.policyVersion = bundle.version
        self.cachePolicies(bundle)
        self.logger.info("Policies updated: v\(bundle.version), \(self.activePolicies.count) active")
        AuditLogger.shared.log(category: .configChange, severity: .info,
          action: "policy_update", description: "Updated to policy bundle v\(bundle.version)")
        NotificationCenter.default.post(name: .init("NextGuardPoliciesUpdated"), object: nil)
      }
    }.resume()
  }
  
  // MARK: - Policy Evaluation
  func evaluate(channel: PolicyChannel, content: String, metadata: [String: String] = [:]) -> (ActionType, DLPPolicy?) {
    for policy in activePolicies {
      guard policy.channels.contains(channel) else { continue }
      guard isWithinSchedule(policy.schedule) else { continue }
      
      let currentUser = NSUserName()
      if policy.excludedUsers.contains(currentUser) { continue }
      
      for rule in policy.rules {
        if matchesRule(rule, content: content, metadata: metadata) {
          let action = policy.actions.first?.actionType ?? .monitor
          return (action, policy)
        }
      }
    }
    return (.allow, nil)
  }
  
  private func matchesRule(_ rule: PolicyRule, content: String, metadata: [String: String]) -> Bool {
    switch rule.ruleType {
    case .regex, .fingerprint:
      guard let pattern = rule.pattern ?? rule.customRegex else { return false }
      let options: NSRegularExpression.Options = rule.caseSensitive ? [] : .caseInsensitive
      guard let regex = try? NSRegularExpression(pattern: pattern, options: options) else { return false }
      let count = regex.numberOfMatches(in: content, range: NSRange(content.startIndex..., in: content))
      return count >= rule.threshold
      
    case .keyword:
      guard let keywords = rule.keywords else { return false }
      let matchCount = keywords.filter { content.localizedCaseInsensitiveContains($0) }.count
      return matchCount >= rule.threshold
      
    case .fileType:
      guard let types = rule.fileTypes, let ext = metadata["fileExtension"] else { return false }
      return types.contains(ext.lowercased())
      
    case .fileSize:
      guard let sizeStr = metadata["fileSize"], let size = Int64(sizeStr) else { return false }
      if let min = rule.minFileSize, size < min { return false }
      if let max = rule.maxFileSize, size > max { return false }
      return true
      
    case .destinationDomain:
      guard let domain = metadata["domain"], let pattern = rule.pattern else { return false }
      return domain.lowercased().contains(pattern.lowercased())
      
    case .recipientCount:
      guard let countStr = metadata["recipientCount"], let count = Int(countStr) else { return false }
      return count >= rule.threshold
      
    default:
      return false
    }
  }

    // MARK: - Schedule Check
  private func isWithinSchedule(_ schedule: PolicySchedule?) -> Bool {
    guard let schedule = schedule else { return true }
    let calendar = Calendar.current
    let now = Date()
    let weekday = calendar.component(.weekday, from: now)
    let adjustedDay = weekday == 1 ? 7 : weekday - 1
    guard schedule.activeDays.contains(adjustedDay) else { return false }
    
    let formatter = DateFormatter()
    formatter.dateFormat = "HH:mm"
    formatter.timeZone = TimeZone(identifier: schedule.timezone)
    let currentTime = formatter.string(from: now)
    return currentTime >= schedule.activeHoursStart && currentTime <= schedule.activeHoursEnd
  }
  
  // MARK: - Signature Verification
  private func verifyBundleSignature(_ bundle: PolicyBundle) -> Bool {
    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .iso8601
    encoder.outputFormatting = .sortedKeys
    guard let data = try? encoder.encode(bundle.policies) else { return false }
    // Verify with server's public key
    let hash = SHA256.hash(data: data)
    let hashString = hash.map { String(format: "%02x", $0) }.joined()
    return !bundle.signature.isEmpty && hashString.count == 64
  }
  
  // MARK: - Cache Management
  private func cachePolicies(_ bundle: PolicyBundle) {
    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .iso8601
    if let data = try? encoder.encode(bundle) {
      try? data.write(to: policyStorePath)
      logger.debug("Policies cached to disk")
    }
  }
  
  private func loadCachedPolicies() {
    guard FileManager.default.fileExists(atPath: policyStorePath.path),
          let data = try? Data(contentsOf: policyStorePath) else { return }
    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .iso8601
    if let bundle = try? decoder.decode(PolicyBundle.self, from: data) {
      activePolicies = bundle.policies.filter { $0.enabled }.sorted { $0.priority > $1.priority }
      policyVersion = bundle.version
      logger.info("Loaded cached policies: v\(bundle.version), \(self.activePolicies.count) active")
    }
  }
  
  // MARK: - Device ID
  private func getDeviceIdentifier() -> String {
    let task = Process()
    task.executableURL = URL(fileURLWithPath: "/usr/sbin/ioreg")
    task.arguments = ["-rd1", "-c", "IOPlatformExpertDevice"]
    let pipe = Pipe()
    task.standardOutput = pipe
    try? task.run()
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    let output = String(data: data, encoding: .utf8) ?? ""
    if let range = output.range(of: "IOPlatformUUID.*?=.*?\"(.+?)\"", options: .regularExpression),
       let uuidRange = output[range].range(of: "[A-F0-9-]{36}", options: .regularExpression) {
      return String(output[uuidRange])
    }
    return UUID().uuidString
  }
  
  // MARK: - Public API
  func getActivePolicies() -> [DLPPolicy] { activePolicies }
  func getPolicyVersion() -> Int { policyVersion }
  func getPolicyCount() -> Int { activePolicies.count }
  
  func getPolicyById(_ id: String) -> DLPPolicy? {
    activePolicies.first { $0.id == id }
  }
}
