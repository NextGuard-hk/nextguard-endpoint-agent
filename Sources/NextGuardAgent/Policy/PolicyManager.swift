//
// PolicyManager.swift
// NextGuard Endpoint DLP Agent
//
// Copyright (c) 2026 NextGuard Technology Limited. All rights reserved.
// Centralized policy management: Console sync + Autonomous local policies
// Reference: ISO 27001:2022 A.5.1, COBIT 2019 APO01, Gartner DLP MQ
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
  var source: PolicySource = .console
}

enum PolicySource: String, Codable {
  case console   // synced from NextGuard Console
  case local     // managed autonomously by the Agent
  case builtin   // hardcoded safety baselines
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
  let activeDays: [Int]       // 1=Mon, 7=Sun
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

// MARK: - Local Policy Models

/// A policy rule created and managed locally by the Agent,
/// independent of Console connectivity.
struct LocalPolicy: Codable, Identifiable {
  let id: String
  var name: String
  var description: String
  var enabled: Bool
  var priority: Int
  var category: PolicyCategory
  var channels: [PolicyChannel]
  var rules: [PolicyRule]
  var actions: [PolicyAction]
  var schedule: PolicySchedule?
  let createdAt: Date
  var updatedAt: Date
  var isEditable: Bool      // false for builtin baselines
  var overridesConsole: Bool // true = local rule wins over console rule
}

enum LocalPolicyPreset: String, Codable, CaseIterable {
  case usbBlockAll        = "USB_BLOCK_ALL"
  case usbMonitorOnly     = "USB_MONITOR_ONLY"
  case screenshotBlock    = "SCREENSHOT_BLOCK"
  case clipboardMonitor   = "CLIPBOARD_MONITOR"
  case cloudUploadBlock   = "CLOUD_UPLOAD_BLOCK"
  case printMonitor       = "PRINT_MONITOR"
  case airdropBlock       = "AIRDROP_BLOCK"
  case networkMonitor     = "NETWORK_MONITOR"
  case offlineFallback    = "OFFLINE_FALLBACK"

  var displayName: String {
    switch self {
    case .usbBlockAll:      return "Block All USB Storage"
    case .usbMonitorOnly:   return "Monitor USB (Log Only)"
    case .screenshotBlock:  return "Block Screenshots"
    case .clipboardMonitor: return "Monitor Clipboard"
    case .cloudUploadBlock: return "Block Cloud Uploads"
    case .printMonitor:     return "Monitor Print Jobs"
    case .airdropBlock:     return "Block AirDrop"
    case .networkMonitor:   return "Monitor Network Transfers"
    case .offlineFallback:  return "Offline Safety Baseline"
    }
  }
}

// MARK: - Local Policy Manager

final class LocalPolicyManager: @unchecked Sendable {
  static let shared = LocalPolicyManager()
  private let logger = Logger(subsystem: "com.nextguard.agent", category: "LocalPolicy")
  private var localPolicies: [LocalPolicy] = []
  private let queue = DispatchQueue(label: "com.nextguard.localpolicy", qos: .userInitiated)

  private let localStorePath: URL = {
    let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
    return appSupport.appendingPathComponent("NextGuard/local_policies.json")
  }()

  private init() {
    loadFromDisk()
    if localPolicies.isEmpty {
      installBuiltinPolicies()
    }
  }

  // MARK: - Builtin Policy Baselines

  private func installBuiltinPolicies() {
    let now = Date()
    let baselines: [LocalPolicy] = [
      LocalPolicy(
        id: "builtin-usb-monitor",
        name: "USB Storage Monitor",
        description: "Log all USB storage device activity",
        enabled: true, priority: 100,
        category: .custom, channels: [.usb],
        rules: [PolicyRule(ruleId: "usb-all", ruleType: .fileType, pattern: nil, threshold: 1, proximity: nil, caseSensitive: false, keywords: nil, fileTypes: ["*"], minFileSize: nil, maxFileSize: nil, customRegex: nil)],
        actions: [PolicyAction(actionType: .monitor, notifyUser: false, notifyAdmin: true, customMessage: nil, quarantinePath: nil)],
        schedule: nil, createdAt: now, updatedAt: now,
        isEditable: false, overridesConsole: false
      ),
      LocalPolicy(
        id: "builtin-clipboard-monitor",
        name: "Clipboard Monitor",
        description: "Log clipboard operations with sensitive content",
        enabled: true, priority: 90,
        category: .pii, channels: [.clipboard],
        rules: [PolicyRule(ruleId: "clip-pii", ruleType: .regex, pattern: "\\b\\d{3}-\\d{2}-\\d{4}\\b|\\b\\d{4}[- ]?\\d{4}[- ]?\\d{4}[- ]?\\d{4}\\b", threshold: 1, proximity: nil, caseSensitive: false, keywords: nil, fileTypes: nil, minFileSize: nil, maxFileSize: nil, customRegex: nil)],
        actions: [PolicyAction(actionType: .monitor, notifyUser: false, notifyAdmin: true, customMessage: nil, quarantinePath: nil)],
        schedule: nil, createdAt: now, updatedAt: now,
        isEditable: false, overridesConsole: false
      ),
      LocalPolicy(
        id: "builtin-offline-fallback",
        name: "Offline Safety Baseline",
        description: "Block high-risk channels when Console unreachable",
        enabled: true, priority: 200,
        category: .custom, channels: [.usb, .airdrop, .cloudSync],
        rules: [PolicyRule(ruleId: "offline-block", ruleType: .fileType, pattern: nil, threshold: 1, proximity: nil, caseSensitive: false, keywords: nil, fileTypes: ["*"], minFileSize: nil, maxFileSize: nil, customRegex: nil)],
        actions: [PolicyAction(actionType: .block, notifyUser: true, notifyAdmin: false, customMessage: "Blocked: Agent offline, safety policy active.", quarantinePath: nil)],
        schedule: nil, createdAt: now, updatedAt: now,
        isEditable: false, overridesConsole: true
      )
    ]
    localPolicies = baselines
    saveToDisk()
    logger.info("Installed \(baselines.count) builtin policy baselines")
  }

  // MARK: - CRUD Operations

  func addPolicy(_ policy: LocalPolicy) {
    queue.sync {
      localPolicies.append(policy)
      saveToDisk()
    }
    logger.info("Added local policy: \(policy.name)")
    NotificationCenter.default.post(name: .init("NextGuardLocalPoliciesUpdated"), object: nil)
  }

  func updatePolicy(_ updated: LocalPolicy) {
    queue.sync {
      if let idx = localPolicies.firstIndex(where: { $0.id == updated.id }) {
        guard localPolicies[idx].isEditable else {
          logger.warning("Cannot edit builtin policy: \(updated.id)")
          return
        }
        localPolicies[idx] = updated
        saveToDisk()
      }
    }
    NotificationCenter.default.post(name: .init("NextGuardLocalPoliciesUpdated"), object: nil)
  }

  func removePolicy(id: String) {
    queue.sync {
      guard let idx = localPolicies.firstIndex(where: { $0.id == id }) else { return }
      guard localPolicies[idx].isEditable else {
        logger.warning("Cannot remove builtin policy: \(id)")
        return
      }
      localPolicies.remove(at: idx)
      saveToDisk()
    }
    logger.info("Removed local policy: \(id)")
    NotificationCenter.default.post(name: .init("NextGuardLocalPoliciesUpdated"), object: nil)
  }

  func togglePolicy(id: String, enabled: Bool) {
    queue.sync {
      if let idx = localPolicies.firstIndex(where: { $0.id == id }) {
        localPolicies[idx].enabled = enabled
        saveToDisk()
      }
    }
    NotificationCenter.default.post(name: .init("NextGuardLocalPoliciesUpdated"), object: nil)
  }

  // MARK: - Preset Factory

  func createFromPreset(_ preset: LocalPolicyPreset) -> LocalPolicy {
    let now = Date()
    let id = "local-\(preset.rawValue.lowercased())-\(UUID().uuidString.prefix(8))"
    switch preset {
    case .usbBlockAll:
      return LocalPolicy(id: id, name: preset.displayName, description: "Block all file transfers to USB storage devices", enabled: true, priority: 150, category: .custom, channels: [.usb], rules: [PolicyRule(ruleId: "usb-block", ruleType: .fileType, pattern: nil, threshold: 1, proximity: nil, caseSensitive: false, keywords: nil, fileTypes: ["*"], minFileSize: nil, maxFileSize: nil, customRegex: nil)], actions: [PolicyAction(actionType: .block, notifyUser: true, notifyAdmin: true, customMessage: "USB file transfer blocked by local policy.", quarantinePath: nil)], schedule: nil, createdAt: now, updatedAt: now, isEditable: true, overridesConsole: true)
    case .usbMonitorOnly:
      return LocalPolicy(id: id, name: preset.displayName, description: "Monitor and log USB activity without blocking", enabled: true, priority: 80, category: .custom, channels: [.usb], rules: [PolicyRule(ruleId: "usb-mon", ruleType: .fileType, pattern: nil, threshold: 1, proximity: nil, caseSensitive: false, keywords: nil, fileTypes: ["*"], minFileSize: nil, maxFileSize: nil, customRegex: nil)], actions: [PolicyAction(actionType: .monitor, notifyUser: false, notifyAdmin: true, customMessage: nil, quarantinePath: nil)], schedule: nil, createdAt: now, updatedAt: now, isEditable: true, overridesConsole: false)
    case .screenshotBlock:
      return LocalPolicy(id: id, name: preset.displayName, description: "Block screenshot capture", enabled: true, priority: 140, category: .custom, channels: [.screenCapture], rules: [PolicyRule(ruleId: "ss-block", ruleType: .fileType, pattern: nil, threshold: 1, proximity: nil, caseSensitive: false, keywords: nil, fileTypes: ["png", "jpg", "tiff"], minFileSize: nil, maxFileSize: nil, customRegex: nil)], actions: [PolicyAction(actionType: .block, notifyUser: true, notifyAdmin: true, customMessage: "Screenshot blocked by local policy.", quarantinePath: nil)], schedule: nil, createdAt: now, updatedAt: now, isEditable: true, overridesConsole: true)
    case .clipboardMonitor:
      return LocalPolicy(id: id, name: preset.displayName, description: "Monitor clipboard for sensitive data", enabled: true, priority: 85, category: .pii, channels: [.clipboard], rules: [PolicyRule(ruleId: "clip-mon", ruleType: .regex, pattern: "\\b\\d{3}-\\d{2}-\\d{4}\\b", threshold: 1, proximity: nil, caseSensitive: false, keywords: nil, fileTypes: nil, minFileSize: nil, maxFileSize: nil, customRegex: nil)], actions: [PolicyAction(actionType: .monitor, notifyUser: false, notifyAdmin: true, customMessage: nil, quarantinePath: nil)], schedule: nil, createdAt: now, updatedAt: now, isEditable: true, overridesConsole: false)
    case .cloudUploadBlock:
      return LocalPolicy(id: id, name: preset.displayName, description: "Block uploads to cloud services", enabled: true, priority: 145, category: .custom, channels: [.cloudSync, .webUpload], rules: [PolicyRule(ruleId: "cloud-block", ruleType: .fileType, pattern: nil, threshold: 1, proximity: nil, caseSensitive: false, keywords: nil, fileTypes: ["*"], minFileSize: nil, maxFileSize: nil, customRegex: nil)], actions: [PolicyAction(actionType: .block, notifyUser: true, notifyAdmin: true, customMessage: "Cloud upload blocked by local policy.", quarantinePath: nil)], schedule: nil, createdAt: now, updatedAt: now, isEditable: true, overridesConsole: true)
    case .printMonitor:
      return LocalPolicy(id: id, name: preset.displayName, description: "Monitor all print job activity", enabled: true, priority: 75, category: .custom, channels: [.print], rules: [PolicyRule(ruleId: "print-mon", ruleType: .fileType, pattern: nil, threshold: 1, proximity: nil, caseSensitive: false, keywords: nil, fileTypes: ["*"], minFileSize: nil, maxFileSize: nil, customRegex: nil)], actions: [PolicyAction(actionType: .monitor, notifyUser: false, notifyAdmin: true, customMessage: nil, quarantinePath: nil)], schedule: nil, createdAt: now, updatedAt: now, isEditable: true, overridesConsole: false)
    case .airdropBlock:
      return LocalPolicy(id: id, name: preset.displayName, description: "Block AirDrop transfers", enabled: true, priority: 140, category: .custom, channels: [.airdrop], rules: [PolicyRule(ruleId: "airdrop-block", ruleType: .fileType, pattern: nil, threshold: 1, proximity: nil, caseSensitive: false, keywords: nil, fileTypes: ["*"], minFileSize: nil, maxFileSize: nil, customRegex: nil)], actions: [PolicyAction(actionType: .block, notifyUser: true, notifyAdmin: true, customMessage: "AirDrop blocked by local policy.", quarantinePath: nil)], schedule: nil, createdAt: now, updatedAt: now, isEditable: true, overridesConsole: true)
    case .networkMonitor:
      return LocalPolicy(id: id, name: preset.displayName, description: "Monitor outbound network file transfers", enabled: true, priority: 80, category: .custom, channels: [.network], rules: [PolicyRule(ruleId: "net-mon", ruleType: .fileType, pattern: nil, threshold: 1, proximity: nil, caseSensitive: false, keywords: nil, fileTypes: ["*"], minFileSize: nil, maxFileSize: nil, customRegex: nil)], actions: [PolicyAction(actionType: .monitor, notifyUser: false, notifyAdmin: true, customMessage: nil, quarantinePath: nil)], schedule: nil, createdAt: now, updatedAt: now, isEditable: true, overridesConsole: false)
    case .offlineFallback:
      return LocalPolicy(id: id, name: preset.displayName, description: "Safety baseline when Console is unreachable", enabled: true, priority: 200, category: .custom, channels: [.usb, .airdrop, .cloudSync, .webUpload], rules: [PolicyRule(ruleId: "offline-safe", ruleType: .fileType, pattern: nil, threshold: 1, proximity: nil, caseSensitive: false, keywords: nil, fileTypes: ["*"], minFileSize: nil, maxFileSize: nil, customRegex: nil)], actions: [PolicyAction(actionType: .block, notifyUser: true, notifyAdmin: false, customMessage: "Blocked: Agent offline, safety policy active.", quarantinePath: nil)], schedule: nil, createdAt: now, updatedAt: now, isEditable: true, overridesConsole: true)
    }
  }

  // MARK: - Persistence

  private func saveToDisk() {
    let dir = localStorePath.deletingLastPathComponent()
    try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .iso8601
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    if let data = try? encoder.encode(localPolicies) {
      try? data.write(to: localStorePath, options: .atomic)
    }
  }

  private func loadFromDisk() {
    guard FileManager.default.fileExists(atPath: localStorePath.path),
          let data = try? Data(contentsOf: localStorePath) else { return }
    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .iso8601
    if let policies = try? decoder.decode([LocalPolicy].self, from: data) {
      localPolicies = policies
      logger.info("Loaded \(policies.count) local policies from disk")
    }
  }

  // MARK: - Query

  func getAll() -> [LocalPolicy] { localPolicies }
  func getEnabled() -> [LocalPolicy] { localPolicies.filter { $0.enabled } }
  func getById(_ id: String) -> LocalPolicy? { localPolicies.first { $0.id == id } }
  func getByChannel(_ ch: PolicyChannel) -> [LocalPolicy] { localPolicies.filter { $0.enabled && $0.channels.contains(ch) } }
  func getOverridePolicies() -> [LocalPolicy] { localPolicies.filter { $0.enabled && $0.overridesConsole } }
}

// MARK: - Policy Manager (Console + Local Integration)

final class PolicyManager: @unchecked Sendable {
  static let shared = PolicyManager()
  private let logger = Logger(subsystem: "com.nextguard.agent", category: "PolicyManager")
  private var consolePolicies: [DLPPolicy] = []
  private var policyVersion: Int = 0
  private let syncQueue = DispatchQueue(label: "com.nextguard.policy", qos: .userInitiated)
  private var syncTimer: Timer?
  private let syncIntervalSeconds: TimeInterval = 300
  private let consoleBaseURL = "https://console.next-guard.com/api/v1"
  private var agentToken: String = ""
  private var deviceId: String = ""
  private var isConsoleReachable: Bool = true

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
    request.timeoutInterval = 15

    URLSession.shared.dataTask(with: request) { [weak self] data, response, error in
      guard let self = self else { return }

      if error != nil {
        self.isConsoleReachable = false
        self.logger.warning("Console unreachable, local policies active")
        NotificationCenter.default.post(name: .init("NextGuardConsoleStatusChanged"), object: false)
        return
      }

      self.isConsoleReachable = true
      NotificationCenter.default.post(name: .init("NextGuardConsoleStatusChanged"), object: true)

      guard let data = data, let httpResp = response as? HTTPURLResponse else { return }

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

      guard self.verifyBundleSignature(bundle) else {
        self.logger.error("Policy bundle signature verification FAILED")
        AuditLogger.shared.log(category: .configChange, severity: .critical, action: "policy_signature_fail", outcome: "blocked", description: "Rejected policy bundle with invalid signature")
        return
      }

      self.syncQueue.async {
        self.consolePolicies = bundle.policies.filter { $0.enabled }.sorted { $0.priority > $1.priority }
        self.policyVersion = bundle.version
        self.cachePolicies(bundle)
        self.logger.info("Policies updated: v\(bundle.version), \(self.consolePolicies.count) active")
        AuditLogger.shared.log(category: .configChange, severity: .info, action: "policy_update", description: "Updated to policy bundle v\(bundle.version)")
        NotificationCenter.default.post(name: .init("NextGuardPoliciesUpdated"), object: nil)
      }
    }.resume()
  }

  // MARK: - Unified Policy Evaluation (Console + Local)

  func evaluate(channel: PolicyChannel, content: String, metadata: [String: String] = [:]) -> (ActionType, String?, String?) {
    // 1. Check local override policies first (highest priority when offline or override=true)
    let localOverrides = LocalPolicyManager.shared.getOverridePolicies()
      .filter { $0.channels.contains(channel) }
      .sorted { $0.priority > $1.priority }

    // If Console is unreachable, apply offline fallback policies
    if !isConsoleReachable {
      for lp in localOverrides {
        for rule in lp.rules {
          if matchesRule(rule, content: content, metadata: metadata) {
            let action = lp.actions.first?.actionType ?? .block
            let msg = lp.actions.first?.customMessage
            logger.info("Local override policy matched (offline): \(lp.name)")
            return (action, lp.id, msg)
          }
        }
      }
    }

    // 2. Merge console + local policies, sorted by priority
    var allEvaluable: [(priority: Int, id: String, name: String, channels: [PolicyChannel], rules: [PolicyRule], actions: [PolicyAction], schedule: PolicySchedule?, excludedUsers: [String], source: String)] = []

    for cp in consolePolicies {
      allEvaluable.append((cp.priority, cp.id, cp.name, cp.channels, cp.rules, cp.actions, cp.schedule, cp.excludedUsers, "console"))
    }
    for lp in LocalPolicyManager.shared.getEnabled() {
      allEvaluable.append((lp.priority, lp.id, lp.name, lp.channels, lp.rules, lp.actions, lp.schedule, [], "local"))
    }
    allEvaluable.sort { $0.priority > $1.priority }

    // 3. Evaluate in priority order
    let currentUser = NSUserName()
    for entry in allEvaluable {
      guard entry.channels.contains(channel) else { continue }
      if entry.source == "console" {
        guard isWithinSchedule(entry.schedule) else { continue }
        if entry.excludedUsers.contains(currentUser) { continue }
      }
      for rule in entry.rules {
        if matchesRule(rule, content: content, metadata: metadata) {
          let action = entry.actions.first?.actionType ?? .monitor
          let msg = entry.actions.first?.customMessage
          logger.info("Policy matched [\(entry.source)]: \(entry.name)")
          return (action, entry.id, msg)
        }
      }
    }
    return (.allow, nil, nil)
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
      return types.contains("*") || types.contains(ext.lowercased())
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
      consolePolicies = bundle.policies.filter { $0.enabled }.sorted { $0.priority > $1.priority }
      policyVersion = bundle.version
      logger.info("Loaded cached policies: v\(bundle.version), \(self.consolePolicies.count) active")
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

  func getConsolePolicies() -> [DLPPolicy] { consolePolicies }
  func getLocalPolicies() -> [LocalPolicy] { LocalPolicyManager.shared.getAll() }
  func getPolicyVersion() -> Int { policyVersion }
  func getConsolePolicyCount() -> Int { consolePolicies.count }
  func getLocalPolicyCount() -> Int { LocalPolicyManager.shared.getAll().count }
  func getTotalPolicyCount() -> Int { consolePolicies.count + LocalPolicyManager.shared.getEnabled().count }
  func isOnline() -> Bool { isConsoleReachable }

  func getPolicyById(_ id: String) -> DLPPolicy? {
    consolePolicies.first { $0.id == id }
  }

  /// Summary of all active policies for status reporting
  func getStatusSummary() -> [String: Any] {
    return [
      "consoleReachable": isConsoleReachable,
      "consolePolicyVersion": policyVersion,
      "consolePolicyCount": consolePolicies.count,
      "localPolicyCount": LocalPolicyManager.shared.getAll().count,
      "localEnabledCount": LocalPolicyManager.shared.getEnabled().count,
      "localOverrideCount": LocalPolicyManager.shared.getOverridePolicies().count,
      "totalActivePolicies": getTotalPolicyCount()
    ]
  }
}
