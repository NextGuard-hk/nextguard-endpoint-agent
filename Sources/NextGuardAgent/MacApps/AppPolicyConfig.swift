// AppPolicyConfig.swift
// NextGuard DLP Agent - Per-App DLP Policy Configuration
// Configurable policies per application, synced from Management Console

import Foundation

// MARK: - App-Level Policy Configuration
public struct AppDLPPolicy: Codable {
  public let policyId: String
  public let policyName: String
  public let appBundleId: String       // "*" for all apps
  public let appCategory: String?      // filter by category
  public let enabled: Bool
  public let eventTypes: [String]      // which events to monitor
  public let action: String            // ALLOW / BLOCK / WARN / LOG / ENCRYPT
  public let severity: String          // minimum severity to trigger
  public let conditions: PolicyConditions?
}

public struct PolicyConditions: Codable {
  public let maxFileSize: Int64?
  public let blockedExtensions: [String]?
  public let allowedExtensions: [String]?
  public let blockedDomains: [String]?
  public let allowedDomains: [String]?
  public let externalRecipientsOnly: Bool?
  public let regexPatterns: [String]?
  public let workingHoursOnly: Bool?
  public let workingHoursStart: String?
  public let workingHoursEnd: String?
  public let exemptUsers: [String]?
  public let exemptGroups: [String]?
}

// MARK: - App Policy Manager
public class AppPolicyManager {
  public static let shared = AppPolicyManager()
  private var policies: [AppDLPPolicy] = []
  private let configURL = "https://www.next-guard.com/api/v1/app-policies"
  private var refreshTimer: Timer?

  private init() {
    loadDefaultPolicies()
  }

  public func syncPolicies() {
    guard let url = URL(string: configURL) else { return }
    var request = URLRequest(url: url)
    request.httpMethod = "GET"
    request.setValue("application/json", forHTTPHeaderField: "Accept")
    URLSession.shared.dataTask(with: request) { [weak self] data, _, error in
      guard let data = data, error == nil else {
        NSLog("[NextGuard] AppPolicyManager sync failed: \(error?.localizedDescription ?? "")")
        return
      }
      if let decoded = try? JSONDecoder().decode([AppDLPPolicy].self, from: data) {
        self?.policies = decoded
        NSLog("[NextGuard] Synced \(decoded.count) app DLP policies")
      }
    }.resume()
  }

  public func startPeriodicSync(interval: TimeInterval = 300) {
    syncPolicies()
    refreshTimer = Timer.scheduledTimer(withTimeInterval: interval, repeats: true) { [weak self] _ in
      self?.syncPolicies()
    }
  }

  public func evaluate(event: AppDLPEvent) -> DLPAction {
    let matching = policies.filter { p in
      guard p.enabled else { return false }
      if p.appBundleId != "*" && p.appBundleId != event.appBundleId { return false }
      if let cat = p.appCategory, cat != event.appCategory.rawValue { return false }
      if !p.eventTypes.isEmpty && !p.eventTypes.contains(event.eventType.rawValue) { return false }
      return true
    }
    let priority: [String: Int] = ["BLOCK": 5, "QUARANTINE": 4, "ENCRYPT": 3, "WARN": 2, "LOG": 1, "ALLOW": 0]
    var best = "ALLOW"
    for p in matching {
      if let c = p.conditions, !evaluateConditions(c, event: event) { continue }
      if (priority[p.action] ?? 0) > (priority[best] ?? 0) { best = p.action }
    }
    return DLPAction(rawValue: best) ?? .allow
  }

  private func evaluateConditions(_ c: PolicyConditions, event: AppDLPEvent) -> Bool {
    if let maxSize = c.maxFileSize, let path = event.filePath {
      if let a = try? FileManager.default.attributesOfItem(atPath: path),
         let s = a[.size] as? Int64, s > maxSize { return true }
    }
    if let exts = c.blockedExtensions, let fn = event.fileName {
      if exts.contains((fn as NSString).pathExtension.lowercased()) { return true }
    }
    if let domains = c.blockedDomains, let url = event.destinationURL {
      if domains.contains(where: { url.contains($0) }) { return true }
    }
    if c.externalRecipientsOnly == true, let r = event.recipientList {
      let org = UserDefaults.standard.string(forKey: "NGOrgEmailDomain") ?? ""
      if r.contains(where: { !$0.hasSuffix(org) }) { return true }
    }
    if c.workingHoursOnly == true {
      let h = Calendar.current.component(.hour, from: Date())
      let s = Int(c.workingHoursStart?.prefix(2) ?? "9") ?? 9
      let e = Int(c.workingHoursEnd?.prefix(2) ?? "18") ?? 18
      if h < s || h >= e { return true }
    }
    if let patterns = c.regexPatterns, let snippet = event.contentSnippet {
      for p in patterns { if snippet.range(of: p, options: .regularExpression) != nil { return true } }
    }
    return false
  }

  private func loadDefaultPolicies() {
    policies = [
      AppDLPPolicy(policyId: "APP-001", policyName: "Block Credential File Upload to Cloud",
        appBundleId: "*", appCategory: "CloudStorage", enabled: true,
        eventTypes: ["CLOUD_SYNC", "FILE_UPLOAD"], action: "BLOCK", severity: "CRITICAL",
        conditions: PolicyConditions(maxFileSize: nil, blockedExtensions: ["pem","key","cer","pfx","p12","env"],
          allowedExtensions: nil, blockedDomains: nil, allowedDomains: nil, externalRecipientsOnly: nil,
          regexPatterns: nil, workingHoursOnly: nil, workingHoursStart: nil, workingHoursEnd: nil,
          exemptUsers: nil, exemptGroups: nil)),
      AppDLPPolicy(policyId: "APP-002", policyName: "Warn External File Share via Messaging",
        appBundleId: "*", appCategory: "Messaging", enabled: true,
        eventTypes: ["FILE_SEND","FILE_SHARE","MESSAGE_SEND"], action: "WARN", severity: "HIGH",
        conditions: PolicyConditions(maxFileSize: nil, blockedExtensions: nil, allowedExtensions: nil,
          blockedDomains: nil, allowedDomains: nil, externalRecipientsOnly: true,
          regexPatterns: nil, workingHoursOnly: nil, workingHoursStart: nil, workingHoursEnd: nil,
          exemptUsers: nil, exemptGroups: nil)),
      AppDLPPolicy(policyId: "APP-003", policyName: "Block Upload to File Sharing Sites",
        appBundleId: "*", appCategory: "Browser", enabled: true,
        eventTypes: ["FILE_UPLOAD"], action: "BLOCK", severity: "HIGH",
        conditions: PolicyConditions(maxFileSize: 50_000_000, blockedExtensions: nil, allowedExtensions: nil,
          blockedDomains: ["wetransfer.com","mega.nz","mediafire.com","anonfiles.com"], allowedDomains: nil,
          externalRecipientsOnly: nil, regexPatterns: nil, workingHoursOnly: nil, workingHoursStart: nil,
          workingHoursEnd: nil, exemptUsers: nil, exemptGroups: nil)),
      AppDLPPolicy(policyId: "APP-004", policyName: "Log External Transfer Activity",
        appBundleId: "*", appCategory: "FileTransfer", enabled: true,
        eventTypes: ["EXTERNAL_TRANSFER"], action: "WARN", severity: "MEDIUM", conditions: nil),
      AppDLPPolicy(policyId: "APP-005", policyName: "Block PII Paste into Messaging",
        appBundleId: "*", appCategory: "Messaging", enabled: true,
        eventTypes: ["CLIPBOARD_PASTE"], action: "BLOCK", severity: "CRITICAL",
        conditions: PolicyConditions(maxFileSize: nil, blockedExtensions: nil, allowedExtensions: nil,
          blockedDomains: nil, allowedDomains: nil, externalRecipientsOnly: nil,
          regexPatterns: ["\\\\b\\\\d{4}[- ]?\\\\d{4}[- ]?\\\\d{4}[- ]?\\\\d{4}\\\\b","\\\\b\\\\d{3}-\\\\d{2}-\\\\d{4}\\\\b","[A-Z]\\\\d{6}\\\\(?\\\\d\\\\)?"],
          workingHoursOnly: nil, workingHoursStart: nil, workingHoursEnd: nil,
          exemptUsers: nil, exemptGroups: nil)),
      AppDLPPolicy(policyId: "APP-006", policyName: "Warn Email Attachment to External",
        appBundleId: "*", appCategory: "Email", enabled: true,
        eventTypes: ["EMAIL_ATTACHMENT","EMAIL_SEND"], action: "WARN", severity: "HIGH",
        conditions: PolicyConditions(maxFileSize: nil, blockedExtensions: nil, allowedExtensions: nil,
          blockedDomains: nil, allowedDomains: nil, externalRecipientsOnly: true,
          regexPatterns: nil, workingHoursOnly: nil, workingHoursStart: nil, workingHoursEnd: nil,
          exemptUsers: nil, exemptGroups: nil)),
      AppDLPPolicy(policyId: "APP-007", policyName: "Flag After-Hours Data Activity",
        appBundleId: "*", appCategory: nil, enabled: true,
        eventTypes: ["FILE_UPLOAD","CLOUD_SYNC","FILE_SEND","EXTERNAL_TRANSFER"],
        action: "LOG", severity: "MEDIUM",
        conditions: PolicyConditions(maxFileSize: nil, blockedExtensions: nil, allowedExtensions: nil,
          blockedDomains: nil, allowedDomains: nil, externalRecipientsOnly: nil,
          regexPatterns: nil, workingHoursOnly: true, workingHoursStart: "09:00", workingHoursEnd: "18:00",
          exemptUsers: nil, exemptGroups: nil)),
      AppDLPPolicy(policyId: "APP-008", policyName: "Warn Screenshot During Messaging",
        appBundleId: "*", appCategory: "Messaging", enabled: true,
        eventTypes: ["SCREEN_CAPTURE"], action: "WARN", severity: "MEDIUM", conditions: nil)
    ]
    NSLog("[NextGuard] Loaded \(policies.count) default app DLP policies")
  }

  public func getAllPolicies() -> [AppDLPPolicy] { return policies }
  public func addPolicy(_ p: AppDLPPolicy) { policies.append(p) }
  public func removePolicy(id: String) { policies.removeAll { $0.policyId == id } }
  public func updatePolicy(_ p: AppDLPPolicy) { removePolicy(id: p.policyId); addPolicy(p) }
}
