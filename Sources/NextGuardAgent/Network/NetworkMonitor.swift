//
//  NetworkMonitor.swift
//  NextGuard Endpoint DLP Agent
//
//  Copyright (c) 2026 NextGuard Technology Limited. All rights reserved.
//
//  Network traffic DLP inspection using NetworkExtension framework
//  Ref: ISO 27001:2022 A.8.20, NIST SP 800-171 3.13.1, Gartner 2025 SSE MQ
//

import Foundation
import NetworkExtension
import os.log

// MARK: - Network DLP Event
struct NetworkDLPEvent: Codable {
  let id: String
  let timestamp: Date
  let sourceApp: String
  let destinationHost: String
  let destinationPort: Int
  let protocolType: String        // HTTP, HTTPS, SMTP, FTP, etc.
  let direction: NetworkDirection
  let dataSize: Int
  let contentSnippet: String?     // first N bytes for inspection
  let matchedRules: [String]
  let action: DLPAction
  let tlsVersion: String?
}

enum NetworkDirection: String, Codable {
  case outbound, inbound
}

// MARK: - Network Monitor
final class NetworkMonitor: ObservableObject {
  static let shared = NetworkMonitor()
  private let logger = Logger(subsystem: "com.nextguard.agent", category: "NetworkMonitor")
  private let engine = DLPPolicyEngine.shared
  
  @Published var isActive: Bool = false
  @Published var totalInspected: Int = 0
  @Published var totalBlocked: Int = 0
  
  private var filterManager: NEFilterManager?
  private var dnsProxyManager: NEDNSProxyManager?
  private let inspectionQueue = DispatchQueue(label: "com.nextguard.network.inspection", qos: .userInitiated, attributes: .concurrent)
  
  // Monitored protocol ports
  private let monitoredPorts: Set<Int> = [80, 443, 25, 587, 993, 995, 21, 22, 445, 3389]
  
  // Blocked domains (from policy)
  private var blockedDomains: Set<String> = []
  private var allowedDomains: Set<String> = []
  
  // MARK: - Initialization
  private init() {
    loadDomainLists()
  }
  
  // MARK: - Start/Stop Monitoring
  func startMonitoring() {
    logger.info("Starting network DLP monitoring...")
    
    // Request NEFilterManager configuration
    NEFilterManager.shared().loadFromPreferences { [weak self] error in
      guard let self = self else { return }
      if let error = error {
        self.logger.error("Failed to load filter preferences: \(error.localizedDescription)")
        return
      }
      
      let config = NEFilterProviderConfiguration()
      config.filterBrowsers = true
      config.filterSockets = true
      config.filterPackets = false
      config.organization = "NextGuard Technology"
      config.filterDataProviderBundleIdentifier = "com.nextguard.agent.filter-data"
      
      NEFilterManager.shared().providerConfiguration = config
      NEFilterManager.shared().isEnabled = true
      
      NEFilterManager.shared().saveToPreferences { saveError in
        if let saveError = saveError {
          self.logger.error("Failed to save filter preferences: \(saveError.localizedDescription)")
        } else {
          self.logger.info("Network filter enabled successfully")
          DispatchQueue.main.async {
            self.isActive = true
          }
        }
      }
    }
    
    // Start DNS monitoring
    setupDNSMonitoring()
    
    // Start connection observer
    startConnectionObserver()
  }
  
  func stopMonitoring() {
    logger.info("Stopping network DLP monitoring")
    NEFilterManager.shared().isEnabled = false
    NEFilterManager.shared().saveToPreferences { _ in }
    DispatchQueue.main.async {
      self.isActive = false
    }
  }
  
  // MARK: - DNS Monitoring
  private func setupDNSMonitoring() {
    NEDNSProxyManager.shared().loadFromPreferences { [weak self] error in
      guard let self = self else { return }
      if let error = error {
        self.logger.error("DNS proxy load error: \(error.localizedDescription)")
        return
      }
      self.logger.info("DNS monitoring initialized")
    }
  }
  
  // MARK: - Connection Observer
  private func startConnectionObserver() {
    // Monitor NWPathMonitor for connectivity changes
    let monitor = NWPathMonitor()
    monitor.pathUpdateHandler = { [weak self] path in
      guard let self = self else { return }
      if path.status == .satisfied {
        self.logger.info("Network path: connected via \(path.availableInterfaces.map { $0.name })")
      } else {
        self.logger.warning("Network path: disconnected")
      }
    }
    monitor.start(queue: inspectionQueue)
  }
  
  // MARK: - Content Inspection
  func inspectOutboundData(_ data: Data, destination: String, port: Int, sourceApp: String) -> DLPAction {
    totalInspected += 1
    
    // Check domain allowlist/blocklist first
    if blockedDomains.contains(destination) {
      logNetworkEvent(destination: destination, port: port, sourceApp: sourceApp, dataSize: data.count, action: .block, matchedRules: ["domain-blocklist"])
      totalBlocked += 1
      return .block
    }
    
    if allowedDomains.contains(destination) {
      return .allow
    }
    
    // Extract text content for DLP inspection
    guard let textContent = extractTextFromData(data) else {
      return .allow
    }
    
    // Run through DLP policy engine
    let violations = engine.scanContent(textContent, channel: .network)
    
    if !violations.isEmpty {
      let highestSeverity = violations.map { $0.severity }.max() ?? .info
      let action = determineAction(for: highestSeverity)
      let ruleIds = violations.map { $0.ruleId }
      
      logNetworkEvent(destination: destination, port: port, sourceApp: sourceApp, dataSize: data.count, action: action, matchedRules: ruleIds)
      
      if action == .block {
        totalBlocked += 1
      }
      return action
    }
    
    return .allow
  }
  
  // MARK: - Email Inspection (SMTP/IMAP)
  func inspectEmailTraffic(_ data: Data, destination: String, port: Int) -> DLPAction {
    let emailPorts: Set<Int> = [25, 587, 993, 995, 465]
    guard emailPorts.contains(port) else { return .allow }
    
    logger.info("Inspecting email traffic to \(destination):\(port)")
    
    guard let content = String(data: data, encoding: .utf8) else { return .allow }
    
    // Parse email headers and body
    let violations = engine.scanContent(content, channel: .email)
    
    if !violations.isEmpty {
      let action = violations.contains(where: { $0.severity == .critical }) ? DLPAction.block : .audit
      return action
    }
    return .allow
  }
  
  // MARK: - Cloud Upload Detection
  func inspectCloudUpload(_ data: Data, url: URL, sourceApp: String) -> DLPAction {
    let cloudDomains = [
      "drive.google.com", "docs.google.com",
      "dropbox.com", "www.dropbox.com",
      "onedrive.live.com", "sharepoint.com",
      "box.com", "app.box.com",
      "icloud.com", "wetransfer.com",
      "mega.nz", "mediafire.com"
    ]
    
    guard let host = url.host,
          cloudDomains.contains(where: { host.hasSuffix($0) }) else {
      return .allow
    }
    
    logger.info("Cloud upload detected: \(host) from \(sourceApp)")
    
    // Check file content
    let violations = engine.scanContent(data, channel: .cloud)
    
    if !violations.isEmpty {
      return violations.contains(where: { $0.severity == .critical || $0.severity == .high }) ? .block : .audit
    }
    return .allow
  }
  
  // MARK: - Helpers
  private func extractTextFromData(_ data: Data) -> String? {
    // Try UTF-8 first
    if let text = String(data: data, encoding: .utf8) { return text }
    // Try ASCII
    if let text = String(data: data, encoding: .ascii) { return text }
    // Try to detect encoding
    if let text = String(data: data, encoding: .windowsCP1252) { return text }
    return nil
  }
  
  private func determineAction(for severity: DLPSeverity) -> DLPAction {
    switch severity {
    case .critical: return .block
    case .high:     return .block
    case .medium:   return .encrypt
    case .low:      return .audit
    case .info:     return .allow
    }
  }
  
  private func logNetworkEvent(destination: String, port: Int, sourceApp: String, dataSize: Int, action: DLPAction, matchedRules: [String]) {
    let event = NetworkDLPEvent(
      id: UUID().uuidString,
      timestamp: Date(),
      sourceApp: sourceApp,
      destinationHost: destination,
      destinationPort: port,
      protocolType: protocolForPort(port),
      direction: .outbound,
      dataSize: dataSize,
      contentSnippet: nil,
      matchedRules: matchedRules,
      action: action,
      tlsVersion: nil
    )
    
    // Send to management server
    AgentAPIClient.shared.reportNetworkEvent(event)
    logger.warning("Network DLP: \(action.rawValue) traffic to \(destination):\(port) rules=\(matchedRules)")
  }
  
  private func protocolForPort(_ port: Int) -> String {
    switch port {
    case 80:  return "HTTP"
    case 443: return "HTTPS"
    case 25, 587: return "SMTP"
    case 993: return "IMAPS"
    case 995: return "POP3S"
    case 21:  return "FTP"
    case 22:  return "SSH"
    case 445: return "SMB"
    case 3389: return "RDP"
    default:  return "TCP/\(port)"
    }
  }
  
  private func loadDomainLists() {
    // Load from policy config
    let configPath = "/Library/Application Support/NextGuard/domains.json"
    guard let data = FileManager.default.contents(atPath: configPath),
          let config = try? JSONDecoder().decode(DomainConfig.self, from: data) else {
      logger.info("No domain config found, using defaults")
      return
    }
    blockedDomains = Set(config.blocked)
    allowedDomains = Set(config.allowed)
  }
}

// MARK: - Domain Configuration
struct DomainConfig: Codable {
  let blocked: [String]
  let allowed: [String]
}

// MARK: - NWPathMonitor import
import Network

// MARK: - Agent API Client (Network Events)
extension AgentAPIClient {
  func reportNetworkEvent(_ event: NetworkDLPEvent) {
    guard let data = try? JSONEncoder().encode(event) else { return }
    let url = URL(string: "\(AgentConfig.shared.managementServerURL)/api/v1/events/network")!
    var request = URLRequest(url: url)
    request.httpMethod = "POST"
    request.httpBody = data
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.setValue("Bearer \(AgentConfig.shared.apiToken)", forHTTPHeaderField: "Authorization")
    URLSession.shared.dataTask(with: request).resume()
  }
}

// MARK: - AgentAPIClient Singleton
final class AgentAPIClient {
  static let shared = AgentAPIClient()
  private init() {}
}
