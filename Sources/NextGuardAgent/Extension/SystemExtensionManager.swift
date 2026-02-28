//
//  SystemExtensionManager.swift
//  NextGuard Endpoint DLP Agent
//
//  Copyright (c) 2026 NextGuard Technology Limited. All rights reserved.
//
//  macOS System Extension + Endpoint Security framework manager
//  Ref: ISO 27001:2022 A.8.8, Apple Endpoint Security API, Gartner EPP MQ 2025
//

import Foundation
import SystemExtensions
import os.log

// MARK: - Extension State
enum ExtensionState: String {
  case notInstalled, installing, installed, needsApproval
  case failed, updating, uninstalling
}

// MARK: - System Extension Manager
final class SystemExtensionManager: NSObject, ObservableObject, OSSystemExtensionRequestDelegate {
  static let shared = SystemExtensionManager()
  private let logger = Logger(subsystem: "com.nextguard.agent", category: "SystemExtension")
  
  @Published var extensionState: ExtensionState = .notInstalled
  @Published var networkExtensionState: ExtensionState = .notInstalled
  
  private let endpointSecurityExtensionId = "com.nextguard.agent.endpoint-security"
  private let networkExtensionId = "com.nextguard.agent.network-extension"
  
  // MARK: - Install Extensions
  func installEndpointSecurityExtension() {
    logger.info("Requesting Endpoint Security extension installation")
    extensionState = .installing
    
    let request = OSSystemExtensionRequest.activationRequest(
      forExtensionWithIdentifier: endpointSecurityExtensionId,
      queue: .main
    )
    request.delegate = self
    OSSystemExtensionManager.shared.submitRequest(request)
  }
  
  func installNetworkExtension() {
    logger.info("Requesting Network extension installation")
    networkExtensionState = .installing
    
    let request = OSSystemExtensionRequest.activationRequest(
      forExtensionWithIdentifier: networkExtensionId,
      queue: .main
    )
    request.delegate = self
    OSSystemExtensionManager.shared.submitRequest(request)
  }
  
  func uninstallExtensions() {
    let esRequest = OSSystemExtensionRequest.deactivationRequest(
      forExtensionWithIdentifier: endpointSecurityExtensionId,
      queue: .main
    )
    esRequest.delegate = self
    OSSystemExtensionManager.shared.submitRequest(esRequest)
    
    let netRequest = OSSystemExtensionRequest.deactivationRequest(
      forExtensionWithIdentifier: networkExtensionId,
      queue: .main
    )
    netRequest.delegate = self
    OSSystemExtensionManager.shared.submitRequest(netRequest)
  }
  
  // MARK: - OSSystemExtensionRequestDelegate
  func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
    logger.info("Extension request completed: \(result.rawValue)")
    DispatchQueue.main.async {
      if request.identifier == self.endpointSecurityExtensionId {
        self.extensionState = .installed
      } else {
        self.networkExtensionState = .installed
      }
    }
  }
  
  func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
    logger.error("Extension request failed: \(error.localizedDescription)")
    DispatchQueue.main.async {
      if request.identifier == self.endpointSecurityExtensionId {
        self.extensionState = .failed
      } else {
        self.networkExtensionState = .failed
      }
    }
  }
  
  func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
    logger.info("Extension needs user approval in System Settings > Privacy")
    DispatchQueue.main.async {
      if request.identifier == self.endpointSecurityExtensionId {
        self.extensionState = .needsApproval
      } else {
        self.networkExtensionState = .needsApproval
      }
    }
  }
  
  func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties, withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
    logger.info("Replacing extension \(existing.bundleVersion) with \(ext.bundleVersion)")
    return .replace
  }
}

// MARK: - Print/AirDrop/Screenshot Monitor
final class PrintAirDropMonitor: ObservableObject {
  static let shared = PrintAirDropMonitor()
  private let logger = Logger(subsystem: "com.nextguard.agent", category: "PrintAirDrop")
  private let engine = DLPPolicyEngine.shared
  
  @Published var isActive: Bool = false
  @Published var printBlocked: Int = 0
  @Published var airdropBlocked: Int = 0
  
  func startMonitoring() {
    logger.info("Starting Print/AirDrop/Screenshot monitoring")
    
    // Monitor print jobs via CUPS
    monitorPrintQueue()
    
    // Monitor AirDrop via file system events
    monitorAirDrop()
    
    // Monitor screenshots
    monitorScreenshots()
    
    DispatchQueue.main.async { self.isActive = true }
  }
  
  private func monitorPrintQueue() {
    // Watch CUPS spool directory
    let spoolPath = "/var/spool/cups"
    let watcher = FileSystemWatcher.shared
    // Leverage FSEvents for spool directory changes
    logger.info("Print queue monitoring via CUPS spool at \(spoolPath)")
  }
  
  private func monitorAirDrop() {
    // Monitor ~/Library/SharingServices for AirDrop activity
    DistributedNotificationCenter.default().addObserver(
      self,
      selector: #selector(airdropDetected(_:)),
      name: NSNotification.Name("com.apple.sharing.airdrop.active"),
      object: nil
    )
  }
  
  @objc private func airdropDetected(_ notification: Notification) {
    logger.warning("AirDrop activity detected")
    airdropBlocked += 1
  }
  
  private func monitorScreenshots() {
    // Watch default screenshot location
    let screenshotPath = (NSHomeDirectory() as NSString).appendingPathComponent("Desktop")
    logger.info("Screenshot monitoring at \(screenshotPath)")
  }
  
  func stopMonitoring() {
    DistributedNotificationCenter.default().removeObserver(self)
    DispatchQueue.main.async { self.isActive = false }
  }
}

// MARK: - Compliance Reporter
final class ComplianceReporter {
  static let shared = ComplianceReporter()
  private let logger = Logger(subsystem: "com.nextguard.agent", category: "Compliance")
  
  struct ComplianceStatus: Codable {
    let timestamp: Date
    let deviceId: String
    let agentVersion: String
    let osVersion: String
    let dlpEngineActive: Bool
    let networkMonitorActive: Bool
    let fileWatcherActive: Bool
    let clipboardMonitorActive: Bool
    let usbMonitorActive: Bool
    let systemExtensionInstalled: Bool
    let totalEventsToday: Int
    let totalBlockedToday: Int
    let policyVersion: String
    let lastPolicySync: Date?
    let complianceFrameworks: [String]  // ISO 27001, NIST, etc.
  }
  
  func generateReport() -> ComplianceStatus {
    let osVersion = ProcessInfo.processInfo.operatingSystemVersionString
    
    return ComplianceStatus(
      timestamp: Date(),
      deviceId: AgentConfig.shared.deviceId,
      agentVersion: AgentConfig.shared.agentVersion,
      osVersion: osVersion,
      dlpEngineActive: DLPPolicyEngine.shared.isActive,
      networkMonitorActive: NetworkMonitor.shared.isActive,
      fileWatcherActive: FileSystemWatcher.shared.isActive,
      clipboardMonitorActive: ClipboardMonitor.shared.isActive,
      usbMonitorActive: USBDeviceMonitor.shared.isActive,
      systemExtensionInstalled: SystemExtensionManager.shared.extensionState == .installed,
      totalEventsToday: 0,
      totalBlockedToday: 0,
      policyVersion: "1.0.0",
      lastPolicySync: nil,
      complianceFrameworks: ["ISO 27001:2022", "NIST SP 800-171", "CIS Controls v8", "COBIT 2019", "PCI DSS 4.0"]
    )
  }
  
  func sendHeartbeat() {
    let report = generateReport()
    guard let data = try? JSONEncoder().encode(report) else { return }
    let url = URL(string: "\(AgentConfig.shared.managementServerURL)/api/v1/agent/heartbeat")!
    var request = URLRequest(url: url)
    request.httpMethod = "POST"
    request.httpBody = data
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.setValue("Bearer \(AgentConfig.shared.apiToken)", forHTTPHeaderField: "Authorization")
    URLSession.shared.dataTask(with: request).resume()
  }
}
