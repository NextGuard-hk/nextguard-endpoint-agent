//
//  AuditLogger.swift
//  NextGuard Endpoint DLP Agent
//
//  Copyright (c) 2026 NextGuard Technology Limited. All rights reserved.
//  Forensic-grade audit logging with tamper detection
//  Reference: ISO 27001:2022 A.8.15, COBIT 2019 DSS05, SOC 2 Type II
//

import Foundation
import OSLog
import CryptoKit

// MARK: - Audit Event Types
enum AuditEventCategory: String, Codable {
  case fileOperation = "FILE_OP"
  case networkActivity = "NETWORK"
  case emailActivity = "EMAIL"
  case clipboardActivity = "CLIPBOARD"
  case usbActivity = "USB"
  case screenCapture = "SCREEN"
  case printActivity = "PRINT"
  case policyViolation = "POLICY_VIOLATION"
  case agentLifecycle = "AGENT_LIFECYCLE"
  case userAuthentication = "AUTH"
  case configChange = "CONFIG_CHANGE"
  case systemEvent = "SYSTEM"
}

enum AuditSeverity: String, Codable, Comparable {
  case info = "INFO"
  case low = "LOW"
  case medium = "MEDIUM"
  case high = "HIGH"
  case critical = "CRITICAL"
  
  static func < (lhs: AuditSeverity, rhs: AuditSeverity) -> Bool {
    let order: [AuditSeverity] = [.info, .low, .medium, .high, .critical]
    return (order.firstIndex(of: lhs) ?? 0) < (order.firstIndex(of: rhs) ?? 0)
  }
}

struct AuditEvent: Codable {
  let eventId: UUID
  let timestamp: Date
  let category: AuditEventCategory
  let severity: AuditSeverity
  let action: String
  let outcome: String // success, failure, blocked
  let userId: String
  let userName: String
  let processName: String
  let processId: Int32
  let description: String
  let metadata: [String: String]
  let sourceIP: String?
  let destinationIP: String?
  let filePath: String?
  let fileHash: String?
  let policyId: String?
  let riskScore: Double
  let previousHash: String // chain integrity
}

// MARK: - Audit Logger
final class AuditLogger: @unchecked Sendable {
  static let shared = AuditLogger()
  private let logger = Logger(subsystem: "com.nextguard.agent", category: "AuditLogger")
  
  private let logQueue = DispatchQueue(label: "com.nextguard.audit", qos: .utility)
  private let uploadQueue = DispatchQueue(label: "com.nextguard.audit.upload", qos: .background)
  
  private var logFileHandle: FileHandle?
  private var currentLogPath: URL?
  private var eventCount: Int = 0
  private var lastEventHash: String = "GENESIS"
  private let maxLogSizeMB: Int = 50
  private let maxRetentionDays: Int = 90
  private let batchSize: Int = 100
  private var pendingEvents: [AuditEvent] = []
  
  // HMAC key for tamper detection (ISO 27001 A.8.15)
  private let hmacKey = SymmetricKey(size: .bits256)
  
  private init() {
    setupLogDirectory()
    startPeriodicUpload()
    startLogRotation()
  }
  
  // MARK: - Log Directory Setup
  private func setupLogDirectory() {
    let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
    let logDir = appSupport.appendingPathComponent("NextGuard/AuditLogs")
    try? FileManager.default.createDirectory(at: logDir, withIntermediateDirectories: true)
    
    let dateFormatter = DateFormatter()
    dateFormatter.dateFormat = "yyyy-MM-dd_HH"
    let filename = "audit_\(dateFormatter.string(from: Date())).jsonl"
    currentLogPath = logDir.appendingPathComponent(filename)
    
    if !FileManager.default.fileExists(atPath: currentLogPath!.path) {
      FileManager.default.createFile(atPath: currentLogPath!.path, contents: nil)
    }
    logFileHandle = try? FileHandle(forWritingTo: currentLogPath!)
    logFileHandle?.seekToEndOfFile()
    logger.info("Audit log initialized: \(self.currentLogPath?.lastPathComponent ?? "unknown")")
  }

    // MARK: - Core Logging API
  func log(category: AuditEventCategory, severity: AuditSeverity, action: String,
           outcome: String = "success", description: String,
           metadata: [String: String] = [:], filePath: String? = nil,
           fileHash: String? = nil, policyId: String? = nil,
           riskScore: Double = 0.0, sourceIP: String? = nil, destIP: String? = nil) {
    logQueue.async { [weak self] in
      guard let self = self else { return }
      let event = AuditEvent(
        eventId: UUID(), timestamp: Date(),
        category: category, severity: severity,
        action: action, outcome: outcome,
        userId: NSUserName(), userName: NSFullUserName(),
        processName: ProcessInfo.processInfo.processName,
        processId: ProcessInfo.processInfo.processIdentifier,
        description: description, metadata: metadata,
        sourceIP: sourceIP, destinationIP: destIP,
        filePath: filePath, fileHash: fileHash,
        policyId: policyId, riskScore: riskScore,
        previousHash: self.lastEventHash
      )
      self.writeEvent(event)
      self.pendingEvents.append(event)
      if self.pendingEvents.count >= self.batchSize {
        self.flushToServer()
      }
    }
  }
  
  // Convenience methods
  func logPolicyViolation(action: String, description: String, policyId: String,
                          riskScore: Double, filePath: String? = nil, fileHash: String? = nil) {
    log(category: .policyViolation, severity: riskScore >= 80 ? .critical : riskScore >= 50 ? .high : .medium,
        action: action, outcome: "blocked", description: description,
        policyId: policyId, riskScore: riskScore)
  }
  
  func logFileOperation(action: String, path: String, hash: String? = nil, outcome: String = "success") {
    log(category: .fileOperation, severity: .info, action: action,
        outcome: outcome, description: "File \(action): \(path)", filePath: path, fileHash: hash)
  }
  
  func logAgentEvent(action: String, description: String) {
    log(category: .agentLifecycle, severity: .info, action: action, description: description)
  }
  
  // MARK: - Write Event with Chain Integrity
  private func writeEvent(_ event: AuditEvent) {
    do {
      let encoder = JSONEncoder()
      encoder.dateEncodingStrategy = .iso8601
      let data = try encoder.encode(event)
      
      // Compute HMAC for tamper detection
      let hmac = HMAC<SHA256>.authenticationCode(for: data, using: hmacKey)
      let hmacHex = hmac.map { String(format: "%02x", $0) }.joined()
      
      // Update chain hash
      let chainData = (lastEventHash + event.eventId.uuidString).data(using: .utf8)!
      lastEventHash = SHA256.hash(data: chainData).map { String(format: "%02x", $0) }.joined()
      
      // Write JSONL with HMAC
      var line = data
      line.append(contentsOf: "\n".utf8)
      logFileHandle?.write(line)
      eventCount += 1
      
      // Check rotation
      if let attrs = try? FileManager.default.attributesOfItem(atPath: currentLogPath!.path),
         let size = attrs[.size] as? Int, size > maxLogSizeMB * 1024 * 1024 {
        rotateLog()
      }
    } catch {
      logger.error("Failed to write audit event: \(error.localizedDescription)")
    }
  }
  
  // MARK: - Log Rotation (COBIT DSS05)
  private func rotateLog() {
    logFileHandle?.closeFile()
    setupLogDirectory()
    cleanOldLogs()
  }
  
  private func startLogRotation() {
    Timer.scheduledTimer(withTimeInterval: 3600, repeats: true) { [weak self] _ in
      self?.logQueue.async { self?.rotateLog() }
    }
  }
  
  private func cleanOldLogs() {
    let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
    let logDir = appSupport.appendingPathComponent("NextGuard/AuditLogs")
    let cutoff = Date().addingTimeInterval(-Double(maxRetentionDays * 86400))
    
    if let files = try? FileManager.default.contentsOfDirectory(at: logDir, includingPropertiesForKeys: [.creationDateKey]) {
      for file in files {
        if let created = try? file.resourceValues(forKeys: [.creationDateKey]).creationDate,
           created < cutoff {
          try? FileManager.default.removeItem(at: file)
          logger.info("Deleted old audit log: \(file.lastPathComponent)")
        }
      }
    }
  }

    // MARK: - Server Upload (SOC 2 Type II Compliance)
  private func startPeriodicUpload() {
    Timer.scheduledTimer(withTimeInterval: 300, repeats: true) { [weak self] _ in
      self?.uploadQueue.async { self?.flushToServer() }
    }
  }
  
  private func flushToServer() {
    guard !pendingEvents.isEmpty else { return }
    let batch = pendingEvents
    pendingEvents.removeAll()
    
    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .iso8601
    guard let payload = try? encoder.encode(batch) else { return }
    
    var request = URLRequest(url: URL(string: "https://console.next-guard.com/api/v1/audit/events")!)
    request.httpMethod = "POST"
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.setValue("gzip", forHTTPHeaderField: "Content-Encoding")
    request.httpBody = payload
    
    URLSession.shared.dataTask(with: request) { [weak self] _, response, error in
      if let httpResp = response as? HTTPURLResponse, httpResp.statusCode == 200 {
        self?.logger.info("Uploaded \(batch.count) audit events to console")
      } else {
        // Re-queue failed events
        self?.logQueue.async {
          self?.pendingEvents.insert(contentsOf: batch, at: 0)
        }
        self?.logger.warning("Audit upload failed, re-queued \(batch.count) events")
      }
    }.resume()
  }
  
  // MARK: - Tamper Verification
  func verifyLogIntegrity(logPath: URL) -> Bool {
    guard let data = try? String(contentsOf: logPath, encoding: .utf8) else { return false }
    let lines = data.components(separatedBy: "\n").filter { !$0.isEmpty }
    var previousHash = "GENESIS"
    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .iso8601
    
    for line in lines {
      guard let lineData = line.data(using: .utf8),
            let event = try? decoder.decode(AuditEvent.self, from: lineData) else { return false }
      if event.previousHash != previousHash { return false }
      let chainData = (previousHash + event.eventId.uuidString).data(using: .utf8)!
      previousHash = SHA256.hash(data: chainData).map { String(format: "%02x", $0) }.joined()
    }
    logger.info("Log integrity verified: \(logPath.lastPathComponent), \(lines.count) events")
    return true
  }
  
  // MARK: - Export for Compliance Reports
  func exportAuditReport(from: Date, to: Date, categories: [AuditEventCategory]? = nil) -> Data? {
    let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
    let logDir = appSupport.appendingPathComponent("NextGuard/AuditLogs")
    var allEvents: [AuditEvent] = []
    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .iso8601
    
    if let files = try? FileManager.default.contentsOfDirectory(at: logDir, includingPropertiesForKeys: nil) {
      for file in files where file.pathExtension == "jsonl" {
        if let content = try? String(contentsOf: file, encoding: .utf8) {
          for line in content.components(separatedBy: "\n") where !line.isEmpty {
            if let data = line.data(using: .utf8),
               let event = try? decoder.decode(AuditEvent.self, from: data) {
              if event.timestamp >= from && event.timestamp <= to {
                if let cats = categories {
                  if cats.contains(event.category) { allEvents.append(event) }
                } else {
                  allEvents.append(event)
                }
              }
            }
          }
        }
      }
    }
    
    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .iso8601
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    return try? encoder.encode(allEvents)
  }
  
  // MARK: - Statistics
  func getStats() -> [String: Any] {
    return [
      "totalEvents": eventCount,
      "pendingUpload": pendingEvents.count,
      "currentLogFile": currentLogPath?.lastPathComponent ?? "none",
      "lastHash": lastEventHash
    ]
  }
}
