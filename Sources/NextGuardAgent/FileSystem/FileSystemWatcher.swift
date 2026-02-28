//
//  FileSystemWatcher.swift
//  NextGuard Endpoint DLP Agent
//
//  Copyright (c) 2026 NextGuard Technology Limited. All rights reserved.
//
//  Real-time file system monitoring using FSEvents + Endpoint Security
//  Ref: ISO 27001:2022 A.8.10, NIST SP 800-171 3.8.1, CIS Controls v8 3.4
//

import Foundation
import os.log

// MARK: - File Event Types
enum FileEventType: String, Codable {
  case created, modified, deleted, renamed, moved
  case copied, attributeChanged, opened, closed
}

// MARK: - File DLP Event
struct FileDLPEvent: Codable {
  let id: String
  let timestamp: Date
  let eventType: FileEventType
  let filePath: String
  let fileName: String
  let fileExtension: String
  let fileSize: Int64
  let processName: String
  let processId: Int32
  let userId: UInt32
  let matchedRules: [String]
  let action: DLPAction
  let hash: String?  // SHA-256 fingerprint
}

// MARK: - Sensitive File Classification
enum FileClassification: String, Codable {
  case topSecret, confidential, restricted, internal_, public_
  case pii, phi, pci, intellectualProperty, sourceCode
  case financial, legal, hrPersonnel, unknown
}

// MARK: - File System Watcher
final class FileSystemWatcher: ObservableObject {
  static let shared = FileSystemWatcher()
  private let logger = Logger(subsystem: "com.nextguard.agent", category: "FileSystemWatcher")
  private let engine = DLPPolicyEngine.shared
  
  @Published var isActive: Bool = false
  @Published var totalScanned: Int = 0
  @Published var totalBlocked: Int = 0
  
  private var eventStream: FSEventStreamRef?
  private let watchQueue = DispatchQueue(label: "com.nextguard.filesystem.watch", qos: .utility)
  private let scanQueue = DispatchQueue(label: "com.nextguard.filesystem.scan", qos: .userInitiated, attributes: .concurrent)
  
  // Monitored paths
  private var monitoredPaths: [String] = [
    NSHomeDirectory(),
    "/tmp",
    "/var/tmp",
    "/Users/Shared"
  ]
  
  // Sensitive file extensions
  private let sensitiveExtensions: Set<String> = [
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "csv", "tsv", "json", "xml", "yaml", "yml",
    "txt", "rtf", "md", "log",
    "zip", "rar", "7z", "tar", "gz",
    "sql", "db", "sqlite", "mdb",
    "pem", "key", "crt", "cer", "p12", "pfx",
    "swift", "py", "js", "ts", "java", "cpp", "h", "go", "rs",
    "env", "cfg", "conf", "ini",
    "jpg", "jpeg", "png", "heic", "tiff"
  ]
  
  // Max file size to scan (50MB)
  private let maxScanSize: Int64 = 50 * 1024 * 1024
  
  private init() {}
  
  // MARK: - Start / Stop
  func startWatching() {
    guard !isActive else { return }
    logger.info("Starting file system DLP watcher")
    
    let pathsToWatch = monitoredPaths as CFArray
    
    var context = FSEventStreamContext(
      version: 0, info: Unmanaged.passUnretained(self).toOpaque(),
      retain: nil, release: nil, copyDescription: nil
    )
    
    let flags: FSEventStreamCreateFlags = UInt32(
      kFSEventStreamCreateFlagUseCFTypes |
      kFSEventStreamCreateFlagFileEvents |
      kFSEventStreamCreateFlagNoDefer
    )
    
    eventStream = FSEventStreamCreate(
      nil,
      fsEventCallback,
      &context,
      pathsToWatch,
      FSEventStreamEventId(kFSEventStreamEventIdSinceNow),
      0.5,  // 500ms latency
      flags
    )
    
    if let stream = eventStream {
      FSEventStreamSetDispatchQueue(stream, watchQueue)
      FSEventStreamStart(stream)
      DispatchQueue.main.async { self.isActive = true }
      logger.info("FSEvent stream started for \(self.monitoredPaths.count) paths")
    }
  }
  
  func stopWatching() {
    guard let stream = eventStream else { return }
    FSEventStreamStop(stream)
    FSEventStreamInvalidate(stream)
    FSEventStreamRelease(stream)
    eventStream = nil
    DispatchQueue.main.async { self.isActive = false }
    logger.info("File system watcher stopped")
  }
  
  // MARK: - FSEvents Callback
  private let fsEventCallback: FSEventStreamCallback = { _, info, numEvents, eventPaths, eventFlags, eventIds in
    guard let info = info else { return }
    let watcher = Unmanaged<FileSystemWatcher>.fromOpaque(info).takeUnretainedValue()
    guard let paths = unsafeBitCast(eventPaths, to: NSArray.self) as? [String] else { return }
    
    for i in 0..<numEvents {
      let path = paths[i]
      let flags = eventFlags[i]
      watcher.handleFileEvent(path: path, flags: flags)
    }
  }
  
  // MARK: - Handle File Event
  func handleFileEvent(path: String, flags: UInt32) {
    let url = URL(fileURLWithPath: path)
    let ext = url.pathExtension.lowercased()
    
    // Skip non-sensitive extensions for performance
    guard sensitiveExtensions.contains(ext) || ext.isEmpty else { return }
    
    // Skip system/hidden files
    let fileName = url.lastPathComponent
    if fileName.hasPrefix(".") || path.contains("/.Trash/") { return }
    if path.contains("/Library/Caches/") || path.contains("/.git/") { return }
    
    // Determine event type
    let eventType = classifyEvent(flags: flags)
    
    scanQueue.async { [weak self] in
      self?.scanFile(at: path, eventType: eventType)
    }
  }
  
  // MARK: - File Scanning
  func scanFile(at path: String, eventType: FileEventType) {
    totalScanned += 1
    let url = URL(fileURLWithPath: path)
    
    // Get file attributes
    guard let attrs = try? FileManager.default.attributesOfItem(atPath: path) else { return }
    let fileSize = (attrs[.size] as? Int64) ?? 0
    
    // Skip files too large
    guard fileSize <= maxScanSize && fileSize > 0 else { return }
    
    // Read file content
    guard let data = FileManager.default.contents(atPath: path) else { return }
    
    // Calculate SHA-256 hash for fingerprinting
    let hash = computeSHA256(data: data)
    
    // Run DLP scan
    let violations = engine.scanContent(data, channel: .file)
    
    if !violations.isEmpty {
      let highestSeverity = violations.map { $0.severity }.max() ?? .info
      let action = actionForSeverity(highestSeverity)
      let ruleIds = violations.map { $0.ruleId }
      
      let event = FileDLPEvent(
        id: UUID().uuidString,
        timestamp: Date(),
        eventType: eventType,
        filePath: path,
        fileName: url.lastPathComponent,
        fileExtension: url.pathExtension,
        fileSize: fileSize,
        processName: ProcessInfo.processInfo.processName,
        processId: ProcessInfo.processInfo.processIdentifier,
        userId: getuid(),
        matchedRules: ruleIds,
        action: action,
        hash: hash
      )
      
      // Report to server
      AgentAPIClient.shared.reportFileEvent(event)
      
      if action == .block {
        totalBlocked += 1
        blockFileAccess(at: path)
      } else if action == .quarantine {
        quarantineFile(at: path)
      }
      
      logger.warning("File DLP: \(action.rawValue) \(url.lastPathComponent) rules=\(ruleIds)")
    }
  }
  
  // MARK: - File Classification (AI-assisted)
  func classifyFile(at path: String) -> FileClassification {
    let url = URL(fileURLWithPath: path)
    let ext = url.pathExtension.lowercased()
    let name = url.lastPathComponent.lowercased()
    
    // Extension-based classification
    if ["pem", "key", "crt", "cer", "p12", "pfx", "env"].contains(ext) {
      return .confidential
    }
    if ["sql", "db", "sqlite", "mdb"].contains(ext) {
      return .restricted
    }
    
    // Name-based classification
    if name.contains("confidential") || name.contains("secret") { return .confidential }
    if name.contains("salary") || name.contains("payroll") || name.contains("hr") { return .hrPersonnel }
    if name.contains("financial") || name.contains("budget") || name.contains("revenue") { return .financial }
    if name.contains("legal") || name.contains("contract") || name.contains("nda") { return .legal }
    if name.contains("patient") || name.contains("medical") || name.contains("health") { return .phi }
    
    return .unknown
  }
  
  // MARK: - Block / Quarantine Actions
  private func blockFileAccess(at path: String) {
    // Set immutable flag to prevent access
    let attrs: [FileAttributeKey: Any] = [.immutable: true]
    try? FileManager.default.setAttributes(attrs, ofItemAtPath: path)
    logger.warning("Blocked file access: \(path)")
  }
  
  private func quarantineFile(at path: String) {
    let quarantineDir = "/Library/Application Support/NextGuard/Quarantine"
    try? FileManager.default.createDirectory(atPath: quarantineDir, withIntermediateDirectories: true)
    let dest = (quarantineDir as NSString).appendingPathComponent(UUID().uuidString + "_" + (path as NSString).lastPathComponent)
    try? FileManager.default.moveItem(atPath: path, toPath: dest)
    logger.warning("Quarantined file: \(path) -> \(dest)")
  }
  
  // MARK: - SHA-256 Hash
  private func computeSHA256(data: Data) -> String {
    var hash = [UInt8](repeating: 0, count: 32)
    data.withUnsafeBytes { buffer in
      _ = CC_SHA256(buffer.baseAddress, CC_LONG(data.count), &hash)
    }
    return hash.map { String(format: "%02x", $0) }.joined()
  }
  
  // MARK: - Helpers
  private func classifyEvent(flags: UInt32) -> FileEventType {
    if flags & UInt32(kFSEventStreamEventFlagItemCreated) != 0 { return .created }
    if flags & UInt32(kFSEventStreamEventFlagItemRemoved) != 0 { return .deleted }
    if flags & UInt32(kFSEventStreamEventFlagItemRenamed) != 0 { return .renamed }
    if flags & UInt32(kFSEventStreamEventFlagItemModified) != 0 { return .modified }
    if flags & UInt32(kFSEventStreamEventFlagItemInodeMetaMod) != 0 { return .attributeChanged }
    return .modified
  }
  
  private func actionForSeverity(_ severity: DLPSeverity) -> DLPAction {
    switch severity {
    case .critical: return .block
    case .high:     return .quarantine
    case .medium:   return .encrypt
    case .low:      return .audit
    case .info:     return .allow
    }
  }
}

// MARK: - CommonCrypto Import
import CommonCrypto

// MARK: - API Client Extension
extension AgentAPIClient {
  func reportFileEvent(_ event: FileDLPEvent) {
    guard let data = try? JSONEncoder().encode(event) else { return }
    let url = URL(string: "\(AgentConfig.shared.managementServerURL)/api/v1/events/file")!
    var request = URLRequest(url: url)
    request.httpMethod = "POST"
    request.httpBody = data
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.setValue("Bearer \(AgentConfig.shared.apiToken)", forHTTPHeaderField: "Authorization")
    URLSession.shared.dataTask(with: request).resume()
  }
}
