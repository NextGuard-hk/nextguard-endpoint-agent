//
//  ClipboardMonitor.swift
//  NextGuard Endpoint DLP Agent
//
//  Copyright (c) 2026 NextGuard Technology Limited. All rights reserved.
//
//  Clipboard DLP monitoring - prevents sensitive data copy/paste exfiltration
//  Ref: ISO 27001:2022 A.8.12, NIST SP 800-171 3.1.3, Gartner Endpoint DLP MQ 2025
//

import Foundation
import AppKit
import os.log

// MARK: - Clipboard DLP Event
struct ClipboardDLPEvent: Codable {
  let id: String
  let timestamp: Date
  let sourceApp: String
  let destinationApp: String?
  let contentType: ClipboardContentType
  let contentLength: Int
  let matchedRules: [String]
  let action: DLPAction
  let snippet: String?  // redacted snippet for audit
}

enum ClipboardContentType: String, Codable {
  case plainText, richText, html, image, fileURL, pdf, other
}

// MARK: - Clipboard Monitor
final class ClipboardMonitor: ObservableObject {
  static let shared = ClipboardMonitor()
  private let logger = Logger(subsystem: "com.nextguard.agent", category: "ClipboardMonitor")
  private let engine = DLPPolicyEngine.shared
  
  @Published var isActive: Bool = false
  @Published var totalInspected: Int = 0
  @Published var totalBlocked: Int = 0
  
  private var pollTimer: Timer?
  private var lastChangeCount: Int = 0
  private let inspectionQueue = DispatchQueue(label: "com.nextguard.clipboard", qos: .userInteractive)
  
  // Configurable settings
  private var pollInterval: TimeInterval = 0.5  // 500ms polling
  private var maxContentLength: Int = 5 * 1024 * 1024  // 5MB max
  private var enableScreenshotDetection: Bool = true
  
  private init() {}
  
  // MARK: - Start / Stop
  func startMonitoring() {
    guard !isActive else { return }
    logger.info("Starting clipboard DLP monitoring")
    lastChangeCount = NSPasteboard.general.changeCount
    
    pollTimer = Timer.scheduledTimer(withTimeInterval: pollInterval, repeats: true) { [weak self] _ in
      self?.checkClipboard()
    }
    RunLoop.current.add(pollTimer!, forMode: .common)
    
    DispatchQueue.main.async { self.isActive = true }
  }
  
  func stopMonitoring() {
    pollTimer?.invalidate()
    pollTimer = nil
    DispatchQueue.main.async { self.isActive = false }
    logger.info("Clipboard monitoring stopped")
  }
  
  // MARK: - Clipboard Check
  private func checkClipboard() {
    let pasteboard = NSPasteboard.general
    let currentCount = pasteboard.changeCount
    
    guard currentCount != lastChangeCount else { return }
    lastChangeCount = currentCount
    
    inspectionQueue.async { [weak self] in
      self?.inspectClipboardContent(pasteboard)
    }
  }
  
  // MARK: - Content Inspection
  private func inspectClipboardContent(_ pasteboard: NSPasteboard) {
    totalInspected += 1
    
    let sourceApp = NSWorkspace.shared.frontmostApplication?.localizedName ?? "Unknown"
    
    // Check for text content
    if let text = pasteboard.string(forType: .string), !text.isEmpty {
      inspectTextContent(text, sourceApp: sourceApp, contentType: .plainText)
      return
    }
    
    // Check for rich text
    if let rtfData = pasteboard.data(forType: .rtf) {
      if let attrString = NSAttributedString(rtf: rtfData, documentAttributes: nil) {
        inspectTextContent(attrString.string, sourceApp: sourceApp, contentType: .richText)
      }
      return
    }
    
    // Check for HTML
    if let html = pasteboard.string(forType: .html) {
      inspectTextContent(html, sourceApp: sourceApp, contentType: .html)
      return
    }
    
    // Check for file URLs (drag & drop exfiltration)
    if let urls = pasteboard.readObjects(forClasses: [NSURL.self]) as? [URL] {
      for url in urls where url.isFileURL {
        inspectFileURL(url, sourceApp: sourceApp)
      }
      return
    }
    
    // Check for images (screenshot detection)
    if enableScreenshotDetection {
      if let _ = pasteboard.data(forType: .tiff) ?? pasteboard.data(forType: .png) {
        handleScreenshotDetection(sourceApp: sourceApp)
      }
    }
  }
  
  // MARK: - Text Inspection
  private func inspectTextContent(_ text: String, sourceApp: String, contentType: ClipboardContentType) {
    guard text.count <= maxContentLength else {
      logger.warning("Clipboard content too large: \(text.count) chars")
      return
    }
    
    let violations = engine.scanContent(text, channel: .clipboard)
    
    if !violations.isEmpty {
      let highestSeverity = violations.map { $0.severity }.max() ?? .info
      let action = actionForSeverity(highestSeverity)
      let ruleIds = violations.map { $0.ruleId }
      
      // Create redacted snippet for audit log
      let snippet = createRedactedSnippet(from: text, maxLength: 100)
      
      let event = ClipboardDLPEvent(
        id: UUID().uuidString,
        timestamp: Date(),
        sourceApp: sourceApp,
        destinationApp: nil,
        contentType: contentType,
        contentLength: text.count,
        matchedRules: ruleIds,
        action: action,
        snippet: snippet
      )
      
      AgentAPIClient.shared.reportClipboardEvent(event)
      
      if action == .block {
        clearClipboard()
        totalBlocked += 1
        showBlockNotification(ruleIds: ruleIds, sourceApp: sourceApp)
      }
      
      logger.warning("Clipboard DLP: \(action.rawValue) from \(sourceApp) rules=\(ruleIds)")
    }
  }
  
  // MARK: - File URL Inspection
  private func inspectFileURL(_ url: URL, sourceApp: String) {
    guard let data = try? Data(contentsOf: url) else { return }
    
    let violations = engine.scanContent(data, channel: .clipboard)
    
    if !violations.isEmpty {
      let action: DLPAction = violations.contains(where: { $0.severity == .critical }) ? .block : .audit
      if action == .block {
        clearClipboard()
        totalBlocked += 1
      }
      logger.warning("Clipboard file DLP: \(action.rawValue) \(url.lastPathComponent)")
    }
  }
  
  // MARK: - Screenshot Detection
  private func handleScreenshotDetection(sourceApp: String) {
    logger.info("Screenshot detected in clipboard from \(sourceApp)")
    
    let event = ClipboardDLPEvent(
      id: UUID().uuidString,
      timestamp: Date(),
      sourceApp: sourceApp,
      destinationApp: nil,
      contentType: .image,
      contentLength: 0,
      matchedRules: ["screenshot-detection"],
      action: .audit,
      snippet: nil
    )
    AgentAPIClient.shared.reportClipboardEvent(event)
  }
  
  // MARK: - Actions
  private func clearClipboard() {
    DispatchQueue.main.async {
      NSPasteboard.general.clearContents()
      NSPasteboard.general.setString("[Content blocked by NextGuard DLP Policy]", forType: .string)
    }
  }
  
  private func showBlockNotification(ruleIds: [String], sourceApp: String) {
    DispatchQueue.main.async {
      let notification = NSUserNotification()
      notification.title = "NextGuard DLP"
      notification.informativeText = "Clipboard content blocked: sensitive data detected in \(sourceApp)"
      notification.soundName = NSUserNotificationDefaultSoundName
      NSUserNotificationCenter.default.deliver(notification)
    }
  }
  
  // MARK: - Helpers
  private func createRedactedSnippet(from text: String, maxLength: Int) -> String {
    let trimmed = String(text.prefix(maxLength))
    // Redact potential sensitive patterns
    var redacted = trimmed
    let patterns = [
      "\\b\\d{4}[- ]?\\d{4}[- ]?\\d{4}[- ]?\\d{4}\\b",  // credit card
      "\\b\\d{3}-\\d{2}-\\d{4}\\b",                        // SSN
      "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"   // email
    ]
    for pattern in patterns {
      if let regex = try? NSRegularExpression(pattern: pattern) {
        redacted = regex.stringByReplacingMatches(in: redacted, range: NSRange(redacted.startIndex..., in: redacted), withTemplate: "[REDACTED]")
      }
    }
    return redacted
  }
  
  private func actionForSeverity(_ severity: DLPSeverity) -> DLPAction {
    switch severity {
    case .critical: return .block
    case .high:     return .block
    case .medium:   return .notify
    case .low:      return .audit
    case .info:     return .allow
    }
  }
}

// MARK: - API Client Extension
extension AgentAPIClient {
  func reportClipboardEvent(_ event: ClipboardDLPEvent) {
    guard let data = try? JSONEncoder().encode(event) else { return }
    let url = URL(string: "\(AgentConfig.shared.managementServerURL)/api/v1/events/clipboard")!
    var request = URLRequest(url: url)
    request.httpMethod = "POST"
    request.httpBody = data
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.setValue("Bearer \(AgentConfig.shared.apiToken)", forHTTPHeaderField: "Authorization")
    URLSession.shared.dataTask(with: request).resume()
  }
}
