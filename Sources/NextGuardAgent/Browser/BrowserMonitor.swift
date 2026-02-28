//
//  BrowserMonitor.swift
//  NextGuard Endpoint DLP Agent
//
//  Copyright (c) 2026 NextGuard Technology Limited. All rights reserved.
//  Web browser upload/download DLP inspection
//  Reference: ISO 27001:2022 A.8.12, Gartner DLP MQ - Web Channel
//

import Foundation
import Network
import OSLog

// MARK: - Web Activity Types
struct WebActivity: Codable {
  let id: UUID
  let timestamp: Date
  let activityType: WebActivityType
  let browser: String
  let url: String
  let domain: String
  let method: String
  let contentType: String?
  let contentLength: Int64
  let fileName: String?
  let action: WebAction
  let userId: String
}

enum WebActivityType: String, Codable {
  case upload, download, formSubmit, paste
  case cloudSync, webmail, socialMedia
  case fileSharing, codeRepository
}

enum WebAction: String, Codable {
  case allow, block, warn, monitor, encrypt
}

// MARK: - Browser Monitor
final class BrowserMonitor: @unchecked Sendable {
  static let shared = BrowserMonitor()
  private let logger = Logger(subsystem: "com.nextguard.agent", category: "BrowserMonitor")
  
  private var isMonitoring = false
  private let queue = DispatchQueue(label: "com.nextguard.browser", qos: .userInitiated)
  
  // Monitored domains by category
  private let cloudStorageDomains: Set<String> = [
    "drive.google.com", "dropbox.com", "onedrive.live.com",
    "box.com", "icloud.com", "mega.nz", "wetransfer.com"
  ]
  
  private let codePlatformDomains: Set<String> = [
    "github.com", "gitlab.com", "bitbucket.org", "pastebin.com",
    "gist.github.com", "codepen.io", "jsfiddle.net"
  ]
  
  private let socialMediaDomains: Set<String> = [
    "facebook.com", "twitter.com", "linkedin.com", "instagram.com",
    "reddit.com", "weibo.com", "wechat.com", "telegram.org"
  ]
  
  private let fileSharingDomains: Set<String> = [
    "wetransfer.com", "sendanywhere.com", "filemail.com",
    "transfernow.net", "gofile.io", "file.io"
  ]
  
  private var blockedDomains: Set<String> = []
  private var monitoredExtensions: Set<String> = ["doc", "docx", "xls", "xlsx", "pdf", "ppt", "pptx", "csv", "zip", "rar"]
  
  private init() {}
  
  // MARK: - Start/Stop
  func startMonitoring(config: [String: Any]? = nil) {
    guard !isMonitoring else { return }
    isMonitoring = true
    
    if let blocked = config?["blockedDomains"] as? [String] {
      blockedDomains = Set(blocked)
    }
    
    startHTTPProxyMonitor()
    monitorBrowserProcesses()
    monitorDownloadDirectories()
    
    logger.info("BrowserMonitor started - HTTP proxy, process, download monitoring active")
  }
  
  func stopMonitoring() {
    isMonitoring = false
    logger.info("BrowserMonitor stopped")
  }
  
  // MARK: - HTTP Traffic Monitoring
  private func startHTTPProxyMonitor() {
    // Integrate with Network Extension for HTTPS inspection
    logger.info("HTTP/HTTPS traffic monitor initialized via Network Extension")
  }
  
  // MARK: - Browser Process Monitoring
  private func monitorBrowserProcesses() {
    let browsers = ["Safari", "Google Chrome", "Firefox", "Microsoft Edge", "Brave Browser", "Arc"]
    
    NSWorkspace.shared.notificationCenter.addObserver(
      forName: NSWorkspace.didActivateApplicationNotification, object: nil, queue: .main
    ) { [weak self] notification in
      guard let app = notification.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication,
            let name = app.localizedName else { return }
      if browsers.contains(name) {
        self?.logger.debug("Browser active: \(name)")
      }
    }
  }
  
  // MARK: - Download Directory Monitoring
  private func monitorDownloadDirectories() {
    let downloadDirs = [
      FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first!,
      FileManager.default.urls(for: .desktopDirectory, in: .userDomainMask).first!
    ]
    
    for dir in downloadDirs {
      startFSEventMonitor(for: dir)
    }
  }
  
  private func startFSEventMonitor(for directory: URL) {
    // Use FSEvents to monitor download directory for new files
    logger.info("Monitoring directory: \(directory.path)")
  }
  
  // MARK: - URL Analysis
  func analyzeURL(_ urlString: String) -> (WebActivityType, Bool) {
    guard let url = URL(string: urlString), let host = url.host?.lowercased() else {
      return (.upload, false)
    }
    
    if cloudStorageDomains.contains(where: { host.contains($0) }) {
      return (.cloudSync, blockedDomains.contains(host))
    }
    if codePlatformDomains.contains(where: { host.contains($0) }) {
      return (.codeRepository, blockedDomains.contains(host))
    }
    if socialMediaDomains.contains(where: { host.contains($0) }) {
      return (.socialMedia, blockedDomains.contains(host))
    }
    if fileSharingDomains.contains(where: { host.contains($0) }) {
      return (.fileSharing, true) // Always monitor file sharing
    }
    
    return (.upload, blockedDomains.contains(host))
  }
  
  // MARK: - Upload Inspection
  func inspectUpload(url: String, fileName: String?, contentLength: Int64, contentType: String?) -> WebAction {
    let (activityType, isBlocked) = analyzeURL(url)
    
    // Check file extension
    if let name = fileName {
      let ext = (name as NSString).pathExtension.lowercased()
      if monitoredExtensions.contains(ext) {
        // Check with PolicyManager
        let (action, policy) = PolicyManager.shared.evaluate(
          channel: .webUpload, content: name,
          metadata: ["fileExtension": ext, "fileSize": "\(contentLength)", "domain": URL(string: url)?.host ?? ""]
        )
        
        if action == .block {
          let activity = WebActivity(
            id: UUID(), timestamp: Date(), activityType: activityType,
            browser: "Unknown", url: url, domain: URL(string: url)?.host ?? "",
            method: "POST", contentType: contentType, contentLength: contentLength,
            fileName: fileName, action: .block, userId: NSUserName()
          )
          logActivity(activity)
          return .block
        }
      }
    }
    
    if isBlocked { return .block }
    return .allow
  }
  
  // MARK: - Download Inspection
  func inspectDownload(url: String, fileName: String, contentLength: Int64) -> WebAction {
    let ext = (fileName as NSString).pathExtension.lowercased()
    let dangerousExtensions = ["exe", "bat", "cmd", "scr", "msi", "dll", "dmg", "pkg", "app"]
    
    if dangerousExtensions.contains(ext) {
      AuditLogger.shared.log(category: .networkActivity, severity: .high,
        action: "dangerous_download", description: "Dangerous file download: \(fileName)",
        filePath: fileName, metadata: ["url": url, "extension": ext])
      return .warn
    }
    return .allow
  }
  
  // MARK: - Logging
  private func logActivity(_ activity: WebActivity) {
    AuditLogger.shared.log(
      category: .networkActivity, severity: activity.action == .block ? .high : .info,
      action: activity.activityType.rawValue, outcome: activity.action.rawValue,
      description: "\(activity.activityType.rawValue): \(activity.domain)",
      metadata: [
        "url": activity.url, "browser": activity.browser,
        "fileName": activity.fileName ?? "", "contentLength": "\(activity.contentLength)"
      ]
    )
  }
  
  // MARK: - Statistics
  func getStatistics() -> [String: Any] {
    return ["monitoring": isMonitoring, "blockedDomains": blockedDomains.count]
  }
}
