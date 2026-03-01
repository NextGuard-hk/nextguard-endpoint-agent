// BrowserMonitor.swift
// NextGuard DLP Agent - Browser DLP Monitor
// Monitors Safari, Chrome, Firefox, Edge, Brave for upload/download/webmail activity

import Foundation
import AppKit

public class BrowserAppMonitor: AppSubMonitor {
  private var eventHandler: ((AppDLPEvent) -> Void)?
  private var isRunning = false
  private var downloadWatchers: [DispatchSourceFileSystemObject] = []
  private let queue = DispatchQueue(label: "com.nextguard.browser", qos: .utility)
  private var lastDownloadSnapshot: [String: Date] = [:]

  // Known webmail / cloud upload domains to flag
  private let sensitiveUploadDomains = [
    "mail.google.com", "outlook.live.com", "outlook.office.com",
    "mail.yahoo.com", "mail.163.com", "mail.qq.com",
    "drive.google.com", "dropbox.com", "box.com",
    "wetransfer.com", "sendspace.com", "file.io",
    "pastebin.com", "hastebin.com", "gist.github.com",
    "mega.nz", "mediafire.com", "anonfiles.com"
  ]

  // Sensitive file extensions for download monitoring
  private let sensitiveExtensions = Set([
    "docx", "doc", "xlsx", "xls", "pptx", "ppt", "pdf", "csv",
    "zip", "rar", "7z", "tar", "gz",
    "sql", "db", "sqlite", "mdb", "accdb",
    "pem", "key", "cer", "pfx", "p12",
    "env", "conf", "config", "ini",
    "json", "xml", "yaml", "yml"
  ])

  public init() {}

  public func start(eventHandler: @escaping (AppDLPEvent) -> Void) {
    self.eventHandler = eventHandler
    isRunning = true
    NSLog("[NextGuard] BrowserAppMonitor started")
    monitorDownloadsFolder()
    monitorBrowserHistoryDBs()
  }

  public func stop() {
    isRunning = false
    downloadWatchers.forEach { $0.cancel() }
    downloadWatchers.removeAll()
    NSLog("[NextGuard] BrowserAppMonitor stopped")
  }

  // MARK: - Downloads Folder Monitoring
  private func monitorDownloadsFolder() {
    let home = FileManager.default.homeDirectoryForCurrentUser.path
    let downloadPaths = [
      "\(home)/Downloads",
      "\(home)/Desktop"  // some browsers default to Desktop
    ]
    for path in downloadPaths {
      guard FileManager.default.fileExists(atPath: path) else { continue }
      snapshotDirectory(path: path)
      let fd = open(path, O_EVTONLY)
      guard fd >= 0 else { continue }
      let source = DispatchSource.makeFileSystemObjectSource(
        fileDescriptor: fd,
        eventMask: [.write, .rename],
        queue: queue
      )
      source.setEventHandler { [weak self] in
        self?.handleDownloadEvent(path: path)
      }
      source.setCancelHandler { close(fd) }
      source.resume()
      downloadWatchers.append(source)
    }
  }

  private func snapshotDirectory(path: String) {
    guard let files = try? FileManager.default.contentsOfDirectory(atPath: path) else { return }
    for file in files {
      let fullPath = "\(path)/\(file)"
      if let attrs = try? FileManager.default.attributesOfItem(atPath: fullPath),
         let modDate = attrs[.modificationDate] as? Date {
        lastDownloadSnapshot[fullPath] = modDate
      }
    }
  }

  private func handleDownloadEvent(path: String) {
    guard isRunning else { return }
    guard let files = try? FileManager.default.contentsOfDirectory(atPath: path) else { return }

    // Identify which browser is active
    let activeBrowser = detectActiveBrowser()

    for file in files {
      // Skip partial downloads
      if file.hasSuffix(".crdownload") || file.hasSuffix(".download") || file.hasSuffix(".part") { continue }

      let fullPath = "\(path)/\(file)"
      guard let attrs = try? FileManager.default.attributesOfItem(atPath: fullPath),
            let modDate = attrs[.modificationDate] as? Date else { continue }

      // Check if this is a new file (not in our snapshot or modified recently)
      if let lastMod = lastDownloadSnapshot[fullPath], lastMod == modDate { continue }
      guard Date().timeIntervalSince(modDate) < 10.0 else { continue }
      lastDownloadSnapshot[fullPath] = modDate

      let ext = (file as NSString).pathExtension.lowercased()
      let fileSize = (attrs[.size] as? Int64) ?? 0
      var severity: DLPSeverity = .low
      var rules: [String] = ["BROWSER_DOWNLOAD"]

      if sensitiveExtensions.contains(ext) {
        severity = .medium
        rules.append("SENSITIVE_FILE_DOWNLOAD")
      }
      if ["pem", "key", "cer", "pfx", "p12", "env"].contains(ext) {
        severity = .critical
        rules.append("CREDENTIAL_FILE_DOWNLOAD")
      }
      if fileSize > 50 * 1024 * 1024 {
        severity = severity == .critical ? .critical : .high
        rules.append("LARGE_FILE_DOWNLOAD")
      }

      let event = AppDLPEvent(
        appBundleId: activeBrowser?.rawValue ?? "unknown",
        appName: activeBrowser?.displayName ?? "Browser",
        appCategory: .browser,
        eventType: .fileDownload,
        severity: severity,
        filePath: fullPath,
        fileName: file,
        matchedRules: rules,
        action: evaluateAction(severity: severity),
        userName: NSUserName(),
        deviceId: getDeviceId()
      )
      eventHandler?(event)
    }
  }

  // MARK: - Browser History DB Monitoring (upload detection)
  private func monitorBrowserHistoryDBs() {
    let home = FileManager.default.homeDirectoryForCurrentUser.path
    let historyPaths: [(MonitoredApp, String)] = [
      (.chrome, "\(home)/Library/Application Support/Google/Chrome/Default/History"),
      (.edge, "\(home)/Library/Application Support/Microsoft Edge/Default/History"),
      (.brave, "\(home)/Library/Application Support/BraveSoftware/Brave-Browser/Default/History"),
      (.firefox, "\(home)/Library/Application Support/Firefox/Profiles")
    ]
    for (app, path) in historyPaths {
      let checkPath = app == .firefox ? findFirefoxProfile(basePath: path) : path
      guard let validPath = checkPath, FileManager.default.fileExists(atPath: validPath) else { continue }
      let fd = open(validPath, O_EVTONLY)
      guard fd >= 0 else { continue }
      let source = DispatchSource.makeFileSystemObjectSource(
        fileDescriptor: fd,
        eventMask: .write,
        queue: queue
      )
      source.setEventHandler { [weak self] in
        self?.checkUploadActivity(browser: app)
      }
      source.setCancelHandler { close(fd) }
      source.resume()
      downloadWatchers.append(source)
      NSLog("[NextGuard] Watching \(app.displayName) history DB")
    }
  }

  private func findFirefoxProfile(basePath: String) -> String? {
    guard let profiles = try? FileManager.default.contentsOfDirectory(atPath: basePath) else { return nil }
    for profile in profiles where profile.hasSuffix(".default-release") {
      return "\(basePath)/\(profile)/places.sqlite"
    }
    return nil
  }

  private func checkUploadActivity(browser: MonitoredApp) {
    guard isRunning else { return }
    // Detect if an upload input or webmail compose window is active
    guard let activeApp = NSWorkspace.shared.frontmostApplication,
          activeApp.bundleIdentifier == browser.rawValue else { return }

    // Log that browser history changed while browser is active
    // Full URL analysis would require reading the SQLite DB
    let event = AppDLPEvent(
      appBundleId: browser.rawValue,
      appName: browser.displayName,
      appCategory: .browser,
      eventType: .fileUpload,
      severity: .low,
      matchedRules: ["BROWSER_ACTIVITY_MONITOR"],
      action: .log,
      userName: NSUserName(),
      deviceId: getDeviceId()
    )
    eventHandler?(event)
  }

  // MARK: - URL Classification (called by Network Extension or proxy)
  public func classifyURL(url: String, browser: MonitoredApp) -> DLPAction {
    guard isRunning else { return .allow }
    let lowered = url.lowercased()
    for domain in sensitiveUploadDomains {
      if lowered.contains(domain) {
        let event = AppDLPEvent(
          appBundleId: browser.rawValue,
          appName: browser.displayName,
          appCategory: .browser,
          eventType: .fileUpload,
          severity: .high,
          destinationURL: url,
          matchedRules: ["SENSITIVE_UPLOAD_DOMAIN", "WEBMAIL_UPLOAD"],
          action: .warn,
          userName: NSUserName(),
          deviceId: getDeviceId()
        )
        eventHandler?(event)
        return .warn
      }
    }
    return .allow
  }

  // MARK: - Helpers
  private func detectActiveBrowser() -> MonitoredApp? {
    guard let bundleId = NSWorkspace.shared.frontmostApplication?.bundleIdentifier else { return nil }
    let browsers: [MonitoredApp] = [.safari, .chrome, .firefox, .edge, .brave]
    return browsers.first { $0.rawValue == bundleId }
  }

  private func evaluateAction(severity: DLPSeverity) -> DLPAction {
    switch severity {
    case .critical: return .block
    case .high:     return .warn
    case .medium:   return .log
    case .low:      return .log
    case .info:     return .allow
    }
  }

  private func getDeviceId() -> String {
    return Host.current().localizedName ?? "unknown-mac"
  }
}
