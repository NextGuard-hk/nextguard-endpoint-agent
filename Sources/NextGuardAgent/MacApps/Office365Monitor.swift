// Office365Monitor.swift
// NextGuard DLP Agent - Microsoft Office 365 Apps Monitor
// Monitors Word, Excel, PowerPoint, Outlook, OneDrive, Teams, SharePoint

import Foundation
import AppKit

// MARK: - Protocol for all sub-monitors
public protocol AppSubMonitor {
  func start(eventHandler: @escaping (AppDLPEvent) -> Void)
  func stop()
}

// MARK: - Office 365 Monitor
public class Office365Monitor: AppSubMonitor {
  private var eventHandler: ((AppDLPEvent) -> Void)?
  private var fileWatchers: [DispatchSourceFileSystemObject] = []
  private var watchedPaths: [String] = []
  private let queue = DispatchQueue(label: "com.nextguard.office365", qos: .utility)
  private var isRunning = false

  // Sensitive file extensions handled by Office apps
  private let sensitiveExtensions = [
    "docx", "doc", "docm",          // Word
    "xlsx", "xls", "xlsm", "csv",   // Excel
    "pptx", "ppt", "pptm",          // PowerPoint
    "pdf", "rtf", "txt"
  ]

  public init() {}

  public func start(eventHandler: @escaping (AppDLPEvent) -> Void) {
    self.eventHandler = eventHandler
    isRunning = true
    NSLog("[NextGuard] Office365Monitor started")
    monitorOneDriveFolders()
    monitorSharePointSync()
    registerOfficeNotifications()
  }

  public func stop() {
    isRunning = false
    fileWatchers.forEach { $0.cancel() }
    fileWatchers.removeAll()
    NSLog("[NextGuard] Office365Monitor stopped")
  }

  // MARK: - OneDrive Folder Monitoring
  private func monitorOneDriveFolders() {
    let homeDir = FileManager.default.homeDirectoryForCurrentUser.path
    let oneDrivePaths = [
      "\(homeDir)/OneDrive",
      "\(homeDir)/Library/CloudStorage/OneDrive-Personal",
      "\(homeDir)/Library/CloudStorage/OneDrive-"
    ]
    for path in oneDrivePaths {
      if FileManager.default.fileExists(atPath: path) {
        watchDirectory(path: path, app: .onedrive)
        NSLog("[NextGuard] Watching OneDrive path: \(path)")
      }
    }
  }

  // MARK: - SharePoint Sync Monitoring
  private func monitorSharePointSync() {
    let homeDir = FileManager.default.homeDirectoryForCurrentUser.path
    let spPaths = [
      "\(homeDir)/Library/CloudStorage/OneDrive-",  // SharePoint syncs here
      "\(homeDir)/SharePoint"
    ]
    for path in spPaths {
      if FileManager.default.fileExists(atPath: path) {
        watchDirectory(path: path, app: .sharepoint)
      }
    }
  }

  // MARK: - File System Watcher
  private func watchDirectory(path: String, app: MonitoredApp) {
    let fd = open(path, O_EVTONLY)
    guard fd >= 0 else { return }
    let source = DispatchSource.makeFileSystemObjectSource(
      fileDescriptor: fd,
      eventMask: [.write, .rename, .delete],
      queue: queue
    )
    source.setEventHandler { [weak self] in
      self?.handleFileSystemEvent(path: path, app: app)
    }
    source.setCancelHandler { close(fd) }
    source.resume()
    fileWatchers.append(source)
  }

  private func handleFileSystemEvent(path: String, app: MonitoredApp) {
    guard isRunning else { return }
    // Enumerate recent changes in the watched directory
    guard let contents = try? FileManager.default.contentsOfDirectory(atPath: path) else { return }
    for item in contents {
      let ext = (item as NSString).pathExtension.lowercased()
      guard sensitiveExtensions.contains(ext) else { continue }
      let fullPath = "\(path)/\(item)"
      guard let attrs = try? FileManager.default.attributesOfItem(atPath: fullPath),
            let modDate = attrs[.modificationDate] as? Date,
            Date().timeIntervalSince(modDate) < 5.0 else { continue }
      // File was modified within last 5 seconds - potential sync/upload
      generateEvent(app: app, path: fullPath, fileName: item, eventType: .cloudSync)
    }
  }

  // MARK: - NSWorkspace / Pasteboard Notifications for Office Apps
  private func registerOfficeNotifications() {
    // Monitor print jobs from Office apps via NSWorkspace
    DistributedNotificationCenter.default().addObserver(
      self,
      selector: #selector(handlePrintNotification(_:)),
      name: NSNotification.Name("com.apple.printjob.started"),
      object: nil
    )
    // Monitor Save As dialogs via accessibility (requires accessibility permission)
    NotificationCenter.default.addObserver(
      self,
      selector: #selector(handleSavePanel(_:)),
      name: NSNotification.Name("com.nextguard.savePanelDetected"),
      object: nil
    )
  }

  @objc private func handlePrintNotification(_ notification: Notification) {
    guard isRunning else { return }
    // Detect which Office app triggered the print
    let runningOfficeApps: [MonitoredApp] = [.word, .excel, .powerpoint, .outlook]
    let activeApp = NSWorkspace.shared.frontmostApplication
    for officeApp in runningOfficeApps {
      if activeApp?.bundleIdentifier == officeApp.rawValue {
        let event = AppDLPEvent(
          appBundleId: officeApp.rawValue,
          appName: officeApp.displayName,
          appCategory: .office365,
          eventType: .filePrint,
          severity: .medium,
          matchedRules: ["PRINT_SENSITIVE_DOCUMENT"],
          action: evaluateAction(severity: .medium),
          userName: NSUserName(),
          deviceId: getDeviceId()
        )
        eventHandler?(event)
        break
      }
    }
  }

  @objc private func handleSavePanel(_ notification: Notification) {
    // Handle Save-As to external/removable drives
    guard isRunning else { return }
    if let path = notification.userInfo?["path"] as? String {
      let isExternal = path.hasPrefix("/Volumes/")
      if isExternal {
        generateEvent(app: .word, path: path, fileName: URL(fileURLWithPath: path).lastPathComponent, eventType: .fileSaveAs, severity: .high)
      }
    }
  }

  // MARK: - Teams File Share Detection
  public func checkTeamsFileSharing(fileName: String, recipients: [String]) {
    guard isRunning else { return }
    let severity: DLPSeverity = recipients.contains(where: { !$0.hasSuffix(getOrgDomain()) }) ? .high : .low
    let event = AppDLPEvent(
      appBundleId: MonitoredApp.teams.rawValue,
      appName: "Microsoft Teams",
      appCategory: .messaging,
      eventType: .fileShare,
      severity: severity,
      fileName: fileName,
      recipientList: recipients,
      matchedRules: severity == .high ? ["EXTERNAL_FILE_SHARE", "DATA_EXFILTRATION"] : ["INTERNAL_FILE_SHARE"],
      action: evaluateAction(severity: severity),
      userName: NSUserName(),
      deviceId: getDeviceId()
    )
    eventHandler?(event)
  }

  // MARK: - Outlook Email Attachment Detection
  public func checkOutlookAttachment(fileName: String, recipients: [String], fileSize: Int64) {
    guard isRunning else { return }
    let hasExternalRecipient = recipients.contains { !$0.hasSuffix(getOrgDomain()) }
    let isLargeFile = fileSize > 10 * 1024 * 1024  // 10MB
    var rules: [String] = []
    var severity: DLPSeverity = .info
    if hasExternalRecipient {
      rules.append("EMAIL_EXTERNAL_RECIPIENT")
      severity = .high
    }
    if isLargeFile {
      rules.append("LARGE_FILE_ATTACHMENT")
      severity = severity == .high ? .critical : .medium
    }
    let ext = (fileName as NSString).pathExtension.lowercased()
    if sensitiveExtensions.contains(ext) {
      rules.append("SENSITIVE_FILE_TYPE")
    }
    if rules.isEmpty { rules = ["EMAIL_ATTACHMENT_LOG"] }
    let event = AppDLPEvent(
      appBundleId: MonitoredApp.outlook.rawValue,
      appName: "Microsoft Outlook",
      appCategory: .email,
      eventType: .emailAttachment,
      severity: severity,
      fileName: fileName,
      recipientList: recipients,
      matchedRules: rules,
      action: evaluateAction(severity: severity),
      userName: NSUserName(),
      deviceId: getDeviceId()
    )
    eventHandler?(event)
  }

  // MARK: - Helpers
  private func generateEvent(
    app: MonitoredApp,
    path: String,
    fileName: String,
    eventType: AppEventType,
    severity: DLPSeverity = .medium
  ) {
    let event = AppDLPEvent(
      appBundleId: app.rawValue,
      appName: app.displayName,
      appCategory: app.category,
      eventType: eventType,
      severity: severity,
      filePath: path,
      fileName: fileName,
      matchedRules: rulesForEvent(eventType: eventType, severity: severity),
      action: evaluateAction(severity: severity),
      userName: NSUserName(),
      deviceId: getDeviceId()
    )
    eventHandler?(event)
  }

  private func rulesForEvent(eventType: AppEventType, severity: DLPSeverity) -> [String] {
    switch eventType {
    case .cloudSync:        return ["CLOUD_SYNC_MONITORING", "ONEDRIVE_UPLOAD_DETECT"]
    case .fileSaveAs:       return ["SAVE_AS_EXTERNAL_DRIVE"]
    case .filePrint:        return ["PRINT_JOB_DLP"]
    case .emailAttachment:  return ["OUTLOOK_ATTACHMENT_DLP"]
    case .fileShare:        return ["TEAMS_FILE_SHARE_DLP"]
    default:                return ["OFFICE365_DLP_GENERIC"]
    }
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

  private func getOrgDomain() -> String {
    // Read from agent config; fallback to empty so external check always triggers
    return UserDefaults.standard.string(forKey: "NGOrgEmailDomain") ?? ""
  }
}
