// CloudStorageMonitor.swift
// NextGuard DLP Agent - Cloud Storage & File Transfer Monitor
// Monitors iCloud, Dropbox, Google Drive, Box, OneDrive, AirDrop, USB drives

import Foundation
import AppKit
import DiskArbitration

public class CloudStorageMonitor: AppSubMonitor {
  private var eventHandler: ((AppDLPEvent) -> Void)?
  private var isRunning = false
  private var watchers: [DispatchSourceFileSystemObject] = []
  private let queue = DispatchQueue(label: "com.nextguard.cloudstorage", qos: .utility)
  private var diskSession: DASession?

  // Cloud storage sync directories
  private var cloudPaths: [(MonitoredApp, String)] {
    let home = FileManager.default.homeDirectoryForCurrentUser.path
    return [
      (.iCloud,      "\(home)/Library/Mobile Documents/com~apple~CloudDocs"),
      (.dropbox,     "\(home)/Dropbox"),
      (.dropbox,     "\(home)/Library/CloudStorage/Dropbox"),
      (.googleDrive, "\(home)/Library/CloudStorage/GoogleDrive"),
      (.googleDrive, "\(home)/Google Drive"),
      (.box,         "\(home)/Box"),
      (.box,         "\(home)/Library/CloudStorage/Box"),
      (.onedrive,    "\(home)/OneDrive"),
      (.onedrive,    "\(home)/Library/CloudStorage/OneDrive-Personal")
    ]
  }

  // Sensitive file patterns
  private let sensitiveExtensions = Set([
    "docx", "doc", "xlsx", "xls", "pptx", "pdf", "csv",
    "zip", "rar", "7z", "tar", "gz",
    "sql", "db", "sqlite", "mdb",
    "pem", "key", "cer", "pfx", "env",
    "json", "xml", "yaml", "conf"
  ])

  public init() {}

  public func start(eventHandler: @escaping (AppDLPEvent) -> Void) {
    self.eventHandler = eventHandler
    isRunning = true
    NSLog("[NextGuard] CloudStorageMonitor started")
    monitorCloudFolders()
    monitorAirDrop()
    monitorUSBDrives()
  }

  public func stop() {
    isRunning = false
    watchers.forEach { $0.cancel() }
    watchers.removeAll()
    diskSession = nil
    NSLog("[NextGuard] CloudStorageMonitor stopped")
  }

  // MARK: - Cloud Folder Watchers
  private func monitorCloudFolders() {
    for (app, path) in cloudPaths {
      guard FileManager.default.fileExists(atPath: path) else { continue }
      let fd = open(path, O_EVTONLY)
      guard fd >= 0 else { continue }
      let source = DispatchSource.makeFileSystemObjectSource(
        fileDescriptor: fd,
        eventMask: [.write, .rename, .delete],
        queue: queue
      )
      source.setEventHandler { [weak self] in
        self?.handleCloudFolderEvent(app: app, path: path)
      }
      source.setCancelHandler { close(fd) }
      source.resume()
      watchers.append(source)
      NSLog("[NextGuard] Watching cloud path: \(app.displayName) -> \(path)")
    }
  }

  private func handleCloudFolderEvent(app: MonitoredApp, path: String) {
    guard isRunning else { return }
    guard let files = try? FileManager.default.contentsOfDirectory(atPath: path) else { return }
    for file in files {
      let ext = (file as NSString).pathExtension.lowercased()
      let fullPath = "\(path)/\(file)"
      guard let attrs = try? FileManager.default.attributesOfItem(atPath: fullPath),
            let modDate = attrs[.modificationDate] as? Date,
            Date().timeIntervalSince(modDate) < 10.0 else { continue }

      let fileSize = (attrs[.size] as? Int64) ?? 0
      var severity: DLPSeverity = .low
      var rules: [String] = ["CLOUD_SYNC_DETECTED"]

      if sensitiveExtensions.contains(ext) {
        severity = .medium
        rules.append("SENSITIVE_FILE_CLOUD_UPLOAD")
      }
      if ["pem", "key", "env", "pfx"].contains(ext) {
        severity = .critical
        rules.append("CREDENTIAL_CLOUD_UPLOAD")
      }
      if fileSize > 100 * 1024 * 1024 {
        severity = severity == .critical ? .critical : .high
        rules.append("LARGE_CLOUD_UPLOAD")
      }

      let event = AppDLPEvent(
        appBundleId: app.rawValue,
        appName: app.displayName,
        appCategory: .cloudStorage,
        eventType: .cloudSync,
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

  // MARK: - AirDrop Monitoring
  private func monitorAirDrop() {
    // AirDrop received files go to ~/Downloads by default
    // We also watch the AirDrop staging area
    let home = FileManager.default.homeDirectoryForCurrentUser.path
    let airdropPaths = [
      "\(home)/Library/Sharing"
    ]
    for path in airdropPaths {
      guard FileManager.default.fileExists(atPath: path) else { continue }
      let fd = open(path, O_EVTONLY)
      guard fd >= 0 else { continue }
      let source = DispatchSource.makeFileSystemObjectSource(
        fileDescriptor: fd,
        eventMask: [.write, .rename],
        queue: queue
      )
      source.setEventHandler { [weak self] in
        self?.handleAirDropEvent(path: path)
      }
      source.setCancelHandler { close(fd) }
      source.resume()
      watchers.append(source)
    }
  }

  private func handleAirDropEvent(path: String) {
    guard isRunning else { return }
    let event = AppDLPEvent(
      appBundleId: "com.apple.AirDrop",
      appName: "AirDrop",
      appCategory: .fileTransfer,
      eventType: .externalTransfer,
      severity: .high,
      filePath: path,
      matchedRules: ["AIRDROP_TRANSFER_DETECTED"],
      action: .warn,
      userName: NSUserName(),
      deviceId: getDeviceId()
    )
    eventHandler?(event)
  }

  // MARK: - USB / External Drive Monitoring
  private func monitorUSBDrives() {
    // Watch /Volumes for new mount points
    let volumesPath = "/Volumes"
    let fd = open(volumesPath, O_EVTONLY)
    guard fd >= 0 else { return }
    let source = DispatchSource.makeFileSystemObjectSource(
      fileDescriptor: fd,
      eventMask: [.write, .rename],
      queue: queue
    )
    source.setEventHandler { [weak self] in
      self?.handleVolumeMountEvent()
    }
    source.setCancelHandler { close(fd) }
    source.resume()
    watchers.append(source)
    NSLog("[NextGuard] Watching /Volumes for USB drive activity")
  }

  private func handleVolumeMountEvent() {
    guard isRunning else { return }
    guard let volumes = try? FileManager.default.contentsOfDirectory(atPath: "/Volumes") else { return }
    for volume in volumes {
      // Skip Macintosh HD and system volumes
      if volume == "Macintosh HD" || volume.hasPrefix(".") { continue }
      let volumePath = "/Volumes/\(volume)"
      // Check if this is an external (removable) volume
      let event = AppDLPEvent(
        appBundleId: "com.apple.DiskUtility",
        appName: "External Drive: \(volume)",
        appCategory: .fileTransfer,
        eventType: .externalTransfer,
        severity: .high,
        filePath: volumePath,
        matchedRules: ["USB_DRIVE_MOUNTED", "EXTERNAL_STORAGE_DETECTED"],
        action: .warn,
        userName: NSUserName(),
        deviceId: getDeviceId()
      )
      eventHandler?(event)
    }
  }

  // MARK: - Helpers
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

// MARK: - Email App Monitor (Apple Mail, Spark)
public class EmailAppMonitor: AppSubMonitor {
  private var eventHandler: ((AppDLPEvent) -> Void)?
  private var isRunning = false
  private let queue = DispatchQueue(label: "com.nextguard.email", qos: .utility)

  public init() {}

  public func start(eventHandler: @escaping (AppDLPEvent) -> Void) {
    self.eventHandler = eventHandler
    isRunning = true
    NSLog("[NextGuard] EmailAppMonitor started")
    monitorMailAttachments()
  }

  public func stop() {
    isRunning = false
  }

  private func monitorMailAttachments() {
    let home = FileManager.default.homeDirectoryForCurrentUser.path
    let mailPaths = [
      "\(home)/Library/Containers/com.apple.mail/Data/Library/Mail Downloads",
      "\(home)/Library/Mail"
    ]
    for path in mailPaths {
      guard FileManager.default.fileExists(atPath: path) else { continue }
      let fd = open(path, O_EVTONLY)
      guard fd >= 0 else { continue }
      let source = DispatchSource.makeFileSystemObjectSource(
        fileDescriptor: fd,
        eventMask: [.write],
        queue: queue
      )
      source.setEventHandler { [weak self] in
        guard self?.isRunning == true else { return }
        let event = AppDLPEvent(
          appBundleId: MonitoredApp.appleMail.rawValue,
          appName: "Apple Mail",
          appCategory: .email,
          eventType: .emailAttachment,
          severity: .medium,
          filePath: path,
          matchedRules: ["EMAIL_ATTACHMENT_ACTIVITY"],
          action: .log,
          userName: NSUserName(),
          deviceId: Host.current().localizedName ?? "unknown-mac"
        )
        self?.eventHandler?(event)
      }
      source.setCancelHandler { close(fd) }
      source.resume()
    }
  }
}

// MARK: - File Transfer App Monitor (FileZilla, Cyberduck, Transmit)
public class FileTransferMonitor: AppSubMonitor {
  private var eventHandler: ((AppDLPEvent) -> Void)?
  private var isRunning = false

  public init() {}

  public func start(eventHandler: @escaping (AppDLPEvent) -> Void) {
    self.eventHandler = eventHandler
    isRunning = true
    NSLog("[NextGuard] FileTransferMonitor started")
    monitorFTPActivity()
  }

  public func stop() {
    isRunning = false
  }

  private func monitorFTPActivity() {
    // Monitor when FTP/SFTP apps become active
    NSWorkspace.shared.notificationCenter.addObserver(
      self,
      selector: #selector(appActivated(_:)),
      name: NSWorkspace.didActivateApplicationNotification,
      object: nil
    )
  }

  @objc private func appActivated(_ notification: Notification) {
    guard isRunning else { return }
    guard let app = notification.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication,
          let bundleId = app.bundleIdentifier,
          let monitored = MonitoredApp(rawValue: bundleId),
          monitored.category == .fileTransfer else { return }

    let event = AppDLPEvent(
      appBundleId: bundleId,
      appName: monitored.displayName,
      appCategory: .fileTransfer,
      eventType: .externalTransfer,
      severity: .high,
      matchedRules: ["FTP_CLIENT_ACTIVE", "EXTERNAL_TRANSFER_TOOL"],
      action: .warn,
      userName: NSUserName(),
      deviceId: Host.current().localizedName ?? "unknown-mac"
    )
    eventHandler?(event)
  }
}
