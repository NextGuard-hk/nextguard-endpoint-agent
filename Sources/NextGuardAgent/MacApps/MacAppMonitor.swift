// MacAppMonitor.swift
// NextGuard DLP Agent - macOS Application DLP Monitor
// Monitors DLP events across productivity, messaging, and collaboration apps

import Foundation
import AppKit
import Combine

// MARK: - Supported App Bundle IDs
public enum MonitoredApp: String, CaseIterable {
  // Microsoft Office 365
  case word = "com.microsoft.Word"
  case excel = "com.microsoft.Excel"
  case powerpoint = "com.microsoft.Powerpoint"
  case outlook = "com.microsoft.Outlook"
  case onenote = "com.microsoft.onenote.mac"
  case onedrive = "com.microsoft.OneDrive"
  case teams = "com.microsoft.teams"
  case teams2 = "com.microsoft.teams2"
  case sharepoint = "com.microsoft.SharePoint"
  // Messaging & Collaboration
  case whatsapp = "net.whatsapp.WhatsApp"
  case wechat = "com.tencent.xinWeChat"
  case telegram = "ru.keepcoder.Telegram"
  case signal = "org.whispersystems.signal-desktop"
  case slack = "com.tinyspeck.slackmacgap"
  case zoom = "us.zoom.xos"
  case webex = "Cisco-Systems.Spark"
  case discord = "com.hnc.Discord"
  case lark = "com.larksuite.lark"
  case dingtalk = "com.laiwang.DingTalk"
  // Browsers
  case safari = "com.apple.Safari"
  case chrome = "com.google.Chrome"
  case firefox = "org.mozilla.firefox"
  case edge = "com.microsoft.edgemac"
  case brave = "com.brave.Browser"
  // Cloud Storage
  case dropbox = "com.getdropbox.dropbox"
  case googleDrive = "com.google.GoogleDrive"
  case box = "com.box.desktop"
  case iCloud = "com.apple.CloudDocs"
  // Email Clients
  case appleMail = "com.apple.mail"
  case spark = "com.readdle.SparkDesktop"
  // Developer / Transfer Tools
  case filezilla = "org.filezilla-project.filezilla"
  case cyberduck = "ch.sudo.cyberduck"
  case transmit = "com.panic.Transmit"

  public var displayName: String {
    switch self {
    case .word: return "Microsoft Word"
    case .excel: return "Microsoft Excel"
    case .powerpoint: return "Microsoft PowerPoint"
    case .outlook: return "Microsoft Outlook"
    case .onenote: return "Microsoft OneNote"
    case .onedrive: return "Microsoft OneDrive"
    case .teams: return "Microsoft Teams"
    case .teams2: return "Microsoft Teams (New)"
    case .sharepoint: return "Microsoft SharePoint"
    case .whatsapp: return "WhatsApp"
    case .wechat: return "WeChat"
    case .telegram: return "Telegram"
    case .signal: return "Signal"
    case .slack: return "Slack"
    case .zoom: return "Zoom"
    case .webex: return "Cisco Webex"
    case .discord: return "Discord"
    case .lark: return "Lark / Feishu"
    case .dingtalk: return "DingTalk"
    case .safari: return "Safari"
    case .chrome: return "Google Chrome"
    case .firefox: return "Mozilla Firefox"
    case .edge: return "Microsoft Edge"
    case .brave: return "Brave Browser"
    case .dropbox: return "Dropbox"
    case .googleDrive: return "Google Drive"
    case .box: return "Box"
    case .iCloud: return "iCloud Drive"
    case .appleMail: return "Apple Mail"
    case .spark: return "Spark Mail"
    case .filezilla: return "FileZilla"
    case .cyberduck: return "Cyberduck"
    case .transmit: return "Transmit"
    }
  }

  public var category: AppCategory {
    switch self {
    case .word, .excel, .powerpoint, .outlook, .onenote, .sharepoint:
      return .office365
    case .onedrive:
      return .cloudStorage
    case .teams, .teams2, .whatsapp, .wechat, .telegram, .signal, .slack, .zoom, .webex, .discord, .lark, .dingtalk:
      return .messaging
    case .safari, .chrome, .firefox, .edge, .brave:
      return .browser
    case .dropbox, .googleDrive, .box, .iCloud:
      return .cloudStorage
    case .appleMail, .spark:
      return .email
    case .filezilla, .cyberduck, .transmit:
      return .fileTransfer
    }
  }
}

public enum AppCategory: String, Codable {
  case office365 = "Office365"
  case messaging = "Messaging"
  case browser = "Browser"
  case cloudStorage = "CloudStorage"
  case email = "Email"
  case fileTransfer = "FileTransfer"
}

// MARK: - App DLP Event
public struct AppDLPEvent: Codable {
  public let id: String
  public let timestamp: Date
  public let appBundleId: String
  public let appName: String
  public let appCategory: AppCategory
  public let eventType: AppEventType
  public let severity: DLPSeverity
  public let filePath: String?
  public let fileName: String?
  public let destinationURL: String?
  public let recipientList: [String]?
  public let contentSnippet: String?
  public let matchedRules: [String]
  public let action: DLPAction
  public let userName: String
  public let deviceId: String

  public init(
    appBundleId: String,
    appName: String,
    appCategory: AppCategory,
    eventType: AppEventType,
    severity: DLPSeverity,
    filePath: String? = nil,
    fileName: String? = nil,
    destinationURL: String? = nil,
    recipientList: [String]? = nil,
    contentSnippet: String? = nil,
    matchedRules: [String],
    action: DLPAction,
    userName: String,
    deviceId: String
  ) {
    self.id = UUID().uuidString
    self.timestamp = Date()
    self.appBundleId = appBundleId
    self.appName = appName
    self.appCategory = appCategory
    self.eventType = eventType
    self.severity = severity
    self.filePath = filePath
    self.fileName = fileName
    self.destinationURL = destinationURL
    self.recipientList = recipientList
    self.contentSnippet = contentSnippet
    self.matchedRules = matchedRules
    self.action = action
    self.userName = userName
    self.deviceId = deviceId
  }
}

public enum AppEventType: String, Codable {
  case fileSend = "FILE_SEND"
  case fileUpload = "FILE_UPLOAD"
  case fileDownload = "FILE_DOWNLOAD"
  case filePrint = "FILE_PRINT"
  case clipboardPaste = "CLIPBOARD_PASTE"
  case screenCapture = "SCREEN_CAPTURE"
  case messageSend = "MESSAGE_SEND"
  case emailSend = "EMAIL_SEND"
  case emailForward = "EMAIL_FORWARD"
  case emailAttachment = "EMAIL_ATTACHMENT"
  case fileSaveAs = "FILE_SAVE_AS"
  case fileShare = "FILE_SHARE"
  case cloudSync = "CLOUD_SYNC"
  case externalTransfer = "EXTERNAL_TRANSFER"
}

// NOTE: DLPSeverity and DLPAction are defined in DLPPolicyEngine.swift
// Do not redefine them here to avoid ambiguity errors

// MARK: - Mac App Monitor (Coordinator)
public class MacAppMonitor: NSObject {
  public static let shared = MacAppMonitor()
  private var cancellables = Set<AnyCancellable>()
  private let eventQueue = DispatchQueue(label: "com.nextguard.appmonitor", qos: .utility)
  private let eventPublisher = PassthroughSubject<AppDLPEvent, Never>()
  public var onEvent: ((AppDLPEvent) -> Void)?

  // Sub-monitors
  private let office365Monitor = Office365Monitor()
  private let messagingMonitor = MessagingAppMonitor()
  private let browserMonitor = BrowserAppMonitor()
  private let cloudMonitor = CloudStorageMonitor()
  private let emailMonitor = EmailAppMonitor()
  private let fileTransferMonitor = FileTransferMonitor()

  private override init() {
    super.init()
    setupEventPipeline()
  }

  private func setupEventPipeline() {
    eventPublisher
      .receive(on: eventQueue)
      .sink { [weak self] event in
        self?.onEvent?(event)
        self?.reportToConsole(event: event)
      }
      .store(in: &cancellables)
  }

  public func startMonitoring() {
    NSLog("[NextGuard] MacAppMonitor starting all app monitors")
    office365Monitor.start { [weak self] e in self?.eventPublisher.send(e) }
    messagingMonitor.start { [weak self] e in self?.eventPublisher.send(e) }
    browserMonitor.start { [weak self] e in self?.eventPublisher.send(e) }
    cloudMonitor.start { [weak self] e in self?.eventPublisher.send(e) }
    emailMonitor.start { [weak self] e in self?.eventPublisher.send(e) }
    fileTransferMonitor.start{ [weak self] e in self?.eventPublisher.send(e) }
    registerWorkspaceNotifications()
  }

  public func stopMonitoring() {
    office365Monitor.stop()
    messagingMonitor.stop()
    browserMonitor.stop()
    cloudMonitor.stop()
    emailMonitor.stop()
    fileTransferMonitor.stop()
    NSLog("[NextGuard] MacAppMonitor stopped")
  }

  // MARK: - NSWorkspace App Launch / Termination Tracking
  private func registerWorkspaceNotifications() {
    let nc = NSWorkspace.shared.notificationCenter
    nc.addObserver(self,
      selector: #selector(appDidLaunch(_:)),
      name: NSWorkspace.didLaunchApplicationNotification,
      object: nil)
    nc.addObserver(self,
      selector: #selector(appDidTerminate(_:)),
      name: NSWorkspace.didTerminateApplicationNotification,
      object: nil)
  }

  @objc private func appDidLaunch(_ notification: Notification) {
    guard let app = notification.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication,
          let bundleId = app.bundleIdentifier else { return }
    if MonitoredApp(rawValue: bundleId) != nil {
      NSLog("[NextGuard] Monitored app launched: \(bundleId)")
    }
  }

  @objc private func appDidTerminate(_ notification: Notification) {
    guard let app = notification.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication,
          let bundleId = app.bundleIdentifier else { return }
    if MonitoredApp(rawValue: bundleId) != nil {
      NSLog("[NextGuard] Monitored app terminated: \(bundleId)")
    }
  }

  // MARK: - Report to Console API
  private func reportToConsole(event: AppDLPEvent) {
    guard let url = URL(string: "https://www.next-guard.com/api/v1/app-dlp-events") else { return }
    var request = URLRequest(url: url)
    request.httpMethod = "POST"
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .iso8601
    guard let body = try? encoder.encode(event) else { return }
    request.httpBody = body
    URLSession.shared.dataTask(with: request) { _, _, error in
      if let error = error {
        NSLog("[NextGuard] Failed to report app DLP event: \(error)")
      }
    }.resume()
  }
}
