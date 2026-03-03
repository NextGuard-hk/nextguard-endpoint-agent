// MessagingAppMonitor.swift
// NextGuard DLP Agent - Messaging & Collaboration Apps Monitor
// Monitors WhatsApp, WeChat, Telegram, Signal, Slack, Teams, Zoom, Webex, Discord, Lark, DingTalk

import Foundation
import AppKit

public class MessagingAppMonitor: AppSubMonitor {
  private var eventHandler: ((AppDLPEvent) -> Void)?
  private var isRunning = false
  private var clipboardTimer: Timer?
  private var lastPasteboardCount: Int = 0
  private var networkWatcher: DispatchSourceFileSystemObject?
  private let queue = DispatchQueue(label: "com.nextguard.messaging", qos: .utility)

  // App-specific data directories on macOS
  private let appDataPaths: [MonitoredApp: [String]] = {
    let home = FileManager.default.homeDirectoryForCurrentUser.path
    return [
      .whatsapp: [
        "\(home)/Library/Group Containers/group.net.whatsapp.WhatsApp.shared/Message/Media",
        "\(home)/Library/Containers/net.whatsapp.WhatsApp/Data"
      ],
      .wechat: [
        "\(home)/Library/Containers/com.tencent.xinWeChat/Data/Library/Application Support/com.tencent.xinWeChat",
        "\(home)/Library/Containers/com.tencent.xinWeChat/Data/Documents"
      ],
      .telegram: [
        "\(home)/Library/Group Containers/6N38VWS5BX.ru.keepcoder.Telegram/account-*/postbox",
        "\(home)/Library/Containers/ru.keepcoder.Telegram/Data"
      ],
      .signal: [
        "\(home)/Library/Application Support/Signal"
      ],
      .slack: [
        "\(home)/Library/Containers/com.tinyspeck.slackmacgap/Data/Library/Application Support/Slack"
      ],
      .teams: [
        "\(home)/Library/Application Support/Microsoft/Teams",
        "\(home)/Library/Containers/com.microsoft.teams2/Data"
      ],
      .teams2: [
        "\(home)/Library/Containers/com.microsoft.teams2/Data/Library/Application Support/Microsoft/Teams"
      ],
      .zoom: [
        "\(home)/Library/Application Support/zoom.us"
      ],
      .webex: [
        "\(home)/Library/Application Support/Cisco Spark"
      ],
      .discord: [
        "\(home)/Library/Application Support/discord"
      ],
      .lark: [
        "\(home)/Library/Containers/com.larksuite.lark/Data"
      ],
      .dingtalk: [
        "\(home)/Library/Containers/com.laiwang.DingTalk/Data"
      ]
    ]
  }()

  // File types that indicate file sharing via messaging
  private let fileShareExtensions = Set([
    "pdf", "docx", "doc", "xlsx", "xls", "pptx", "ppt", "csv",
    "zip", "rar", "7z", "tar", "gz",
    "jpg", "jpeg", "png", "gif", "bmp", "tiff",
    "mp4", "mov", "avi", "mkv",
    "txt", "rtf", "json", "xml", "sql", "db"
  ])

  public init() {}

  public func start(eventHandler: @escaping (AppDLPEvent) -> Void) {
    self.eventHandler = eventHandler
    isRunning = true
    lastPasteboardCount = NSPasteboard.general.changeCount
    NSLog("[NextGuard] MessagingAppMonitor started")
    startClipboardMonitor()
    monitorFileTransfers()
    monitorScreenCapture()
  }

  public func stop() {
    isRunning = false
    clipboardTimer?.invalidate()
    clipboardTimer = nil
    networkWatcher?.cancel()
    NSLog("[NextGuard] MessagingAppMonitor stopped")
  }

  // MARK: - Clipboard / Paste Monitoring
  // Detects when user copies sensitive data and pastes into a messaging app
  private func startClipboardMonitor() {
    clipboardTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
      self?.checkClipboardActivity()
    }
  }

  private func checkClipboardActivity() {
    guard isRunning else { return }
    let pb = NSPasteboard.general
    let currentCount = pb.changeCount
    guard currentCount != lastPasteboardCount else { return }
    lastPasteboardCount = currentCount

    // Check if a monitored messaging app is the frontmost app
    guard let activeApp = NSWorkspace.shared.frontmostApplication,
          let bundleId = activeApp.bundleIdentifier,
          let monitored = MonitoredApp(rawValue: bundleId),
          monitored.category == .messaging else { return }

    // Check clipboard content for sensitive data patterns
    let content = pb.string(forType: .string) ?? ""
    let sensitivity = analyzeSensitivity(text: content)
    guard sensitivity.severity.rawValue != DLPSeverity.info.rawValue else { return }

    let event = AppDLPEvent(
      appBundleId: bundleId,
      appName: monitored.displayName,
      appCategory: .messaging,
      eventType: .clipboardPaste,
      severity: sensitivity.severity,
      contentSnippet: String(content.prefix(50)) + (content.count > 50 ? "..." : ""),
      matchedRules: sensitivity.rules,
      action: evaluateAction(severity: sensitivity.severity),
      userName: NSUserName(),
      deviceId: getDeviceId()
    )
    eventHandler?(event)
  }

  // MARK: - File Transfer Monitoring via FS Events
  // Watch app data directories for new file uploads/downloads
  private func monitorFileTransfers() {
    for (app, paths) in appDataPaths {
      for path in paths {
        let expandedPath = (path as NSString).expandingTildeInPath
        guard FileManager.default.fileExists(atPath: expandedPath) else { continue }
        let fd = open(expandedPath, O_EVTONLY)
        guard fd >= 0 else { continue }
        let source = DispatchSource.makeFileSystemObjectSource(
          fileDescriptor: fd,
          eventMask: [.write, .rename],
          queue: queue
        )
        source.setEventHandler { [weak self] in
          self?.handleAppFileActivity(app: app, path: expandedPath)
        }
        source.setCancelHandler { close(fd) }
        source.resume()
        NSLog("[NextGuard] Watching messaging data path: \(expandedPath)")
      }
    }
  }

  private func handleAppFileActivity(app: MonitoredApp, path: String) {
    guard isRunning else { return }
    guard let files = try? FileManager.default.contentsOfDirectory(atPath: path) else { return }
    for file in files {
      let ext = (file as NSString).pathExtension.lowercased()
      guard fileShareExtensions.contains(ext) else { continue }
      let fullPath = "\(path)/\(file)"
      guard let attrs = try? FileManager.default.attributesOfItem(atPath: fullPath),
            let modDate = attrs[.modificationDate] as? Date,
            Date().timeIntervalSince(modDate) < 10.0 else { continue }

      let fileSize = (attrs[.size] as? Int64) ?? 0
      let severity: DLPSeverity = fileSize > 25 * 1024 * 1024 ? .high : .medium

      let event = AppDLPEvent(
        appBundleId: app.rawValue,
        appName: app.displayName,
        appCategory: .messaging,
        eventType: .fileSend,
        severity: severity,
        filePath: fullPath,
        fileName: file,
        matchedRules: ["MESSAGING_FILE_TRANSFER", "\(app.displayName.uppercased())_FILE_SHARE"],
        action: evaluateAction(severity: severity),
        userName: NSUserName(),
        deviceId: getDeviceId()
      )
      eventHandler?(event)
    }
  }

  // MARK: - Screen Capture Detection
  // Detect screenshots while messaging apps are active
  private func monitorScreenCapture() {
    let screenshotPath = "\(FileManager.default.homeDirectoryForCurrentUser.path)/Desktop"
    let fd = open(screenshotPath, O_EVTONLY)
    guard fd >= 0 else { return }
    let source = DispatchSource.makeFileSystemObjectSource(
      fileDescriptor: fd,
      eventMask: .write,
      queue: queue
    )
    source.setEventHandler { [weak self] in
      self?.checkScreenshotWhileMessaging()
    }
    source.setCancelHandler { close(fd) }
    source.resume()
  }

  private func checkScreenshotWhileMessaging() {
    guard isRunning else { return }
    guard let activeApp = NSWorkspace.shared.frontmostApplication,
          let bundleId = activeApp.bundleIdentifier,
          let monitored = MonitoredApp(rawValue: bundleId),
          monitored.category == .messaging else { return }

    let event = AppDLPEvent(
      appBundleId: bundleId,
      appName: monitored.displayName,
      appCategory: .messaging,
      eventType: .screenCapture,
      severity: .medium,
      matchedRules: ["SCREENSHOT_DURING_MESSAGING"],
      action: .log,
      userName: NSUserName(),
      deviceId: getDeviceId()
    )
    eventHandler?(event)
  }

  // MARK: - Sensitivity Analysis
  private struct SensitivityResult {
    let severity: DLPSeverity
    let rules: [String]
  }

  private func analyzeSensitivity(text: String) -> SensitivityResult {
    var rules: [String] = []
    var maxSeverity = DLPSeverity.info

    // Credit card pattern
    if text.range(of: "\\b\\d{4}[- ]?\\d{4}[- ]?\\d{4}[- ]?\\d{4}\\b", options: .regularExpression) != nil {
      rules.append("PCI_CREDIT_CARD")
      maxSeverity = .critical
    }
    // SSN / HKID patterns
    if text.range(of: "\\b\\d{3}-\\d{2}-\\d{4}\\b", options: .regularExpression) != nil {
      rules.append("PII_SSN")
      maxSeverity = .critical
    }
    if text.range(of: "[A-Z]\\d{6}\\(?\\d\\)?", options: .regularExpression) != nil {
      rules.append("PII_HKID")
      maxSeverity = .critical
    }
    // Email addresses (bulk)
    let emailMatchCount = (try? NSRegularExpression(pattern: "[\\w.+-]+@[\\w-]+\\.[\\w.]+").numberOfMatches(in: text, range: NSRange(text.startIndex..., in: text))) ?? 0
    if emailMatchCount >= 5 {
      rules.append("BULK_EMAIL_EXFILTRATION")
      maxSeverity = max(maxSeverity, .high)
    }
    // Source code patterns
    let codeKeywords = ["func ", "class ", "import ", "SELECT ", "INSERT ", "def ", "const ", "private key"]
    if codeKeywords.contains(where: { text.contains($0) }) {
      rules.append("SOURCE_CODE_LEAK")
      maxSeverity = max(maxSeverity, .high)
    }
    // Passport pattern
    if text.range(of: "\\b[A-Z]\\d{8}\\b", options: .regularExpression) != nil {
      rules.append("PII_PASSPORT")
      maxSeverity = max(maxSeverity, .high)
    }
    if rules.isEmpty {
      rules = ["CLIPBOARD_MONITOR"]
    }
    return SensitivityResult(severity: maxSeverity, rules: rules)
  }

  private func max(_ a: DLPSeverity, _ b: DLPSeverity) -> DLPSeverity {
    let order: [DLPSeverity] = [.info, .low, .medium, .high, .critical]
    let ai = order.firstIndex(of: a) ?? 0
    let bi = order.firstIndex(of: b) ?? 0
    return ai >= bi ? a : b
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
