//
//  ScreenCaptureMonitor.swift
//  NextGuard Endpoint DLP Agent
//
//  Copyright (c) 2026 NextGuard Technology Limited. All rights reserved.
//  Screen capture and recording prevention/detection
//  Reference: ISO 27001:2022 A.8.12, Gartner DLP MQ - Endpoint Channels
//

import Foundation
import AppKit
import OSLog
import CoreGraphics

// MARK: - Screen Capture Event
struct ScreenCaptureEvent: Codable {
  let id: UUID
  let timestamp: Date
  let eventType: CaptureEventType
  let applicationName: String
  let applicationBundleId: String
  let windowTitle: String?
  let action: CaptureAction
  let userId: String
}

enum CaptureEventType: String, Codable {
  case screenshot
  case screenRecording
  case screenShare
  case remoteDesktop
  case virtualMachine
}

enum CaptureAction: String, Codable {
  case allowed
  case blocked
  case watermarked
  case logged
}

// MARK: - Screen Capture Monitor
final class ScreenCaptureMonitor: @unchecked Sendable {
  static let shared = ScreenCaptureMonitor()
  private let logger = Logger(subsystem: "com.nextguard.agent", category: "ScreenCapture")
  
  private var isMonitoring = false
  private let queue = DispatchQueue(label: "com.nextguard.screen", qos: .userInitiated)
  private var screenshotObserver: Any?
  private var pollingTimer: Timer?
  
  private var blockedApps: Set<String> = [
    "com.teamviewer.TeamViewer", "us.zoom.xos",
    "com.anydesk.anydesk", "com.logmein.GoToMeeting"
  ]
  
  private var watermarkEnabled = true
  private var watermarkText: String = ""
  
  private init() {}
  
  // MARK: - Start/Stop
  func startMonitoring(config: [String: Any]? = nil) {
    guard !isMonitoring else { return }
    isMonitoring = true
    if let blocked = config?["blockedApps"] as? [String] {
      blockedApps = Set(blocked)
    }
    watermarkEnabled = config?["watermarkEnabled"] as? Bool ?? true
    watermarkText = config?["watermarkText"] as? String ?? "\(NSUserName()) - NextGuard Protected"
    
    observeScreenshots()
    monitorScreenRecording()
    monitorScreenSharing()
    detectVirtualMachines()
    logger.info("ScreenCaptureMonitor started")
  }
  
  func stopMonitoring() {
    isMonitoring = false
    if let observer = screenshotObserver {
      DistributedNotificationCenter.default().removeObserver(observer)
    }
    pollingTimer?.invalidate()
    logger.info("ScreenCaptureMonitor stopped")
  }
  
  // MARK: - Screenshot Detection
  private func observeScreenshots() {
    screenshotObserver = DistributedNotificationCenter.default().addObserver(
      forName: NSNotification.Name("com.apple.screencaptureui.capture"),
      object: nil, queue: .main
    ) { [weak self] notification in
      self?.handleScreenshotDetected(notification)
    }
    monitorScreenshotDirectory()
  }
  
  private func handleScreenshotDetected(_ notification: Notification) {
    let frontApp = NSWorkspace.shared.frontmostApplication
    let event = ScreenCaptureEvent(
      id: UUID(), timestamp: Date(), eventType: .screenshot,
      applicationName: frontApp?.localizedName ?? "Unknown",
      applicationBundleId: frontApp?.bundleIdentifier ?? "",
      windowTitle: getActiveWindowTitle(),
      action: shouldBlockCapture(bundleId: frontApp?.bundleIdentifier) ? .blocked : .watermarked,
      userId: NSUserName()
    )
    processEvent(event)
  }
  
  private func monitorScreenshotDirectory() {
    let desktopURL = FileManager.default.urls(for: .desktopDirectory, in: .userDomainMask).first!
    pollingTimer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { [weak self] _ in
      guard let self = self else { return }
      let files = (try? FileManager.default.contentsOfDirectory(at: desktopURL, includingPropertiesForKeys: [.creationDateKey])) ?? []
      for file in files {
        if file.lastPathComponent.hasPrefix("Screenshot"),
           let created = try? file.resourceValues(forKeys: [.creationDateKey]).creationDate,
           Date().timeIntervalSince(created) < 3.0 {
          self.handleNewScreenshotFile(at: file)
        }
      }
    }
  }
  
  private func handleNewScreenshotFile(at url: URL) {
    if watermarkEnabled { applyWatermark(to: url) }
    logger.info("Screenshot detected: \(url.lastPathComponent)")
    AuditLogger.shared.log(category: .screenCapture, severity: .medium,
      action: "screenshot_taken", description: "Screenshot: \(url.lastPathComponent)", filePath: url.path)
  }
  
  // MARK: - Screen Recording Detection
  private func monitorScreenRecording() {
    queue.async { [weak self] in
      Timer.scheduledTimer(withTimeInterval: 5.0, repeats: true) { [weak self] _ in
        self?.checkForScreenRecording()
      }
    }
  }
  
  private func checkForScreenRecording() {
    let windowList = CGWindowListCopyWindowInfo(.optionAll, kCGNullWindowID) as? [[String: Any]] ?? []
    let recordingApps = ["QuickTime Player", "OBS", "ScreenFlow", "Camtasia", "Loom"]
    for window in windowList {
      guard let ownerName = window[kCGWindowOwnerName as String] as? String else { continue }
      if recordingApps.contains(where: { ownerName.contains($0) }) {
        let event = ScreenCaptureEvent(
          id: UUID(), timestamp: Date(), eventType: .screenRecording,
          applicationName: ownerName, applicationBundleId: "",
          windowTitle: window[kCGWindowName as String] as? String,
          action: .logged, userId: NSUserName()
        )
        processEvent(event)
      }
    }
  }
  
  // MARK: - Screen Sharing Detection
  private func monitorScreenSharing() {
    NSWorkspace.shared.notificationCenter.addObserver(
      forName: NSWorkspace.didLaunchApplicationNotification, object: nil, queue: .main
    ) { [weak self] notification in
      guard let app = notification.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication,
            let bundleId = app.bundleIdentifier else { return }
      if self?.blockedApps.contains(bundleId) == true {
        AuditLogger.shared.log(category: .screenCapture, severity: .high,
          action: "screen_share_detected", outcome: "detected",
          description: "Screen sharing app: \(app.localizedName ?? bundleId)")
      }
    }
  }
  
  // MARK: - VM Detection
  private func detectVirtualMachines() {
    let vmIndicators = ["VMware", "VirtualBox", "Parallels", "QEMU", "Xen"]
    let hwModel = Host.current().localizedName ?? ""
    for indicator in vmIndicators {
      if hwModel.contains(indicator) {
        logger.warning("Virtual machine detected: \(indicator)")
        AuditLogger.shared.log(category: .screenCapture, severity: .high,
          action: "vm_detected", description: "Running inside VM: \(indicator)")
      }
    }
  }
  
  // MARK: - Watermarking
  private func applyWatermark(to imageURL: URL) {
    guard let image = NSImage(contentsOf: imageURL) else { return }
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: Int(image.size.width),
      pixelsHigh: Int(image.size.height), bitsPerSample: 8, samplesPerPixel: 4,
      hasAlpha: true, isPlanar: false, colorSpaceName: .calibratedRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    image.draw(in: NSRect(origin: .zero, size: image.size))
    let attrs: [NSAttributedString.Key: Any] = [
      .font: NSFont.systemFont(ofSize: 14, weight: .light),
      .foregroundColor: NSColor(white: 0.5, alpha: 0.3)
    ]
    let text = "\(watermarkText) | \(Date())"
    for y in stride(from: 50, to: Int(image.size.height), by: 150) {
      for x in stride(from: 50, to: Int(image.size.width), by: 400) {
        text.draw(at: NSPoint(x: x, y: y), withAttributes: attrs)
      }
    }
    NSGraphicsContext.restoreGraphicsState()
    if let pngData = rep.representation(using: .png, properties: [:]) {
      try? pngData.write(to: imageURL)
    }
    logger.debug("Watermark applied to \(imageURL.lastPathComponent)")
  }
  
  // MARK: - Helpers
  private func shouldBlockCapture(bundleId: String?) -> Bool {
    guard let id = bundleId else { return false }
    return blockedApps.contains(id)
  }
  
  private func getActiveWindowTitle() -> String? {
    let windows = CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID) as? [[String: Any]] ?? []
    return windows.first { ($0[kCGWindowLayer as String] as? Int) == 0 }?[kCGWindowName as String] as? String
  }
  
  private func processEvent(_ event: ScreenCaptureEvent) {
    AuditLogger.shared.log(category: .screenCapture,
      severity: event.action == .blocked ? .high : .medium,
      action: event.eventType.rawValue, outcome: event.action.rawValue,
      description: "\(event.eventType.rawValue) by \(event.applicationName)",
      metadata: ["bundleId": event.applicationBundleId, "window": event.windowTitle ?? ""])
  }
}
