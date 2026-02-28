// NextGuard Endpoint DLP Agent - Shared Type Definitions
// Copyright (c) 2026 NextGuard Technology Limited. All rights reserved.

import Foundation
import AppKit

// MARK: - Channel Monitor Coordinator

class ChannelMonitorCoordinator {
  static let shared = ChannelMonitorCoordinator()
  private init() {}

  private var monitors: [String: Any] = [:]

  func register(_ monitor: Any, for channel: String) {
    monitors[channel] = monitor
  }

  func startAll() {
    // Start all registered monitors
  }

  func stopAll() {
    monitors.removeAll()
  }
}

// MARK: - Menu Bar View

class MenuBarView {
  private var statusItem: NSStatusItem?

  init() {
    statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    statusItem?.button?.title = "NG"
  }

  func updateStatus(_ status: String) {
    statusItem?.button?.title = status
  }
}

// MARK: - Heartbeat Service

class HeartbeatService {
  static let shared = HeartbeatService()
  private var timer: Timer?
  private init() {}

  func start() {
    timer = Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { _ in
      // Send heartbeat to server
    }
  }

  func stop() {
    timer?.invalidate()
    timer = nil
  }
}

// MARK: - Web Activity Types (used by BrowserMonitor)

enum WebAction: String {
  case allow
  case block
  case warn
}

struct WebActivity {
  enum ActivityType: String {
    case navigation
    case download
    case upload
  }

  let url: String
  let domain: String
  let activityType: ActivityType
  let action: WebAction
  let browser: String
  let fileName: String?
  let contentLength: Int64
  let timestamp: Date
}

// MARK: - DLP Types

enum DLPChannel: String {
  case clipboard
  case file
  case email
  case browser
  case usb
  case network
  case screen
}

enum DLPSeverity: String, Comparable {
  case low
  case medium
  case high
  case critical

  static func < (lhs: DLPSeverity, rhs: DLPSeverity) -> Bool {
    let order: [DLPSeverity] = [.low, .medium, .high, .critical]
    return order.firstIndex(of: lhs)! < order.firstIndex(of: rhs)!
  }
}

enum DLPAction: String {
  case allow
  case alert
  case block
  case audit
  case encrypt
}

struct DLPViolation {
  let pattern: String
  let severity: DLPSeverity
  let matchedContent: String
  let channel: DLPChannel
  let timestamp: Date
}

// MARK: - Audit Types

enum AuditCategory: String {
  case fileActivity
  case networkActivity
  case clipboardActivity
  case usbActivity
  case emailActivity
  case browserActivity
  case screenActivity
  case policyViolation
  case systemEvent
}
