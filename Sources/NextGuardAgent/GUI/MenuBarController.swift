//
//  MenuBarController.swift
//  NextGuardAgent
//
//  NextGuard DLP - Menu Bar Controller
//  Manages the macOS menu bar status item and dropdown menu
//

import Cocoa
import Combine
import SwiftUI

// MARK: - Menu Bar Controller

final class MenuBarController: NSObject, ObservableObject {
  private var statusItem: NSStatusItem?
  private var popover: NSPopover?
  private var mainWindowController: MainWindowController?
  private var cancellables = Set<AnyCancellable>()

  @Published var connectionStatus: ConnectionStatus = .disconnected
  @Published var agentMode: AgentMode = .standalone
  @Published var lastSyncTime: Date?
  @Published var pendingIncidentCount: Int = 0
  @Published var isProtectionActive: Bool = true

  enum ConnectionStatus: String {
    case connected = "Connected"
    case disconnected = "Disconnected"
    case syncing = "Syncing..."
    case error = "Error"

    var icon: String {
      switch self {
      case .connected: return "shield.checkmark.fill"
      case .disconnected: return "shield.slash"
      case .syncing: return "arrow.triangle.2.circlepath"
      case .error: return "exclamationmark.shield"
      }
    }

    var color: NSColor {
      switch self {
      case .connected: return .systemGreen
      case .disconnected: return .systemGray
      case .syncing: return .systemBlue
      case .error: return .systemRed
      }
    }
  }

  // MARK: - Setup

  func setupMenuBar() {
    statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)

    if let button = statusItem?.button {
      button.image = NSImage(systemSymbolName: "shield.checkmark.fill", accessibilityDescription: "NextGuard DLP")
      button.image?.size = NSSize(width: 18, height: 18)
      button.image?.isTemplate = true
      button.action = #selector(handleStatusItemClick(_:))
      button.target = self
      button.sendAction(on: [.leftMouseUp, .rightMouseUp])
    }

    buildMenu()
    startStatusMonitoring()
  }

  // MARK: - Menu Construction

  private func buildMenu() {
    let menu = NSMenu()
    menu.autoenablesItems = false

    // Header - Agent Status
    let headerItem = NSMenuItem()
    headerItem.view = createStatusHeaderView()
    menu.addItem(headerItem)
    menu.addItem(NSMenuItem.separator())

    // Protection Status
    let protectionItem = NSMenuItem(
      title: isProtectionActive ? "Protection: Active" : "Protection: Paused",
      action: nil, keyEquivalent: ""
    )
    protectionItem.image = NSImage(systemSymbolName: isProtectionActive ? "checkmark.circle.fill" : "pause.circle", accessibilityDescription: nil)
    menu.addItem(protectionItem)

    // Agent Mode
    let modeItem = NSMenuItem(
      title: "Mode: \(agentMode.rawValue.capitalized)",
      action: nil, keyEquivalent: ""
    )
    modeItem.image = NSImage(systemSymbolName: (agentMode == .managed ? "building.2.fill" : "person.fill"), accessibilityDescription: nil)
    menu.addItem(modeItem)
    menu.addItem(NSMenuItem.separator())

    // Quick Actions
    let openDashboard = NSMenuItem(title: "Open Dashboard", action: #selector(openMainWindow), keyEquivalent: "d")
    openDashboard.target = self
    menu.addItem(openDashboard)

    let viewPolicies = NSMenuItem(title: "View Policies", action: #selector(openPolicies), keyEquivalent: "p")
    viewPolicies.target = self
    menu.addItem(viewPolicies)

    let viewIncidents = NSMenuItem(title: "Incidents (\(pendingIncidentCount))", action: #selector(openIncidents), keyEquivalent: "i")
    viewIncidents.target = self
    if pendingIncidentCount > 0 {
      viewIncidents.badge = NSMenuItemBadge(count: pendingIncidentCount)
    }
    menu.addItem(viewIncidents)
    menu.addItem(NSMenuItem.separator())

    // Sync Status
    let syncItem = NSMenuItem(
      title: lastSyncTime != nil ? "Last Sync: \(formatTime(lastSyncTime!))" : "Not Synced",
      action: #selector(syncNow), keyEquivalent: "s"
    )
    syncItem.target = self
    syncItem.image = NSImage(systemSymbolName: "arrow.triangle.2.circlepath", accessibilityDescription: nil)
    menu.addItem(syncItem)
    menu.addItem(NSMenuItem.separator())

    // Settings & Quit
    let settingsItem = NSMenuItem(title: "Settings...", action: #selector(openSettings), keyEquivalent: ",")
    settingsItem.target = self
    menu.addItem(settingsItem)

    let consoleItem = NSMenuItem(title: "Open Web Console", action: #selector(openWebConsole), keyEquivalent: "")
    consoleItem.target = self
    menu.addItem(consoleItem)
    menu.addItem(NSMenuItem.separator())

    let quitItem = NSMenuItem(title: "Quit NextGuard Agent", action: #selector(quitApp), keyEquivalent: "q")
    quitItem.target = self
    menu.addItem(quitItem)

    statusItem?.menu = menu
  }

  private func createStatusHeaderView() -> NSView {
    let view = NSView(frame: NSRect(x: 0, y: 0, width: 280, height: 60))

    let iconView = NSImageView(frame: NSRect(x: 12, y: 12, width: 36, height: 36))
    iconView.image = NSImage(systemSymbolName: connectionStatus.icon, accessibilityDescription: nil)
    iconView.contentTintColor = connectionStatus.color
    view.addSubview(iconView)

    let titleLabel = NSTextField(labelWithString: "NextGuard DLP Agent")
    titleLabel.frame = NSRect(x: 56, y: 32, width: 200, height: 18)
    titleLabel.font = .boldSystemFont(ofSize: 13)
    view.addSubview(titleLabel)

    let statusLabel = NSTextField(labelWithString: connectionStatus.rawValue)
    statusLabel.frame = NSRect(x: 56, y: 14, width: 200, height: 16)
    statusLabel.font = .systemFont(ofSize: 11)
    statusLabel.textColor = connectionStatus.color
    view.addSubview(statusLabel)

    return view
  }

  // MARK: - Actions

  @objc private func handleStatusItemClick(_ sender: NSStatusBarButton) {
    guard let event = NSApp.currentEvent else { return }
    if event.type == .rightMouseUp {
      statusItem?.menu = nil
      buildMenu()
      statusItem?.button?.performClick(nil)
    }
  }

  @objc func openMainWindow() {
    if mainWindowController == nil {
      mainWindowController = MainWindowController()
    }
    mainWindowController?.showWindow(nil)
    NSApp.activate(ignoringOtherApps: true)
  }

  @objc func openPolicies() {
    openMainWindow()
    mainWindowController?.navigateTo(tab: .policies)
  }

  @objc func openIncidents() {
    openMainWindow()
    mainWindowController?.navigateTo(tab: .incidents)
  }

  @objc func openSettings() {
    openMainWindow()
    mainWindowController?.navigateTo(tab: .settings)
  }

  @objc func syncNow() {
    connectionStatus = .syncing
    updateMenuBarIcon()
    NotificationCenter.default.post(name: .init("NextGuardSyncRequested"), object: nil)
  }

  @objc func openWebConsole() {
    if let url = URL(string: "https://www.next-guard.com/console") {
      NSWorkspace.shared.open(url)
    }
  }

  @objc func quitApp() {
    NSApplication.shared.terminate(nil)
  }

  // MARK: - Status Monitoring

  private func startStatusMonitoring() {
    Timer.publish(every: 30, on: .main, in: .common)
      .autoconnect()
      .sink { [weak self] _ in
        self?.refreshStatus()
      }
      .store(in: &cancellables)
  }

  func refreshStatus() {
    buildMenu()
    updateMenuBarIcon()
  }

  func updateConnectionStatus(_ status: ConnectionStatus) {
    connectionStatus = status
    updateMenuBarIcon()
    buildMenu()
  }

  func updateIncidentCount(_ count: Int) {
    pendingIncidentCount = count
    buildMenu()
    if count > 0 {
      showIncidentBadge()
    }
  }

  private func updateMenuBarIcon() {
    if let button = statusItem?.button {
      let iconName = connectionStatus.icon
      button.image = NSImage(systemSymbolName: iconName, accessibilityDescription: "NextGuard DLP - \(connectionStatus.rawValue)")
      button.image?.isTemplate = (connectionStatus == .connected || connectionStatus == .disconnected)
    }
  }

  private func showIncidentBadge() {
    if let button = statusItem?.button {
      button.appearsDisabled = false
      // Flash the icon briefly for new incidents
      NSAnimationContext.runAnimationGroup({ context in
        context.duration = 0.3
        button.alphaValue = 0.3
      }) {
        NSAnimationContext.runAnimationGroup({ context in
          context.duration = 0.3
          button.alphaValue = 1.0
        })
      }
    }
  }

  // MARK: - Helpers

  private func formatTime(_ date: Date) -> String {
    let formatter = RelativeDateTimeFormatter()
    formatter.unitsStyle = .abbreviated
    return formatter.localizedString(for: date, relativeTo: Date())
  }

  // MARK: - Notifications

  func showNotification(title: String, body: String, isBlocked: Bool = false) {
    let notification = NSUserNotification()
    notification.title = title
    notification.informativeText = body
    notification.soundName = isBlocked ? NSUserNotificationDefaultSoundName : nil
    NSUserNotificationCenter.default.deliver(notification)
  }
}
