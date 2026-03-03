//
//  MainWindowController.swift
//  NextGuardAgent
//
//  Main application window controller with sidebar navigation
//  Inspired by Forcepoint DLP, Palo Alto Cortex XDR, McAfee DLP, Zscaler Agent UIs
//

import Cocoa
import SwiftUI
import Combine

// MARK: - Navigation Tab

enum NavigationTab: String, CaseIterable, Identifiable {
  case dashboard = "Dashboard"
  case policies = "Policies"
  case incidents = "Incidents"
  case settings = "Settings"

  var id: String { rawValue }

  var icon: String {
    switch self {
    case .dashboard: return "shield.checkmark.fill"
    case .policies: return "doc.text.fill"
    case .incidents: return "exclamationmark.triangle.fill"
    case .settings: return "gearshape.fill"
    }
  }
}

// MARK: - Main Window Controller

final class MainWindowController: NSWindowController, ObservableObject {
  @Published var selectedTab: NavigationTab = .dashboard
  @Published var agentStatus = AgentStatusInfo()

  private var cancellables = Set<AnyCancellable>()

  convenience init() {
    let contentView = MainContentView()
    let hostingController = NSHostingController(rootView: contentView)

    let window = NSWindow(
      contentRect: NSRect(x: 0, y: 0, width: 960, height: 640),
      styleMask: [.titled, .closable, .miniaturizable, .resizable],
      backing: .buffered,
      defer: false
    )
    window.title = "NextGuard DLP Agent"
    window.center()
    window.setFrameAutosaveName("NextGuardMainWindow")
    window.contentViewController = hostingController
    window.minSize = NSSize(width: 780, height: 520)
    window.isReleasedWhenClosed = false
    window.titlebarAppearsTransparent = true
    window.titleVisibility = .hidden
    window.toolbarStyle = .unified

    self.init(window: window)
  }

  func navigateTo(tab: NavigationTab) {
    selectedTab = tab
    NotificationCenter.default.post(
      name: .init("NextGuardNavigateTab"),
      object: tab.rawValue
    )
  }
}

// MARK: - Agent Status Info

struct AgentStatusInfo {
  var isConnected: Bool = false
  var protectionEnabled: Bool = true
  var agentVersion: String = "1.0.0"
  var lastPolicySync: Date?
  var activePolicyCount: Int = 0
  var todayIncidentCount: Int = 0
  var todayBlockCount: Int = 0
  var todayAuditCount: Int = 0
  var endpointId: String = ""
  var enrollmentStatus: String = "Not Enrolled"
}

// MARK: - Main Content View (SwiftUI)

struct MainContentView: View {
  @State private var selectedTab: NavigationTab = .dashboard
  @State private var agentStatus = AgentStatusInfo()
  @StateObject private var policyStore = PolicyStoreManager()
  @StateObject private var incidentStore = IncidentStoreManager()

  var body: some View {
    NavigationSplitView {
      sidebarView
    } detail: {
      detailView
    }
    .frame(minWidth: 780, minHeight: 520)
    .onReceive(NotificationCenter.default.publisher(for: .init("NextGuardNavigateTab"))) { notification in
      if let tabName = notification.object as? String,
         let tab = NavigationTab(rawValue: tabName) {
        selectedTab = tab
      }
    }
  }

  // MARK: - Sidebar

  private var sidebarView: some View {
    VStack(spacing: 0) {
      // Agent Header
      VStack(spacing: 8) {
        Image(systemName: "shield.checkmark.fill")
          .font(.system(size: 32))
          .foregroundColor(.accentColor)
        Text("NextGuard DLP")
          .font(.headline)
        Text(agentStatus.isConnected ? "Connected" : "Disconnected")
          .font(.caption)
          .foregroundColor(agentStatus.isConnected ? .green : .red)
          .padding(.horizontal, 8)
          .padding(.vertical, 2)
          .background(
            Capsule()
              .fill(agentStatus.isConnected ? Color.green.opacity(0.15) : Color.red.opacity(0.15))
          )
      }
      .padding(.vertical, 16)

      Divider()

      // Navigation Items
      List(NavigationTab.allCases, selection: $selectedTab) { tab in
        Label(tab.rawValue, systemImage: tab.icon)
          .tag(tab)
      }
      .listStyle(.sidebar)

      Spacer()

      // Footer - Version
      VStack(spacing: 4) {
        Divider()
        Text("v\(agentStatus.agentVersion)")
          .font(.caption2)
          .foregroundColor(.secondary)
        Text(agentStatus.enrollmentStatus)
          .font(.caption2)
          .foregroundColor(.secondary)
      }
      .padding(.bottom, 8)
    }
    .frame(minWidth: 180, idealWidth: 200, maxWidth: 220)
  }

  // MARK: - Detail View

  @ViewBuilder
  private var detailView: some View {
    switch selectedTab {
    case .dashboard:
      StatusDashboardView(status: $agentStatus)
    case .policies:
      PolicyManagementContentView(store: policyStore)
    case .incidents:
      IncidentLogContentView(store: incidentStore)
    case .settings:
      AgentSettingsContentView()
    }
  }
}

// MARK: - Policy Store Manager

class PolicyStoreManager: ObservableObject {
  @Published var policies: [LocalPolicy] = []
  @Published var isLoading: Bool = false

  struct LocalPolicy: Identifiable {
    let id = UUID()
    var name: String
    var description: String
    var action: PolicyAction
    var isEnabled: Bool
    var category: String
    var patterns: [String]
    var source: PolicySource
    var lastUpdated: Date
  }

  enum PolicyAction: String, CaseIterable {
    case block = "Block"
    case audit = "Audit"
    case allow = "Allow"
    case encrypt = "Encrypt"

    var icon: String {
      switch self {
      case .block: return "xmark.shield.fill"
      case .audit: return "eye.fill"
      case .allow: return "checkmark.shield"
      case .encrypt: return "lock.shield.fill"
      }
    }

    var color: Color {
      switch self {
      case .block: return .red
      case .audit: return .orange
      case .allow: return .green
      case .encrypt: return .blue
      }
    }
  }

  enum PolicySource: String {
    case server = "Server"
    case local = "Local"
  }

  func loadPolicies() {
    isLoading = true
    // Load from local storage and merge with server policies
    DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { [weak self] in
      self?.isLoading = false
    }
  }

  func addLocalPolicy(_ policy: LocalPolicy) {
    policies.append(policy)
    savePolicies()
  }

  func togglePolicy(_ policy: LocalPolicy) {
    if let index = policies.firstIndex(where: { $0.id == policy.id }) {
      policies[index].isEnabled.toggle()
      savePolicies()
    }
  }

  func deletePolicy(_ policy: LocalPolicy) {
    policies.removeAll { $0.id == policy.id }
    savePolicies()
  }

  private func savePolicies() {
    // Persist to local storage
  }
}

// MARK: - Incident Store Manager

class IncidentStoreManager: ObservableObject {
  @Published var incidents: [DLPIncident] = []
  @Published var isLoading: Bool = false

  struct DLPIncident: Identifiable {
    let id = UUID()
    var timestamp: Date
    var policyName: String
    var action: String
    var filePath: String
    var destination: String
    var severity: Severity
    var details: String
    var isAcknowledged: Bool = false
  }

  enum Severity: String, CaseIterable {
    case critical = "Critical"
    case high = "High"
    case medium = "Medium"
    case low = "Low"

    var color: Color {
      switch self {
      case .critical: return .red
      case .high: return .orange
      case .medium: return .yellow
      case .low: return .green
      }
    }
  }

  func loadIncidents() {
    isLoading = true
    DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { [weak self] in
      self?.isLoading = false
    }
  }

  func acknowledgeIncident(_ incident: DLPIncident) {
    if let index = incidents.firstIndex(where: { $0.id == incident.id }) {
      incidents[index].isAcknowledged = true
    }
  }
}
