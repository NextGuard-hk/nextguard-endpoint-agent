//
//  MainWindowController.swift
//  NextGuardAgent
//
//  Main application window + sidebar navigation
//  NOTE: Uses PolicyStore.shared (defined in PolicyStore.swift)
//  AgentStatusInfo, RuleAction, GUIPolicyRule defined in PolicyStore.swift
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

  convenience init() {
    // Inject PolicyStore.shared as environment object
    let contentView = MainContentView()
      .environmentObject(PolicyStore.shared)
    let hostingController = NSHostingController(rootView: contentView)
    let window = NSWindow(
      contentRect: NSRect(x: 0, y: 0, width: 960, height: 640),
      styleMask: [.titled, .closable, .miniaturizable, .resizable],
      backing: .buffered, defer: false
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
    NotificationCenter.default.post(name: .init("NextGuardNavigateTab"), object: tab.rawValue)
  }
}

// MARK: - Main Content View

struct MainContentView: View {
  @State private var selectedTab: NavigationTab = .dashboard
  @EnvironmentObject var policyStore: PolicyStore
  @StateObject private var incidentLog = IncidentLogStore()

  var body: some View {
    NavigationSplitView {
      sidebarView
    } detail: {
      detailView
    }
    .frame(minWidth: 780, minHeight: 520)
    .onReceive(NotificationCenter.default.publisher(for: .init("NextGuardNavigateTab"))) { n in
      if let tabName = n.object as? String, let tab = NavigationTab(rawValue: tabName) {
        selectedTab = tab
      }
    }
  }

  private var sidebarView: some View {
    VStack(spacing: 0) {
      VStack(spacing: 8) {
        Image(systemName: "shield.checkmark.fill")
          .font(.system(size: 32)).foregroundColor(.accentColor)
        Text("NextGuard DLP").font(.headline)
        Text(policyStore.agentStatus.isConnectedToConsole ? "Connected" : "Offline")
          .font(.caption)
          .foregroundColor(policyStore.agentStatus.isConnectedToConsole ? .green : .orange)
          .padding(.horizontal, 8).padding(.vertical, 2)
          .background(Capsule().fill(
            policyStore.agentStatus.isConnectedToConsole
              ? Color.green.opacity(0.15) : Color.orange.opacity(0.15)
          ))
      }
      .padding(.vertical, 16)
      Divider()
      List(NavigationTab.allCases, selection: $selectedTab) { tab in
        Label(tab.rawValue, systemImage: tab.icon).tag(tab)
      }
      .listStyle(.sidebar)
      Spacer()
      VStack(spacing: 4) {
        Divider()
        Text("v\(policyStore.agentStatus.agentVersion)")
          .font(.caption2).foregroundColor(.secondary)
        if let tid = policyStore.agentStatus.tenantId {
          Text(tid).font(.caption2).foregroundColor(.secondary).lineLimit(1)
        }
      }
      .padding(.bottom, 8)
    }
    .frame(minWidth: 180, idealWidth: 200, maxWidth: 220)
  }

  @ViewBuilder
  private var detailView: some View {
    switch selectedTab {
    case .dashboard: DashboardTabView()
    case .policies: PoliciesTabView()
    case .incidents: IncidentsTabView(store: incidentLog)
    case .settings: AgentSettingsContentView()
    }
  }
}

// MARK: - Dashboard Tab

struct DashboardTabView: View {
  @EnvironmentObject var policyStore: PolicyStore
  @State private var animateShield = false

  var body: some View {
    ScrollView {
      VStack(spacing: 20) {
        // Protection Status Card
        HStack(spacing: 20) {
          ZStack {
            Circle()
              .fill(policyStore.agentStatus.isProtected ? Color.green.opacity(0.15) : Color.red.opacity(0.15))
              .frame(width: 80, height: 80)
            Image(systemName: policyStore.agentStatus.isProtected ? "shield.checkmark.fill" : "shield.slash.fill")
              .font(.system(size: 36))
              .foregroundColor(policyStore.agentStatus.isProtected ? .green : .red)
              .scaleEffect(animateShield ? 1.05 : 1.0)
          }
          .onAppear {
            withAnimation(.easeInOut(duration: 2).repeatForever(autoreverses: true)) {
              animateShield = true
            }
          }
          VStack(alignment: .leading, spacing: 6) {
            Text(policyStore.agentStatus.isProtected ? "Protection Active" : "Protection Paused")
              .font(.title2.bold())
            Text(policyStore.agentStatus.isConnectedToConsole
              ? "Connected to NextGuard Console"
              : "Offline Mode — Local Policies Active")
              .font(.subheadline).foregroundColor(.secondary)
            if let sync = policyStore.agentStatus.lastSyncTime {
              Label("Synced \(sync, style: .relative)", systemImage: "arrow.triangle.2.circlepath")
                .font(.caption).foregroundColor(.secondary)
            }
          }
          Spacer()
          Button("Sync Now") {
            NotificationCenter.default.post(name: .init("NextGuardSyncRequested"), object: nil)
          }
        }
        .padding(20)
        .background(RoundedRectangle(cornerRadius: 12).fill(Color(nsColor: .controlBackgroundColor)))
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(
          policyStore.agentStatus.isProtected ? Color.green.opacity(0.3) : Color.red.opacity(0.3), lineWidth: 1
        ))

        // Stats Grid
        LazyVGrid(columns: Array(repeating: GridItem(.flexible()), count: 4), spacing: 16) {
          DashStatCard(title: "Active Policies",
            value: "\(policyStore.policies.filter { $0.enabled }.count)",
            icon: "doc.text.fill", color: .blue)
          DashStatCard(title: "Today Incidents",
            value: "\(policyStore.agentStatus.totalIncidentsToday)",
            icon: "exclamationmark.triangle.fill", color: .orange)
          DashStatCard(title: "Blocked",
            value: "\(policyStore.agentStatus.blockedToday)",
            icon: "xmark.shield.fill", color: .red)
          DashStatCard(title: "Audited",
            value: "\(policyStore.agentStatus.auditedToday)",
            icon: "eye.fill", color: .purple)
        }
      }
      .padding(24)
    }
    .frame(maxWidth: .infinity, maxHeight: .infinity)
  }
}

struct DashStatCard: View {
  let title: String; let value: String; let icon: String; let color: Color
  var body: some View {
    VStack(spacing: 8) {
      Image(systemName: icon).font(.title2).foregroundColor(color)
      Text(value).font(.title.bold())
      Text(title).font(.caption).foregroundColor(.secondary)
    }
    .frame(maxWidth: .infinity).padding(16)
    .background(RoundedRectangle(cornerRadius: 10).fill(Color(nsColor: .controlBackgroundColor)))
    .overlay(RoundedRectangle(cornerRadius: 10).stroke(color.opacity(0.2), lineWidth: 1))
  }
}

// MARK: - Policies Tab

struct PoliciesTabView: View {
  @EnvironmentObject var policyStore: PolicyStore

  var body: some View {
    VStack(spacing: 0) {
      HStack {
        Image(systemName: "doc.text.fill").foregroundColor(.blue)
        Text("DLP Policies").font(.title2.bold())
        Spacer()
      }
      .padding(16)
      Divider()
      List(policyStore.policies) { policy in
        HStack {
          Circle()
            .fill(policy.action == .block ? Color.red : policy.action == .audit ? Color.orange : Color.green)
            .frame(width: 8, height: 8)
          VStack(alignment: .leading, spacing: 2) {
            Text(policy.name).font(.body.bold())
            Text(policy.description).font(.caption).foregroundColor(.secondary)
          }
          Spacer()
          Text(policy.action.displayName)
            .font(.caption).padding(.horizontal, 8).padding(.vertical, 3)
            .background(Capsule().fill(
              policy.action == .block ? Color.red.opacity(0.15) :
              policy.action == .audit ? Color.orange.opacity(0.15) : Color.green.opacity(0.15)
            ))
          Toggle("", isOn: Binding(
            get: { policy.enabled },
            set: { _ in policyStore.togglePolicy(policy) }
          ))
          .labelsHidden()
        }
        .padding(.vertical, 4)
      }
    }
    .frame(maxWidth: .infinity, maxHeight: .infinity)
  }
}

// MARK: - Incident Log Store

class IncidentLogStore: ObservableObject {
  @Published var incidents: [LocalIncident] = []
  struct LocalIncident: Identifiable {
    let id = UUID()
    var timestamp: Date
    var policyName: String
    var action: String
    var details: String
    var severity: String
  }
}

// MARK: - Incidents Tab

struct IncidentsTabView: View {
  @ObservedObject var store: IncidentLogStore
  @State private var searchText = ""

  var body: some View {
    VStack(spacing: 0) {
      HStack {
        Image(systemName: "exclamationmark.triangle.fill").foregroundColor(.orange)
        Text("Incident Log").font(.title2.bold())
        Spacer()
        TextField("Search...", text: $searchText)
          .textFieldStyle(.roundedBorder).frame(width: 200)
      }
      .padding(16)
      Divider()
      if store.incidents.isEmpty {
        VStack(spacing: 12) {
          Image(systemName: "checkmark.shield").font(.system(size: 48)).foregroundColor(.green)
          Text("No Incidents").font(.title3.bold())
          Text("No DLP violations detected on this endpoint.").foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
      } else {
        List(store.incidents.filter { i in
          searchText.isEmpty || i.policyName.localizedCaseInsensitiveContains(searchText)
        }) { incident in
          HStack {
            Circle()
              .fill(incident.action == "Block" ? Color.red : Color.orange)
              .frame(width: 8, height: 8)
            VStack(alignment: .leading) {
              Text(incident.policyName).font(.body.bold())
              Text(incident.timestamp, style: .relative).font(.caption).foregroundColor(.secondary)
            }
            Spacer()
            Text(incident.action).font(.caption)
          }
        }
      }
    }
    .frame(maxWidth: .infinity, maxHeight: .infinity)
  }
}
