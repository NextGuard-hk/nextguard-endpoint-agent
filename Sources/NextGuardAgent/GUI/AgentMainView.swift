//
//  AgentMainView.swift
//  NextGuardAgent
//
//  Main popover view - inspired by Zscaler Client Connector & Cortex XDR
//

import SwiftUI

struct AgentMainView: View {
    @EnvironmentObject var policyStore: PolicyStore
    @State private var selectedTab: AgentTab = .status
    
    enum AgentTab {
        case status, policies, settings
    }
    
    var body: some View {
        VStack(spacing: 0) {
            // Header
            headerView
            
            // Tab Bar
            tabBar
            
            // Content
            Group {
                switch selectedTab {
                case .status:
                    AgentStatusView()
                        .environmentObject(policyStore)
                case .policies:
                    PolicyManagementView()
                        .environmentObject(policyStore)
                case .settings:
                    AgentSettingsView()
                        .environmentObject(policyStore)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .frame(width: 360, height: 480)
        .background(Color(NSColor.windowBackgroundColor))
    }
    
    // MARK: - Header
    
    var headerView: some View {
        HStack(spacing: 10) {
            // Logo
            ZStack {
                RoundedRectangle(cornerRadius: 8)
                    .fill(LinearGradient(
                        colors: [Color.blue, Color.purple],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    ))
                    .frame(width: 36, height: 36)
                Image(systemName: "shield.fill")
                    .foregroundColor(.white)
                    .font(.system(size: 18, weight: .bold))
            }
            
            VStack(alignment: .leading, spacing: 2) {
                Text("NextGuard Agent")
                    .font(.system(size: 14, weight: .bold))
                Text("v\(policyStore.agentStatus.agentVersion)")
                    .font(.system(size: 11))
                    .foregroundColor(.secondary)
            }
            
            Spacer()
            
            // Connection Status Pill
            connectionBadge
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 12)
        .background(Color(NSColor.controlBackgroundColor))
    }
    
    var connectionBadge: some View {
        HStack(spacing: 4) {
            Circle()
                .fill(policyStore.agentStatus.isConnectedToConsole ? Color.green : Color.orange)
                .frame(width: 7, height: 7)
            Text(policyStore.agentStatus.isConnectedToConsole ? "Console" : "Local")
                .font(.system(size: 10, weight: .medium))
                .foregroundColor(policyStore.agentStatus.isConnectedToConsole ? .green : .orange)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
        .background(
            RoundedRectangle(cornerRadius: 10)
                .fill(policyStore.agentStatus.isConnectedToConsole
                      ? Color.green.opacity(0.12)
                      : Color.orange.opacity(0.12))
        )
    }
    
    // MARK: - Tab Bar
    
    var tabBar: some View {
        HStack(spacing: 0) {
            tabButton(title: "Status", icon: "shield.checkered", tab: .status)
            tabButton(title: "Policies", icon: "doc.text.magnifyingglass", tab: .policies)
            tabButton(title: "Settings", icon: "gearshape", tab: .settings)
        }
        .background(Color(NSColor.controlBackgroundColor))
        .overlay(Divider(), alignment: .bottom)
    }
    
    func tabButton(title: String, icon: String, tab: AgentTab) -> some View {
        Button(action: { selectedTab = tab }) {
            VStack(spacing: 3) {
                Image(systemName: icon)
                    .font(.system(size: 14))
                Text(title)
                    .font(.system(size: 10))
            }
            .foregroundColor(selectedTab == tab ? .accentColor : .secondary)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 8)
            .background(
                selectedTab == tab
                    ? Color.accentColor.opacity(0.1)
                    : Color.clear
            )
        }
        .buttonStyle(.plain)
    }
}

// MARK: - Settings View

struct AgentSettingsView: View {
    @EnvironmentObject var policyStore: PolicyStore
    @State private var consoleUrl: String = ""
    @State private var tenantId: String = ""
    @State private var showSaved = false
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                // Console Connection
                settingsSection(title: "Console Connection") {
                    VStack(alignment: .leading, spacing: 8) {
                        Label("Console URL", systemImage: "link")
                            .font(.system(size: 11, weight: .medium))
                            .foregroundColor(.secondary)
                        TextField("https://next-guard.com", text: $consoleUrl)
                            .textFieldStyle(.roundedBorder)
                            .font(.system(size: 12))
                        
                        Label("Tenant ID", systemImage: "person.2")
                            .font(.system(size: 11, weight: .medium))
                            .foregroundColor(.secondary)
                            .padding(.top, 4)
                        TextField("tenant-id", text: $tenantId)
                            .textFieldStyle(.roundedBorder)
                            .font(.system(size: 12))
                    }
                }
                
                // Sync
                settingsSection(title: "Sync") {
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Last sync")
                                .font(.system(size: 12))
                            if let syncTime = policyStore.agentStatus.lastSyncTime {
                                Text(syncTime, style: .relative)
                                    .font(.system(size: 11))
                                    .foregroundColor(.secondary)
                            } else {
                                Text("Never")
                                    .font(.system(size: 11))
                                    .foregroundColor(.secondary)
                            }
                        }
                        Spacer()
                        Button("Sync Now") {
                            policyStore.fetchPoliciesFromConsole()
                        }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                    }
                }
                
                // Save Button
                Button(action: saveSettings) {
                    HStack {
                        Spacer()
                        if showSaved {
                            Label("Saved!", systemImage: "checkmark.circle.fill")
                                .foregroundColor(.green)
                        } else {
                            Text("Save Settings")
                        }
                        Spacer()
                    }
                }
                .buttonStyle(.borderedProminent)
                .padding(.top, 8)
            }
            .padding(14)
        }
        .onAppear {
            consoleUrl = policyStore.agentStatus.consoleUrl
            tenantId = policyStore.agentStatus.tenantId ?? ""
        }
    }
    
    func settingsSection<Content: View>(title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(.system(size: 12, weight: .semibold))
                .foregroundColor(.primary)
            content()
        }
        .padding(12)
        .background(RoundedRectangle(cornerRadius: 8).fill(Color(NSColor.controlBackgroundColor)))
    }
    
    func saveSettings() {
        policyStore.agentStatus.consoleUrl = consoleUrl
        policyStore.agentStatus.tenantId = tenantId.isEmpty ? nil : tenantId
        
        withAnimation {
            showSaved = true
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
            showSaved = false
        }
    }
}

#Preview {
    AgentMainView()
        .environmentObject(PolicyStore.shared)
}
