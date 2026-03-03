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
                .fill(policyStore.agentStatus.isConnectedToConsole ? Color.green.opacity(0.12) : Color.orange.opacity(0.12))
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
                selectedTab == tab ? Color.accentColor.opacity(0.1) : Color.clear
            )
        }
        .buttonStyle(.plain)
    }
}
