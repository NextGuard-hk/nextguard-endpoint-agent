//
//  AgentStatusView.swift
//  NextGuardAgent
//
//  Protection status dashboard - inspired by Cortex XDR & Zscaler
//

import SwiftUI

struct AgentStatusView: View {
    @EnvironmentObject var policyStore: PolicyStore
    
    var body: some View {
        ScrollView {
            VStack(spacing: 12) {
                // Protection Status Card
                protectionStatusCard
                
                // Stats Row
                statsRow
                
                // Active Policies Summary
                activePoliciesSummary
                
                // Recent Activity
                recentActivitySection
            }
            .padding(12)
        }
    }
    
    // MARK: - Protection Status Card
    
    var protectionStatusCard: some View {
        VStack(spacing: 10) {
            HStack {
                // Big shield icon
                ZStack {
                    Circle()
                        .fill(protectionGradient)
                        .frame(width: 56, height: 56)
                    Image(systemName: protectionIcon)
                        .font(.system(size: 26, weight: .bold))
                        .foregroundColor(.white)
                }
                
                VStack(alignment: .leading, spacing: 4) {
                    Text(protectionTitle)
                        .font(.system(size: 16, weight: .bold))
                        .foregroundColor(protectionTitleColor)
                    Text(protectionSubtitle)
                        .font(.system(size: 11))
                        .foregroundColor(.secondary)
                }
                
                Spacer()
            }
            
            // Sync status
            if let syncTime = policyStore.agentStatus.lastSyncTime {
                HStack {
                    Image(systemName: "arrow.clockwise")
                        .font(.system(size: 10))
                        .foregroundColor(.secondary)
                    Text("Last synced \(syncTime, style: .relative)")
                        .font(.system(size: 10))
                        .foregroundColor(.secondary)
                    Spacer()
                    Button("Sync") {
                        policyStore.fetchPoliciesFromConsole()
                    }
                    .font(.system(size: 10))
                    .buttonStyle(.plain)
                    .foregroundColor(.accentColor)
                }
            } else {
                HStack {
                    Image(systemName: "exclamationmark.circle")
                        .font(.system(size: 10))
                        .foregroundColor(.orange)
                    Text("Running on local policies only")
                        .font(.system(size: 10))
                        .foregroundColor(.secondary)
                    Spacer()
                }
            }
        }
        .padding(14)
        .background(
            RoundedRectangle(cornerRadius: 10)
                .fill(Color(NSColor.controlBackgroundColor))
        )
    }
    
    // MARK: - Stats
    
    var statsRow: some View {
        HStack(spacing: 8) {
            statCard(
                value: "\(policyStore.agentStatus.totalIncidentsToday)",
                label: "Total Today",
                icon: "chart.bar",
                color: .blue
            )
            statCard(
                value: "\(policyStore.agentStatus.blockedToday)",
                label: "Blocked",
                icon: "xmark.shield.fill",
                color: .red
            )
            statCard(
                value: "\(policyStore.agentStatus.auditedToday)",
                label: "Audited",
                icon: "eye.fill",
                color: .orange
            )
        }
    }
    
    func statCard(value: String, label: String, icon: String, color: Color) -> some View {
        VStack(spacing: 4) {
            Image(systemName: icon)
                .font(.system(size: 14))
                .foregroundColor(color)
            Text(value)
                .font(.system(size: 18, weight: .bold))
            Text(label)
                .font(.system(size: 9))
                .foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 10)
        .background(RoundedRectangle(cornerRadius: 8).fill(Color(NSColor.controlBackgroundColor)))
    }
    
    // MARK: - Active Policies
    
    var activePoliciesSummary: some View {
        let enabled = policyStore.policies.filter { $0.enabled }
        let blockCount = enabled.filter { $0.action == .block }.count
        let auditCount = enabled.filter { $0.action == .audit }.count
        
        return VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Active Policies")
                    .font(.system(size: 12, weight: .semibold))
                Spacer()
                Text("\(enabled.count) enabled")
                    .font(.system(size: 10))
                    .foregroundColor(.secondary)
            }
            
            HStack(spacing: 8) {
                policyPill(count: blockCount, label: "Block", color: .red)
                policyPill(count: auditCount, label: "Audit", color: .orange)
                policyPill(count: enabled.filter { $0.action == .allow }.count, label: "Allow", color: .green)
            }
        }
        .padding(12)
        .background(RoundedRectangle(cornerRadius: 8).fill(Color(NSColor.controlBackgroundColor)))
    }
    
    func policyPill(count: Int, label: String, color: Color) -> some View {
        HStack(spacing: 4) {
            Circle().fill(color).frame(width: 7, height: 7)
            Text("\(count) \(label)")
                .font(.system(size: 10))
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
        .background(RoundedRectangle(cornerRadius: 12).fill(color.opacity(0.1)))
    }
    
    // MARK: - Recent Activity
    
    var recentActivitySection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Quick Actions")
                .font(.system(size: 12, weight: .semibold))
            
            VStack(spacing: 6) {
                quickActionRow(
                    icon: "arrow.clockwise.circle",
                    title: "Sync Policies from Console",
                    subtitle: "Fetch latest policies from \(policyStore.agentStatus.consoleUrl)",
                    color: .blue
                ) {
                    policyStore.fetchPoliciesFromConsole()
                }
                
                Divider()
                
                quickActionRow(
                    icon: "safari",
                    title: "Open Console Dashboard",
                    subtitle: "View incidents and reports",
                    color: .purple
                ) {
                    if let url = URL(string: policyStore.agentStatus.consoleUrl + "/console") {
                        NSWorkspace.shared.open(url)
                    }
                }
            }
        }
        .padding(12)
        .background(RoundedRectangle(cornerRadius: 8).fill(Color(NSColor.controlBackgroundColor)))
    }
    
    func quickActionRow(icon: String, title: String, subtitle: String, color: Color, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: 10) {
                Image(systemName: icon)
                    .font(.system(size: 16))
                    .foregroundColor(color)
                    .frame(width: 24)
                VStack(alignment: .leading, spacing: 1) {
                    Text(title)
                        .font(.system(size: 11, weight: .medium))
                        .foregroundColor(.primary)
                    Text(subtitle)
                        .font(.system(size: 10))
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                }
                Spacer()
                Image(systemName: "chevron.right")
                    .font(.system(size: 10))
                    .foregroundColor(.secondary)
            }
        }
        .buttonStyle(.plain)
    }
    
    // MARK: - Computed Helpers
    
    var protectionIcon: String {
        policyStore.agentStatus.isProtected ? "shield.fill" : "shield.slash.fill"
    }
    
    var protectionGradient: LinearGradient {
        if policyStore.agentStatus.isProtected {
            return LinearGradient(colors: [.green, .teal], startPoint: .topLeading, endPoint: .bottomTrailing)
        } else {
            return LinearGradient(colors: [.red, .orange], startPoint: .topLeading, endPoint: .bottomTrailing)
        }
    }
    
    var protectionTitle: String {
        policyStore.agentStatus.isProtected ? "Protected" : "At Risk"
    }
    
    var protectionTitleColor: Color {
        policyStore.agentStatus.isProtected ? .green : .red
    }
    
    var protectionSubtitle: String {
        let count = policyStore.policies.filter { $0.enabled }.count
        return "\(count) active \(count == 1 ? "rule" : "rules") enforced"
    }
}

#Preview {
    AgentStatusView()
        .environmentObject(PolicyStore.shared)
        .frame(width: 360, height: 350)
}
