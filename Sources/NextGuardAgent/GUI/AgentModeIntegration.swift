//
// AgentModeIntegration.swift
// NextGuardAgent
//
// Integration layer: connects AgentModeManager + LocalPolicyEngine
// to the GUI views (Dashboard, Policies, Settings, Sidebar)
// This file provides agent-mode-aware replacement views
//

import SwiftUI

// MARK: - Agent-Mode-Aware Settings Content View
// Replaces AgentSettingsContentView() in MainWindowController detailView
struct AgentSettingsContentView: View {
    @StateObject private var modeManager = AgentModeManager.shared
    @State private var selectedSection: SettingsSection = .connection

    enum SettingsSection: String, CaseIterable, Identifiable {
        case connection = "Connection"
        case enrollment = "Organisation"
        case monitoring = "Monitoring"
        case about = "About"
        var id: String { rawValue }
    }

    var body: some View {
        VStack(spacing: 0) {
            // Settings Header
            HStack {
                Image(systemName: "gearshape.fill").foregroundColor(.secondary)
                Text("Settings").font(.title2.bold())
                Spacer()
                // Agent Mode Badge
                agentModeBadge
            }
            .padding(16)
            Divider()

            HStack(spacing: 0) {
                // Settings sidebar
                VStack(spacing: 2) {
                    ForEach(SettingsSection.allCases) { section in
                        settingsSidebarItem(section)
                    }
                    Spacer()
                }
                .frame(width: 160)
                .padding(.vertical, 8)

                Divider()

                // Content
                ScrollView {
                    switch selectedSection {
                    case .connection:
                        AgentSettingsView()
                    case .enrollment:
                        EnrollmentView()
                    case .monitoring:
                        monitoringSection
                    case .about:
                        aboutSection
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func settingsSidebarItem(_ section: SettingsSection) -> some View {
        Button(action: { selectedSection = section }) {
            HStack {
                Image(systemName: iconFor(section))
                    .frame(width: 20)
                Text(section.rawValue)
                    .font(.system(size: 12))
                Spacer()
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
            .background(selectedSection == section ?
                Color.accentColor.opacity(0.12) : Color.clear)
            .cornerRadius(6)
        }
        .buttonStyle(.plain)
        .padding(.horizontal, 8)
    }

    private func iconFor(_ section: SettingsSection) -> String {
        switch section {
        case .connection: return "cloud.fill"
        case .enrollment: return "building.2.fill"
        case .monitoring: return "eye.fill"
        case .about: return "info.circle.fill"
        }
    }

    private var agentModeBadge: some View {
        let isManaged = modeManager.mode == AgentMode.managed
        return HStack(spacing: 6) {
            Circle()
                .fill(isManaged ? Color.blue : Color.green)
                .frame(width: 8, height: 8)
            Text(isManaged ? "Managed" : "Standalone")
                .font(.caption).fontWeight(.medium)
        }
        .padding(.horizontal, 10).padding(.vertical, 4)
        .background(Capsule().fill(
            isManaged ?
            Color.blue.opacity(0.12) : Color.green.opacity(0.12)
        ))
    }

    // MARK: - Monitoring Section
    private var monitoringSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Monitoring Channels").font(.headline).padding(.top, 16)

            let channels: [(String, String, String, Bool)] = [
                ("clipboard.fill", "Clipboard", "Monitor copy/paste operations", true),
                ("envelope.fill", "Email", "Scan outgoing email attachments", true),
                ("externaldrive.fill", "USB / Removable Media", "Block unauthorised transfers", true),
                ("network", "Network Upload", "Monitor web uploads and cloud sync", true),
                ("printer.fill", "Print", "Audit print-to-file operations", false),
            ]

            ForEach(channels, id: \.1) { icon, title, subtitle, active in
                HStack(spacing: 10) {
                    Image(systemName: icon)
                        .font(.system(size: 14))
                        .foregroundColor(active ? .blue : .secondary)
                        .frame(width: 22)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(title).font(.system(size: 12, weight: .medium))
                        Text(subtitle).font(.system(size: 10)).foregroundColor(.secondary)
                    }
                    Spacer()
                    Text(active ? "Active" : "Off")
                        .font(.system(size: 10, weight: .semibold))
                        .padding(.horizontal, 8).padding(.vertical, 3)
                        .background(RoundedRectangle(cornerRadius: 8).fill(
                            active ? Color.green.opacity(0.15) : Color.secondary.opacity(0.1)
                        ))
                        .foregroundColor(active ? .green : .secondary)
                }
                .padding(.vertical, 4)
                if title != "Print" { Divider() }
            }

            if modeManager.managedSettingsLocked {
                HStack(spacing: 6) {
                    Image(systemName: "lock.fill").foregroundColor(.orange).font(.caption)
                    Text("Monitoring channels are managed by your organisation.")
                        .font(.caption).foregroundColor(.orange)
                }
                .padding(8)
                .background(RoundedRectangle(cornerRadius: 6).fill(Color.orange.opacity(0.08)))
            }
        }
        .padding(16)
    }

    // MARK: - About Section
    private var aboutSection: some View {
        let isManaged = modeManager.mode == AgentMode.managed
        return VStack(alignment: .leading, spacing: 10) {
            Text("About NextGuard Agent").font(.headline).padding(.top, 16)

            VStack(spacing: 0) {
                aboutRow("Version", AgentConfig.shared.agentVersion)
                Divider()
                aboutRow("Agent Mode", isManaged ? "Managed" : "Standalone")
                Divider()
                if let device = modeManager.enrolledDevice {
                    aboutRow("Tenant", device.tenantName)
                    Divider()
                    aboutRow("Device ID", String(device.deviceId.prefix(16)) + "...")
                    Divider()
                    aboutRow("Console", device.consoleUrl)
                    Divider()
                }
                aboutRow("Engine", "LocalPolicyEngine + PolicyHierarchyEngine")
            }
            .background(RoundedRectangle(cornerRadius: 10).fill(Color(NSColor.controlBackgroundColor)))
        }
        .padding(16)
    }

    private func aboutRow(_ label: String, _ value: String) -> some View {
        HStack {
            Text(label).font(.system(size: 11)).foregroundColor(.secondary)
            Spacer()
            Text(value).font(.system(size: 11, weight: .medium)).lineLimit(1)
        }
        .padding(.horizontal, 12).padding(.vertical, 7)
    }
}

// MARK: - Enhanced Dashboard with Agent Mode
struct AgentModeDashboardOverlay: View {
    @StateObject private var modeManager = AgentModeManager.shared
    @StateObject private var engine = LocalPolicyEngine.shared

    var body: some View {
        let isManaged = modeManager.mode == AgentMode.managed
        VStack(spacing: 12) {
            // Agent Mode Banner
            HStack(spacing: 10) {
                Image(systemName: isManaged ? "building.2.fill" : "laptopcomputer")
                    .foregroundColor(isManaged ? .blue : .green)
                VStack(alignment: .leading, spacing: 2) {
                    Text(isManaged ? "Managed Mode" : "Standalone Mode")
                        .font(.subheadline.bold())
                    if isManaged {
                        Text(modeManager.enrolledDevice?.tenantName ?? "Organisation")
                            .font(.caption).foregroundColor(.secondary)
                    } else {
                        Text("Local policies active \u{2022} \(engine.localRules.filter { $0.isEnabled }.count) rules")
                            .font(.caption).foregroundColor(.secondary)
                    }
                }
                Spacer()
                if isManaged {
                    // Console reachability
                    HStack(spacing: 4) {
                        Circle()
                            .fill(modeManager.isConsoleReachable ? Color.green : Color.orange)
                            .frame(width: 6, height: 6)
                        Text(modeManager.isConsoleReachable ? "Console Online" : "Offline")
                            .font(.caption2).foregroundColor(.secondary)
                    }
                }
            }
            .padding(12)
            .background(RoundedRectangle(cornerRadius: 10).fill(
                isManaged ?
                Color.blue.opacity(0.06) : Color.green.opacity(0.06)
            ))
            .overlay(RoundedRectangle(cornerRadius: 10).stroke(
                isManaged ?
                Color.blue.opacity(0.15) : Color.green.opacity(0.15),
                lineWidth: 1
            ))

            // Policy Engine Stats
            HStack(spacing: 16) {
                miniStat("Local Rules", "\(engine.localRules.count)", .blue)
                miniStat("Server Rules", "\(engine.serverRules.count)", .purple)
                miniStat("Active", "\(engine.allActiveRules.count)", .green)
                miniStat("Mode", engine.agentMode.rawValue, .orange)
            }
        }
    }

    private func miniStat(_ label: String, _ value: String, _ color: Color) -> some View {
        VStack(spacing: 4) {
            Text(value).font(.headline).foregroundColor(color)
            Text(label).font(.caption2).foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(8)
        .background(RoundedRectangle(cornerRadius: 8).fill(Color(NSColor.controlBackgroundColor)))
    }
}

// MARK: - Sidebar Agent Mode Badge (for MainContentView sidebar)
struct SidebarAgentBadge: View {
    @StateObject private var modeManager = AgentModeManager.shared

    var body: some View {
        let isManaged = modeManager.mode == AgentMode.managed
        VStack(spacing: 4) {
            Divider()
            HStack(spacing: 6) {
                Image(systemName: isManaged ? "building.2.fill" : "laptopcomputer")
                    .font(.caption2)
                    .foregroundColor(isManaged ? .blue : .green)
                Text(isManaged ? "Managed" : "Standalone")
                    .font(.caption2).fontWeight(.medium)
                    .foregroundColor(isManaged ? .blue : .green)
            }
            .padding(.horizontal, 10).padding(.vertical, 4)
            .background(Capsule().fill(
                isManaged ?
                Color.blue.opacity(0.1) : Color.green.opacity(0.1)
            ))
            if isManaged, let name = modeManager.enrolledDevice?.tenantName {
                Text(name)
                    .font(.caption2)
                    .foregroundColor(.secondary)
                    .lineLimit(1)
            }
        }
        .padding(.bottom, 4)
    }
}

// MARK: - OfflineQueueManager stub (referenced by AgentModeManager)
class OfflineQueueManager {
    static let shared = OfflineQueueManager()
    func enterOfflineMode() {
        print("[OfflineQueue] Entered offline mode - caching incidents locally")
    }
        func enqueueAuditEvent(_ entry: TamperAuditEntry) {
        print("[OfflineQueue] Queued audit event: \(entry.action)")
    }
    func flushQueueIfNeeded() {
        print("[OfflineQueue] Flushing queued incidents to Console")
    }
}
