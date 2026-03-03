//
//  AgentSettingsView.swift
//  NextGuardAgent
//
//  Agent settings panel - Console connection, scan preferences, about
//  Design inspired by Zscaler Client Connector & Forcepoint DLP Agent
//

import SwiftUI
import AppKit

struct AgentSettingsView: View {
    @EnvironmentObject var policyStore: PolicyStore
    @State private var tenantIdInput: String = ""
    @State private var consoleUrlInput: String = ""
    @State private var showSaved = false

    var body: some View {
        ScrollView {
            VStack(spacing: 12) {
                // Console Connection Section
                consoleSection

                // Monitoring Section
                monitoringSection

                // About Section
                aboutSection
            }
            .padding(12)
        }
        .onAppear {
            tenantIdInput = policyStore.agentStatus.tenantId ?? ""
            consoleUrlInput = policyStore.agentStatus.consoleUrl
        }
    }

    // MARK: - Console Connection
    var consoleSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            sectionHeader("Console Connection", icon: "cloud.fill", color: .blue)

            VStack(spacing: 8) {
                settingsRow {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Tenant ID")
                            .font(.system(size: 11, weight: .medium))
                        TextField("Enter tenant ID", text: $tenantIdInput)
                            .textFieldStyle(.plain)
                            .font(.system(size: 11))
                            .padding(6)
                            .background(RoundedRectangle(cornerRadius: 5).fill(Color(NSColor.textBackgroundColor)))
                    }
                }

                settingsRow {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Console URL")
                            .font(.system(size: 11, weight: .medium))
                        TextField("https://next-guard.com", text: $consoleUrlInput)
                            .textFieldStyle(.plain)
                            .font(.system(size: 11))
                            .padding(6)
                            .background(RoundedRectangle(cornerRadius: 5).fill(Color(NSColor.textBackgroundColor)))
                    }
                }

                HStack {
                    // Connection status indicator
                    HStack(spacing: 5) {
                        Circle()
                            .fill(policyStore.agentStatus.isConnectedToConsole ? Color.green : Color.orange)
                            .frame(width: 8, height: 8)
                        Text(policyStore.agentStatus.isConnectedToConsole ? "Connected" : "Offline")
                            .font(.system(size: 10))
                            .foregroundColor(.secondary)
                    }
                    Spacer()

                    if showSaved {
                        Text("Saved!")
                            .font(.system(size: 10))
                            .foregroundColor(.green)
                    }

                    Button("Save & Connect") {
                        saveConsoleSettings()
                    }
                    .font(.system(size: 11, weight: .medium))
                    .padding(.horizontal, 10)
                    .padding(.vertical, 5)
                    .background(RoundedRectangle(cornerRadius: 6).fill(Color.accentColor))
                    .foregroundColor(.white)
                    .buttonStyle(.plain)
                }
            }
        }
        .padding(12)
        .background(RoundedRectangle(cornerRadius: 10).fill(Color(NSColor.controlBackgroundColor)))
    }

    // MARK: - Monitoring
    var monitoringSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            sectionHeader("Monitoring Channels", icon: "eye.fill", color: .purple)

            VStack(spacing: 4) {
                monitoringRow(icon: "clipboard.fill", title: "Clipboard", subtitle: "Monitor copy/paste operations", active: true)
                Divider()
                monitoringRow(icon: "envelope.fill", title: "Email", subtitle: "Scan outgoing email attachments", active: true)
                Divider()
                monitoringRow(icon: "externaldrive.fill", title: "USB / Removable Media", subtitle: "Block unauthorised data transfers", active: true)
                Divider()
                monitoringRow(icon: "network", title: "Network Upload", subtitle: "Monitor web uploads and cloud sync", active: true)
                Divider()
                monitoringRow(icon: "printer.fill", title: "Print", subtitle: "Audit print-to-file operations", active: false)
            }
            .padding(4)
        }
        .padding(12)
        .background(RoundedRectangle(cornerRadius: 10).fill(Color(NSColor.controlBackgroundColor)))
    }

    func monitoringRow(icon: String, title: String, subtitle: String, active: Bool) -> some View {
        HStack(spacing: 10) {
            Image(systemName: icon)
                .font(.system(size: 13))
                .foregroundColor(active ? .blue : .secondary)
                .frame(width: 20)
            VStack(alignment: .leading, spacing: 1) {
                Text(title)
                    .font(.system(size: 11, weight: .medium))
                Text(subtitle)
                    .font(.system(size: 10))
                    .foregroundColor(.secondary)
            }
            Spacer()
            Text(active ? "Active" : "Off")
                .font(.system(size: 9, weight: .semibold))
                .padding(.horizontal, 7)
                .padding(.vertical, 3)
                .background(RoundedRectangle(cornerRadius: 8).fill(active ? Color.green.opacity(0.15) : Color.secondary.opacity(0.1)))
                .foregroundColor(active ? .green : .secondary)
        }
        .padding(.vertical, 4)
    }

    // MARK: - About
    var aboutSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            sectionHeader("About", icon: "info.circle.fill", color: .gray)

            VStack(spacing: 6) {
                aboutRow(label: "Version", value: policyStore.agentStatus.agentVersion)
                Divider()
                aboutRow(label: "Tenant", value: policyStore.agentStatus.tenantId ?? "Not configured")
                Divider()
                aboutRow(label: "Console", value: policyStore.agentStatus.consoleUrl)
                Divider()
                HStack {
                    Text("Open Console")
                        .font(.system(size: 11))
                        .foregroundColor(.accentColor)
                    Spacer()
                    Image(systemName: "arrow.up.right.square")
                        .font(.system(size: 11))
                        .foregroundColor(.accentColor)
                }
                .contentShape(Rectangle())
                .onTapGesture {
                    if let url = URL(string: policyStore.agentStatus.consoleUrl + "/console") {
                        NSWorkspace.shared.open(url)
                    }
                }
            }
        }
        .padding(12)
        .background(RoundedRectangle(cornerRadius: 10).fill(Color(NSColor.controlBackgroundColor)))
    }

    func aboutRow(label: String, value: String) -> some View {
        HStack {
            Text(label)
                .font(.system(size: 11))
                .foregroundColor(.secondary)
            Spacer()
            Text(value)
                .font(.system(size: 11, weight: .medium))
                .lineLimit(1)
        }
    }

    // MARK: - Helpers
    func sectionHeader(_ title: String, icon: String, color: Color) -> some View {
        HStack(spacing: 6) {
            Image(systemName: icon)
                .font(.system(size: 11))
                .foregroundColor(color)
            Text(title)
                .font(.system(size: 12, weight: .semibold))
        }
    }

    func settingsRow<Content: View>(@ViewBuilder content: () -> Content) -> some View {
        content()
    }

    private func saveConsoleSettings() {
        policyStore.agentStatus.tenantId = tenantIdInput.isEmpty ? nil : tenantIdInput
        policyStore.agentStatus.consoleUrl = consoleUrlInput.isEmpty ? "https://next-guard.com" : consoleUrlInput
        policyStore.fetchPoliciesFromConsole()
        showSaved = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
            showSaved = false
        }
    }
}
