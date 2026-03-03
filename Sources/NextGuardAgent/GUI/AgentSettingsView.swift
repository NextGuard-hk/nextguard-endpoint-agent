//
// AgentSettingsView.swift
// NextGuardAgent
//
// Agent settings panel - Console connection with AgentModeManager awareness
// When in managed+locked mode, fields are disabled
// Design inspired by Zscaler Client Connector & Forcepoint DLP Agent
//

import SwiftUI
import AppKit

struct AgentSettingsView: View {
    @EnvironmentObject var policyStore: PolicyStore
    @StateObject private var modeManager = AgentModeManager.shared
    @State private var tenantIdInput: String = ""
    @State private var consoleUrlInput: String = ""
    @State private var showSaved = false

    private var isLocked: Bool {
        modeManager.mode == AgentMode.managed && modeManager.managedSettingsLocked
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            // Managed Lock Banner
            if isLocked {
                HStack(spacing: 8) {
                    Image(systemName: "lock.fill").foregroundColor(.orange)
                    Text(modeManager.managedByOrgMessage)
                        .font(.caption).foregroundColor(.orange)
                }
                .padding(10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(RoundedRectangle(cornerRadius: 8).fill(Color.orange.opacity(0.08)))
            }

            // Console Connection Section
            consoleSection
        }
        .padding(16)
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
                            .disabled(isLocked)
                            .opacity(isLocked ? 0.6 : 1.0)
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
                            .disabled(isLocked)
                            .opacity(isLocked ? 0.6 : 1.0)
                    }
                }

                HStack {
                    // Connection status
                    HStack(spacing: 5) {
                        Circle()
                            .fill(policyStore.agentStatus.isConnectedToConsole ? Color.green : Color.orange)
                            .frame(width: 8, height: 8)
                        Text(policyStore.agentStatus.isConnectedToConsole ? "Connected" : "Offline")
                            .font(.system(size: 10))
                            .foregroundColor(.secondary)
                    }

                    // Agent mode indicator
                    let isManaged = modeManager.mode == AgentMode.managed
                    HStack(spacing: 4) {
                        Image(systemName: isManaged ? "building.2.fill" : "laptopcomputer")
                            .font(.system(size: 9))
                        Text(isManaged ? "Managed" : "Standalone")
                            .font(.system(size: 9))
                    }
                    .foregroundColor(isManaged ? .blue : .green)
                    .padding(.horizontal, 6).padding(.vertical, 2)
                    .background(Capsule().fill(
                        isManaged ? Color.blue.opacity(0.1) : Color.green.opacity(0.1)
                    ))

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
                    .background(RoundedRectangle(cornerRadius: 6).fill(
                        isLocked ? Color.secondary.opacity(0.3) : Color.accentColor
                    ))
                    .foregroundColor(.white)
                    .buttonStyle(.plain)
                    .disabled(isLocked)
                }
            }
        }
        .padding(12)
        .background(RoundedRectangle(cornerRadius: 10).fill(Color(NSColor.controlBackgroundColor)))
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
