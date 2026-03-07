//
// AgentSettingsView.swift
// NextGuardAgent
//
// Agent settings panel - Console connection + DNS Filter toggle
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

    // DNS Filter state - reads from DNSFilter.shared
    @State private var dnsFilterEnabled: Bool = DNSFilter.shared.isEnabled
    @State private var newDomain: String = ""
    @State private var customDomains: [String] = DNSFilter.shared.customBlocklist
    @State private var showDNSDetail: Bool = false
    @State private var blockPageMessage: String = BlockPageServer.shared.customBlockMessage

    private var isLocked: Bool {
        modeManager.mode == AgentMode.managed && modeManager.managedSettingsLocked
    }

    var body: some View {
        ScrollView {
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
                // DNS Filter Section
                dnsFilterSection
                // Console Connection Section
                consoleSection
            }
            .padding(16)
        }
        .onAppear {
            tenantIdInput = policyStore.agentStatus.tenantId ?? ""
            consoleUrlInput = policyStore.agentStatus.consoleUrl
            dnsFilterEnabled = DNSFilter.shared.isEnabled
            customDomains = DNSFilter.shared.customBlocklist
            blockPageMessage = BlockPageServer.shared.customBlockMessage
        }
    }

    // MARK: - DNS Filter Section
    var dnsFilterSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            sectionHeader("DNS Filter", icon: "network.badge.shield.half.filled", color: .purple)
            VStack(spacing: 8) {
                // Enable/Disable Toggle
                settingsRow {
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("DNS Filtering")
                                .font(.system(size: 11, weight: .medium))
                            Text(dnsFilterEnabled
                                ? "Blocking \(DNSFilter.shared.blockedDomains.count) domains (incl. nba.com)"
                                : "Disabled – all domains are accessible")
                                .font(.system(size: 10))
                                .foregroundColor(.secondary)
                        }
                        Spacer()
                        Toggle("", isOn: $dnsFilterEnabled)
                            .toggleStyle(.switch)
                            .controlSize(.small)
                            .disabled(isLocked)
                            .onChange(of: dnsFilterEnabled) { newValue in
                                DNSFilter.shared.isEnabled = newValue
                            }
                    }
                }
                // Status indicator
                if dnsFilterEnabled {
                    HStack(spacing: 5) {
                        Circle()
                            .fill(DNSFilter.shared.isFiltering ? Color.green : Color.orange)
                            .frame(width: 7, height: 7)
                        Text(DNSFilter.shared.isFiltering
                            ? "Active – /etc/hosts sinkhole applied"
                            : "Starting...")
                            .font(.system(size: 10))
                            .foregroundColor(.secondary)
                        Spacer()
                    }
                    .padding(.horizontal, 4)
                    // Expand/collapse domain list
                    Button(action: { showDNSDetail.toggle() }) {
                        HStack(spacing: 4) {
                            Image(systemName: showDNSDetail ? "chevron.up" : "chevron.down")
                                .font(.system(size: 9))
                            Text(showDNSDetail ? "Hide Settings" : "Block Page Settings")
                                .font(.system(size: 10))
                        }
                        .foregroundColor(.accentColor)
                    }
                    .buttonStyle(.plain)
                    if showDNSDetail {
                        // Block Page Custom Message
                        VStack(alignment: .leading, spacing: 6) {
                            Text("Custom Block Page Message")
                                .font(.system(size: 11, weight: .medium))
                                .foregroundColor(.secondary)
                            TextEditor(text: $blockPageMessage)
                                .font(.system(size: 12))
                                .frame(minHeight: 60, maxHeight: 80)
                                .padding(6)
                                .background(Color(NSColor.controlBackgroundColor))
                                .cornerRadius(6)
                                .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.secondary.opacity(0.3)))
                            Button("Save Message") {
                                BlockPageServer.shared.customBlockMessage = blockPageMessage
                            }
                            .font(.system(size: 11))
                            .buttonStyle(.borderedProminent)
                            .controlSize(.small)
                        }
                        .padding(.bottom, 8)
                        dnsBlocklistEditor
                    }
                }
            }
        }
        .padding(12)
        .background(RoundedRectangle(cornerRadius: 10).fill(Color(NSColor.controlBackgroundColor)))
    }

    // MARK: - DNS Blocklist Editor
    var dnsBlocklistEditor: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Custom Blocked Domains")
                .font(.system(size: 10, weight: .semibold))
                .foregroundColor(.secondary)
            // Built-in notice
            HStack(spacing: 4) {
                Image(systemName: "info.circle").font(.system(size: 9)).foregroundColor(.blue)
                Text("Built-in: nba.com, nbastore.com (always blocked when DNS Filter is on)")
                    .font(.system(size: 9))
                    .foregroundColor(.secondary)
            }
            // Custom domain list
            if customDomains.isEmpty {
                Text("No custom domains added")
                    .font(.system(size: 10))
                    .foregroundColor(.secondary)
                    .padding(.vertical, 2)
            } else {
                ForEach(customDomains, id: \.self) { domain in
                    HStack {
                        Image(systemName: "xmark.circle.fill")
                            .font(.system(size: 10))
                            .foregroundColor(.red)
                            .onTapGesture {
                                DNSFilter.shared.removeDomain(domain)
                                customDomains = DNSFilter.shared.customBlocklist
                            }
                        Text(domain)
                            .font(.system(size: 10, design: .monospaced))
                        Spacer()
                    }
                }
            }
            // Add new domain
            HStack(spacing: 6) {
                TextField("e.g. youtube.com", text: $newDomain)
                    .textFieldStyle(.plain)
                    .font(.system(size: 10))
                    .padding(5)
                    .background(RoundedRectangle(cornerRadius: 4).fill(Color(NSColor.textBackgroundColor)))
                    .disabled(isLocked)
                Button("Block") {
                    guard !newDomain.isEmpty else { return }
                    DNSFilter.shared.addDomain(newDomain)
                    customDomains = DNSFilter.shared.customBlocklist
                    newDomain = ""
                }
                .font(.system(size: 10, weight: .medium))
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .background(RoundedRectangle(cornerRadius: 5).fill(Color.red.opacity(0.8)))
                .foregroundColor(.white)
                .buttonStyle(.plain)
                .disabled(isLocked || newDomain.isEmpty)
            }
        }
        .padding(8)
        .background(RoundedRectangle(cornerRadius: 8).fill(Color(NSColor.windowBackgroundColor)))
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
