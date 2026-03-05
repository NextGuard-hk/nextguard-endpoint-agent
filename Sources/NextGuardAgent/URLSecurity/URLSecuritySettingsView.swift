//
// URLSecuritySettingsView.swift
// NextGuardAgent
//
// Copyright (c) 2026 NextGuard Technology Limited. All rights reserved.
// URL Security Settings UI - Scan URLs, manage whitelist/blacklist
//

import SwiftUI

struct URLSecuritySettingsView: View {
    @StateObject private var scanner = URLSecurityScanner.shared
    @State private var urlToScan: String = ""
    @State private var latestResult: URLScanResult? = nil
    @State private var showingResult = false
    @State private var newWhitelistDomain: String = ""
    @State private var newBlacklistDomain: String = ""
    @State private var selectedTab: Int = 0

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("URL Security").font(.headline).padding(.top, 16)

            // Status & Stats
            HStack(spacing: 16) {
                statCard("URLs Scanned", "\(scanner.scannedCount)", "doc.text.magnifyingglass", .blue)
                statCard("Threats Found", "\(scanner.threatsDetected)", "exclamationmark.triangle.fill", .red)
                statCard("Blocked", "\(scanner.blockedCount)", "hand.raised.fill", .purple)
            }

            Divider()

            // Quick Scan
            VStack(alignment: .leading, spacing: 8) {
                Text("URL Scanner").font(.subheadline.bold())
                HStack {
                    TextField("Enter URL to scan...", text: $urlToScan)
                        .textFieldStyle(.roundedBorder)
                        .onSubmit { performScan() }
                    Button(action: performScan) {
                        HStack(spacing: 4) {
                            Image(systemName: "magnifyingglass")
                            Text("Scan")
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(urlToScan.isEmpty)
                }
            }

            // Scan Result
            if let result = latestResult {
                scanResultView(result)
            }

            Divider()

            // Settings
            VStack(alignment: .leading, spacing: 8) {
                Text("Protection Settings").font(.subheadline.bold())
                Toggle("Enable URL Security", isOn: $scanner.isEnabled)
                    .toggleStyle(.switch)
                Toggle("Real-time Clipboard Monitoring", isOn: $scanner.isRealTimeEnabled)
                    .toggleStyle(.switch)
                HStack {
                    Text("Block Mode").font(.caption)
                    Spacer()
                    Picker("", selection: $scanner.blockMode) {
                        ForEach(URLSecurityScanner.BlockMode.allCases, id: \.self) { mode in
                            Text(mode.rawValue).tag(mode)
                        }
                    }
                    .frame(width: 160)
                }
            }

            Divider()

            // Tabs: History / Whitelist / Blacklist
            Picker("", selection: $selectedTab) {
                            Text("Threat Intel").tag(3)
                Text("Scan History").tag(0)
                Text("Whitelist").tag(1)
                Text("Blacklist").tag(2)
            }
            .pickerStyle(.segmented)

            if selectedTab == 0 {
                        } else if selectedTab == 3 {
            threatIntelView
                historyView
            } else if selectedTab == 1 {
                whitelistView
            } else {
                blacklistView
            }
        }
        .padding(16)
    }

    private func performScan() {
        guard !urlToScan.isEmpty else { return }
        latestResult = scanner.scanURL(urlToScan)
        showingResult = true
    }

    // MARK: - Stat Card
    private func statCard(_ title: String, _ value: String, _ icon: String, _ color: Color) -> some View {
        VStack(spacing: 4) {
            Image(systemName: icon).font(.system(size: 16)).foregroundColor(color)
            Text(value).font(.headline).foregroundColor(color)
            Text(title).font(.caption2).foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(8)
        .background(RoundedRectangle(cornerRadius: 8).fill(color.opacity(0.08)))
    }

    // MARK: - Scan Result View
    private func scanResultView(_ result: URLScanResult) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Image(systemName: result.threatLevel.icon)
                    .foregroundColor(colorForThreat(result.threatLevel))
                    .font(.title2)
                VStack(alignment: .leading, spacing: 2) {
                    Text(result.domain).font(.system(size: 13, weight: .semibold))
                    Text(result.threatLevel.rawValue)
                        .font(.caption).fontWeight(.bold)
                        .foregroundColor(colorForThreat(result.threatLevel))
                }
                Spacer()
                // Risk Score
                ZStack {
                    Circle().stroke(colorForThreat(result.threatLevel).opacity(0.3), lineWidth: 3)
                        .frame(width: 44, height: 44)
                    Circle().trim(from: 0, to: CGFloat(result.riskScore) / 100)
                        .stroke(colorForThreat(result.threatLevel), style: StrokeStyle(lineWidth: 3, lineCap: .round))
                        .frame(width: 44, height: 44)
                        .rotationEffect(.degrees(-90))
                    Text("\(result.riskScore)").font(.system(size: 12, weight: .bold))
                        .foregroundColor(colorForThreat(result.threatLevel))
                }
            }

            // Categories
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 4) {
                    ForEach(result.categories, id: \.self) { cat in
                        Text(cat.rawValue)
                            .font(.system(size: 9, weight: .medium))
                            .padding(.horizontal, 6).padding(.vertical, 2)
                            .background(Capsule().fill(colorForThreat(result.threatLevel).opacity(0.15)))
                            .foregroundColor(colorForThreat(result.threatLevel))
                    }
                }
            }

            // Details
            ForEach(result.details, id: \.self) { detail in
                HStack(alignment: .top, spacing: 6) {
                    Image(systemName: "info.circle").font(.caption2).foregroundColor(.secondary)
                    Text(detail).font(.system(size: 10)).foregroundColor(.secondary)
                }
            }

            // SSL indicator
            HStack(spacing: 4) {
                Image(systemName: result.sslValid ? "lock.fill" : "lock.open.fill")
                    .font(.caption2)
                    .foregroundColor(result.sslValid ? .green : .red)
                Text(result.sslValid ? "Encrypted (HTTPS)" : "Not Encrypted (HTTP)")
                    .font(.caption2).foregroundColor(.secondary)
            }
        }
        .padding(12)
        .background(RoundedRectangle(cornerRadius: 10).fill(
            colorForThreat(result.threatLevel).opacity(0.05)
        ))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(
            colorForThreat(result.threatLevel).opacity(0.2), lineWidth: 1
        ))
    }

    // MARK: - History View
    private var historyView: some View {
        VStack(alignment: .leading, spacing: 4) {
            if scanner.scanHistory.isEmpty {
                Text("No scan history yet. Enter a URL above to scan.")
                    .font(.caption).foregroundColor(.secondary)
                    .padding(.vertical, 20)
                    .frame(maxWidth: .infinity)
            } else {
                HStack {
                    Text("Recent Scans").font(.caption).foregroundColor(.secondary)
                    Spacer()
                    Button("Clear History") { scanner.clearHistory(); latestResult = nil }
                        .font(.caption).foregroundColor(.red)
                }
                ScrollView {
                    ForEach(scanner.scanHistory.prefix(20)) { result in
                        HStack(spacing: 8) {
                            Image(systemName: result.threatLevel.icon)
                                .font(.caption)
                                .foregroundColor(colorForThreat(result.threatLevel))
                                .frame(width: 16)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(result.domain).font(.system(size: 11, weight: .medium)).lineLimit(1)
                                Text(result.url).font(.system(size: 9)).foregroundColor(.secondary).lineLimit(1)
                            }
                            Spacer()
                            Text("\(result.riskScore)")
                                .font(.system(size: 10, weight: .bold))
                                .foregroundColor(colorForThreat(result.threatLevel))
                            Text(result.scannedAt, style: .relative)
                                .font(.system(size: 9)).foregroundColor(.secondary)
                        }
                        .padding(.vertical, 3)
                        Divider()
                    }
                }
                .frame(maxHeight: 200)
            }
        }
    }

    // MARK: - Whitelist View
    private var whitelistView: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Trusted domains that will always be allowed.")
                .font(.caption).foregroundColor(.secondary)
            HStack {
                TextField("Add trusted domain...", text: $newWhitelistDomain)
                    .textFieldStyle(.roundedBorder)
                Button("Add") {
                    scanner.addToWhitelist(newWhitelistDomain)
                    newWhitelistDomain = ""
                }.disabled(newWhitelistDomain.isEmpty)
            }
            ForEach(scanner.whitelistedDomains, id: \.self) { domain in
                HStack {
                    Image(systemName: "checkmark.shield.fill").foregroundColor(.green).font(.caption)
                    Text(domain).font(.system(size: 11))
                    Spacer()
                    Button(action: { scanner.removeFromWhitelist(domain) }) {
                        Image(systemName: "trash").font(.caption).foregroundColor(.red)
                    }.buttonStyle(.plain)
                }
            }
            if scanner.whitelistedDomains.isEmpty {
                Text("No whitelisted domains.").font(.caption).foregroundColor(.secondary)
            }
        }
    }

    // MARK: - Blacklist View
    private var blacklistView: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Blocked domains that will always be denied.")
                .font(.caption).foregroundColor(.secondary)
            HStack {
                TextField("Add blocked domain...", text: $newBlacklistDomain)
                    .textFieldStyle(.roundedBorder)
                Button("Add") {
                    scanner.addToBlacklist(newBlacklistDomain)
                    newBlacklistDomain = ""
                }.disabled(newBlacklistDomain.isEmpty)
            }
            ForEach(scanner.blacklistedDomains, id: \.self) { domain in
                HStack {
                    Image(systemName: "xmark.shield.fill").foregroundColor(.red).font(.caption)
                    Text(domain).font(.system(size: 11))
                    Spacer()
                    Button(action: { scanner.removeFromBlacklist(domain) }) {
                        Image(systemName: "trash").font(.caption).foregroundColor(.red)
                    }.buttonStyle(.plain)
                }
            }
            if scanner.blacklistedDomains.isEmpty {
                Text("No blacklisted domains.").font(.caption).foregroundColor(.secondary)
            }
        }
    }

    // MARK: - Color Helper
    private func colorForThreat(_ level: URLThreatLevel) -> Color {
        switch level {
        case .safe: return .green
        case .suspicious: return .orange
        case .dangerous: return .red
        case .blocked: return .purple
        }
    }
    
    // MARK: - Threat Intelligence Settings View

    @StateObject private var tiService = ThreatIntelligenceService.shared

    private var threatIntelView: some View {
        VStack(alignment: .leading, spacing: 12) {
            // TI Enable Toggle
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Threat Intelligence").font(.subheadline.bold())
                    Text("Query external threat databases for enterprise-grade URL protection")
                        .font(.caption).foregroundColor(.secondary)
                }
                Spacer()
                Toggle("", isOn: $tiService.isEnabled).toggleStyle(.switch)
            }

            if tiService.isEnabled {
                Divider()

                // Stats row
                HStack(spacing: 12) {
                    tiStatCard("Providers", "\(tiService.enabledProviders.count)", "server.rack", .blue)
                    tiStatCard("Queries", "\(tiService.totalQueriesCount)", "arrow.up.arrow.down", .teal)
                    tiStatCard("Threats", "\(tiService.threatsFoundCount)", "shield.lefthalf.filled", .red)
                }

                Divider()

                // Provider List
                Text("Intelligence Providers").font(.caption.bold()).foregroundColor(.secondary)

                ForEach(tiService.providers) { provider in
                    HStack(spacing: 10) {
                        Image(systemName: provider.isEnabled ? "checkmark.circle.fill" : "circle")
                            .foregroundColor(provider.isEnabled ? .green : .secondary)
                            .font(.system(size: 14))
                        VStack(alignment: .leading, spacing: 1) {
                            Text(provider.name).font(.system(size: 12, weight: .medium))
                            Text(provider.description).font(.system(size: 9)).foregroundColor(.secondary).lineLimit(1)
                        }
                        Spacer()
                        if provider.requiresAPIKey {
                            Image(systemName: provider.apiKey.isEmpty ? "key.slash" : "key.fill")
                                .font(.system(size: 11))
                                .foregroundColor(provider.apiKey.isEmpty ? .orange : .green)
                        } else {
                            Text("Free").font(.system(size: 9)).foregroundColor(.green)
                                .padding(.horizontal, 5).padding(.vertical, 2)
                                .background(Capsule().fill(Color.green.opacity(0.15)))
                        }
                    }
                    .padding(.vertical, 4)
                    .padding(.horizontal, 8)
                    .background(RoundedRectangle(cornerRadius: 6).fill(Color.primary.opacity(0.04)))
                }

                Divider()

                // Cache settings
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Result Cache").font(.caption.bold())
                        Text("Cache TI results to reduce API calls")
                            .font(.system(size: 9)).foregroundColor(.secondary)
                    }
                    Spacer()
                    Button("Clear Cache") {
                        tiService.clearCache()
                    }
                    .font(.caption)
                    .foregroundColor(.orange)
                }

                // Timeout setting
                HStack {
                    Text("Query Timeout").font(.caption)
                    Spacer()
                    Text("\(Int(tiService.queryTimeout))s")
                        .font(.caption.bold())
                        .foregroundColor(.secondary)
                }
            }
        }
    }

    private func tiStatCard(_ title: String, _ value: String, _ icon: String, _ color: Color) -> some View {
        VStack(spacing: 4) {
            Image(systemName: icon).font(.system(size: 14)).foregroundColor(color)
            Text(value).font(.subheadline.bold()).foregroundColor(color)
            Text(title).font(.system(size: 9)).foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(8)
        .background(RoundedRectangle(cornerRadius: 8).fill(color.opacity(0.08)))
    }
}
