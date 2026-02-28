//
// SharedTypes.swift
// NextGuard Endpoint DLP Agent - Shared Type Definitions
//
// Copyright (c) 2026 NextGuard Technology Limited. All rights reserved.
//

import Foundation
import SwiftUI
import AppKit
import os.log

// MARK: - Channel Monitor Coordinator

class ChannelMonitorCoordinator {
    static let shared = ChannelMonitorCoordinator()
    private init() {}

    private var monitors: [String: Any] = [:]

    func register(_ monitor: Any, for channel: String) {
        monitors[channel] = monitor
    }

    func startAll() {
        // Start all registered monitors
        for (channel, _) in monitors {
            Logger(subsystem: "com.nextguard.agent", category: "ChannelCoordinator")
                .info("Starting monitor for channel: \(channel)")
        }
    }

    func stopAll() {
        monitors.removeAll()
    }
}

// MARK: - SwiftUI Menu Bar View

struct NextGuardMenuBarView: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("NextGuard DLP Active", systemImage: "shield.checkered")
                .font(.headline)
            Divider()
            Text("Monitoring all channels")
                .font(.caption)
                .foregroundColor(.secondary)
            Divider()
            Button("Open Dashboard") {
                NSWorkspace.shared.open(URL(string: "https://console.next-guard.com")!)
            }
            Button("Quit NextGuard") {
                NSApplication.shared.terminate(nil)
            }
        }
        .padding()
        .frame(width: 240)
    }
}

// MARK: - SwiftUI Settings View

struct NextGuardSettingsView: View {
    var body: some View {
        TabView {
            GeneralSettingsTab()
                .tabItem { Label("General", systemImage: "gear") }
            PolicySettingsTab()
                .tabItem { Label("Policies", systemImage: "shield") }
            AboutSettingsTab()
                .tabItem { Label("About", systemImage: "info.circle") }
        }
        .padding()
        .frame(width: 500, height: 400)
    }
}

private struct GeneralSettingsTab: View {
    var body: some View {
        Form {
            Text("NextGuard Endpoint DLP Agent")
                .font(.headline)
            Text("Configure agent settings from the management console.")
                .foregroundColor(.secondary)
        }
    }
}

private struct PolicySettingsTab: View {
    var body: some View {
        Form {
            Text("Active Policies: \(DLPPolicyEngine.shared.activePolicies.count)")
            Text("Policy updates are managed by your administrator.")
                .foregroundColor(.secondary)
        }
    }
}

private struct AboutSettingsTab: View {
    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: "shield.checkered")
                .font(.system(size: 48))
            Text("NextGuard Endpoint DLP Agent")
                .font(.title2)
            Text("Version 1.0.0")
                .foregroundColor(.secondary)
            Text("Copyright (c) 2026 NextGuard Technology Limited")
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .padding()
        .frame(width: 400, height: 300)
    }
}

// MARK: - Heartbeat Service

class HeartbeatService {
    static let shared = HeartbeatService()
    private var timer: Timer?
    private init() {}

    func start() {
        timer = Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { _ in
            ComplianceReporter.shared.sendHeartbeat()
        }
    }

    func stop() {
        timer?.invalidate()
        timer = nil
    }
}

// MARK: - Web Activity Types (used by BrowserMonitor)

enum WebAction: String {
    case allow
    case block
    case warn
}

struct WebActivity {
    enum ActivityType: String {
        case navigation
        case download
        case upload
    }
    let url: String
    let domain: String
    let activityType: ActivityType
    let action: WebAction
    let browser: String
    let fileName: String?
    let contentLength: Int64
    let timestamp: Date
}

// MARK: - Audit Types

enum AuditCategory: String {
    case fileActivity
    case networkActivity
    case clipboardActivity
    case usbActivity
    case emailActivity
    case browserActivity
    case screenActivity
    case policyViolation
    case systemEvent
}

// MARK: - DLP Policy Engine isActive Extension

extension DLPPolicyEngine {
    var isActive: Bool {
        return !activePolicies.isEmpty
    }
}
