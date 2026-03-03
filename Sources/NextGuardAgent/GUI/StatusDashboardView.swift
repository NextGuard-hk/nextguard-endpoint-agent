//
//  StatusDashboardView.swift
//  NextGuardAgent
//
//  Real-time dashboard showing agent status, stats, and protection overview
//

import SwiftUI
import Combine

// MARK: - Status Dashboard View

struct StatusDashboardView: View {
  @Binding var status: AgentStatusInfo
  @State private var animateShield = false

  var body: some View {
    ScrollView {
      VStack(spacing: 20) {
        protectionStatusCard
        statsGrid
        recentActivitySection
        systemInfoSection
      }
      .padding(24)
    }
    .frame(maxWidth: .infinity, maxHeight: .infinity)
    .background(Color(nsColor: .windowBackgroundColor))
  }

  // MARK: - Protection Status Card

  private var protectionStatusCard: some View {
    HStack(spacing: 20) {
      ZStack {
        Circle()
          .fill(status.protectionEnabled ? Color.green.opacity(0.15) : Color.red.opacity(0.15))
          .frame(width: 80, height: 80)
        Image(systemName: status.protectionEnabled ? "shield.checkmark.fill" : "shield.slash.fill")
          .font(.system(size: 36))
          .foregroundColor(status.protectionEnabled ? .green : .red)
          .scaleEffect(animateShield ? 1.05 : 1.0)
      }
      .onAppear {
        withAnimation(.easeInOut(duration: 2).repeatForever(autoreverses: true)) {
          animateShield = true
        }
      }

      VStack(alignment: .leading, spacing: 6) {
        Text(status.protectionEnabled ? "Protection Active" : "Protection Disabled")
          .font(.title2.bold())
        Text(status.isConnected ? "Connected to NextGuard Console" : "Offline Mode - Local Policies Active")
          .font(.subheadline)
          .foregroundColor(.secondary)
        HStack(spacing: 12) {
          Label(status.isConnected ? "Online" : "Offline", systemImage: status.isConnected ? "wifi" : "wifi.slash")
            .font(.caption)
            .foregroundColor(status.isConnected ? .green : .orange)
          if let syncTime = status.lastPolicySync {
            Label("Synced \(syncTime, style: .relative)", systemImage: "arrow.triangle.2.circlepath")
              .font(.caption)
              .foregroundColor(.secondary)
          }
        }
      }

      Spacer()

      VStack(spacing: 8) {
        Button(action: { status.protectionEnabled.toggle() }) {
          Text(status.protectionEnabled ? "Pause" : "Resume")
            .frame(width: 80)
        }
        .controlSize(.large)

        Button("Sync Now") {
          NotificationCenter.default.post(name: .init("NextGuardSyncRequested"), object: nil)
        }
        .controlSize(.small)
      }
    }
    .padding(20)
    .background(RoundedRectangle(cornerRadius: 12).fill(Color(nsColor: .controlBackgroundColor)))
    .overlay(RoundedRectangle(cornerRadius: 12).stroke(status.protectionEnabled ? Color.green.opacity(0.3) : Color.red.opacity(0.3), lineWidth: 1))
  }

  // MARK: - Stats Grid

  private var statsGrid: some View {
    LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible()), GridItem(.flexible()), GridItem(.flexible())], spacing: 16) {
      StatCard(title: "Active Policies", value: "\(status.activePolicyCount)", icon: "doc.text.fill", color: .blue)
      StatCard(title: "Today Incidents", value: "\(status.todayIncidentCount)", icon: "exclamationmark.triangle.fill", color: .orange)
      StatCard(title: "Blocked", value: "\(status.todayBlockCount)", icon: "xmark.shield.fill", color: .red)
      StatCard(title: "Audited", value: "\(status.todayAuditCount)", icon: "eye.fill", color: .purple)
    }
  }

  // MARK: - Recent Activity

  private var recentActivitySection: some View {
    VStack(alignment: .leading, spacing: 12) {
      HStack {
        Text("Recent Activity")
          .font(.headline)
        Spacer()
        Button("View All") {
          NotificationCenter.default.post(name: .init("NextGuardNavigateTab"), object: "Incidents")
        }
        .buttonStyle(.link)
      }

      if status.todayIncidentCount == 0 {
        HStack {
          Spacer()
          VStack(spacing: 8) {
            Image(systemName: "checkmark.circle")
              .font(.system(size: 32))
              .foregroundColor(.green)
            Text("No incidents today")
              .foregroundColor(.secondary)
          }
          .padding(.vertical, 24)
          Spacer()
        }
        .background(RoundedRectangle(cornerRadius: 8).fill(Color(nsColor: .controlBackgroundColor)))
      } else {
        Text("\(status.todayIncidentCount) incidents detected today")
          .padding()
          .frame(maxWidth: .infinity)
          .background(RoundedRectangle(cornerRadius: 8).fill(Color.orange.opacity(0.1)))
      }
    }
    .padding(16)
    .background(RoundedRectangle(cornerRadius: 12).fill(Color(nsColor: .controlBackgroundColor)))
  }

  // MARK: - System Info

  private var systemInfoSection: some View {
    VStack(alignment: .leading, spacing: 12) {
      Text("System Information")
        .font(.headline)

      LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 8) {
        InfoRow(label: "Agent Version", value: status.agentVersion)
        InfoRow(label: "Endpoint ID", value: status.endpointId.isEmpty ? "Not Assigned" : String(status.endpointId.prefix(12)) + "...")
        InfoRow(label: "Enrollment", value: status.enrollmentStatus)
        InfoRow(label: "Policy Source", value: status.isConnected ? "Server + Local" : "Local Only")
      }
    }
    .padding(16)
    .background(RoundedRectangle(cornerRadius: 12).fill(Color(nsColor: .controlBackgroundColor)))
  }
}

// MARK: - Stat Card

struct StatCard: View {
  let title: String
  let value: String
  let icon: String
  let color: Color

  var body: some View {
    VStack(spacing: 8) {
      Image(systemName: icon)
        .font(.title2)
        .foregroundColor(color)
      Text(value)
        .font(.title.bold())
      Text(title)
        .font(.caption)
        .foregroundColor(.secondary)
    }
    .frame(maxWidth: .infinity)
    .padding(16)
    .background(RoundedRectangle(cornerRadius: 10).fill(Color(nsColor: .controlBackgroundColor)))
    .overlay(RoundedRectangle(cornerRadius: 10).stroke(color.opacity(0.2), lineWidth: 1))
  }
}

// MARK: - Info Row

struct InfoRow: View {
  let label: String
  let value: String

  var body: some View {
    HStack {
      Text(label)
        .foregroundColor(.secondary)
        .font(.caption)
      Spacer()
      Text(value)
        .font(.caption)
        .fontWeight(.medium)
    }
    .padding(.vertical, 4)
  }
}
