//
//  EnrollmentView.swift
//  NextGuardAgent
//
//  GUI for Agent Enrollment: Token-based enrollment into Managed Mode
//  Standalone -> Managed transition with mTLS certificate exchange
//  Supports: Manual token enrollment + Leave Managed Mode (with bypass password)
//

import SwiftUI
import AppKit

// MARK: - Enrollment View (Sheet / Full Panel)
struct EnrollmentView: View {
    @StateObject private var modeManager = AgentModeManager.shared
    @StateObject private var enrollmentManager = EnrollmentManager.shared

    @State private var enrollmentToken: String = ""
    @State private var consoleUrl: String = "https://next-guard.com"
    @State private var isEnrolling: Bool = false
    @State private var enrollError: String? = nil
    @State private var showLeaveSheet: Bool = false
    @State private var bypassPassword: String = ""
    @State private var leaveError: String? = nil
    @State private var isLeaving: Bool = false

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                if modeManager.mode == .standalone {
                    enrollmentPanel
                } else {
                    managedStatusPanel
                }
            }
            .padding(20)
        }
        .sheet(isPresented: $showLeaveSheet) {
            leaveSheet
        }
    }

    // MARK: - Enrollment Panel (Standalone)
    private var enrollmentPanel: some View {
        VStack(spacing: 16) {
            // Header
            VStack(spacing: 8) {
                Image(systemName: "building.2.fill")
                    .font(.system(size: 36))
                    .foregroundColor(.blue)
                Text("Join Organisation")
                    .font(.title2.bold())
                Text("Enroll this Mac into your organisation's NextGuard tenant.\nAn enrollment token is required from your Console administrator.")
                    .font(.subheadline)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
            }
            .padding(.vertical, 8)

            // Enrollment Form
            VStack(alignment: .leading, spacing: 10) {
                enrollFormLabel("Console URL")
                TextField("https://next-guard.com", text: $consoleUrl)
                    .textFieldStyle(.plain)
                    .padding(8)
                    .background(RoundedRectangle(cornerRadius: 6).fill(Color(NSColor.textBackgroundColor)))
                    .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.secondary.opacity(0.3), lineWidth: 1))
                    .font(.system(size: 12, design: .monospaced))

                enrollFormLabel("Enrollment Token")
                SecureField("ENR-XXXX-XXXX (provided by admin)", text: $enrollmentToken)
                    .textFieldStyle(.plain)
                    .padding(8)
                    .background(RoundedRectangle(cornerRadius: 6).fill(Color(NSColor.textBackgroundColor)))
                    .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.secondary.opacity(0.3), lineWidth: 1))
                    .font(.system(size: 12, design: .monospaced))

                if let error = enrollError {
                    HStack(spacing: 6) {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundColor(.red)
                        Text(error)
                            .font(.caption)
                            .foregroundColor(.red)
                    }
                    .padding(8)
                    .background(RoundedRectangle(cornerRadius: 6).fill(Color.red.opacity(0.08)))
                }

                enrollmentStateView

                Button(action: beginEnrollment) {
                    HStack {
                        if isEnrolling {
                            ProgressView().scaleEffect(0.7).tint(.white)
                        } else {
                            Image(systemName: "paperplane.fill")
                        }
                        Text(isEnrolling ? "Enrolling..." : "Enroll Device")
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 10)
                    .background(RoundedRectangle(cornerRadius: 8).fill(
                        enrollmentToken.isEmpty ? Color.secondary.opacity(0.3) : Color.blue
                    ))
                    .foregroundColor(enrollmentToken.isEmpty ? .secondary : .white)
                }
                .buttonStyle(.plain)
                .disabled(enrollmentToken.isEmpty || isEnrolling)
            }
            .padding(16)
            .background(RoundedRectangle(cornerRadius: 12).fill(Color(NSColor.controlBackgroundColor)))

            // Info Banner
            HStack(spacing: 10) {
                Image(systemName: "info.circle").foregroundColor(.blue)
                Text("Enrollment uses mutual TLS. Your organisation's policies will be pushed after enrollment is complete.")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            .padding(10)
            .background(RoundedRectangle(cornerRadius: 8).fill(Color.blue.opacity(0.06)))
        }
    }

    @ViewBuilder
    private var enrollmentStateView: some View {
        switch modeManager.enrollmentState {
        case .unenrolled:
            EmptyView()
        case .enrolling:
            HStack(spacing: 8) {
                ProgressView().scaleEffect(0.7)
                Text("Validating token with Console...")
                    .font(.caption).foregroundColor(.secondary)
            }
        case .enrolled:
            HStack(spacing: 6) {
                Image(systemName: "checkmark.circle.fill").foregroundColor(.green)
                Text("Enrollment successful!").font(.caption).foregroundColor(.green)
            }
        case .suspended:
            HStack(spacing: 6) {
                Image(systemName: "pause.circle.fill").foregroundColor(.orange)
                Text("Device suspended by Console.").font(.caption).foregroundColor(.orange)
            }
        case .unenrolling:
            HStack(spacing: 8) {
                ProgressView().scaleEffect(0.7)
                Text("Leaving organisation...").font(.caption).foregroundColor(.secondary)
            }
        }
    }

    // MARK: - Managed Status Panel
    private var managedStatusPanel: some View {
        VStack(spacing: 16) {
            // Org Badge
            VStack(spacing: 8) {
                ZStack {
                    Circle()
                        .fill(Color.blue.opacity(0.12))
                        .frame(width: 72, height: 72)
                    Image(systemName: "building.2.fill")
                        .font(.system(size: 30))
                        .foregroundColor(.blue)
                }
                Text(modeManager.enrolledDevice?.tenantName ?? "Organisation")
                    .font(.title3.bold())
                Text("This device is managed")
                    .font(.subheadline)
                    .foregroundColor(.secondary)
            }

            // Device Info Card
            if let device = modeManager.enrolledDevice {
                VStack(spacing: 0) {
                    deviceInfoRow(label: "Device ID", value: String(device.deviceId.prefix(12)) + "...")
                    Divider().padding(.leading, 16)
                    deviceInfoRow(label: "Tenant ID", value: device.tenantId)
                    Divider().padding(.leading, 16)
                    deviceInfoRow(label: "Enrolled By", value: device.enrolledBy)
                    Divider().padding(.leading, 16)
                    deviceInfoRow(label: "Enrolled At", value: DateFormatter.localizedString(from: device.enrolledAt, dateStyle: .medium, timeStyle: .none))
                    Divider().padding(.leading, 16)
                    deviceInfoRow(label: "Policy Lock", value: device.policyLockLevel.rawValue.capitalized)
                    Divider().padding(.leading, 16)
                    deviceInfoRow(label: "Console", value: device.consoleUrl)
                }
                .background(RoundedRectangle(cornerRadius: 12).fill(Color(NSColor.controlBackgroundColor)))

                // Console Reachability
                HStack(spacing: 8) {
                    Circle()
                        .fill(modeManager.isConsoleReachable ? Color.green : Color.orange)
                        .frame(width: 8, height: 8)
                    Text(modeManager.isConsoleReachable ? "Console reachable" : "Console unreachable — using cached policies")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    Spacer()
                    if let sync = device.lastPolicySync {
                        Text("Last sync \(sync, style: .relative)")
                            .font(.caption2)
                            .foregroundColor(.secondary)
                    }
                }
                .padding(.horizontal, 4)
            }

            // Lock Level Banner
            if modeManager.managedSettingsLocked {
                HStack(spacing: 8) {
                    Image(systemName: "lock.fill").foregroundColor(.orange)
                    Text("Settings are locked by your organisation.")
                        .font(.caption)
                        .foregroundColor(.orange)
                }
                .padding(10)
                .frame(maxWidth: .infinity)
                .background(RoundedRectangle(cornerRadius: 8).fill(Color.orange.opacity(0.08)))
            }

            // Leave Org Button
            Button(action: { showLeaveSheet = true }) {
                HStack {
                    Image(systemName: "arrow.backward.circle")
                    Text("Leave Organisation")
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 10)
                .background(RoundedRectangle(cornerRadius: 8).stroke(Color.red.opacity(0.5), lineWidth: 1))
                .foregroundColor(.red)
            }
            .buttonStyle(.plain)
        }
    }

    // MARK: - Leave Sheet
    private var leaveSheet: some View {
        VStack(spacing: 20) {
            Image(systemName: "arrow.backward.circle.fill")
                .font(.system(size: 40))
                .foregroundColor(.red)

            Text("Leave Organisation?")
                .font(.title3.bold())

            Text("You will need a bypass password issued by your Console admin.\nAll Console-managed policies will be removed.")
                .font(.subheadline)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)

            SecureField("Bypass password", text: $bypassPassword)
                .textFieldStyle(.roundedBorder)
                .frame(width: 280)

            if let error = leaveError {
                Text(error)
                    .font(.caption)
                    .foregroundColor(.red)
            }

            HStack(spacing: 16) {
                Button("Cancel") {
                    showLeaveSheet = false
                    bypassPassword = ""
                    leaveError = nil
                }
                .buttonStyle(.bordered)

                Button(action: confirmLeave) {
                    HStack {
                        if isLeaving { ProgressView().scaleEffect(0.7) }
                        Text(isLeaving ? "Leaving..." : "Confirm Leave")
                    }
                }
                .buttonStyle(.borderedProminent)
                .tint(.red)
                .disabled(isLeaving)
            }
        }
        .padding(32)
        .frame(width: 380)
    }

    // MARK: - Actions
    private func beginEnrollment() {
        enrollError = nil
        isEnrolling = true
        Task {
            do {
                try await EnrollmentManager.shared.enroll(
                    token: enrollmentToken,
                    consoleUrl: consoleUrl
                )
                await MainActor.run { isEnrolling = false }
            } catch {
                await MainActor.run {
                    isEnrolling = false
                    enrollError = error.localizedDescription
                }
            }
        }
    }

    private func confirmLeave() {
        isLeaving = true
        leaveError = nil
        AgentModeManager.shared.leaveManaged(bypassPassword: bypassPassword) { success in
            isLeaving = false
            if success {
                showLeaveSheet = false
                bypassPassword = ""
            } else {
                leaveError = "Incorrect bypass password. Contact your Console admin."
            }
        }
    }

    // MARK: - Helpers
    private func enrollFormLabel(_ text: String) -> some View {
        Text(text)
            .font(.system(size: 11, weight: .medium))
            .foregroundColor(.secondary)
    }

    private func deviceInfoRow(label: String, value: String) -> some View {
        HStack {
            Text(label)
                .font(.system(size: 11))
                .foregroundColor(.secondary)
            Spacer()
            Text(value)
                .font(.system(size: 11, weight: .medium))
                .lineLimit(1)
                .truncationMode(.middle)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 7)
    }
}

// MARK: - Enrollment Manager (singleton stub for GUI)
// Full implementation is in Management/EnrollmentManager.swift
extension EnrollmentManager {
    static let shared = EnrollmentManager()
}
