//
// AntiVirusSettingsView.swift
// NextGuardAgent
//
// Copyright (c) 2026 NextGuard Technology Limited. All rights reserved.
//

import SwiftUI

struct AntiVirusSettingsView: View {
    @StateObject private var scanner = AntiVirusScanner.shared
    @State private var showCustomPathPicker = false
    @State private var customScanPath = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            // Header
            HStack {
                Image(systemName: "shield.checkerboard")
                    .font(.title2).foregroundColor(.blue)
                VStack(alignment: .leading) {
                    Text("Anti-Virus Protection").font(.headline)
                    Text("Scan your Mac for viruses, trojans, and other threats")
                        .font(.caption).foregroundColor(.secondary)
                }
                Spacer()
                // Signature info
                VStack(alignment: .trailing, spacing: 2) {
                    Text("Signatures: \(scanner.signatureCount)")
                        .font(.caption2).foregroundColor(.secondary)
                    Text("DB: \(scanner.signatureVersion)")
                        .font(.caption2).foregroundColor(.secondary)
                }
            }
            .padding(.top, 16)

            Divider()

            // Real-time Protection Toggle
            HStack {
                Image(systemName: "shield.fill")
                    .foregroundColor(scanner.isRealTimeEnabled ? .green : .secondary)
                VStack(alignment: .leading) {
                    Text("Real-time Protection").font(.system(size: 12, weight: .medium))
                    Text("Automatically scan new and modified files")
                        .font(.system(size: 10)).foregroundColor(.secondary)
                }
                Spacer()
                Toggle("", isOn: $scanner.isRealTimeEnabled)
                    .toggleStyle(.switch)
                    .onChange(of: scanner.isRealTimeEnabled) { val in
                        scanner.toggleRealTimeProtection(val)
                    }
            }

            Divider()

            // Scan Status
            scanStatusView

            Divider()

            // Scan Buttons
            HStack(spacing: 12) {
                Button(action: { scanner.startQuickScan() }) {
                    HStack {
                        Image(systemName: "hare.fill")
                        Text("Quick Scan")
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 8)
                }
                .buttonStyle(.borderedProminent)
                .disabled(isScanRunning)

                Button(action: { scanner.startFullScan() }) {
                    HStack {
                        Image(systemName: "tortoise.fill")
                        Text("Full Scan")
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 8)
                }
                .buttonStyle(.bordered)
                .disabled(isScanRunning)
            }

            // Custom Scan
            HStack {
                TextField("Custom path to scan...", text: $customScanPath)
                    .textFieldStyle(.roundedBorder)
                Button("Scan") {
                    if !customScanPath.isEmpty {
                        scanner.startCustomScan(paths: [customScanPath])
                    }
                }
                .disabled(customScanPath.isEmpty || isScanRunning)
            }

            if isScanRunning {
                Button("Cancel Scan") { scanner.cancelScan() }
                    .foregroundColor(.red)
            }

            Divider()

            // Detections List
            if !scanner.detections.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Detected Threats (\(scanner.detections.count))")
                        .font(.subheadline.bold())
                        .foregroundColor(.red)

                    ForEach(scanner.detections) { threat in
                        threatRow(threat)
                    }
                }
            }

            // Quarantine
            if !scanner.quarantinedFiles.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Quarantined Files (\(scanner.quarantinedFiles.count))")
                        .font(.subheadline.bold())

                    ForEach(scanner.quarantinedFiles) { file in
                        HStack {
                            Image(systemName: "lock.shield.fill")
                                .foregroundColor(.orange)
                            VStack(alignment: .leading) {
                                Text(file.fileName).font(.system(size: 11, weight: .medium))
                                Text(file.signatureName).font(.system(size: 10)).foregroundColor(.secondary)
                            }
                            Spacer()
                            Button("Delete") { scanner.deleteQuarantined(file) }
                                .font(.caption)
                                .foregroundColor(.red)
                        }
                    }
                }
            }

            // Last Scan Info
            if let lastScan = scanner.lastScanDate {
                HStack {
                    Image(systemName: "clock").foregroundColor(.secondary)
                    Text("Last scan: \(lastScan.formatted())")
                        .font(.caption).foregroundColor(.secondary)
                }
            }

            Spacer()
        }
        .padding(16)
    }

    private var isScanRunning: Bool {
        if case .scanning = scanner.scanStatus { return true }
        return false
    }

    @ViewBuilder
    private var scanStatusView: some View {
        switch scanner.scanStatus {
        case .idle:
            HStack(spacing: 8) {
                Circle().fill(Color.green).frame(width: 8, height: 8)
                Text("Protection Active - No threats detected")
                    .font(.system(size: 12)).foregroundColor(.green)
            }
        case .scanning(let progress, let file):
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    ProgressView()
                        .scaleEffect(0.7)
                    Text("Scanning... \(Int(progress * 100))%")
                        .font(.system(size: 12, weight: .medium))
                }
                ProgressView(value: progress)
                    .progressViewStyle(.linear)
                Text(file)
                    .font(.system(size: 10))
                    .foregroundColor(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
        case .completed(let results):
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Image(systemName: results.threatsFound > 0 ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                        .foregroundColor(results.threatsFound > 0 ? .red : .green)
                    Text(results.threatsFound > 0 ? "\(results.threatsFound) threat(s) found!" : "No threats found")
                        .font(.system(size: 12, weight: .medium))
                        .foregroundColor(results.threatsFound > 0 ? .red : .green)
                }
                Text("\(results.scanType.rawValue): \(results.filesScanned) files scanned in \(results.durationString)")
                    .font(.system(size: 10)).foregroundColor(.secondary)
            }
        case .cancelled:
            HStack(spacing: 8) {
                Image(systemName: "xmark.circle.fill").foregroundColor(.orange)
                Text("Scan cancelled").font(.system(size: 12)).foregroundColor(.orange)
            }
        case .error(let msg):
            HStack(spacing: 8) {
                Image(systemName: "exclamationmark.triangle.fill").foregroundColor(.red)
                Text(msg).font(.system(size: 12)).foregroundColor(.red)
            }
        }
    }

    private func threatRow(_ threat: ThreatDetection) -> some View {
        HStack(spacing: 10) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundColor(threat.severity >= .high ? .red : .orange)
            VStack(alignment: .leading, spacing: 2) {
                Text(threat.fileName).font(.system(size: 11, weight: .medium))
                Text(threat.signatureName).font(.system(size: 10)).foregroundColor(.secondary)
                Text("\(threat.threatType.rawValue) • \(threat.severity.rawValue)")
                    .font(.system(size: 9)).foregroundColor(.red)
            }
            Spacer()
            if !threat.quarantined {
                Button("Quarantine") { scanner.quarantineFile(threat) }
                    .font(.caption)
                    .buttonStyle(.bordered)
            } else {
                Text("Quarantined")
                    .font(.caption).foregroundColor(.orange)
            }
        }
        .padding(6)
        .background(RoundedRectangle(cornerRadius: 6).fill(Color.red.opacity(0.05)))
    }
}
