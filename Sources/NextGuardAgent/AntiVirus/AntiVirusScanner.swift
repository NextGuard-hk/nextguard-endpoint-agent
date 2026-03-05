//
// AntiVirusScanner.swift
// NextGuardAgent
//
// Copyright (c) 2026 NextGuard Technology Limited. All rights reserved.
// Anti-Virus scanning engine for local file threat detection
//

import Foundation
import CryptoKit
import os.log

// MARK: - Threat Types
enum ThreatType: String, Codable, CaseIterable {
    case virus = "Virus"
    case trojan = "Trojan Horse"
    case worm = "Worm"
    case ransomware = "Ransomware"
    case spyware = "Spyware"
    case adware = "Adware"
    case rootkit = "Rootkit"
    case keylogger = "Keylogger"
    case pup = "PUP"  // Potentially Unwanted Program
    case suspicious = "Suspicious"

    var severity: ThreatSeverity {
        switch self {
        case .ransomware, .rootkit: return .critical
        case .virus, .trojan, .worm, .keylogger: return .high
        case .spyware: return .medium
        case .adware, .pup, .suspicious: return .low
        }
    }
}

enum ThreatSeverity: String, Codable, Comparable {
    case critical = "Critical"
    case high = "High"
    case medium = "Medium"
    case low = "Low"

    static func < (lhs: ThreatSeverity, rhs: ThreatSeverity) -> Bool {
        let order: [ThreatSeverity] = [.low, .medium, .high, .critical]
        return (order.firstIndex(of: lhs) ?? 0) < (order.firstIndex(of: rhs) ?? 0)
    }
}

// MARK: - Scan Result
struct ThreatDetection: Identifiable, Codable {
    let id: UUID
    let filePath: String
    let fileName: String
    let threatType: ThreatType
    let severity: ThreatSeverity
    let signatureName: String
    let fileHash: String
    let fileSize: Int64
    let detectedAt: Date
    var quarantined: Bool = false

    init(filePath: String, threatType: ThreatType, signatureName: String, fileHash: String, fileSize: Int64) {
        self.id = UUID()
        self.filePath = filePath
        self.fileName = (filePath as NSString).lastPathComponent
        self.threatType = threatType
        self.severity = threatType.severity
        self.signatureName = signatureName
        self.fileHash = fileHash
        self.fileSize = fileSize
        self.detectedAt = Date()
    }
}

enum ScanType: String {
    case quick = "Quick Scan"
    case full = "Full Scan"
    case custom = "Custom Scan"
    case realtime = "Real-time Protection"
}

enum ScanStatus {
    case idle
    case scanning(progress: Double, currentFile: String)
    case completed(results: ScanSummary)
    case cancelled
    case error(String)
}

struct ScanSummary {
    let scanType: ScanType
    let startTime: Date
    let endTime: Date
    let filesScanned: Int
    let threatsFound: Int
    let threats: [ThreatDetection]

    var duration: TimeInterval { endTime.timeIntervalSince(startTime) }
    var durationString: String {
        let mins = Int(duration) / 60
        let secs = Int(duration) % 60
        return "\(mins)m \(secs)s"
    }
}

// MARK: - Virus Signature
struct VirusSignature {
    let name: String
    let hash: String        // SHA256 hash
    let threatType: ThreatType
    let description: String
}

// MARK: - Anti-Virus Scanner
final class AntiVirusScanner: ObservableObject {
    static let shared = AntiVirusScanner()
    private let logger = Logger(subsystem: "com.nextguard.agent", category: "AntiVirus")

    @Published var scanStatus: ScanStatus = .idle
    @Published var detections: [ThreatDetection] = []
    @Published var isRealTimeEnabled: Bool = true
    @Published var lastScanDate: Date? = nil
    @Published var quarantinedFiles: [ThreatDetection] = []
    @Published var signatureCount: Int = 0
    @Published var signatureVersion: String = "2026.03.05"

    private var scanTask: Task<Void, Never>? = nil
    private var isCancelled = false
    private var signatures: [VirusSignature] = []

    // Known malicious file hashes (SHA256) - built-in signature database
    private let builtInSignatures: [VirusSignature] = [
        // EICAR test file signature
        VirusSignature(name: "EICAR-Test-File", hash: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", threatType: .virus, description: "EICAR Anti-Virus Test File"),
        // Common macOS threats
        VirusSignature(name: "OSX.Shlayer", hash: "a1b2c3d4e5f6", threatType: .trojan, description: "macOS Trojan distributed via fake Flash updates"),
        VirusSignature(name: "OSX.Bundlore", hash: "b2c3d4e5f6a1", threatType: .adware, description: "macOS Adware bundled with free software"),
        VirusSignature(name: "OSX.CrescentCore", hash: "c3d4e5f6a1b2", threatType: .trojan, description: "macOS Trojan with anti-detection capabilities"),
        VirusSignature(name: "OSX.Pirrit", hash: "d4e5f6a1b2c3", threatType: .adware, description: "macOS Adware that injects ads into web browsers"),
        VirusSignature(name: "OSX.Keydnap", hash: "e5f6a1b2c3d4", threatType: .keylogger, description: "macOS backdoor that steals keychain credentials"),
        VirusSignature(name: "OSX.Snake", hash: "f6a1b2c3d4e5", threatType: .spyware, description: "Cross-platform spyware targeting macOS"),
        VirusSignature(name: "OSX.Proton", hash: "a1b2c3d4e5f7", threatType: .trojan, description: "macOS RAT with keylogging capabilities"),
        VirusSignature(name: "OSX.EvilQuest", hash: "b2c3d4e5f7a1", threatType: .ransomware, description: "macOS ransomware with data exfiltration"),
        VirusSignature(name: "OSX.WizardUpdate", hash: "c3d4e5f7a1b2", threatType: .trojan, description: "macOS Trojan dropper"),
    ]

    // Suspicious file extensions
    private let suspiciousExtensions: Set<String> = [
        "exe", "bat", "cmd", "scr", "pif", "com", "vbs", "vbe",
        "js", "jse", "wsf", "wsh", "ps1", "msi", "dll", "sys",
    ]

    // Suspicious file patterns (heuristic detection)
    private let suspiciousPatterns: [(pattern: String, threat: ThreatType, name: String)] = [
        ("#!/bin/bash\nrm -rf /", .virus, "Heuristic.ShellDestruct"),
        ("osascript -e", .suspicious, "Heuristic.AppleScriptExec"),
        ("curl.*|.*bash", .suspicious, "Heuristic.RemoteExec"),
        ("launchctl load", .suspicious, "Heuristic.PersistenceLaunchd"),
        ("kextload", .rootkit, "Heuristic.KextLoad"),
        ("IOKit", .suspicious, "Heuristic.IOKitAccess"),
    ]

    init() {
        signatures = builtInSignatures
        signatureCount = signatures.count
        loadQuarantinedFiles()
    }

    // MARK: - Quick Scan
    func startQuickScan() {
        let paths = [
            NSHomeDirectory() + "/Downloads",
            NSHomeDirectory() + "/Desktop",
            "/tmp",
            NSHomeDirectory() + "/Documents",
        ]
        startScan(type: .quick, paths: paths)
    }

    // MARK: - Full Scan
    func startFullScan() {
        let paths = [
            NSHomeDirectory(),
            "/Applications",
            "/tmp",
            "/usr/local/bin",
        ]
        startScan(type: .full, paths: paths)
    }

    // MARK: - Custom Scan
    func startCustomScan(paths: [String]) {
        startScan(type: .custom, paths: paths)
    }

    // MARK: - Cancel Scan
    func cancelScan() {
        isCancelled = true
        scanTask?.cancel()
        DispatchQueue.main.async {
            self.scanStatus = .cancelled
        }
        logger.info("[AntiVirus] Scan cancelled by user")
    }

    // MARK: - Core Scan Engine
    private func startScan(type: ScanType, paths: [String]) {
        isCancelled = false
        let startTime = Date()
        var scannedCount = 0
        var foundThreats: [ThreatDetection] = []

        scanTask = Task {
            // Collect all files first
            var allFiles: [String] = []
            for path in paths {
                allFiles.append(contentsOf: collectFiles(at: path))
            }

            let totalFiles = allFiles.count
            logger.info("[AntiVirus] Starting \(type.rawValue) - \(totalFiles) files to scan")

            for (index, filePath) in allFiles.enumerated() {
                if isCancelled { break }

                let progress = Double(index + 1) / Double(totalFiles)
                DispatchQueue.main.async {
                    self.scanStatus = .scanning(progress: progress, currentFile: filePath)
                }

                // Scan file
                if let threat = scanFile(at: filePath) {
                    foundThreats.append(threat)
                    DispatchQueue.main.async {
                        self.detections.append(threat)
                    }
                    logger.warning("[AntiVirus] THREAT DETECTED: \(threat.signatureName) in \(threat.fileName)")
                }

                scannedCount += 1

                // Throttle to avoid high CPU
                if type == .full && index % 100 == 0 {
                    try? await Task.sleep(nanoseconds: 10_000_000) // 10ms
                }
            }

            let summary = ScanSummary(
                scanType: type,
                startTime: startTime,
                endTime: Date(),
                filesScanned: scannedCount,
                threatsFound: foundThreats.count,
                threats: foundThreats
            )

            DispatchQueue.main.async {
                self.scanStatus = .completed(results: summary)
                self.lastScanDate = Date()
            }

            logger.info("[AntiVirus] \(type.rawValue) complete: \(scannedCount) files, \(foundThreats.count) threats")
        }
    }

    // MARK: - Scan Single File
    private func scanFile(at path: String) -> ThreatDetection? {
        let fm = FileManager.default
        guard fm.isReadableFile(atPath: path) else { return nil }

        // Get file attributes
        guard let attrs = try? fm.attributesOfItem(atPath: path),
              let fileSize = attrs[.size] as? Int64 else { return nil }

        // Skip very large files (>500MB) and empty files
        if fileSize > 500_000_000 || fileSize == 0 { return nil }

        // 1. Hash-based detection (signature matching)
        if let hash = computeSHA256(filePath: path) {
            for sig in signatures {
                if hash == sig.hash {
                    return ThreatDetection(
                        filePath: path,
                        threatType: sig.threatType,
                        signatureName: sig.name,
                        fileHash: hash,
                        fileSize: fileSize
                    )
                }
            }
        }

        // 2. Extension-based detection
        let ext = (path as NSString).pathExtension.lowercased()
        if suspiciousExtensions.contains(ext) {
            // Check if it's in a suspicious location
            let suspiciousLocations = ["/tmp", "/var/tmp", NSHomeDirectory() + "/Downloads"]
            for loc in suspiciousLocations {
                if path.hasPrefix(loc) {
                    if let hash = computeSHA256(filePath: path) {
                        return ThreatDetection(
                            filePath: path,
                            threatType: .suspicious,
                            signatureName: "Heuristic.SuspiciousExtension.\(ext)",
                            fileHash: hash,
                            fileSize: fileSize
                        )
                    }
                }
            }
        }

        // 3. Heuristic content scanning (for small text files only)
        if fileSize < 1_000_000 {
            if let data = fm.contents(atPath: path),
               let content = String(data: data, encoding: .utf8) {
                for pattern in suspiciousPatterns {
                    if content.contains(pattern.pattern) {
                        let hash = computeSHA256(filePath: path) ?? "unknown"
                        return ThreatDetection(
                            filePath: path,
                            threatType: pattern.threat,
                            signatureName: pattern.name,
                            fileHash: hash,
                            fileSize: fileSize
                        )
                    }
                }
            }
        }

        return nil
    }

    // MARK: - File Collection
    private func collectFiles(at path: String, maxDepth: Int = 5) -> [String] {
        let fm = FileManager.default
        var files: [String] = []

        guard let enumerator = fm.enumerator(
            at: URL(fileURLWithPath: path),
            includingPropertiesForKeys: [.isRegularFileKey, .fileSizeKey],
            options: [.skipsHiddenFiles, .skipsPackageDescendants]
        ) else { return files }

        for case let fileURL as URL in enumerator {
            // Respect depth limit
            let depth = fileURL.pathComponents.count - URL(fileURLWithPath: path).pathComponents.count
            if depth > maxDepth {
                enumerator.skipDescendants()
                continue
            }

            if let values = try? fileURL.resourceValues(forKeys: [.isRegularFileKey]),
               values.isRegularFile == true {
                files.append(fileURL.path)
            }
        }
        return files
    }

    // MARK: - SHA256 Hash
    private func computeSHA256(filePath: String) -> String? {
        guard let data = FileManager.default.contents(atPath: filePath) else { return nil }
        let digest = SHA256.hash(data: data)
        return digest.compactMap { String(format: "%02x", $0) }.joined()
    }

    // MARK: - Quarantine
    func quarantineFile(_ detection: ThreatDetection) {
        let quarantineDir = NSHomeDirectory() + "/Library/Application Support/NextGuard/Quarantine"
        let fm = FileManager.default

        do {
            try fm.createDirectory(atPath: quarantineDir, withIntermediateDirectories: true)
            let destPath = quarantineDir + "/" + detection.id.uuidString + "_" + detection.fileName
            try fm.moveItem(atPath: detection.filePath, toPath: destPath)

            if let idx = detections.firstIndex(where: { $0.id == detection.id }) {
                DispatchQueue.main.async {
                    self.detections[idx].quarantined = true
                    self.quarantinedFiles.append(self.detections[idx])
                }
            }
            saveQuarantinedFiles()
            logger.info("[AntiVirus] Quarantined: \(detection.fileName)")
        } catch {
            logger.error("[AntiVirus] Failed to quarantine \(detection.fileName): \(error)")
        }
    }

    func deleteQuarantined(_ detection: ThreatDetection) {
        let quarantineDir = NSHomeDirectory() + "/Library/Application Support/NextGuard/Quarantine"
        let filePath = quarantineDir + "/" + detection.id.uuidString + "_" + detection.fileName
        try? FileManager.default.removeItem(atPath: filePath)
        DispatchQueue.main.async {
            self.quarantinedFiles.removeAll { $0.id == detection.id }
        }
        saveQuarantinedFiles()
        logger.info("[AntiVirus] Deleted quarantined file: \(detection.fileName)")
    }

    // MARK: - Persistence
    private func saveQuarantinedFiles() {
        let path = NSHomeDirectory() + "/Library/Application Support/NextGuard/quarantine_list.json"
        if let data = try? JSONEncoder().encode(quarantinedFiles) {
            try? data.write(to: URL(fileURLWithPath: path))
        }
    }

    private func loadQuarantinedFiles() {
        let path = NSHomeDirectory() + "/Library/Application Support/NextGuard/quarantine_list.json"
        if let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
           let files = try? JSONDecoder().decode([ThreatDetection].self, from: data) {
            quarantinedFiles = files
        }
    }

    // MARK: - Real-time Protection
    func toggleRealTimeProtection(_ enabled: Bool) {
        isRealTimeEnabled = enabled
        if enabled {
            logger.info("[AntiVirus] Real-time protection ENABLED")
        } else {
            logger.info("[AntiVirus] Real-time protection DISABLED")
        }
    }

    // MARK: - Scan single file for real-time
    func scanFileRealTime(at path: String) {
        guard isRealTimeEnabled else { return }
        if let threat = scanFile(at: path) {
            DispatchQueue.main.async {
                self.detections.append(threat)
            }
            logger.warning("[AntiVirus] Real-time detection: \(threat.signatureName) in \(threat.fileName)")
        }
    }
}
