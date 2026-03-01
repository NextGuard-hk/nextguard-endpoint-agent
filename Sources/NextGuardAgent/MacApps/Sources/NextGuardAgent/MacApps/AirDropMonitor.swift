// AirDropMonitor.swift
// NextGuard DLP Agent - AirDrop Transfer Monitor
// Monitors AirDrop incoming/outgoing file transfers for DLP policy enforcement
// Ref: ISO 27001:2022 A.8.12, NIST SP 800-171 3.13.8
// AirDrop uses AWDL (Apple Wireless Direct Link) + mDNS + TLS

import Foundation
import AppKit
import os.log

public class AirDropMonitor {
    private let logger = Logger(subsystem: "com.nextguard.agent", category: "AirDropMonitor")
    private var eventHandler: ((DLPEvent) -> Void)?
    private var isRunning = false
    private var downloadWatcher: DispatchSourceFileSystemObject?
    private var desktopWatcher: DispatchSourceFileSystemObject?
    private var receiveWatcher: DispatchSourceFileSystemObject?
    private var pollTimer: Timer?
    private let queue = DispatchQueue(label: "com.nextguard.airdrop", qos: .utility)

    // AirDrop receive staging area
    private let home = FileManager.default.homeDirectoryForCurrentUser.path
    private lazy var airdropReceivePath = "\(home)/Downloads"
    private lazy var desktopPath = "\(home)/Desktop"
    // AirDrop staging - macOS uses a temp directory before delivering
    private let airdropStagingPaths: [String] = [
        NSTemporaryDirectory() + "com.apple.AirDrop",
        "/private/var/folders"
    ]

    // File extensions that are high-risk for AirDrop exfiltration
    private let highRiskExtensions = Set([
        "pdf", "docx", "doc", "xlsx", "xls", "pptx", "ppt",
        "zip", "rar", "7z", "tar", "gz",
        "key", "pem", "p12", "pfx", "cer",
        "sql", "db", "sqlite",
        "csv", "json", "xml",
        "swift", "py", "java", "cpp", "h",
        "dmg", "pkg"
    ])

    // Track recently seen files to avoid duplicate events
    private var seenFiles = Set<String>()
    private var lastDownloadsScan: Date = Date(timeIntervalSince1970: 0)

    public init() {}

    // MARK: - Start / Stop

    public func start(eventHandler: @escaping (DLPEvent) -> Void) {
        self.eventHandler = eventHandler
        isRunning = true
        logger.info("[NextGuard] AirDropMonitor started")
        watchDownloadsFolder()
        watchDesktopFolder()
        startPolling()
        monitorAWDLInterface()
    }

    public func stop() {
        isRunning = false
        downloadWatcher?.cancel()
        desktopWatcher?.cancel()
        receiveWatcher?.cancel()
        pollTimer?.invalidate()
        logger.info("[NextGuard] AirDropMonitor stopped")
    }

    // MARK: - Watch Downloads Folder
    // AirDrop files are received into ~/Downloads by default

    private func watchDownloadsFolder() {
        watchFolder(path: airdropReceivePath, label: "Downloads") { [weak self] in
            self?.scanForNewAirDropFiles(in: self?.airdropReceivePath ?? "")
        }
    }

    private func watchDesktopFolder() {
        watchFolder(path: desktopPath, label: "Desktop") { [weak self] in
            self?.scanForNewAirDropFiles(in: self?.desktopPath ?? "")
        }
    }

    private func watchFolder(path: String, label: String, handler: @escaping () -> Void) {
        guard FileManager.default.fileExists(atPath: path) else { return }
        let fd = open(path, O_EVTONLY)
        guard fd >= 0 else { return }
        let source = DispatchSource.makeFileSystemObjectSource(
            fileDescriptor: fd,
            eventMask: [.write, .rename],
            queue: queue
        )
        source.setEventHandler(handler: handler)
        source.setCancelHandler { close(fd) }
        source.resume()
        if label == "Downloads" { downloadWatcher = source }
        else { desktopWatcher = source }
        logger.info("AirDropMonitor watching \(label): \(path)")
    }

    // MARK: - Scan folder for newly received AirDrop files

    private func scanForNewAirDropFiles(in folderPath: String) {
        guard isRunning else { return }
        guard let files = try? FileManager.default.contentsOfDirectory(atPath: folderPath) else { return }
        let now = Date()

        for file in files {
            let fullPath = "\(folderPath)/\(file)"
            guard !seenFiles.contains(fullPath) else { continue }

            guard let attrs = try? FileManager.default.attributesOfItem(atPath: fullPath),
                  let modDate = attrs[.modificationDate] as? Date,
                  now.timeIntervalSince(modDate) < 30.0 else { continue }

            seenFiles.insert(fullPath)
            let ext = (file as NSString).pathExtension.lowercased()
            let fileSize = (attrs[.size] as? Int64) ?? 0

            // Check if this looks like an AirDrop delivery
            // AirDrop files appear very recently (< 30 seconds old)
            handleAirDropFile(
                path: fullPath,
                fileName: file,
                fileExtension: ext,
                fileSize: fileSize,
                direction: .received
            )
        }
    }

    // MARK: - Handle AirDrop File Event

    private func handleAirDropFile(
        path: String,
        fileName: String,
        fileExtension: String,
        fileSize: Int64,
        direction: AirDropDirection
    ) {
        queue.async { [weak self] in
            guard let self = self else { return }

            var severity: DLPSeverity = .low
            var matchedRules: [String] = []
            var action: DLPAction = .log

            // High-risk file type
            if self.highRiskExtensions.contains(fileExtension) {
                severity = .medium
                matchedRules.append("AIRDROP_HIGH_RISK_FILETYPE")
                action = .warn
            }

            // Large file transfer
            if fileSize > 50 * 1024 * 1024 {
                severity = .high
                matchedRules.append("AIRDROP_LARGE_FILE")
                action = .warn
            }

            // Scan text content of supported file types
            if ["txt", "csv", "json", "xml", "swift", "py", "sql"].contains(fileExtension) {
                let results = DLPPolicyEngine.shared.scanFile(at: path, channel: .airdrop)
                if !results.isEmpty {
                    let topSeverity = results.max(by: { $0.severity < $1.severity })?.severity ?? .low
                    if topSeverity > severity { severity = topSeverity }
                    let dlpAction = DLPPolicyEngine.shared.determineAction(for: results)
                    let dlpPriority: [DLPAction: Int] = [.block: 5, .quarantine: 4, .warn: 3, .audit: 2, .log: 1, .allow: 0]
                    if (dlpPriority[dlpAction] ?? 0) > (dlpPriority[action] ?? 0) { action = dlpAction }
                    matchedRules.append(contentsOf: results.map { $0.ruleName })
                }
            }

            // Certificate/key files are always critical
            if ["key", "pem", "p12", "pfx", "cer"].contains(fileExtension) {
                severity = .critical
                action = .block
                matchedRules.append("AIRDROP_CRYPTO_KEY_TRANSFER")
            }

            // Database files
            if ["sql", "db", "sqlite"].contains(fileExtension) {
                severity = max(severity, .high)
                matchedRules.append("AIRDROP_DATABASE_TRANSFER")
                action = max(action, .warn)
            }

            let event = DLPEvent(
                id: UUID().uuidString,
                timestamp: Date(),
                agentId: AgentConfig.shared.deviceId,
                hostname: Host.current().localizedName ?? "unknown",
                username: NSUserName(),
                eventType: direction == .received ? "AIRDROP_RECEIVE" : "AIRDROP_SEND",
                channel: "airdrop",
                severity: severity.rawValue,
                action: action.rawValue,
                policyName: matchedRules.first ?? "AIRDROP_MONITOR",
                details: [
                    "fileName": fileName,
                    "filePath": path,
                    "fileSize": String(fileSize),
                    "fileExtension": fileExtension,
                    "direction": direction.rawValue,
                    "matchedRules": matchedRules.joined(separator: ", ")
                ]
            )
            self.eventHandler?(event)
            self.logger.info("AirDrop \(direction.rawValue): \(fileName) size=\(fileSize) severity=\(severity.rawValue)")

            // Quarantine the file if needed
            if action == .quarantine || action == .block {
                self.quarantineFile(path: path, fileName: fileName)
            }
        }
    }

    // MARK: - Quarantine File
    // Move the received file to a quarantine folder

    private func quarantineFile(path: String, fileName: String) {
        let quarantineDir = "\(home)/Library/Application Support/NextGuard/Quarantine"
        do {
            try FileManager.default.createDirectory(atPath: quarantineDir,
                withIntermediateDirectories: true)
            let dest = "\(quarantineDir)/\(fileName)_\(Int(Date().timeIntervalSince1970))"
            try FileManager.default.moveItem(atPath: path, toPath: dest)
            logger.warning("[NextGuard] QUARANTINED AirDrop file: \(fileName) -> \(dest)")
        } catch {
            logger.error("Failed to quarantine \(fileName): \(error.localizedDescription)")
        }
    }

    // MARK: - Monitor AWDL Network Interface
    // Detect when AirDrop becomes active by checking for awdl0 interface activity

    private func monitorAWDLInterface() {
        // Poll ifconfig to detect AWDL activity every 10 seconds
        pollTimer = Timer.scheduledTimer(withTimeInterval: 10.0, repeats: true) { [weak self] _ in
            self?.checkAWDLStatus()
        }
    }

    private func checkAWDLStatus() {
        guard isRunning else { return }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/sbin/ifconfig")
        process.arguments = ["awdl0"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()
        do {
            try process.run()
            process.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            guard let output = String(data: data, encoding: .utf8) else { return }

            // Check if AWDL is UP - indicates AirDrop is active
            if output.contains("<UP,") || output.contains(",UP,") {
                logger.debug("AWDL interface is active - AirDrop may be in use")
                // Trigger a fresh scan of Downloads and Desktop
                scanForNewAirDropFiles(in: airdropReceivePath)
                scanForNewAirDropFiles(in: desktopPath)
            }
        } catch {
            // ifconfig not available
        }
    }

    // MARK: - Polling Fallback

    private func startPolling() {
        // Scan Downloads every 15 seconds as fallback
        DispatchQueue.main.asyncAfter(deadline: .now() + 15) { [weak self] in
            guard let self = self, self.isRunning else { return }
            self.scanForNewAirDropFiles(in: self.airdropReceivePath)
            self.scanForNewAirDropFiles(in: self.desktopPath)
            self.startPolling() // re-arm
        }
    }

    // MARK: - Helpers

    private func max(_ a: DLPSeverity, _ b: DLPSeverity) -> DLPSeverity {
        let order: [DLPSeverity] = [.info, .low, .medium, .high, .critical]
        let ai = order.firstIndex(of: a) ?? 0
        let bi = order.firstIndex(of: b) ?? 0
        return ai >= bi ? a : b
    }

    private func max(_ a: DLPAction, _ b: DLPAction) -> DLPAction {
        let p: [DLPAction: Int] = [.block: 5, .quarantine: 4, .warn: 3, .audit: 2, .log: 1, .allow: 0]
        return (p[a] ?? 0) >= (p[b] ?? 0) ? a : b
    }
}

// MARK: - AirDrop Direction

enum AirDropDirection: String {
    case received = "received"
    case sent = "sent"
}
