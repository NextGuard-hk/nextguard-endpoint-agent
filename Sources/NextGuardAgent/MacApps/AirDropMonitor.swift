//
//  AirDropMonitor.swift
//  NextGuardAgent
//
//  AirDrop/AWDL Channel DLP Monitor
//  Monitors and controls AirDrop file transfers to prevent data exfiltration
//

import Foundation
import Combine
import Network

/// AirDrop transfer event information
struct AirDropEvent {
    let id: String
    let timestamp: Date
    let direction: TransferDirection
    let peerName: String?
    let peerDeviceType: String?
    let files: [AirDropFileInfo]
    let totalSize: Int64
    var action: AirDropAction = .pending
}

struct AirDropFileInfo {
    let name: String
    let size: Int64
    let mimeType: String
    let utType: String?
}

enum TransferDirection {
    case incoming
    case outgoing
}

enum AirDropAction: String {
    case pending = "pending"
    case allowed = "allowed"
    case blocked = "blocked"
    case flagged = "flagged"
}

enum AirDropDiscoverability: String {
    case noOne = "no_one"
    case contactsOnly = "contacts_only"
    case everyone = "everyone"
}

/// Monitors AirDrop/AWDL for DLP policy enforcement
class AirDropMonitor {
    private var isMonitoring = false
    private var sharingdWatcher: DispatchSourceFileSystemObject?
    private var awdlMonitor: NWPathMonitor?
    private let eventSubject = PassthroughSubject<AirDropEvent, Never>()
    var eventPublisher: AnyPublisher<AirDropEvent, Never> {
        eventSubject.eraseToAnyPublisher()
    }

    // Policy configuration
    private var blockAllTransfers = false
    private var blockOutgoing = false
    private var blockedFileTypes: Set<String> = []
    private var maxTransferSize: Int64 = 100_000_000 // 100MB
    private var sensitivePatterns: [String] = []
    private var enforcedDiscoverability: AirDropDiscoverability? = nil

    func startMonitoring() {
        guard !isMonitoring else { return }
        isMonitoring = true
        watchSharingDaemon()
        monitorAWDLInterface()
        watchDropFolder()
        NSLog("[NextGuard] AirDropMonitor started")
    }

    func stopMonitoring() {
        isMonitoring = false
        sharingdWatcher?.cancel()
        sharingdWatcher = nil
        awdlMonitor?.cancel()
        awdlMonitor = nil
        NSLog("[NextGuard] AirDropMonitor stopped")
    }

    func configure(blockAll: Bool, blockOutgoing: Bool, blockedTypes: [String],
                   maxSize: Int64, patterns: [String], discoverability: AirDropDiscoverability?) {
        self.blockAllTransfers = blockAll
        self.blockOutgoing = blockOutgoing
        self.blockedFileTypes = Set(blockedTypes)
        self.maxTransferSize = maxSize
        self.sensitivePatterns = patterns
        self.enforcedDiscoverability = discoverability

        if let disc = discoverability {
            enforceDiscoverability(disc)
        }
    }

    // MARK: - AWDL Network Monitoring

    private func monitorAWDLInterface() {
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in
            let awdlAvailable = path.availableInterfaces.contains { $0.name.hasPrefix("awdl") }
            if awdlAvailable {
                NSLog("[NextGuard] AWDL interface active - AirDrop capable")
            }
        }
        monitor.start(queue: DispatchQueue.global(qos: .utility))
        awdlMonitor = monitor
    }

    // MARK: - Sharing Daemon Monitoring

    private func watchSharingDaemon() {
        // Monitor sharingd process for AirDrop activity
        let sharingdPath = "/var/folders"
        pollSharingDaemon()
    }

    private func pollSharingDaemon() {
        DispatchQueue.global(qos: .utility).async { [weak self] in
            while self?.isMonitoring == true {
                self?.checkAirDropActivity()
                Thread.sleep(forTimeInterval: 1.0)
            }
        }
    }

    private func checkAirDropActivity() {
        // Check for active AirDrop transfers via sharingd
        let process = Process()
        let pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/log")
        process.arguments = ["show", "--predicate",
                            "subsystem == 'com.apple.sharing' AND category == 'AirDrop'",
                            "--last", "5s", "--style", "compact"]
        process.standardOutput = pipe

        do {
            try process.run()
            process.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            if let output = String(data: data, encoding: .utf8), !output.isEmpty {
                parseAirDropLogs(output)
            }
        } catch {
            // Silently continue - log access may require elevated privileges
        }
    }

    private func parseAirDropLogs(_ output: String) {
        let lines = output.components(separatedBy: "\n")
        for line in lines {
            if line.contains("AirDrop") && (line.contains("send") || line.contains("receive")) {
                let direction: TransferDirection = line.contains("send") ? .outgoing : .incoming
                let event = AirDropEvent(
                    id: UUID().uuidString,
                    timestamp: Date(),
                    direction: direction,
                    peerName: extractPeerName(from: line),
                    peerDeviceType: nil,
                    files: [],
                    totalSize: 0
                )
                evaluateTransfer(event)
            }
        }
    }

    private func extractPeerName(from log: String) -> String? {
        // Extract peer device name from log entry
        if let range = log.range(of: "peer=") {
            let sub = log[range.upperBound...]
            if let endRange = sub.range(of: " ") {
                return String(sub[..<endRange.lowerBound])
            }
        }
        return nil
    }

    // MARK: - Drop Folder Monitoring

    private func watchDropFolder() {
        let dropPath = NSString(string: "~/Library/Application Support/com.apple.sharing").expandingTildeInPath
        guard FileManager.default.fileExists(atPath: dropPath) else { return }

        let fd = open(dropPath, O_EVTONLY)
        guard fd >= 0 else { return }

        let source = DispatchSource.makeFileSystemObjectSource(
            fileDescriptor: fd,
            eventMask: [.write, .extend],
            queue: DispatchQueue.global(qos: .utility)
        )

        source.setEventHandler { [weak self] in
            self?.handleDropFolderChange(at: dropPath)
        }

        source.setCancelHandler { close(fd) }
        source.resume()
        sharingdWatcher = source
    }

    private func handleDropFolderChange(at path: String) {
        // Detect new files appearing in AirDrop staging area
        guard let items = try? FileManager.default.contentsOfDirectory(atPath: path) else { return }
        for item in items {
            let fullPath = (path as NSString).appendingPathComponent(item)
            if let attrs = try? FileManager.default.attributesOfItem(atPath: fullPath) {
                let size = attrs[.size] as? Int64 ?? 0
                let file = AirDropFileInfo(
                    name: item,
                    size: size,
                    mimeType: "application/octet-stream",
                    utType: nil
                )
                let event = AirDropEvent(
                    id: UUID().uuidString,
                    timestamp: Date(),
                    direction: .incoming,
                    peerName: nil,
                    peerDeviceType: nil,
                    files: [file],
                    totalSize: size
                )
                evaluateTransfer(event)
            }
        }
    }

    // MARK: - Policy Evaluation

    private func evaluateTransfer(_ event: AirDropEvent) {
        var mutableEvent = event

        if blockAllTransfers {
            mutableEvent.action = .blocked
            reportEvent(mutableEvent, reason: "All AirDrop transfers are blocked by policy")
            return
        }

        if blockOutgoing && event.direction == .outgoing {
            mutableEvent.action = .blocked
            reportEvent(mutableEvent, reason: "Outgoing AirDrop transfers are blocked")
            return
        }

        if event.totalSize > maxTransferSize {
            mutableEvent.action = .blocked
            reportEvent(mutableEvent, reason: "Transfer exceeds maximum size limit")
            return
        }

        for file in event.files {
            let ext = (file.name as NSString).pathExtension.lowercased()
            if blockedFileTypes.contains(ext) {
                mutableEvent.action = .blocked
                reportEvent(mutableEvent, reason: "File type .\(ext) is blocked for AirDrop")
                return
            }

            let nameLower = file.name.lowercased()
            for pattern in sensitivePatterns {
                if nameLower.contains(pattern.lowercased()) {
                    mutableEvent.action = .flagged
                    reportEvent(mutableEvent, reason: "Filename matches sensitive pattern: \(pattern)")
                    return
                }
            }
        }

        mutableEvent.action = .allowed
        reportEvent(mutableEvent, reason: "Transfer passed all policy checks")
    }

    // MARK: - Discoverability Enforcement

    private func enforceDiscoverability(_ level: AirDropDiscoverability) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/defaults")

        switch level {
        case .noOne:
            process.arguments = ["write", "com.apple.sharingd", "DiscoverableMode", "Off"]
        case .contactsOnly:
            process.arguments = ["write", "com.apple.sharingd", "DiscoverableMode", "Contacts Only"]
        case .everyone:
            process.arguments = ["write", "com.apple.sharingd", "DiscoverableMode", "Everyone"]
        }

        try? process.run()
        process.waitUntilExit()
        NSLog("[NextGuard] AirDrop discoverability enforced: \(level.rawValue)")
    }

    func getCurrentDiscoverability() -> AirDropDiscoverability {
        let process = Process()
        let pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/defaults")
        process.arguments = ["read", "com.apple.sharingd", "DiscoverableMode"]
        process.standardOutput = pipe

        do {
            try process.run()
            process.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            if let output = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) {
                switch output {
                case "Off": return .noOne
                case "Contacts Only": return .contactsOnly
                case "Everyone": return .everyone
                default: return .contactsOnly
                }
            }
        } catch {}
        return .contactsOnly
    }

    // MARK: - Reporting

    private func reportEvent(_ event: AirDropEvent, reason: String) {
        eventSubject.send(event)
        let direction = event.direction == .outgoing ? "OUT" : "IN"
        let fileNames = event.files.map { $0.name }.joined(separator: ", ")
        NSLog("[NextGuard] AirDrop DLP [\(direction)]: \(event.action.rawValue) - \(reason) | Files: \(fileNames)")
    }
}
