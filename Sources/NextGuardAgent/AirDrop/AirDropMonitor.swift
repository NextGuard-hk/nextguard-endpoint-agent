//
//  AirDropMonitor.swift
//  NextGuard Endpoint DLP Agent
//
//  Copyright (c) 2026 NextGuard Technology Limited. All rights reserved.
//
//  AirDrop file transfer DLP monitoring using FSEvents
//  Ref: ISO 27001:2022 A.8.12, NIST SP 800-171 3.1.3
//

import Foundation
import os.log

// MARK: - AirDrop Transfer Info
struct AirDropTransferInfo: Codable, Identifiable {
    let id: String
    let fileName: String
    let filePath: String
    let fileSize: Int64
    let direction: AirDropDirection
    let timestamp: Date
}

enum AirDropDirection: String, Codable {
    case incoming, outgoing
}

// MARK: - AirDrop DLP Event
struct AirDropDLPEvent: Codable {
    let id: String
    let timestamp: Date
    let transfer: AirDropTransferInfo
    let action: DLPAction
    let matchedRules: [String]
}

// MARK: - AirDrop Monitor
final class AirDropMonitor: ObservableObject {
    static let shared = AirDropMonitor()
    private let logger = Logger(subsystem: "com.nextguard.agent", category: "AirDropMonitor")

    @Published var isActive: Bool = false
    @Published var totalTransfers: Int = 0
    @Published var blockedTransfers: Int = 0

    private var eventStream: FSEventStreamRef?
    private let policyEngine = DLPPolicyEngine.shared
    private let localPolicyEngine = LocalPolicyEngine.shared
    private var processedFiles: Set<String> = []

    // AirDrop staging directories on macOS
    private let airDropPaths: [String] = [
        NSHomeDirectory() + "/Library/Sharing",
        "/private/var/folders",  // tmp staging
        NSHomeDirectory() + "/Downloads"  // received files land here
    ]

    private init() {}

    // MARK: - Start / Stop
    func startMonitoring() {
        guard !isActive else { return }
        logger.info("Starting AirDrop DLP monitoring")

        startFSEventStream()
        monitorSharingDaemon()

        DispatchQueue.main.async {
            self.isActive = true
        }
        print("[OK] AirDrop monitoring started")
    }

    func stopMonitoring() {
        if let stream = eventStream {
            FSEventStreamStop(stream)
            FSEventStreamInvalidate(stream)
            FSEventStreamRelease(stream)
            eventStream = nil
        }
        DispatchQueue.main.async {
            self.isActive = false
        }
        logger.info("AirDrop monitoring stopped")
    }

    // MARK: - FSEvents Stream
    private func startFSEventStream() {
        let pathsToWatch = airDropPaths as CFArray

        var context = FSEventStreamContext(
            version: 0,
            info: Unmanaged.passUnretained(self).toOpaque(),
            retain: nil,
            release: nil,
            copyDescription: nil
        )

        let flags: FSEventStreamCreateFlags =
            UInt32(kFSEventStreamCreateFlagUseCFTypes) |
            UInt32(kFSEventStreamCreateFlagFileEvents) |
            UInt32(kFSEventStreamCreateFlagNoDefer)

        guard let stream = FSEventStreamCreate(
            kCFAllocatorDefault,
            { (streamRef, clientCallbackInfo, numEvents, eventPaths, eventFlags, eventIds) in
                guard let info = clientCallbackInfo else { return }
                let monitor = Unmanaged<AirDropMonitor>.fromOpaque(info).takeUnretainedValue()
                let paths = Unmanaged<CFArray>.fromOpaque(eventPaths).takeUnretainedValue() as! [String]
                monitor.handleFSEvents(paths: paths, flags: eventFlags, count: numEvents)
            },
            &context,
            pathsToWatch,
            FSEventStreamEventId(kFSEventStreamEventIdSinceNow),
            0.5,  // latency
            flags
        ) else {
            logger.error("Failed to create FSEvent stream for AirDrop")
            return
        }

        eventStream = stream
        FSEventStreamSetDispatchQueue(stream, DispatchQueue.global(qos: .utility))
        FSEventStreamStart(stream)
    }

    // MARK: - Event Handling
    private func handleFSEvents(paths: [String], flags: UnsafePointer<FSEventStreamEventFlags>, count: Int) {
        for i in 0..<count {
            let path = paths[i]
            let flag = flags[i]

            // Filter for AirDrop-related file events
            guard isAirDropRelated(path) else { continue }

            // Skip if already processed
            guard !processedFiles.contains(path) else { continue }

            // Check if it's a file creation/modification
            let isCreated = (flag & UInt32(kFSEventStreamEventFlagItemCreated)) != 0
            let isModified = (flag & UInt32(kFSEventStreamEventFlagItemModified)) != 0
            let isFile = (flag & UInt32(kFSEventStreamEventFlagItemIsFile)) != 0

            if isFile && (isCreated || isModified) {
                processedFiles.insert(path)
                evaluateAirDropFile(path)
            }
        }
    }

    private func isAirDropRelated(_ path: String) -> Bool {
        // AirDrop uses sharingd and DropZone
        let airDropIndicators = [
            "/Library/Sharing/",
            "com.apple.AirDrop",
            "DropZone",
            "/sharingd/"
        ]
        return airDropIndicators.contains(where: { path.contains($0) }) ||
               (path.contains("/Downloads/") && isRecentFile(path))
    }

    private func isRecentFile(_ path: String) -> Bool {
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: path),
              let created = attrs[.creationDate] as? Date else { return false }
        return Date().timeIntervalSince(created) < 5.0  // within 5 seconds
    }

    // MARK: - Policy Evaluation
    private func evaluateAirDropFile(_ filePath: String) {
        totalTransfers += 1
        logger.info("AirDrop file detected: \(filePath)")

        // Get file info
        let fileSize: Int64 = (try? FileManager.default.attributesOfItem(atPath: filePath)[.size] as? Int64) ?? 0
        let fileName = URL(fileURLWithPath: filePath).lastPathComponent

        let transfer = AirDropTransferInfo(
            id: UUID().uuidString,
            fileName: fileName,
            filePath: filePath,
            fileSize: fileSize,
            direction: filePath.contains("/Downloads/") ? .incoming : .outgoing,
            timestamp: Date()
        )

        // Scan file content
        let results = policyEngine.scanFile(at: filePath, channel: .airdrop)
        let action = policyEngine.determineAction(for: results)

        if action == .block {
            // Quarantine the file
            let quarantinePath = "/Library/Application Support/NextGuard/Quarantine/"
            try? FileManager.default.createDirectory(atPath: quarantinePath, withIntermediateDirectories: true)
            let dest = quarantinePath + fileName
            try? FileManager.default.moveItem(atPath: filePath, toPath: dest)
            blockedTransfers += 1
            logger.warning("AirDrop BLOCKED: \(fileName) quarantined")
        }

        // Log incidents
        for result in results {
            let guiAction: RuleAction = result.action == .block ? .block : .audit
            IncidentStoreManager.shared.addIncident(
                policyName: result.ruleName,
                action: guiAction,
                details: "AirDrop \(transfer.direction.rawValue): \(fileName) (\(fileSize) bytes) - \(result.matches.count) matches",
                channel: "AirDrop"
            )
        }

        // Report to console
        Task {
            for result in results {
                await ManagementClient.shared.reportIncident(
                    policyId: result.ruleId,
                    channel: "airdrop",
                    severity: result.severity.rawValue,
                    action: result.action.rawValue,
                    matchCount: result.matches.count,
                    details: "AirDrop \(transfer.direction.rawValue): \(fileName)"
                )
            }
        }
    }

    // MARK: - sharingd Process Monitoring
    private func monitorSharingDaemon() {
        // Monitor sharingd (AirDrop daemon) activity via process list
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/log")
            process.arguments = ["stream", "--predicate", "subsystem == 'com.apple.sharing'"]

            let pipe = Pipe()
            process.standardOutput = pipe

            pipe.fileHandleForReading.readabilityHandler = { handle in
                let data = handle.availableData
                guard !data.isEmpty,
                      let line = String(data: data, encoding: .utf8) else { return }

                if line.contains("AirDrop") && (line.contains("send") || line.contains("receive")) {
                    self?.logger.info("AirDrop activity: \(line.prefix(200))")
                }
            }

            try? process.run()
        }
    }
}
