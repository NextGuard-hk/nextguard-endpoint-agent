// PrinterMonitor.swift
// NextGuard DLP Agent - Print Channel Monitor
// Monitors print jobs for sensitive data exfiltration via CUPS
// Ref: ISO 27001:2022 A.8.12, Forcepoint/Symantec Print DLP

import Foundation
import AppKit
import os.log

public class PrinterMonitor {
    private let logger = Logger(subsystem: "com.nextguard.agent", category: "PrinterMonitor")
    private var eventHandler: ((DLPEvent) -> Void)?
    private var isRunning = false
    private var cupsWatcher: DispatchSourceFileSystemObject?
    private var jobPollTimer: Timer?
    private let queue = DispatchQueue(label: "com.nextguard.printer", qos: .utility)

    // CUPS spool directory - where print jobs are staged
    private let cupsSpool = "/var/spool/cups"
    // CUPS log file
    private let cupsAccessLog = "/var/log/cups/access_log"
    private let cupsPageLog = "/var/log/cups/page_log"

    // Track seen job IDs to avoid duplicate events
    private var seenJobIds = Set<String>()

    public init() {}

    // MARK: - Start / Stop

    public func start(eventHandler: @escaping (DLPEvent) -> Void) {
        self.eventHandler = eventHandler
        isRunning = true
        logger.info("[NextGuard] PrinterMonitor started")
        startCUPSMonitoring()
        startJobPolling()
        monitorCUPSLog()
    }

    public func stop() {
        isRunning = false
        cupsWatcher?.cancel()
        cupsWatcher = nil
        jobPollTimer?.invalidate()
        jobPollTimer = nil
        logger.info("[NextGuard] PrinterMonitor stopped")
    }

    // MARK: - CUPS Spool Directory Watching
    // Monitor /var/spool/cups for new print job files (requires elevated perms or sandbox entitlement)

    private func startCUPSMonitoring() {
        guard FileManager.default.fileExists(atPath: cupsSpool) else {
            logger.warning("CUPS spool not accessible at \(self.cupsSpool)")
            return
        }
        let fd = open(cupsSpool, O_EVTONLY)
        guard fd >= 0 else {
            logger.warning("Cannot open CUPS spool fd")
            return
        }
        let source = DispatchSource.makeFileSystemObjectSource(
            fileDescriptor: fd,
            eventMask: [.write, .rename],
            queue: queue
        )
        source.setEventHandler { [weak self] in
            self?.handleSpoolActivity()
        }
        source.setCancelHandler { close(fd) }
        source.resume()
        cupsWatcher = source
        logger.info("Watching CUPS spool: \(self.cupsSpool)")
    }

    private func handleSpoolActivity() {
        guard isRunning else { return }
        guard let files = try? FileManager.default.contentsOfDirectory(atPath: cupsSpool) else { return }

        for file in files {
            // CUPS job data files start with 'd' (e.g. d00001-001)
            guard file.hasPrefix("d"), !seenJobIds.contains(file) else { continue }
            seenJobIds.insert(file)

            let fullPath = "\(cupsSpool)/\(file)"
            analyzePrintJob(path: fullPath, jobId: file)
        }
    }

    // MARK: - Print Job Content Analysis

    private func analyzePrintJob(path: String, jobId: String) {
        queue.async { [weak self] in
            guard let self = self else { return }

            // Read PostScript/PDF print job data
            guard let data = FileManager.default.contents(atPath: path) else { return }
            let fileSize = Int64(data.count)

            // Try to extract text content from PostScript
            let textContent = self.extractTextFromPrintData(data)

            // Scan content through DLP engine
            let results = DLPPolicyEngine.shared.scanContent(
                textContent,
                channel: .print,
                filePath: path,
                processName: "cupsd"
            )

            // Determine action
            let action = DLPPolicyEngine.shared.determineAction(for: results)
            let severity = results.max(by: { $0.severity < $1.severity })?.severity ?? .low

            guard !results.isEmpty || fileSize > 10 * 1024 * 1024 else { return }

            let matchedRules = results.map { $0.ruleName }
            let event = DLPEvent(
                id: UUID().uuidString,
                timestamp: Date(),
                agentId: AgentConfig.shared.deviceId,
                hostname: Host.current().localizedName ?? "unknown",
                username: NSUserName(),
                eventType: "PRINT_JOB",
                channel: "print",
                severity: severity.rawValue,
                action: action.rawValue,
                policyName: matchedRules.first ?? "PRINT_MONITOR",
                details: [
                    "jobId": jobId,
                    "filePath": path,
                    "fileSize": String(fileSize),
                    "matchedRules": matchedRules.joined(separator: ", "),
                    "contentPreview": String(textContent.prefix(100))
                ]
            )
            self.eventHandler?(event)
            self.logger.info("Print job DLP event: \(jobId) severity=\(severity.rawValue) action=\(action.rawValue)")

            // Block: cancel the print job if critical
            if action == .block {
                self.cancelPrintJob(jobId: jobId)
            }
        }
    }

    // MARK: - Text Extraction from PostScript / PDF

    private func extractTextFromPrintData(_ data: Data) -> String {
        // PostScript text is mostly ASCII
        var text = ""
        if let raw = String(data: data, encoding: .utf8) {
            text = raw
        } else if let raw = String(data: data, encoding: .isoLatin1) {
            text = raw
        }
        // Extract text between PostScript show commands
        // Pattern: (text string) show
        let pattern = #"\(([^)]{1,500})\)\s*show"#
        if let regex = try? NSRegularExpression(pattern: pattern),
           text.count < 500_000 {
            let nsText = text as NSString
            let matches = regex.matches(in: text, range: NSRange(location: 0, length: nsText.length))
            let extracted = matches.compactMap { m -> String? in
                guard m.numberOfRanges > 1 else { return nil }
                return nsText.substring(with: m.range(at: 1))
            }
            if !extracted.isEmpty {
                return extracted.joined(separator: " ")
            }
        }
        // Fallback: return printable ASCII from raw data
        return String(text.filter { $0.isLetter || $0.isNumber || $0.isWhitespace || $0.isPunctuation }.prefix(50_000))
    }

    // MARK: - Cancel Print Job via CUPS API

    private func cancelPrintJob(jobId: String) {
        // Extract numeric job ID from filename like d00001-001
        let numericId = jobId.replacingOccurrences(of: "d", with: "").components(separatedBy: "-").first ?? ""
        guard !numericId.isEmpty else { return }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/cancel")
        process.arguments = [numericId]
        do {
            try process.run()
            logger.warning("[NextGuard] BLOCKED print job \(numericId) - sensitive data detected")
        } catch {
            logger.error("Failed to cancel print job \(numericId): \(error.localizedDescription)")
        }
    }

    // MARK: - CUPS Page Log Monitoring
    // Monitor page_log for completed print jobs (printer name, pages, user)

    private func monitorCUPSLog() {
        guard FileManager.default.fileExists(atPath: cupsPageLog) else { return }

        let fd = open(cupsPageLog, O_EVTONLY)
        guard fd >= 0 else { return }

        let source = DispatchSource.makeFileSystemObjectSource(
            fileDescriptor: fd,
            eventMask: .extend,
            queue: queue
        )

        var lastOffset: UInt64 = 0
        // Seed with current file size
        if let attrs = try? FileManager.default.attributesOfItem(atPath: cupsPageLog),
           let size = attrs[.size] as? UInt64 {
            lastOffset = size
        }

        source.setEventHandler { [weak self] in
            guard let self = self else { return }
            guard let handle = FileHandle(forReadingAtPath: self.cupsPageLog) else { return }
            defer { handle.closeFile() }
            handle.seek(toFileOffset: lastOffset)
            let newData = handle.readDataToEndOfFile()
            lastOffset += UInt64(newData.count)
            guard let newLines = String(data: newData, encoding: .utf8) else { return }
            for line in newLines.components(separatedBy: "\n") where !line.isEmpty {
                self.parsePageLogEntry(line)
            }
        }
        source.setCancelHandler { close(fd) }
        source.resume()
    }

    // MARK: - Parse CUPS page_log entry
    // Format: printer user job-id date-time page num-copies job-billing job-originating-host-name job-name media sides

    private func parsePageLogEntry(_ line: String) {
        let parts = line.components(separatedBy: " ")
        guard parts.count >= 6 else { return }
        let printer = parts[0]
        let user = parts[1]
        let jobId = parts[2]
        let pageCount = Int(parts[5]) ?? 1

        // High page count = potential bulk print data exfiltration
        let severity: DLPSeverity = pageCount > 50 ? .high : pageCount > 10 ? .medium : .low
        let action: DLPAction = pageCount > 100 ? .warn : .log

        let event = DLPEvent(
            id: UUID().uuidString,
            timestamp: Date(),
            agentId: AgentConfig.shared.deviceId,
            hostname: Host.current().localizedName ?? "unknown",
            username: user,
            eventType: "PRINT_COMPLETED",
            channel: "print",
            severity: severity.rawValue,
            action: action.rawValue,
            policyName: "PRINT_VOLUME_MONITOR",
            details: [
                "printer": printer,
                "jobId": jobId,
                "pageCount": String(pageCount),
                "user": user
            ]
        )
        eventHandler?(event)
        logger.info("Print completed: printer=\(printer) user=\(user) pages=\(pageCount)")
    }

    // MARK: - Job Polling (fallback for environments where FS watch fails)

    private func startJobPolling() {
        jobPollTimer = Timer.scheduledTimer(withTimeInterval: 5.0, repeats: true) { [weak self] _ in
            self?.pollActivePrintJobs()
        }
    }

    private func pollActivePrintJobs() {
        guard isRunning else { return }
        // Use lpstat to get active job list
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/lpstat")
        process.arguments = ["-o"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()
        do {
            try process.run()
            process.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            guard let output = String(data: data, encoding: .utf8), !output.isEmpty else { return }
            parseLpstatOutput(output)
        } catch {
            // lpstat not available or no printers
        }
    }

    private func parseLpstatOutput(_ output: String) {
        // lpstat -o format: printer-jobid username date size
        for line in output.components(separatedBy: "\n") where !line.isEmpty {
            let parts = line.components(separatedBy: " ").filter { !$0.isEmpty }
            guard parts.count >= 3 else { continue }
            let jobDesc = parts[0] // e.g. HP_LaserJet-42
            let user = parts[1]

            guard !seenJobIds.contains(jobDesc) else { continue }
            seenJobIds.insert(jobDesc)

            logger.info("Active print job detected: \(jobDesc) by \(user)")

            let event = DLPEvent(
                id: UUID().uuidString,
                timestamp: Date(),
                agentId: AgentConfig.shared.deviceId,
                hostname: Host.current().localizedName ?? "unknown",
                username: user,
                eventType: "PRINT_ACTIVE",
                channel: "print",
                severity: DLPSeverity.low.rawValue,
                action: DLPAction.log.rawValue,
                policyName: "PRINT_ACTIVITY",
                details: ["jobDescription": jobDesc, "user": user]
            )
            eventHandler?(event)
        }
    }
}
