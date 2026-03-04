//
//  PrintMonitor.swift
//  NextGuard Endpoint DLP Agent
//
//  Copyright (c) 2026 NextGuard Technology Limited. All rights reserved.
//
//  Print job DLP monitoring using CUPS/macOS print system
//  Ref: ISO 27001:2022 A.8.12, NIST SP 800-171 3.1.3
//

import Foundation
import os.log

// MARK: - Print Job Info
struct PrintJobInfo: Codable, Identifiable {
    let id: String
    let jobId: Int
    let printerName: String
    let documentName: String
    let userName: String
    let pageCount: Int
    let timestamp: Date
    let filePath: String?
}

// MARK: - Print DLP Event
struct PrintDLPEvent: Codable {
    let id: String
    let timestamp: Date
    let job: PrintJobInfo
    let action: DLPAction
    let matchedRules: [String]
    let channel: String
}

// MARK: - Print Monitor
final class PrintMonitor: ObservableObject {
    static let shared = PrintMonitor()
    private let logger = Logger(subsystem: "com.nextguard.agent", category: "PrintMonitor")

    @Published var isActive: Bool = false
    @Published var totalPrintJobs: Int = 0
    @Published var blockedPrintJobs: Int = 0

    private var cupsMonitorTimer: Timer?
    private var knownJobIds: Set<Int> = []
    private let policyEngine = DLPPolicyEngine.shared
    private let localPolicyEngine = LocalPolicyEngine.shared

    private init() {}

    // MARK: - Start / Stop
    func startMonitoring() {
        guard !isActive else { return }
        logger.info("Starting print DLP monitoring")

        // Monitor CUPS spool directory for new print jobs
        startCUPSPolling()
        // Monitor print-to-PDF via FSEvents
        startPDFExportMonitoring()

        DispatchQueue.main.async {
            self.isActive = true
        }
        print("[OK] Print monitoring started")
    }

    func stopMonitoring() {
        cupsMonitorTimer?.invalidate()
        cupsMonitorTimer = nil
        DispatchQueue.main.async {
            self.isActive = false
        }
        logger.info("Print monitoring stopped")
    }

    // MARK: - CUPS Spool Monitoring
    private func startCUPSPolling() {
        // Poll CUPS job list every 2 seconds
        cupsMonitorTimer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { [weak self] _ in
            self?.checkCUPSJobs()
        }
    }

    private func checkCUPSJobs() {
        // Use lpstat to get active print jobs
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

            parseAndEvaluateJobs(output)
        } catch {
            logger.error("Failed to query CUPS: \(error.localizedDescription)")
        }
    }

    private func parseAndEvaluateJobs(_ lpstatOutput: String) {
        // lpstat -o format: "printer-123 username 1024 Mon 01 Jan 2026 10:00:00"
        let lines = lpstatOutput.components(separatedBy: "\n").filter { !$0.isEmpty }

        for line in lines {
            let parts = line.components(separatedBy: CharacterSet.whitespaces).filter { !$0.isEmpty }
            guard parts.count >= 4 else { continue }

            let jobFullId = parts[0] // e.g. "HP_LaserJet-123"
            let components = jobFullId.components(separatedBy: "-")
            guard let jobIdStr = components.last, let jobId = Int(jobIdStr) else { continue }

            // Skip already processed jobs
            guard !knownJobIds.contains(jobId) else { continue }
            knownJobIds.insert(jobId)

            let printerName = components.dropLast().joined(separator: "-")
            let userName = parts[1]

            let job = PrintJobInfo(
                id: UUID().uuidString,
                jobId: jobId,
                printerName: printerName,
                documentName: "Print Job #\(jobId)",
                userName: userName,
                pageCount: 0,
                timestamp: Date(),
                filePath: nil
            )

            evaluatePrintJob(job)
        }
    }

    // MARK: - Print-to-PDF Monitoring
    private func startPDFExportMonitoring() {
        // Watch common PDF export directories
        let pdfPaths = [
            NSHomeDirectory() + "/Desktop",
            NSHomeDirectory() + "/Documents",
            NSHomeDirectory() + "/Downloads"
        ]

        for path in pdfPaths {
            monitorDirectory(path) { [weak self] filePath in
                if filePath.hasSuffix(".pdf") {
                    self?.evaluatePDFExport(filePath)
                }
            }
        }
    }

    private func monitorDirectory(_ path: String, handler: @escaping (String) -> Void) {
        let fd = open(path, O_EVTONLY)
        guard fd >= 0 else { return }

        let source = DispatchSource.makeFileSystemObjectSource(
            fileDescriptor: fd,
            eventMask: .write,
            queue: DispatchQueue.global(qos: .utility)
        )

        source.setEventHandler {
            // Check for new PDF files
            if let enumerator = FileManager.default.enumerator(atPath: path) {
                while let file = enumerator.nextObject() as? String {
                    if file.hasSuffix(".pdf") {
                        handler(path + "/" + file)
                    }
                    enumerator.skipDescendants()
                }
            }
        }

        source.setCancelHandler {
            close(fd)
        }

        source.resume()
    }

    // MARK: - Policy Evaluation
    private func evaluatePrintJob(_ job: PrintJobInfo) {
        totalPrintJobs += 1
        logger.info("Print job detected: \(job.printerName) job #\(job.jobId)")

        // Try to read spool file content for DLP scanning
        let spoolPath = "/var/spool/cups/d\(String(format: "%05d", job.jobId))-001"
        var contentToScan = ""

        if let data = FileManager.default.contents(atPath: spoolPath),
           let text = String(data: data, encoding: .utf8) {
            contentToScan = text
        }

        // Scan content with DLP engine
        let results = policyEngine.scanContent(contentToScan, channel: .print, processName: "PrintJob")
        let localMatch = localPolicyEngine.evaluate(
            content: contentToScan,
            filePath: nil,
            destination: job.printerName,
            app: "Print"
        )

        let action = policyEngine.determineAction(for: results)
        let finalAction = (localMatch?.action == .block) ? .block : action

        if finalAction == .block {
            cancelPrintJob(job.jobId)
            blockedPrintJobs += 1
            logger.warning("Print job BLOCKED: #\(job.jobId) on \(job.printerName)")
        }

        // Log incident
        let matchedRules = results.map { $0.ruleName }
        let event = PrintDLPEvent(
            id: UUID().uuidString,
            timestamp: Date(),
            job: job,
            action: finalAction,
            matchedRules: matchedRules,
            channel: "print"
        )

        // Report to incident store
        for result in results {
            let guiAction: RuleAction = result.action == .block ? .block : .audit
            IncidentStoreManager.shared.addIncident(
                policyName: result.ruleName,
                action: guiAction,
                details: "Print job #\(job.jobId) on \(job.printerName): \(result.matches.count) matches",
                channel: "Print"
            )
        }

        // Report to console
        Task {
            for result in results {
                await ManagementClient.shared.reportIncident(
                    policyId: result.ruleId,
                    channel: "print",
                    severity: result.severity.rawValue,
                    action: result.action.rawValue,
                    matchCount: result.matches.count,
                    details: "Print job #\(job.jobId) on \(job.printerName)"
                )
            }
        }
    }

    private func evaluatePDFExport(_ filePath: String) {
        logger.info("PDF export detected: \(filePath)")

        let results = policyEngine.scanFile(at: filePath, channel: .print)
        let action = policyEngine.determineAction(for: results)

        if action == .block {
            // Move to quarantine
            let quarantinePath = "/Library/Application Support/NextGuard/Quarantine/"
            try? FileManager.default.createDirectory(atPath: quarantinePath, withIntermediateDirectories: true)
            let dest = quarantinePath + URL(fileURLWithPath: filePath).lastPathComponent
            try? FileManager.default.moveItem(atPath: filePath, toPath: dest)
            logger.warning("PDF export BLOCKED and quarantined: \(filePath)")
        }

        for result in results {
            let guiAction: RuleAction = result.action == .block ? .block : .audit
            IncidentStoreManager.shared.addIncident(
                policyName: result.ruleName,
                action: guiAction,
                details: "PDF export: \(filePath) - \(result.matches.count) matches",
                channel: "Print"
            )
        }
    }

    // MARK: - CUPS Job Control
    private func cancelPrintJob(_ jobId: Int) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/cancel")
        process.arguments = [String(jobId)]
        try? process.run()
        process.waitUntilExit()
    }
}
