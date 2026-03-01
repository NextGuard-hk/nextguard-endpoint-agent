//
//  PrinterMonitor.swift
//  NextGuardAgent
//
//  CUPS Print Channel DLP Monitor
//  Monitors and controls print jobs to prevent data exfiltration via printing
//

import Foundation
import Combine

/// Print job information captured from CUPS
struct PrintJobInfo {
    let jobId: Int
    let printerName: String
    let documentName: String
    let userName: String
    let pageCount: Int
    let copies: Int
    let jobSize: Int64
    let createdAt: Date
    let mimeType: String
    let printerURI: String
    var state: PrintJobState = .pending
}

enum PrintJobState: String {
    case pending = "pending"
    case held = "held"
    case processing = "processing"
    case completed = "completed"
    case cancelled = "cancelled"
    case blocked = "blocked"
}

enum PrinterType {
    case local
    case network
    case virtual // PDF printers
    case airprint
    case unknown
}

struct PrinterInfo {
    let name: String
    let uri: String
    let type: PrinterType
    let location: String?
    let isShared: Bool
}

/// Monitors CUPS print subsystem for DLP policy enforcement
class PrinterMonitor {
    private var isMonitoring = false
    private var cupsWatcher: Process?
    private var notificationPipe: Pipe?
    private let eventSubject = PassthroughSubject<PrintJobInfo, Never>()
    var eventPublisher: AnyPublisher<PrintJobInfo, Never> {
        eventSubject.eraseToAnyPublisher()
    }

    private var blockedPrinters: Set<String> = []
    private var sensitiveKeywords: [String] = []
    private var maxJobSizeBytes: Int64 = 50_000_000 // 50MB default
    private var allowVirtualPrinters = true
    private var auditAllJobs = true

    func startMonitoring() {
        guard !isMonitoring else { return }
        isMonitoring = true
        startCUPSNotificationListener()
        pollActivePrintJobs()
        NSLog("[NextGuard] PrinterMonitor started")
    }

    func stopMonitoring() {
        isMonitoring = false
        cupsWatcher?.terminate()
        cupsWatcher = nil
        NSLog("[NextGuard] PrinterMonitor stopped")
    }

    func configure(blockedPrinters: [String], keywords: [String], maxSize: Int64) {
        self.blockedPrinters = Set(blockedPrinters)
        self.sensitiveKeywords = keywords
        self.maxJobSizeBytes = maxSize
    }

    // MARK: - CUPS Integration

    private func startCUPSNotificationListener() {
        let pipe = Pipe()
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/lpstat")
        process.arguments = ["-W", "not-completed"]
        process.standardOutput = pipe

        pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty, let output = String(data: data, encoding: .utf8) else { return }
            self?.parseLpstatOutput(output)
        }

        notificationPipe = pipe
        cupsWatcher = process

        do {
            try process.run()
        } catch {
            NSLog("[NextGuard] Failed to start CUPS monitor: \(error)")
        }
    }

    private func pollActivePrintJobs() {
        DispatchQueue.global(qos: .utility).async { [weak self] in
            while self?.isMonitoring == true {
                self?.checkActiveJobs()
                Thread.sleep(forTimeInterval: 2.0)
            }
        }
    }

    private func checkActiveJobs() {
        let process = Process()
        let pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/lpstat")
        process.arguments = ["-o", "-l"]
        process.standardOutput = pipe

        do {
            try process.run()
            process.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            if let output = String(data: data, encoding: .utf8) {
                parseLpstatOutput(output)
            }
        } catch {
            NSLog("[NextGuard] lpstat poll error: \(error)")
        }
    }

    private func parseLpstatOutput(_ output: String) {
        let lines = output.components(separatedBy: "\n")
        for line in lines where !line.isEmpty {
            if let job = parseJobLine(line) {
                evaluateAndProcess(job)
            }
        }
    }

    private func parseJobLine(_ line: String) -> PrintJobInfo? {
        // Parse lpstat output format: "printer-jobid user size date"
        let parts = line.components(separatedBy: CharacterSet.whitespaces)
            .filter { !$0.isEmpty }
        guard parts.count >= 4 else { return nil }

        let jobParts = parts[0].components(separatedBy: "-")
        let printerName = jobParts.dropLast().joined(separator: "-")
        let jobId = Int(jobParts.last ?? "0") ?? 0
        let userName = parts[1]
        let jobSize = Int64(parts[2]) ?? 0

        return PrintJobInfo(
            jobId: jobId,
            printerName: printerName,
            documentName: "unknown",
            userName: userName,
            pageCount: 0,
            copies: 1,
            jobSize: jobSize,
            createdAt: Date(),
            mimeType: "application/octet-stream",
            printerURI: printerName
        )
    }

    // MARK: - Policy Evaluation

    private func evaluateAndProcess(_ job: PrintJobInfo) {
        var mutableJob = job

        // Check blocked printers
        if blockedPrinters.contains(job.printerName) {
            mutableJob.state = .blocked
            cancelPrintJob(job.jobId)
            reportEvent(mutableJob, action: "blocked", reason: "Printer is on blocked list")
            return
        }

        // Check file size
        if job.jobSize > maxJobSizeBytes {
            mutableJob.state = .blocked
            cancelPrintJob(job.jobId)
            reportEvent(mutableJob, action: "blocked", reason: "Job exceeds maximum size limit")
            return
        }

        // Check sensitive keywords in document name
        let docLower = job.documentName.lowercased()
        for keyword in sensitiveKeywords {
            if docLower.contains(keyword.lowercased()) {
                mutableJob.state = .held
                holdPrintJob(job.jobId)
                reportEvent(mutableJob, action: "held", reason: "Document contains sensitive keyword: \(keyword)")
                return
            }
        }

        // Audit if enabled
        if auditAllJobs {
            reportEvent(mutableJob, action: "allowed", reason: "Job passed all policy checks")
        }
    }

    private func cancelPrintJob(_ jobId: Int) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/cancel")
        process.arguments = [String(jobId)]
        try? process.run()
        process.waitUntilExit()
        NSLog("[NextGuard] Cancelled print job \(jobId)")
    }

    private func holdPrintJob(_ jobId: Int) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/lp")
        process.arguments = ["-i", String(jobId), "-H", "hold"]
        try? process.run()
        process.waitUntilExit()
        NSLog("[NextGuard] Held print job \(jobId)")
    }

    // MARK: - Reporting

    private func reportEvent(_ job: PrintJobInfo, action: String, reason: String) {
        eventSubject.send(job)
        NSLog("[NextGuard] Print DLP: \(action) job \(job.jobId) on \(job.printerName) - \(reason)")
    }

    // MARK: - Printer Discovery

    func getAvailablePrinters() -> [PrinterInfo] {
        let process = Process()
        let pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/lpstat")
        process.arguments = ["-p", "-l"]
        process.standardOutput = pipe

        do {
            try process.run()
            process.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            if let output = String(data: data, encoding: .utf8) {
                return parsePrinterList(output)
            }
        } catch {
            NSLog("[NextGuard] Failed to list printers: \(error)")
        }
        return []
    }

    private func parsePrinterList(_ output: String) -> [PrinterInfo] {
        var printers: [PrinterInfo] = []
        let blocks = output.components(separatedBy: "\n\n")
        for block in blocks where !block.isEmpty {
            let name = block.components(separatedBy: " ").dropFirst().first ?? "unknown"
            let isNetwork = block.contains("ipp://") || block.contains("lpd://")
            let isVirtual = block.lowercased().contains("pdf") || block.lowercased().contains("virtual")
            let type: PrinterType = isVirtual ? .virtual : (isNetwork ? .network : .local)
            printers.append(PrinterInfo(
                name: String(name),
                uri: "",
                type: type,
                location: nil,
                isShared: block.contains("shared")
            ))
        }
        return printers
    }
}
