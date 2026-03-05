//
//  ScreenCaptureMonitor.swift
//  NextGuard Endpoint DLP Agent
//
//  Copyright (c) 2026 NextGuard Technology Limited. All rights reserved.
//  Screenshot/Screen recording DLP monitoring
//  Ref: ISO 27001:2022 A.8.12, CIS Controls v8 3.3
//

import Foundation
import AppKit
import os.log
import Vision

// MARK: - Screen Capture Policy
enum ScreenCapturePolicy: String, Codable {
    case allow, auditOnly, blockAll, blockThirdParty
}

// MARK: - Screen Capture Monitor
final class ScreenCaptureMonitor: ObservableObject {
    static let shared = ScreenCaptureMonitor()
    private let logger = Logger(subsystem: "com.nextguard.agent", category: "ScreenCapture")

    @Published var isActive: Bool = false
    @Published var totalCaptures: Int = 0
    @Published var blockedCaptures: Int = 0

    private var screenshotWatcher: DispatchSourceFileSystemObject?
    private var processMonitorTimer: Timer?
    private var knownScreenshots: Set<String> = []
    var currentPolicy: ScreenCapturePolicy = .auditOnly

    private let screenCaptureApps = [
        "screencaptureui", "Screenshot", "screencapture",
        "QuickTime Player", "OBS", "ScreenFlow",
        "Snagit", "Skitch", "CleanShot", "Monosnap",
        "Loom", "Kap", "LICEcap"
    ]

    private init() {}

    func startMonitoring() {
        guard !isActive else { return }
        logger.info("Starting screen capture DLP monitoring")
        watchScreenshotDirectory()
        monitorCaptureProcesses()
        DispatchQueue.main.async { self.isActive = true }
        print("[OK] Screen capture monitoring started")
    }

    func stopMonitoring() {
        screenshotWatcher?.cancel()
        screenshotWatcher = nil
        processMonitorTimer?.invalidate()
        processMonitorTimer = nil
        DispatchQueue.main.async { self.isActive = false }
        logger.info("Screen capture monitoring stopped")
    }

    private func watchScreenshotDirectory() {
        let screenshotPath = getScreenshotDirectory()
        let fd = open(screenshotPath, O_EVTONLY)
        guard fd >= 0 else { return }
        let source = DispatchSource.makeFileSystemObjectSource(
            fileDescriptor: fd, eventMask: .write,
            queue: DispatchQueue.global(qos: .utility)
        )
        source.setEventHandler { [weak self] in
            self?.checkForNewScreenshots(in: screenshotPath)
        }
        source.setCancelHandler { close(fd) }
        screenshotWatcher = source
        source.resume()
    }

    private func getScreenshotDirectory() -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/defaults")
        process.arguments = ["read", "com.apple.screencapture", "location"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()
        do {
            try process.run()
            process.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            if let path = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines), !path.isEmpty {
                return path
            }
        } catch {}
        return NSHomeDirectory() + "/Desktop"
    }

    private func checkForNewScreenshots(in directory: String) {
        guard let files = try? FileManager.default.contentsOfDirectory(atPath: directory) else { return }
        for file in files {
            let filePath = directory + "/" + file
            guard (file.hasPrefix("Screenshot") || file.hasPrefix("Screen Shot") || file.hasPrefix("Screen Recording")) &&
                  (file.hasSuffix(".png") || file.hasSuffix(".jpg") || file.hasSuffix(".mov") || file.hasSuffix(".mp4")) else { continue }
            guard !knownScreenshots.contains(filePath) else { continue }
            guard let attrs = try? FileManager.default.attributesOfItem(atPath: filePath),
                  let created = attrs[.creationDate] as? Date,
                  Date().timeIntervalSince(created) < 5.0 else { continue }
            knownScreenshots.insert(filePath)
            let isRecording = file.hasSuffix(".mov") || file.hasSuffix(".mp4")
            handleCapture(filePath: filePath, isRecording: isRecording, appName: "screencapture")
        }
    }

    private func monitorCaptureProcesses() {
        processMonitorTimer = Timer.scheduledTimer(withTimeInterval: 3.0, repeats: true) { [weak self] _ in
            self?.checkRunningCaptureApps()
        }
    }

    private func checkRunningCaptureApps() {
        let runningApps = NSWorkspace.shared.runningApplications
        for app in runningApps {
            guard let name = app.localizedName else { continue }
            if screenCaptureApps.contains(where: { name.lowercased().contains($0.lowercased()) }) {
                if currentPolicy == .blockThirdParty && name != "screencapture" && name != "Screenshot" {
                    logger.warning("Third-party capture app blocked: \(name)")
                    app.terminate()
                    IncidentStoreManager.shared.addIncident(
                        policyName: "Screen Capture Policy",
                        action: "Block",
                        details: "Third-party capture app terminated: \(name)"
                    )
                }
            }
        }
    }
    private let policyEngine = DLPPolicyEngine.shared
    private let localPolicyEngine = LocalPolicyEngine.shared

    // MARK: - OCR Text Extraction (Vision Framework)
    private func extractText(from imagePath: String, completion: @escaping (String?) -> Void) {
        guard let image = NSImage(contentsOfFile: imagePath),
              let cgImage = image.cgImage(forProposedRect: nil, context: nil, hints: nil) else {
            completion(nil)
            return
        }
        let request = VNRecognizeTextRequest { request, error in
            guard let observations = request.results as? [VNRecognizedTextObservation] else {
                completion(nil)
                return
            }
            let text = observations.compactMap { $0.topCandidates(1).first?.string }.joined(separator: "\n")
            completion(text.isEmpty ? nil : text)
        }
        request.recognitionLevel = .accurate
        request.recognitionLanguages = ["en", "zh-Hant", "zh-Hans"]
        let handler = VNImageRequestHandler(cgImage: cgImage, options: [:])
        DispatchQueue.global(qos: .utility).async {
            try? handler.perform([request])
        }
    }


    
    private func handleCapture(filePath: String, isRecording: Bool, appName: String) {
        totalCaptures += 1
        let captureType = isRecording ? "screenRecording" : "screenshot"
        logger.info("Screen capture detected: \(captureType) by \(appName)")

                // OCR + DLP Policy Scanning for screenshots
        if !isRecording {
            extractText(from: filePath) { [weak self] ocrText in
                guard let self = self else { return }
                if let text = ocrText {
                    self.logger.info("OCR extracted \(text.count) characters from screenshot")
                    // Scan with DLP Policy Engine
                    let results = self.policyEngine.scanContent(text, channel: .screenshot, filePath: filePath, processName: appName)
                    let localMatch = self.localPolicyEngine.evaluate(content: text, filePath: filePath, destination: nil as String?, app: appName)
                    if !results.isEmpty || localMatch != nil {
                        let action = self.policyEngine.determineAction(for: results)
                        self.logger.warning("Screenshot DLP MATCH: \(results.count) policy violations detected")
                        if action == .block || action == .quarantine {
                            try? FileManager.default.removeItem(atPath: filePath)
                            DispatchQueue.main.async { self.blockedCaptures += 1 }
                            self.logger.warning("Screenshot BLOCKED and deleted: \(filePath)")
                        }
                        for result in results {
                            IncidentStoreManager.shared.addIncident(
                                policyName: result.ruleName,
                                action: result.action == .block ? "Block" : "Audit",
                                details: "Screenshot OCR: \(result.matches.count) matches for \(result.ruleName) in \(filePath)"
                            )
                        }
                        if let local = localMatch {
                            IncidentStoreManager.shared.addIncident(
                                policyName: local.matchedRule.name,
                                action: local.action.rawValue,
                                details: "Screenshot OCR (local): matched \(local.matchedRule.name) in \(filePath)"
                            )
                        }
                        Task {
                            for result in results {
                                await ManagementClient.shared.reportIncident(
                                    policyId: result.ruleId,
                                    channel: "screenshot",
                                    severity: result.severity.rawValue,
                                    action: result.action.rawValue,
                                    matchCount: result.matches.count,
                                    details: "Screenshot OCR: \(result.ruleName)"
                                )
                            }
                        }
                    } else {
                        self.logger.info("Screenshot OCR: no sensitive content detected")
                    }
                } else {
                    self.logger.info("Screenshot OCR: no text extracted (image only)")
                }
            }
            return  // OCR handles all incident logic for screenshots
        }

        var action: DLPAction = .audit
        switch currentPolicy {
        case .allow: action = .allow
        case .auditOnly: action = .audit
        case .blockAll: action = .block
        case .blockThirdParty:
            action = (appName == "screencapture" || appName == "Screenshot") ? .audit : .block
        }

        if action == .block {
            try? FileManager.default.removeItem(atPath: filePath)
            blockedCaptures += 1
            logger.warning("Screenshot BLOCKED and deleted: \(filePath)")
        }

        IncidentStoreManager.shared.addIncident(
            policyName: "Screen Capture Detection",
            action: action == .block ? "Block" : "Audit",
            details: "\(captureType) by \(appName): \(filePath)"
        )

        Task {
            await ManagementClient.shared.reportIncident(
                policyId: "screen-capture",
                channel: "screenshot",
                severity: "medium",
                action: action.rawValue,
                matchCount: 1,
                details: "\(captureType) by \(appName)"
            )
        }
    }
}
