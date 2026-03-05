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

    private let policyEngine = DLPPolicyEngine.shared
    private let localPolicyEngine = LocalPolicyEngine.shared

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
        print("[ScreenCapture] Watching directory: \(screenshotPath)")
        let fd = open(screenshotPath, O_EVTONLY)
        guard fd >= 0 else {
            print("[ScreenCapture] ERROR: Cannot open directory: \(screenshotPath)")
            return
        }
        let source = DispatchSource.makeFileSystemObjectSource(
            fileDescriptor: fd,
            eventMask: .write,
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
                print("[ScreenCapture] Custom screenshot dir: \(path)")
                return path
            }
        } catch {}
        let desktop = NSHomeDirectory() + "/Desktop"
        print("[ScreenCapture] Using default screenshot dir: \(desktop)")
        return desktop
    }

    private func checkForNewScreenshots(in directory: String) {
        guard let files = try? FileManager.default.contentsOfDirectory(atPath: directory) else { return }
        for file in files {
            let filePath = directory + "/" + file
            // Match macOS screenshot naming: English + Chinese locales
            let isScreenshot = file.hasPrefix("Screenshot") || file.hasPrefix("Screen Shot") ||
                               file.hasPrefix("Screen Recording") || file.contains("截圖") || file.contains("截屏")
            let isValidExt = file.hasSuffix(".png") || file.hasSuffix(".jpg") ||
                             file.hasSuffix(".mov") || file.hasSuffix(".mp4")
            guard isScreenshot && isValidExt else { continue }
            guard !knownScreenshots.contains(filePath) else { continue }
            guard let attrs = try? FileManager.default.attributesOfItem(atPath: filePath),
                  let created = attrs[.creationDate] as? Date,
                  Date().timeIntervalSince(created) < 10.0 else { continue }
            knownScreenshots.insert(filePath)
            print("[ScreenCapture] New screenshot detected: \(file)")
            let isRecording = file.hasSuffix(".mov") || file.hasSuffix(".mp4")
            handleCapture(filePath: filePath, isRecording: isRecording, appName: "screencapture")
        }
        if knownScreenshots.count > 1000 { knownScreenshots.removeAll() }
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

    // MARK: - OCR Text Extraction (Vision Framework)
    private func extractText(from imagePath: String, completion: @escaping (String?) -> Void) {
        guard let image = NSImage(contentsOfFile: imagePath),
              let tiffData = image.tiffRepresentation,
              let bitmap = NSBitmapImageRep(data: tiffData),
              let cgImage = bitmap.cgImage else {
            print("[ScreenCapture] OCR: Failed to load image: \(imagePath)")
            completion(nil)
            return
        }
        print("[ScreenCapture] OCR: Processing image \(Int(image.size.width))x\(Int(image.size.height))")
        let request = VNRecognizeTextRequest { request, error in
            if let error = error {
                print("[ScreenCapture] OCR error: \(error.localizedDescription)")
                completion(nil)
                return
            }
            guard let observations = request.results as? [VNRecognizedTextObservation] else {
                print("[ScreenCapture] OCR: No observations")
                completion(nil)
                return
            }
            let text = observations.compactMap { $0.topCandidates(1).first?.string }.joined(separator: " ")
            print("[ScreenCapture] OCR: Extracted \(text.count) chars, \(observations.count) text blocks")
            completion(text.isEmpty ? nil : text)
        }
        request.recognitionLevel = .accurate
        request.recognitionLanguages = ["en", "zh-Hant", "zh-Hans"]
        request.usesLanguageCorrection = true
        let handler = VNImageRequestHandler(cgImage: cgImage, options: [:])
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                try handler.perform([request])
            } catch {
                print("[ScreenCapture] OCR perform error: \(error)")
                completion(nil)
            }
        }
    }

    // MARK: - Handle Capture
    private func handleCapture(filePath: String, isRecording: Bool, appName: String) {
        DispatchQueue.main.async { self.totalCaptures += 1 }
        let captureType = isRecording ? "screenRecording" : "screenshot"
        logger.info("Screen capture detected: \(captureType) by \(appName)")
        print("[ScreenCapture] handleCapture: \(captureType) at \(filePath)")

        // For screenshots, run OCR + DLP policy scanning
        if !isRecording {
            // Small delay to ensure file is fully written
            DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + 1.0) { [weak self] in
                guard let self = self else { return }
                self.extractText(from: filePath) { [weak self] ocrText in
                    guard let self = self else { return }
                    if let text = ocrText, !text.isEmpty {
                        print("[ScreenCapture] OCR text preview: \(String(text.prefix(200)))")
                        // Scan with DLP Policy Engine
                        let results = self.policyEngine.scanContent(text, channel: .screenshot, filePath: filePath, processName: appName)
                        let localMatch = self.localPolicyEngine.evaluate(content: text, filePath: filePath, destination: nil as String?, app: appName)

                        if !results.isEmpty || localMatch != nil {
                            let action = self.policyEngine.determineAction(for: results)
                            print("[ScreenCapture] DLP MATCH! \(results.count) server rules, local=\(localMatch != nil), action=\(action.rawValue)")

                            if action == .block || action == .quarantine {
                                try? FileManager.default.removeItem(atPath: filePath)
                                DispatchQueue.main.async { self.blockedCaptures += 1 }
                                self.logger.warning("Screenshot BLOCKED: \(filePath)")
                            }
                            for result in results {
                                IncidentStoreManager.shared.addIncident(
                                    policyName: result.ruleName,
                                    action: result.action == .block ? "Block" : "Audit",
                                    details: "Screenshot OCR: \(result.matches.count) matches for \(result.ruleName)"
                                )
                            }
                            if let local = localMatch {
                                IncidentStoreManager.shared.addIncident(
                                    policyName: local.matchedRule.name,
                                    action: local.action.rawValue,
                                    details: "Screenshot OCR (local): \(local.matchedRule.name)"
                                )
                            }
                            Task {
                                for result in results {
                                    await ManagementClient.shared.reportIncident(
                                        policyId: result.ruleId, channel: "screenshot",
                                        severity: result.severity.rawValue, action: result.action.rawValue,
                                        matchCount: result.matches.count,
                                        details: "Screenshot OCR: \(result.ruleName)"
                                    )
                                }
                            }
                        } else {
                            print("[ScreenCapture] OCR scan: no sensitive content detected")
                            // Still log as audit event
                            IncidentStoreManager.shared.addIncident(
                                policyName: "Screen Capture Detection",
                                action: "Audit",
                                details: "Screenshot captured (OCR clean): \(filePath)"
                            )
                        }
                    } else {
                        print("[ScreenCapture] OCR: no text found, logging basic capture")
                        IncidentStoreManager.shared.addIncident(
                            policyName: "Screen Capture Detection",
                            action: "Audit",
                            details: "Screenshot captured (no OCR text): \(filePath)"
                        )
                    }
                }
            }
            return
        }

        // Screen recording (non-OCR path)
        IncidentStoreManager.shared.addIncident(
            policyName: "Screen Capture Detection",
            action: "Audit",
            details: "\(captureType) by \(appName): \(filePath)"
        )
        Task {
            await ManagementClient.shared.reportIncident(
                policyId: "screen-capture", channel: "screenshot",
                severity: "medium", action: "audit",
                matchCount: 1, details: "\(captureType) by \(appName)"
            )
        }
    }
}
