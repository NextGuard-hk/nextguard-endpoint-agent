//
//  ScreenCaptureMonitor.swift
//  NextGuard Endpoint DLP Agent
//
//  Copyright (c) 2026 NextGuard Technology Limited. All rights reserved.
//
import Foundation
import AppKit
import os.log
import Vision

enum ScreenCapturePolicy: String, Codable {
    case allow, auditOnly, blockAll, blockThirdParty
}

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

    // MARK: - Start / Stop
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
    }

    // MARK: - Directory Watcher
    private func watchScreenshotDirectory() {
        let path = getScreenshotDirectory()
        print("[ScreenCapture] Watching: \(path)")
        let fd = open(path, O_EVTONLY)
        guard fd >= 0 else {
            print("[ScreenCapture] ERROR: Cannot open: \(path)")
            return
        }
        let src = DispatchSource.makeFileSystemObjectSource(
            fileDescriptor: fd, eventMask: .write,
            queue: DispatchQueue.global(qos: .utility)
        )
        src.setEventHandler { [weak self] in self?.checkForNewScreenshots(in: path) }
        src.setCancelHandler { close(fd) }
        screenshotWatcher = src
        src.resume()
    }

    private func getScreenshotDirectory() -> String {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/defaults")
        p.arguments = ["read", "com.apple.screencapture", "location"]
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = Pipe()
        if let _ = try? p.run() {
            p.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let str = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            if !str.isEmpty { return str }
        }
        return NSHomeDirectory() + "/Desktop"
    }

    private func checkForNewScreenshots(in directory: String) {
        guard let files = try? FileManager.default.contentsOfDirectory(atPath: directory) else { return }
        for file in files {
            let fp = directory + "/" + file
            let isShot = file.hasPrefix("Screenshot") || file.hasPrefix("Screen Shot") ||
                         file.hasPrefix("Screen Recording") || file.contains("截圖") || file.contains("截屏")
            let isImg  = file.hasSuffix(".png") || file.hasSuffix(".jpg") ||
                         file.hasSuffix(".mov") || file.hasSuffix(".mp4")
            guard isShot && isImg else { continue }
            guard !knownScreenshots.contains(fp) else { continue }
            guard let attrs = try? FileManager.default.attributesOfItem(atPath: fp),
                  let created = attrs[.creationDate] as? Date,
                  Date().timeIntervalSince(created) < 15.0 else { continue }
            knownScreenshots.insert(fp)
            print("[ScreenCapture] Detected: \(file)")
            let isRec = file.hasSuffix(".mov") || file.hasSuffix(".mp4")
            DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + 1.5) {
                self.handleCapture(filePath: fp, isRecording: isRec, appName: "screencapture")
            }
        }
        if knownScreenshots.count > 500 { knownScreenshots.removeAll() }
    }

    // MARK: - Process Monitor
    private func monitorCaptureProcesses() {
        processMonitorTimer = Timer.scheduledTimer(withTimeInterval: 3.0, repeats: true) { [weak self] _ in
            self?.checkRunningCaptureApps()
        }
    }

    private func checkRunningCaptureApps() {
        for app in NSWorkspace.shared.runningApplications {
            guard let name = app.localizedName else { continue }
            if screenCaptureApps.contains(where: { name.lowercased().contains($0.lowercased()) }) {
                if currentPolicy == .blockThirdParty && name != "screencapture" && name != "Screenshot" {
                    app.terminate()
                    IncidentStoreManager.shared.addIncident(
                        policyName: "Screen Capture Policy", action: "Block",
                        details: "Third-party capture app terminated: \(name)"
                    )
                }
            }
        }
    }

    // MARK: - OCR (synchronous, runs on background thread)
    private func ocrExtract(from imagePath: String) -> String? {
        print("[ScreenCapture] OCR start: \(imagePath)")
        guard let image = NSImage(contentsOfFile: imagePath) else {
            print("[ScreenCapture] OCR: NSImage load failed")
            return nil
        }
        guard let tiff = image.tiffRepresentation,
              let bmp  = NSBitmapImageRep(data: tiff),
              let cg   = bmp.cgImage else {
            print("[ScreenCapture] OCR: cgImage conversion failed")
            return nil
        }
        print("[ScreenCapture] OCR: image \(Int(image.size.width))x\(Int(image.size.height))")

        var extractedText: String? = nil
        let semaphore = DispatchSemaphore(value: 0)

        let req = VNRecognizeTextRequest { req, err in
            defer { semaphore.signal() }
            if let err = err {
                print("[ScreenCapture] OCR VN error: \(err)")
                return
            }
            let obs = req.results as? [VNRecognizedTextObservation] ?? []
            print("[ScreenCapture] OCR: \(obs.count) text observations")
            let lines = obs.compactMap { $0.topCandidates(1).first?.string }
            let joined = lines.joined(separator: " ")
            print("[ScreenCapture] OCR result (\(joined.count) chars): \(String(joined.prefix(300)))")
            extractedText = joined.isEmpty ? nil : joined
        }
        req.recognitionLevel = .accurate
        req.recognitionLanguages = ["en-US", "zh-Hant", "zh-Hans"]
        req.usesLanguageCorrection = false  // faster, less risk of mangling numbers

        let handler = VNImageRequestHandler(cgImage: cg, options: [:])
        do {
            print("[ScreenCapture] OCR: calling perform...")
            try handler.perform([req])
            print("[ScreenCapture] OCR: perform returned")
        } catch {
            print("[ScreenCapture] OCR: perform threw: \(error)")
            semaphore.signal()
        }
        semaphore.wait()
        return extractedText
    }

    // MARK: - Handle Capture
    private func handleCapture(filePath: String, isRecording: Bool, appName: String) {
        DispatchQueue.main.async { self.totalCaptures += 1 }
        print("[ScreenCapture] handleCapture: \(filePath)")

        guard !isRecording else {
            // Recording: just log
            IncidentStoreManager.shared.addIncident(
                policyName: "Screen Capture Detection", action: "Audit",
                details: "Screen recording: \(filePath)"
            )
            return
        }

        // OCR + DLP scan
        let text = ocrExtract(from: filePath)

        guard let ocrText = text, !ocrText.isEmpty else {
            print("[ScreenCapture] OCR: no text, logging basic audit")
            IncidentStoreManager.shared.addIncident(
                policyName: "Screen Capture Detection", action: "Audit",
                details: "Screenshot (no OCR text): \(filePath)"
            )
            return
        }

        // DLP scan
        let results = policyEngine.scanContent(ocrText, channel: .screenshot, filePath: filePath, processName: appName)
        let localMatch = localPolicyEngine.evaluate(content: ocrText, filePath: filePath, destination: nil as String?, app: appName)
        print("[ScreenCapture] DLP: \(results.count) server matches, local=\(localMatch != nil)")

        if results.isEmpty && localMatch == nil {
            print("[ScreenCapture] DLP: clean")
            IncidentStoreManager.shared.addIncident(
                policyName: "Screen Capture Detection", action: "Audit",
                details: "Screenshot OCR clean: \(filePath)"
            )
            return
        }

        // Policy triggered
        let action = policyEngine.determineAction(for: results)
        print("[ScreenCapture] DLP MATCH action=\(action.rawValue)")

        if action == .block || action == .quarantine {
            try? FileManager.default.removeItem(atPath: filePath)
            DispatchQueue.main.async { self.blockedCaptures += 1 }
        }

        for result in results {
            IncidentStoreManager.shared.addIncident(
                policyName: result.ruleName,
                action: result.action == .block ? "Block" : "Audit",
                details: "Screenshot OCR: \(result.matches.count) match(es) — \(result.ruleName)"
            )
        }
        if let local = localMatch {
            IncidentStoreManager.shared.addIncident(
                policyName: local.matchedRule.name,
                action: local.action.rawValue,
                details: "Screenshot OCR (local policy): \(local.matchedRule.name)"
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
    }
}
