//
//  ScreenCaptureMonitor.swift
//  NextGuard Endpoint DLP Agent
//
//  Copyright (c) 2026 NextGuard Technology Limited. All rights reserved.
//
//  Screenshot/Screen recording DLP monitoring
//  Ref: ISO 27001:2022 A.8.12, CIS Controls v8 3.3
//

import Foundation
import AppKit
import os.log

// MARK: - Screen Capture Event
struct ScreenCaptureEvent: Codable, Identifiable {
    let id: String
    let captureType: CaptureType
    let filePath: String?
    let appName: String?
    let timestamp: Date
    let action: DLPAction
}

enum CaptureType: String, Codable {
    case screenshot, screenRecording, windowCapture
}

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

    // Known screenshot/recording apps to monitor
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
        registerForScreenCaptureNotifications()

        DispatchQueue.main.async {
            self.isActive = true
        }
        print("[OK] Screen capture monitoring started")
    }

    func stopMonitoring() {
        screenshotWatcher?.cancel()
        screenshotWatcher = nil
        processMonitorTimer?.invalidate()
        processMonitorTimer = nil
        DispatchQueue.main.async {
            self.isActive = false
        }
        logger.info("Screen capture monitoring stopped")
    }

    // MARK: - Screenshot Directory Watch
    private func watchScreenshotDirectory() {
        // Default macOS screenshot location
        let screenshotPath = getScreenshotDirectory()
        let fd = open(screenshotPath, O_EVTONLY)
        guard fd >= 0 else {
            logger.warning("Cannot watch screenshot directory: \(screenshotPath)")
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

        source.setCancelHandler {
            close(fd)
        }

        screenshotWatcher = source
        source.resume()
    }

    private func getScreenshotDirectory() -> String {
        // Read macOS screenshot location from defaults
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
            if let path = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
               !path.isEmpty {
                return path
            }
        } catch {}

        return NSHomeDirectory() + "/Desktop"
    }

    private func checkForNewScreenshots(in directory: String) {
        guard let files = try? FileManager.default.contentsOfDirectory(atPath: directory) else { return }

        for file in files {
            let filePath = directory + "/" + file

            // Match macOS screenshot naming pattern
            guard (file.hasPrefix("Screenshot") || file.hasPrefix("Screen Shot") ||
                   file.hasPrefix("Screen Recording")) &&
                  (file.hasSuffix(".png") || file.hasSuffix(".jpg") ||
                   file.hasSuffix(".mov") || file.hasSuffix(".mp4")) else { continue }

            guard !knownScreenshots.contains(filePath) else { continue }

            // Check if file is recent (within 5 seconds)
            guard let attrs = try? FileManager.default.attributesOfItem(atPath: filePath),
                  let created = attrs[.creationDate] as? Date,
                  Date().timeIntervalSince(created) < 5.0 else { continue }

            knownScreenshots.insert(filePath)

            let isRecording = file.hasSuffix(".mov") || file.hasSuffix(".mp4")
            let captureType: CaptureType = isRecording ? .screenRecording : .screenshot

            handleCapture(filePath: filePath, captureType: captureType, appName: "screencapture")
        }
    }

    // MARK: - Process Monitoring
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
                // Third-party screen capture app detected
                if currentPolicy == .blockThirdParty && name != "screencapture" && name != "Screenshot" {
                    logger.warning("Third-party capture app blocked: \(name)")
                    app.terminate()

                    IncidentStoreManager.shared.addIncident(
                        policyName: "Screen Capture Policy",
                        action: .block,
                        details: "Third-party capture app terminated: \(name)",
                        channel: "ScreenCapture"
                    )
                }
            }
        }
    }

    // MARK: - macOS Notifications
    private func registerForScreenCaptureNotifications() {
        // Monitor pasteboard for screenshot content
        DistributedNotificationCenter.default().addObserver(
            self,
            selector: #selector(handleScreenCaptureNotification),
            name: NSNotification.Name("com.apple.screencapture.
took"),
            object: nil
        )
    }

    @objc private func handleScreenCaptureNotification(_ notification: Notification) {
        logger.info("Screen capture notification received")
        totalCaptures += 1

        let event = ScreenCaptureEvent(
            id: UUID().uuidString,
            captureType: .screenshot,
            filePath: nil,
            appName: "screencapture",
            timestamp: Date(),
            action: currentPolicy == .blockAll ? .block : .audit
        )

        IncidentStoreManager.shared.addIncident(
            policyName: "Screen Capture Detection",
            action: currentPolicy == .blockAll ? .block : .audit,
            details: "Screenshot captured via system shortcut",
            channel: "ScreenCapture"
        )
    }

    // MARK: - Capture Handling
    private func handleCapture(filePath: String, captureType: CaptureType, appName: String) {
        totalCaptures += 1
        logger.info("Screen capture detected: \(captureType.rawValue) by \(appName)")

        var action: DLPAction = .audit

        switch currentPolicy {
        case .allow:
            action = .allow
        case .auditOnly:
            action = .audit
        case .blockAll:
            action = .block
        case .blockThirdParty:
            action = (appName == "screencapture" || appName == "Screenshot") ? .audit : .block
        }

        if action == .block {
            // Delete the screenshot
            try? FileManager.default.removeItem(atPath: filePath)
            blockedCaptures += 1
            logger.warning("Screenshot BLOCKED and deleted: \(filePath)")
        }

        let event = ScreenCaptureEvent(
            id: UUID().uuidString,
            captureType: captureType,
            filePath: filePath,
            appName: appName,
            timestamp: Date(),
            action: action
        )

        let guiAction: RuleAction = action == .block ? .block : .audit
        IncidentStoreManager.shared.addIncident(
            policyName: "Screen Capture Detection",
            action: guiAction,
            details: "\(captureType.rawValue) by \(appName): \(filePath)",
            channel: "ScreenCapture"
        )

        // Report to console
        Task {
            await ManagementClient.shared.reportIncident(
                policyId: "screen-capture",
                channel: "screenshot",
                severity: "medium",
                action: action.rawValue,
                matchCount: 1,
                details: "\(captureType.rawValue) by \(appName)"
            )
        }
    }
}
