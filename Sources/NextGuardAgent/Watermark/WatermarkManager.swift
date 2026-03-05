//
// WatermarkManager.swift
// NextGuard Endpoint DLP Agent
//
// Copyright (c) 2026 NextGuard Technology Limited. All rights reserved.
//
// Watermark modes:
//   1) On Screen Watermark  - overlay on the entire screen
//   2) On Application Watermark - overlay on a specific app window
//

import Foundation
import AppKit
import os.log

// MARK: - Watermark Configuration

enum WatermarkMode: String, Codable, CaseIterable {
    case screenWatermark = "screen"
    case applicationWatermark = "application"
    case disabled = "disabled"

    var displayName: String {
        switch self {
        case .screenWatermark: return "On Screen Watermark"
        case .applicationWatermark: return "On Application Watermark"
        case .disabled: return "Disabled"
        }
    }
}

struct WatermarkConfig: Codable {
    var mode: WatermarkMode = .disabled
    var text: String = ""
    var fontSize: CGFloat = 18
    var opacity: CGFloat = 0.08
    var rotation: CGFloat = -30
    var color: String = "gray"  // gray, red, blue
    var showUsername: Bool = true
    var showHostname: Bool = true
    var showTimestamp: Bool = false
    var showCustomText: Bool = false
    var customText: String = ""
    var targetApps: [String] = []  // for application mode: bundle IDs
}

// MARK: - Watermark Manager

final class WatermarkManager: ObservableObject {
    static let shared = WatermarkManager()
    private let logger = Logger(subsystem: "com.nextguard.agent", category: "Watermark")

    @Published var isActive: Bool = false
    @Published var config: WatermarkConfig = WatermarkConfig()

    private var screenWindows: [NSWindow] = []
    private var appWindows: [String: NSWindow] = [:]  // bundleID -> overlay
    private var appObserver: NSObjectProtocol?
    private var refreshTimer: Timer?

    private init() {}

    // MARK: - Public API

    func startWatermark() {
        guard config.mode != .disabled else {
            stopWatermark()
            return
        }
        logger.info("Starting watermark: mode=\(self.config.mode.rawValue)")
        let watermarkText = buildWatermarkText()

        switch config.mode {
        case .screenWatermark:
            applyScreenWatermark(text: watermarkText)
        case .applicationWatermark:
            applyApplicationWatermark(text: watermarkText)
        case .disabled:
            break
        }

        DispatchQueue.main.async { self.isActive = true }
        print("[OK] Watermark started: \(self.config.mode.rawValue)")
    }

    func stopWatermark() {
        removeAllOverlays()
        DispatchQueue.main.async { self.isActive = false }
        print("[OK] Watermark stopped")
    }

    func updateConfig(_ newConfig: WatermarkConfig) {
        config = newConfig
        saveConfig()
        if config.mode != .disabled {
            stopWatermark()
            startWatermark()
        } else {
            stopWatermark()
        }
    }

    // MARK: - Build Watermark Text

    private func buildWatermarkText() -> String {
        var parts: [String] = []
        if config.showUsername {
            parts.append(NSUserName())
        }
        if config.showHostname {
            parts.append(Host.current().localizedName ?? "Mac")
        }
        if config.showTimestamp {
            let fmt = DateFormatter()
            fmt.dateFormat = "yyyy-MM-dd HH:mm"
            parts.append(fmt.string(from: Date()))
        }
        if config.showCustomText && !config.customText.isEmpty {
            parts.append(config.customText)
        }
        let result = parts.joined(separator: " | ")
        return result.isEmpty ? "NextGuard Protected" : result
    }

    // MARK: - 1) On Screen Watermark

    private func applyScreenWatermark(text: String) {
        removeAllOverlays()
        for screen in NSScreen.screens {
            let window = createOverlayWindow(frame: screen.frame, text: text)
            screenWindows.append(window)
        }
        // Refresh timestamp periodically
        if config.showTimestamp {
            refreshTimer = Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { [weak self] _ in
                self?.refreshScreenWatermark()
            }
        }
        logger.info("Screen watermark applied on \(NSScreen.screens.count) screen(s)")
    }

    private func refreshScreenWatermark() {
        let text = buildWatermarkText()
        for window in screenWindows {
            if let view = window.contentView as? WatermarkView {
                view.watermarkText = text
                view.needsDisplay = true
            }
        }
    }

    // MARK: - 2) On Application Watermark

    private func applyApplicationWatermark(text: String) {
        removeAllOverlays()
        // Watch for app activation
        appObserver = NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.didActivateApplicationNotification,
            object: nil, queue: .main
        ) { [weak self] notification in
            guard let self = self,
                  let app = notification.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication,
                  let bundleId = app.bundleIdentifier else { return }
            self.handleAppActivation(bundleId: bundleId, text: self.buildWatermarkText())
        }
        // Also apply to currently active app
        if let frontApp = NSWorkspace.shared.frontmostApplication,
           let bundleId = frontApp.bundleIdentifier {
            handleAppActivation(bundleId: bundleId, text: text)
        }
        logger.info("Application watermark monitoring started")
    }

    private func handleAppActivation(bundleId: String, text: String) {
        // If targetApps is empty, apply to ALL apps (except self)
        let shouldApply: Bool
        if config.targetApps.isEmpty {
            shouldApply = bundleId != Bundle.main.bundleIdentifier
        } else {
            shouldApply = config.targetApps.contains(bundleId)
        }

        if shouldApply {
            showAppOverlay(bundleId: bundleId, text: text)
        } else {
            hideAppOverlay(bundleId: bundleId)
        }
    }

    private func showAppOverlay(bundleId: String, text: String) {
        if appWindows[bundleId] != nil { return }  // already showing
        guard let screen = NSScreen.main else { return }
        let window = createOverlayWindow(frame: screen.visibleFrame, text: text)
        appWindows[bundleId] = window
    }

    private func hideAppOverlay(bundleId: String) {
        appWindows[bundleId]?.orderOut(nil)
        appWindows.removeValue(forKey: bundleId)
    }

    // MARK: - Overlay Window Factory

    private func createOverlayWindow(frame: NSRect, text: String) -> NSWindow {
        let window = NSWindow(
            contentRect: frame,
            styleMask: .borderless,
            backing: .buffered,
            defer: false
        )
        window.level = .statusBar + 1
        window.backgroundColor = .clear
        window.isOpaque = false
        window.ignoresMouseEvents = true
        window.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .stationary]
        window.hasShadow = false

        let watermarkView = WatermarkView(
            frame: frame,
            watermarkText: text,
            fontSize: config.fontSize,
            opacity: config.opacity,
            rotation: config.rotation,
            textColor: watermarkColor()
        )
        window.contentView = watermarkView
        window.orderFrontRegardless()
        return window
    }

    private func watermarkColor() -> NSColor {
        switch config.color {
        case "red": return .systemRed
        case "blue": return .systemBlue
        default: return .gray
        }
    }

    // MARK: - Cleanup

    private func removeAllOverlays() {
        refreshTimer?.invalidate()
        refreshTimer = nil
        for w in screenWindows { w.orderOut(nil) }
        screenWindows.removeAll()
        for (_, w) in appWindows { w.orderOut(nil) }
        appWindows.removeAll()
        if let obs = appObserver {
            NSWorkspace.shared.notificationCenter.removeObserver(obs)
            appObserver = nil
        }
    }

    // MARK: - Persistence

    private func saveConfig() {
        if let data = try? JSONEncoder().encode(config) {
            UserDefaults.standard.set(data, forKey: "ng_watermark_config")
        }
    }

    func loadConfig() {
        if let data = UserDefaults.standard.data(forKey: "ng_watermark_config"),
           let saved = try? JSONDecoder().decode(WatermarkConfig.self, from: data) {
            config = saved
        }
    }
}

// MARK: - Watermark Overlay View

class WatermarkView: NSView {
    var watermarkText: String
    var fontSize: CGFloat
    var opacity: CGFloat
    var rotation: CGFloat
    var textColor: NSColor

    init(frame: NSRect, watermarkText: String, fontSize: CGFloat,
         opacity: CGFloat, rotation: CGFloat, textColor: NSColor) {
        self.watermarkText = watermarkText
        self.fontSize = fontSize
        self.opacity = opacity
        self.rotation = rotation
        self.textColor = textColor
        super.init(frame: frame)
        self.wantsLayer = true
        self.layer?.backgroundColor = NSColor.clear.cgColor
    }

    required init?(coder: NSCoder) { fatalError() }

    override func draw(_ dirtyRect: NSRect) {
        super.draw(dirtyRect)
        guard let context = NSGraphicsContext.current?.cgContext else { return }

        let font = NSFont.systemFont(ofSize: fontSize, weight: .medium)
        let attrs: [NSAttributedString.Key: Any] = [
            .font: font,
            .foregroundColor: textColor.withAlphaComponent(opacity)
        ]
        let textSize = (watermarkText as NSString).size(withAttributes: attrs)

        let spacingX: CGFloat = textSize.width + 80
        let spacingY: CGFloat = textSize.height + 60

        context.saveGState()
        context.translateBy(x: bounds.midX, y: bounds.midY)
        context.rotate(by: rotation * .pi / 180)
        context.translateBy(x: -bounds.midX, y: -bounds.midY)

        let cols = Int(bounds.width / spacingX) + 4
        let rows = Int(bounds.height / spacingY) + 4
        let startX = -spacingX * 2
        let startY = -spacingY * 2

        for row in 0..<rows {
            for col in 0..<cols {
                let x = startX + CGFloat(col) * spacingX
                let y = startY + CGFloat(row) * spacingY
                (watermarkText as NSString).draw(at: NSPoint(x: x, y: y), withAttributes: attrs)
            }
        }

        context.restoreGState()
    }
}
