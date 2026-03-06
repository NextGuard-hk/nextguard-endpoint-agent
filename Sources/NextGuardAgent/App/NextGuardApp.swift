// NextGuardApp.swift
// NextGuard Agent
// Copyright © 2024 NextGuard Technology. All rights reserved.

import SwiftUI
import AppKit

@main
struct NextGuardApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate

    var body: some Scene {
        Settings {
            EmptyView()
        }
    }
}

class AppDelegate: NSObject, NSApplicationDelegate {
    var statusItem: NSStatusItem?
    var popover: NSPopover?
    var statusBarController: StatusBarController?
    var overlayEngine: OverlayEngine?

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Single instance guard: terminate if another instance is already running
        let bundleID = Bundle.main.bundleIdentifier ?? "com.nextguard.agent"
        let runningApps = NSRunningApplication.runningApplications(withBundleIdentifier: bundleID)
        if runningApps.count > 1 {
            NSApplication.shared.terminate(nil)
            return
        }

        // Bring app to front and exit(0) if launched from .build/debug/NextGuardAgent multiple times
        NSApp.setActivationPolicy(.accessory)

        setupStatusBar()
        setupOverlayEngine()

        // Start URL security monitoring
        URLSecurityManager.shared.startMonitoring()
        NetworkFilterManager.shared.configure()
    }

    func applicationWillTerminate(_ notification: Notification) {
        URLSecurityManager.shared.stopMonitoring()
        NetworkFilterManager.shared.cleanup()
    }

    private func setupStatusBar() {
        statusBarController = StatusBarController()
    }

    private func setupOverlayEngine() {
        overlayEngine = OverlayEngine.shared
    }
}
