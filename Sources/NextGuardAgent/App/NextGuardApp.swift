//
// NextGuardApp.swift
// NextGuard Endpoint DLP Agent
//
// Copyright (c) 2026 NextGuard Technology Limited. All rights reserved.
// Enterprise-grade Data Loss Prevention for macOS
//
import AppKit
import SwiftUI
import os.log
import Darwin

@main
class AppDelegate: NSObject, NSApplicationDelegate {
    static let logger = Logger(subsystem: "com.nextguard.agent", category: "App")

    // Single instance lock fd - kept open for lifetime of process so flock stays held
    private static var lockFd: Int32 = -1

    // Core engines
    private let policyEngine = DLPPolicyEngine.shared
    private let localPolicyEngine = LocalPolicyEngine.shared
    private let mgmtClient = ManagementClient.shared

    // GUI controllers - MenuBarController owns the ONLY NSStatusItem
    private var menuBarController: MenuBarController?
    private var mainWindowController: MainWindowController?

    static func main() {
        // ── Single instance guard using flock() ──────────────────────────────
        // lockFd must remain open - OS releases flock when fd closes or process exits
        let lockPath = "/tmp/com.nextguard.agent.lock"
        let fd = open(lockPath, O_CREAT | O_RDWR, 0o600)
        guard fd >= 0 else {
            print("[ERROR] Cannot open lock file")
            exit(1)
        }
        if flock(fd, LOCK_EX | LOCK_NB) != 0 {
            // Another instance is already running - terminate this duplicate
            print("[WARN] NextGuard Agent already running. Terminating duplicate instance.")
            Darwin.close(fd)
            exit(0)
        }
        // Hold lock for the entire process lifetime
        lockFd = fd
        let pidStr = "\(ProcessInfo.processInfo.processIdentifier)\n"
        _ = pidStr.withCString { ptr in write(lockFd, ptr, strlen(ptr)) }

        // ── Launch as menu-bar-only app (no Dock icon, no extra window) ─────
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)  // FIX: was .regular which caused two visible instances
        let delegate = AppDelegate()
        app.delegate = delegate
        app.run()

        // Unlock and release on clean exit
        flock(lockFd, LOCK_UN)
        Darwin.close(lockFd)
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        Self.logger.info("NextGuard DLP Agent v2.4.0 launching")
        print("[OK] Application launched")

        // Setup menu bar FIRST - MenuBarController creates the ONLY status item
        menuBarController = MenuBarController()
        menuBarController?.setupMenuBar()
        print("[OK] Menu bar initialized")

        // Setup main window (hidden by default; opens on demand)
        mainWindowController = MainWindowController()
        print("[OK] Main window controller ready")

        // Start all monitors
        ClipboardMonitor.shared.startMonitoring()
        FileSystemWatcher.shared.startWatching()
        USBDeviceMonitor.shared.startMonitoring()
        AirDropMonitor.shared.startMonitoring()
        PrintMonitor.shared.startMonitoring()
        EmailMonitor.shared.startMonitoring()
        NetworkMonitor.shared.startMonitoring()
        ScreenCaptureMonitor.shared.startMonitoring()
        BrowserMonitor.shared.startMonitoring()
        DNSFilter.shared.startFiltering()
        WatermarkManager.shared.loadConfig()
        WatermarkManager.shared.startWatermark()
        print("[OK] All monitors started (including DNS Filter)")

        // Async: connect to console and load policies
        Task {
            if mgmtClient.tenantId == nil { mgmtClient.setTenantId("tenant-demo") }
            menuBarController?.updateConnectionStatus(.syncing)
            let registered = await mgmtClient.registerAgent()
            if registered {
                Self.logger.info("Agent registered with management console")
                GUIManager.shared.updateConnectionStatus(connected: true, tenantId: mgmtClient.tenantId, consoleUrl: "https://next-guard.com")
                menuBarController?.updateConnectionStatus(.connected)
            } else {
                Self.logger.warning("Running in local mode")
                GUIManager.shared.updateConnectionStatus(connected: false, tenantId: mgmtClient.tenantId, consoleUrl: "https://next-guard.com")
                menuBarController?.updateConnectionStatus(.disconnected)
            }
            let remotePolicies = await mgmtClient.pullPolicies()
            if !remotePolicies.isEmpty {
                policyEngine.loadPoliciesFromConsole(remotePolicies)
                GUIManager.shared.updatePolicyCount(policyEngine.activePolicies.count, source: "remote")
            } else {
                await policyEngine.loadPolicies()
                GUIManager.shared.updatePolicyCount(policyEngine.activePolicies.count, source: "local")
            }
            mgmtClient.startHeartbeat()
            policyEngine.startPolicyRefresh(interval: 300)
        }

        print("[OK] NextGuard Agent v2.4.0 ready")
    }

    func applicationWillTerminate(_ notification: Notification) {
        print("[OK] NextGuard DLP Agent shutting down")
        ClipboardMonitor.shared.stopMonitoring()
        FileSystemWatcher.shared.stopWatching()
        USBDeviceMonitor.shared.stopMonitoring()
        AirDropMonitor.shared.stopMonitoring()
        PrintMonitor.shared.stopMonitoring()
        EmailMonitor.shared.stopMonitoring()
        NetworkMonitor.shared.stopMonitoring()
        ScreenCaptureMonitor.shared.stopMonitoring()
        BrowserMonitor.shared.stopMonitoring()
        DNSFilter.shared.stopFiltering()
        mgmtClient.stopHeartbeat()
        policyEngine.stopPolicyRefresh()
        // NOTE: Do NOT delete or close lockFd here - handled in main() after app.run() returns
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if !flag {
            mainWindowController?.showWindow(nil)
            mainWindowController?.window?.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
        }
        return true
    }
}
