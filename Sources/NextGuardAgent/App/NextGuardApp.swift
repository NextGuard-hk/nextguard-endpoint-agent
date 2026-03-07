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
        let lockPath = "/tmp/com.nextguard.agent.lock"
        let fd = open(lockPath, O_CREAT | O_RDWR, 0o600)
        guard fd >= 0 else {
            print("[ERROR] Cannot open lock file")
            exit(1)
        }
        if flock(fd, LOCK_EX | LOCK_NB) != 0 {
            print("[WARN] NextGuard Agent already running. Terminating duplicate instance.")
            Darwin.close(fd)
            exit(0)
        }
        lockFd = fd
        let pidStr = "\(ProcessInfo.processInfo.processIdentifier)\n"
        _ = pidStr.withCString { ptr in write(lockFd, ptr, strlen(ptr)) }

        // ── Install signal handlers to ensure /etc/hosts cleanup on kill ────
        // This is CRITICAL - pkill/Ctrl+C sends SIGTERM/SIGINT which normally
        // bypasses applicationWillTerminate. We intercept them here.
        let cleanup: @convention(c) (Int32) -> Void = { _ in
            print("[NextGuard] Signal received - cleaning up /etc/hosts...")
            DNSFilter.shared.stopFiltering()
            // Small sleep to let the async queue flush
            Thread.sleep(forTimeInterval: 0.5)
            print("[NextGuard] Cleanup complete. Exiting.")
            exit(0)
        }
        signal(SIGTERM, cleanup)
        signal(SIGINT, cleanup)

        // ── Launch as menu-bar-only app (no Dock icon) ─────────────────────
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        let delegate = AppDelegate()
        app.delegate = delegate
        app.run()

        // Unlock on clean exit
        flock(lockFd, LOCK_UN)
        Darwin.close(lockFd)
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        Self.logger.info("NextGuard DLP Agent v2.4.0 launching")
        print("[OK] Application launched")

        menuBarController = MenuBarController()
        menuBarController?.setupMenuBar()
        print("[OK] Menu bar initialized")

        mainWindowController = MainWindowController()
        print("[OK] Main window controller ready")

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
        print("[NextGuard] Shutting down - removing /etc/hosts entries...")
        // Stop DNS filter SYNCHRONOUSLY to ensure /etc/hosts is cleaned
        DNSFilter.shared.stopFiltering()
        Thread.sleep(forTimeInterval: 0.3)
        ClipboardMonitor.shared.stopMonitoring()
        FileSystemWatcher.shared.stopWatching()
        USBDeviceMonitor.shared.stopMonitoring()
        AirDropMonitor.shared.stopMonitoring()
        PrintMonitor.shared.stopMonitoring()
        EmailMonitor.shared.stopMonitoring()
        NetworkMonitor.shared.stopMonitoring()
        ScreenCaptureMonitor.shared.stopMonitoring()
        BrowserMonitor.shared.stopMonitoring()
        BlockPageServer.shared.stop()
        mgmtClient.stopHeartbeat()
        policyEngine.stopPolicyRefresh()
        print("[NextGuard] Shutdown complete.")
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
