//
// AgentGUIApp.swift
// NextGuard Endpoint DLP Agent - macOS GUI
// Copyright (c) 2026 NextGuard Technology
//
// DESIGN REFERENCE: Inspired by Forcepoint DLP Agent, Palo Alto Cortex XDR,
// McAfee DLP Endpoint, Zscaler Client Connector
//

import SwiftUI
import AppKit

// MARK: - App Entry Point
@main
struct NextGuardAgentApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate

    var body: some Scene {
        Settings {
            EmptyView()
        }
    }
}

// MARK: - App Delegate
class AppDelegate: NSObject, NSApplicationDelegate {
    var statusBarController: StatusBarController?
    var mainWindowController: NSWindowController?

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        statusBarController = StatusBarController()
        setupMainWindow()
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return false
    }

    private func setupMainWindow() {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 920, height: 660),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.center()
        window.title = "NextGuard DLP Agent"
        window.minSize = NSSize(width: 800, height: 560)
        window.contentView = NSHostingView(rootView: AgentMainView())
        window.setFrameAutosaveName("AgentMainWindow")
        mainWindowController = NSWindowController(window: window)
    }

    func showMainWindow() {
        mainWindowController?.showWindow(nil)
        mainWindowController?.window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }
}
