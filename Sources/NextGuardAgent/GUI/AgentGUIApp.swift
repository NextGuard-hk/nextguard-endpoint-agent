//
//  AgentGUIApp.swift
//  NextGuardAgent
//
//  GUI Manager - integrates SwiftUI popover into existing AppDelegate
//  NOTE: @main is in NextGuardApp.swift (App/). This file provides
//  the GUIManager singleton that AppDelegate instantiates.
//
//  DESIGN REFERENCE: Forcepoint DLP Agent, Palo Alto Cortex XDR,
//  McAfee DLP Endpoint, Zscaler Client Connector
//

import SwiftUI
import AppKit

// MARK: - GUI Manager
// Singleton that owns the NSPopover and SwiftUI content
// Called from AppDelegate in NextGuardApp.swift
class GUIManager: NSObject {
    static let shared = GUIManager()

    private var popover: NSPopover!
    private var eventMonitor: EventMonitor?

    private override init() {
        super.init()
        setupPopover()
    }

    private func setupPopover() {
        popover = NSPopover()
        popover.contentSize = NSSize(width: 360, height: 480)
        popover.behavior = .transient
        popover.animates = true
        popover.contentViewController = NSHostingController(
            rootView: AgentMainView()
                .environmentObject(PolicyStore.shared)
        )

        eventMonitor = EventMonitor(mask: [.leftMouseDown, .rightMouseDown]) { [weak self] _ in
            if let self = self, self.popover.isShown {
                self.closePopover()
            }
        }
    }

    func togglePopover(relativeTo button: NSView) {
        if popover.isShown {
            closePopover()
        } else {
            openPopover(relativeTo: button)
        }
    }

    func openPopover(relativeTo button: NSView) {
        popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
        eventMonitor?.start()
    }

    func closePopover() {
        popover.performClose(nil)
        eventMonitor?.stop()
    }

    // Called by AppDelegate when DLP engine reports an incident
    func notifyIncident(policyName: String, action: RuleAction) {
        PolicyStore.shared.recordIncident(action: action)
    }

    // Called by AppDelegate after console sync
    func updateConnectionStatus(connected: Bool, tenantId: String?, consoleUrl: String) {
        DispatchQueue.main.async {
            PolicyStore.shared.agentStatus.isConnectedToConsole = connected
            PolicyStore.shared.agentStatus.tenantId = tenantId
            PolicyStore.shared.agentStatus.consoleUrl = consoleUrl
            if connected {
                PolicyStore.shared.agentStatus.lastSyncTime = Date()
            }
        }
    }

    // Called by AppDelegate when policies are loaded
    func updatePolicyCount(_ count: Int, source: String) {
        DispatchQueue.main.async {
            PolicyStore.shared.agentStatus.isProtected = count > 0
        }
    }
}

// MARK: - Event Monitor
class EventMonitor {
    private var monitor: Any?
    private let mask: NSEvent.EventTypeMask
    private let handler: (NSEvent?) -> Void

    init(mask: NSEvent.EventTypeMask, handler: @escaping (NSEvent?) -> Void) {
        self.mask = mask
        self.handler = handler
    }

    deinit { stop() }

    func start() {
        monitor = NSEvent.addGlobalMonitorForEvents(matching: mask, handler: handler)
    }

    func stop() {
        if let monitor = monitor {
            NSEvent.removeMonitor(monitor)
            self.monitor = nil
        }
    }
}
