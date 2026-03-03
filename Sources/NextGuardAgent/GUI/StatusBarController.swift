//
//  StatusBarController.swift
//  NextGuardAgent
//
//  Manages the macOS menu bar status item and popover
//

import AppKit
import SwiftUI

class StatusBarController: NSObject {
    private var statusItem: NSStatusItem!
    private var popover: NSPopover!
    private var eventMonitor: EventMonitor?
    private var animationTimer: Timer?
    private var isScanning = false
    
    // Status icons
    private let iconProtected = "shield.fill"
    private let iconAlert = "shield.slash.fill"
    private let iconScanning = "shield.lefthalf.filled"
    
    override init() {
        super.init()
        setupStatusItem()
        setupPopover()
        setupEventMonitor()
    }
    
    private func setupStatusItem() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        
        if let button = statusItem.button {
            updateStatusIcon(protected: true)
            button.action = #selector(togglePopover)
            button.target = self
        }
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
    }
    
    private func setupEventMonitor() {
        eventMonitor = EventMonitor(mask: [.leftMouseDown, .rightMouseDown]) { [weak self] _ in
            if let self = self, self.popover.isShown {
                self.closePopover()
            }
        }
    }
    
    @objc func togglePopover() {
        if popover.isShown {
            closePopover()
        } else {
            openPopover()
        }
    }
    
    func openPopover() {
        if let button = statusItem.button {
            popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
            eventMonitor?.start()
        }
    }
    
    func closePopover() {
        popover.performClose(nil)
        eventMonitor?.stop()
    }
    
    func updateStatusIcon(protected: Bool, scanning: Bool = false, alert: Bool = false) {
        guard let button = statusItem.button else { return }
        
        let iconName: String
        let tintColor: NSColor
        
        if alert {
            iconName = iconAlert
            tintColor = .systemRed
        } else if scanning {
            iconName = iconScanning
            tintColor = .systemBlue
        } else if protected {
            iconName = iconProtected
            tintColor = .systemGreen
        } else {
            iconName = iconAlert
            tintColor = .systemOrange
        }
        
        let config = NSImage.SymbolConfiguration(pointSize: 16, weight: .medium)
        if let image = NSImage(systemSymbolName: iconName, accessibilityDescription: "NextGuard")?.withSymbolConfiguration(config) {
            let tinted = image.copy() as! NSImage
            tinted.isTemplate = false
            button.image = tinted
            button.contentTintColor = tintColor
        }
    }
    
    func startScanningAnimation() {
        isScanning = true
        var frame = 0
        animationTimer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { [weak self] _ in
            guard let self = self else { return }
            self.updateStatusIcon(protected: true, scanning: frame % 2 == 0)
            frame += 1
        }
    }
    
    func stopScanningAnimation(protected: Bool) {
        isScanning = false
        animationTimer?.invalidate()
        animationTimer = nil
        updateStatusIcon(protected: protected)
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
    
    deinit {
        stop()
    }
    
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
