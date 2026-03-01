//
//  MainWindowController.swift
//  NextGuard Endpoint DLP Agent
//
//  Copyright (c) 2026 NextGuard Technology Limited. All rights reserved.
//  Fortinet-style rich GUI for DLP Agent configuration and monitoring
//

import AppKit
import os.log

enum SidebarItem: String, CaseIterable {
    case system = "System"
    case dlpPolicies = "DLP Policies"
    case channels = "Channels"
    case logging = "Logging"
    case notifications = "Notifications"
    case about = "About"
    var icon: String {
        switch self {
        case .system: return "gearshape.fill"
        case .dlpPolicies: return "shield.checkered"
        case .channels: return "network"
        case .logging: return "doc.text.fill"
        case .notifications: return "bell.fill"
        case .about: return "info.circle.fill"
        }
    }
}

class MainWindowController: NSObject {
    static let shared = MainWindowController()
    private var window: NSWindow?
    private var sidebarTableView: NSTableView!
    private var contentView: NSView!
    private var selectedItem: SidebarItem = .system
    private let policyEngine = DLPPolicyEngine.shared
    private let mgmtClient = ManagementClient.shared

    func showWindow() {
        if let w = window { w.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true); return }
        let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 780, height: 520), styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
        w.title = "NextGuard DLP Agent"; w.center(); w.minSize = NSSize(width: 680, height: 420); w.isReleasedWhenClosed = false
        let main = NSView(); main.translatesAutoresizingMaskIntoConstraints = false; w.contentView = main
        let hdr = makeHeader(); hdr.translatesAutoresizingMaskIntoConstraints = false; main.addSubview(hdr)
        let sb = makeSidebar(); sb.translatesAutoresizingMaskIntoConstraints = false; main.addSubview(sb)
        contentView = NSView(); contentView.translatesAutoresizingMaskIntoConstraints = false; main.addSubview(contentView)
        let sep = NSBox(); sep.boxType = .separator; sep.translatesAutoresizingMaskIntoConstraints = false; main.addSubview(sep)
        NSLayoutConstraint.activate([
            hdr.topAnchor.constraint(equalTo: main.topAnchor), hdr.leadingAnchor.constraint(equalTo: main.leadingAnchor), hdr.trailingAnchor.constraint(equalTo: main.trailingAnchor), hdr.heightAnchor.constraint(equalToConstant: 56),
            sb.topAnchor.constraint(equalTo: hdr.bottomAnchor), sb.leadingAnchor.constraint(equalTo: main.leadingAnchor), sb.bottomAnchor.constraint(equalTo: main.bottomAnchor), sb.widthAnchor.constraint(equalToConstant: 180),
            sep.topAnchor.constraint(equalTo: hdr.bottomAnchor), sep.leadingAnchor.constraint(equalTo: sb.trailingAnchor), sep.bottomAnchor.constraint(equalTo: main.bottomAnchor), sep.widthAnchor.constraint(equalToConstant: 1),
            contentView.topAnchor.constraint(equalTo: hdr.bottomAnchor), contentView.leadingAnchor.constraint(equalTo: sep.trailingAnchor), contentView.trailingAnchor.constraint(equalTo: main.trailingAnchor), contentView.bottomAnchor.constraint(equalTo: main.bottomAnchor)
        ])
        window = w; showContentForItem(.system); w.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true)
    }

    private func makeHeader() -> NSView {
        let h = NSView(); h.wantsLayer = true; h.layer?.backgroundColor = NSColor(red: 0.08, green: 0.35, blue: 0.15, alpha: 1).cgColor
        let logo = NSImageView(); logo.translatesAutoresizingMaskIntoConstraints = false
        logo.image = NSImage(systemSymbolName: "shield.checkered", accessibilityDescription: "NG"); logo.contentTintColor = .white
        logo.symbolConfiguration = NSImage.SymbolConfiguration(pointSize: 24, weight: .medium); h.addSubview(logo)
        let t = NSTextField(labelWithString: "NextGuard DLP Agent"); t.translatesAutoresizingMaskIntoConstraints = false; t.font = .boldSystemFont(ofSize: 16); t.textColor = .white; h.addSubview(t)
        let dot = NSView(); dot.translatesAutoresizingMaskIntoConstraints = false; dot.wantsLayer = true; dot.layer?.backgroundColor = NSColor.systemGreen.cgColor; dot.layer?.cornerRadius = 5; h.addSubview(dot)
        let s = NSTextField(labelWithString: "Protected"); s.translatesAutoresizingMaskIntoConstraints = false; s.font = .systemFont(ofSize: 12); s.textColor = NSColor(white: 0.9, alpha: 1); h.addSubview(s)
        NSLayoutConstraint.activate([
            logo.leadingAnchor.constraint(equalTo: h.leadingAnchor, constant: 16), logo.centerYAnchor.constraint(equalTo: h.centerYAnchor), logo.widthAnchor.constraint(equalToConstant: 28), logo.heightAnchor.constraint(equalToConstant: 28),
            t.leadingAnchor.constraint(equalTo: logo.trailingAnchor, constant: 10), t.centerYAnchor.constraint(equalTo: h.centerYAnchor),
            dot.trailingAnchor.constraint(equalTo: s.leadingAnchor, constant: -6), dot.centerYAnchor.constraint(equalTo: h.centerYAnchor), dot.widthAnchor.constraint(equalToConstant: 10), dot.heightAnchor.constraint(equalToConstant: 10),
            s.trailingAnchor.constraint(equalTo: h.trailingAnchor, constant: -16), s.centerYAnchor.constraint(equalTo: h.centerYAnchor)
        ])
        return h
    }

    private func makeSidebar() -> NSView {
        let c = NSView(); c.wantsLayer = true; c.layer?.backgroundColor = NSColor(white: 0.15, alpha: 1).cgColor
        let sv = NSScrollView(); sv.translatesAutoresizingMaskIntoConstraints = false; sv.hasVerticalScroller = false; sv.drawsBackground = false
        sidebarTableView = NSTableView(); sidebarTableView.backgroundColor = .clear; sidebarTableView.headerView = nil; sidebarTableView.rowHeight = 40
        sidebarTableView.selectionHighlightStyle = .regular; sidebarTableView.delegate = self; sidebarTableView.dataSource = self
        let col = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("sb")); col.width = 170; sidebarTableView.addTableColumn(col)
        sv.documentView = sidebarTableView; c.addSubview(sv)
        NSLayoutConstraint.activate([sv.topAnchor.constraint(equalTo: c.topAnchor, constant: 8), sv.leadingAnchor.constraint(equalTo: c.leadingAnchor), sv.trailingAnchor.constraint(equalTo: c.trailingAnchor), sv.bottomAnchor.constraint(equalTo: c.bottomAnchor)])
        return c
    }

    func showContentForItem(_ item: SidebarItem) {
        selectedItem = item; contentView.subviews.forEach { $0.removeFromSuperview() }
        switch item {
        case .system: showSystemView()
        case .dlpPolicies: showPoliciesView()
        case .channels: showChannelsView()
        case .logging: showLoggingView()
        case .notifications: showNotificationsView()
        case .about: showAboutView()
        }
    }

    private func addScrollContent(_ pairs: [(String, String)], title: String) {
        let scroll = NSScrollView(); scroll.translatesAutoresizingMaskIntoConstraints = false; scroll.hasVerticalScroller = true; scroll.drawsBackground = false
        let container = NSView()
        let hdr = NSTextField(labelWithString: title); hdr.font = .boldSystemFont(ofSize: 14); hdr.frame = NSRect(x: 20, y: 0, width: 540, height: 24); container.addSubview(hdr)
        var y: CGFloat = 34
        for (k, v) in pairs {
            let kl = NSTextField(labelWithString: k); kl.font = .systemFont(ofSize: 12); kl.textColor = .secondaryLabelColor; kl.frame = NSRect(x: 20, y: y, width: 200, height: 18); container.addSubview(kl)
            let vl = NSTextField(labelWithString: v); vl.font = .systemFont(ofSize: 12); vl.frame = NSRect(x: 230, y: y, width: 320, height: 18); container.addSubview(vl)
            y += 24
        }
        container.frame = NSRect(x: 0, y: 0, width: 580, height: y + 20); scroll.documentView = container; contentView.addSubview(scroll)
        NSLayoutConstraint.activate([scroll.topAnchor.constraint(equalTo: contentView.topAnchor), scroll.leadingAnchor.constraint(equalTo: contentView.leadingAnchor), scroll.trailingAnchor.constraint(equalTo: contentView.trailingAnchor), scroll.bottomAnchor.constraint(equalTo: contentView.bottomAnchor)])
    }

    private func showSystemView() {
        let hostname = ProcessInfo.processInfo.hostName
        let os = ProcessInfo.processInfo.operatingSystemVersionString
        addScrollContent([
            ("Agent Status", "Active - Monitoring"),
            ("Agent ID", mgmtClient.agentId ?? "Not registered"),
            ("Console Connection", "Connected"),
            ("Policies Loaded", "\(policyEngine.activePolicies.count) rules"),
            ("Last Policy Sync", DateFormatter.localizedString(from: Date(), dateStyle: .medium, timeStyle: .medium)),
            ("Uptime", "Running since launch"),
            ("", ""),
            ("--- System Info ---", ""),
            ("Hostname", hostname),
            ("OS Version", "macOS \(os)"),
            ("Agent Version", "1.1.0"),
            ("Architecture", "arm64 / Apple Silicon"),
            ("Console URL", "https://www.next-guard.com/console"),
            ("", ""),
            ("--- Protection ---", ""),
            ("DLP Engine", "Enabled"),
            ("Clipboard Monitor", "Active"),
            ("File System Monitor", "Active"),
            ("Network Monitor", "Active"),
            ("Email Channel", "Active"),
            ("USB Device Control", "Active"),
            ("Print Channel", "Active"),
            ("Screen Capture", "Active"),
            ("Web DLP / URL Filtering", "Active"),
            ("SMB / File Share", "Active"),
            ("Watermark", "Enabled"),
        ], title: "System Status")
    }

    private func showPoliciesView() {
        let scroll = NSScrollView(); scroll.translatesAutoresizingMaskIntoConstraints = false; scroll.hasVerticalScroller = true; scroll.drawsBackground = false
        let container = NSView()
        let hdr = NSTextField(labelWithString: "Active DLP Policies (\(policyEngine.activePolicies.count) rules)")
        hdr.font = .boldSystemFont(ofSize: 14); hdr.frame = NSRect(x: 20, y: 0, width: 540, height: 24); container.addSubview(hdr)
        let cols = ["Policy Name", "Category", "Severity", "Action"]
        let widths: [CGFloat] = [220, 100, 80, 100]
        var x: CGFloat = 20
        for (i, c) in cols.enumerated() {
            let l = NSTextField(labelWithString: c); l.font = .boldSystemFont(ofSize: 11); l.textColor = .secondaryLabelColor
            l.frame = NSRect(x: x, y: 34, width: widths[i], height: 18); container.addSubview(l); x += widths[i]
        }
        var y: CGFloat = 58
        for p in policyEngine.activePolicies {
            x = 20
            let n = NSTextField(labelWithString: p.name); n.font = .systemFont(ofSize: 12); n.frame = NSRect(x: x, y: y, width: 220, height: 18); container.addSubview(n); x += 220
            let cat = NSTextField(labelWithString: p.category); cat.font = .systemFont(ofSize: 12); cat.textColor = .secondaryLabelColor; cat.frame = NSRect(x: x, y: y, width: 100, height: 18); container.addSubview(cat); x += 100
            let sev = NSTextField(labelWithString: p.severity.rawValue); sev.font = .boldSystemFont(ofSize: 11)
            switch p.severity { case .critical: sev.textColor = .systemRed; case .high: sev.textColor = .systemOrange; case .medium: sev.textColor = .systemYellow; case .low: sev.textColor = .systemGreen }
            sev.frame = NSRect(x: x, y: y, width: 80, height: 18); container.addSubview(sev); x += 80
            let act = NSTextField(labelWithString: p.action.rawValue); act.font = .systemFont(ofSize: 12); act.frame = NSRect(x: x, y: y, width: 100, height: 18); container.addSubview(act)
            y += 24
        }
        container.frame = NSRect(x: 0, y: 0, width: 580, height: max(y + 40, 500)); scroll.documentView = container; contentView.addSubview(scroll)
        NSLayoutConstraint.activate([scroll.topAnchor.constraint(equalTo: contentView.topAnchor), scroll.leadingAnchor.constraint(equalTo: contentView.leadingAnchor), scroll.trailingAnchor.constraint(equalTo: contentView.trailingAnchor), scroll.bottomAnchor.constraint(equalTo: contentView.bottomAnchor)])
    }

    private func showChannelsView() {
        addScrollContent([
            ("File System (FSEvents)", "Active"),
            ("Clipboard", "Active"),
            ("Network / HTTP/HTTPS", "Active"),
            ("SMB / File Share", "Active"),
            ("Email (SMTP/IMAP)", "Active"),
            ("USB / Removable Media", "Active"),
            ("Print Channel", "Active"),
            ("Screen Capture", "Active"),
            ("AirDrop", "Active"),
            ("Cloud Storage Sync", "Active"),
            ("Browser Upload", "Active"),
            ("Web URL Filtering", "Active"),
            ("Watermark Overlay", "Enabled"),
        ], title: "Monitored Data Channels")
    }

    private func showLoggingView() {
        addScrollContent([
            ("Log Level", "Info"),
            ("Log Destination", "Local + Console Server"),
            ("Log Rotation", "Daily, 30 days retention"),
            ("Log File Path", "/var/log/nextguard/agent.log"),
            ("Syslog Forwarding", "Enabled (CEF format)"),
            ("SIEM Integration", "Ready (Splunk/QRadar/Sentinel)"),
            ("Debug Mode", "Disabled"),
            ("Audit Trail", "Enabled"),
        ], title: "Logging Configuration")
    }

    private func showNotificationsView() {
        addScrollContent([
            ("Desktop Notifications", "Enabled"),
            ("Alert on Policy Violation", "Enabled (Critical + High)"),
            ("Alert on Block Action", "Enabled"),
            ("Alert on USB Connect", "Enabled"),
            ("Alert on Agent Disconnect", "Enabled"),
            ("Sound Alerts", "Disabled"),
            ("Notification Center", "Integrated"),
            ("Email Alerts to Admin", "Enabled (via Console)"),
        ], title: "Notification Settings")
    }

    private func showAboutView() {
        let c = NSView(); c.translatesAutoresizingMaskIntoConstraints = false; contentView.addSubview(c)
        let logo = NSImageView(); logo.translatesAutoresizingMaskIntoConstraints = false
        logo.image = NSImage(systemSymbolName: "shield.checkered", accessibilityDescription: "NG")
        logo.contentTintColor = .labelColor; logo.symbolConfiguration = NSImage.SymbolConfiguration(pointSize: 48, weight: .medium); c.addSubview(logo)
        let t = NSTextField(labelWithString: "NextGuard Endpoint DLP Agent"); t.font = .boldSystemFont(ofSize: 18); t.translatesAutoresizingMaskIntoConstraints = false; c.addSubview(t)
        let v = NSTextField(labelWithString: "Version 1.1.0 (Build 2026.01)"); v.font = .systemFont(ofSize: 13); v.textColor = .secondaryLabelColor; v.translatesAutoresizingMaskIntoConstraints = false; c.addSubview(v)
        let d = NSTextField(labelWithString: "Enterprise-grade Data Loss Prevention for macOS\nAI-powered | 43+ DLP policies | 13 channels"); d.font = .systemFont(ofSize: 12); d.textColor = .secondaryLabelColor; d.maximumNumberOfLines = 5; d.translatesAutoresizingMaskIntoConstraints = false; c.addSubview(d)
        let cp = NSTextField(labelWithString: "Copyright (c) 2026 NextGuard Technology Limited.\nhttps://www.next-guard.com"); cp.font = .systemFont(ofSize: 11); cp.textColor = .tertiaryLabelColor; cp.maximumNumberOfLines = 3; cp.translatesAutoresizingMaskIntoConstraints = false; c.addSubview(cp)
        NSLayoutConstraint.activate([
            c.topAnchor.constraint(equalTo: contentView.topAnchor), c.leadingAnchor.constraint(equalTo: contentView.leadingAnchor), c.trailingAnchor.constraint(equalTo: contentView.trailingAnchor), c.bottomAnchor.constraint(equalTo: contentView.bottomAnchor),
            logo.topAnchor.constraint(equalTo: c.topAnchor, constant: 40), logo.centerXAnchor.constraint(equalTo: c.centerXAnchor), logo.widthAnchor.constraint(equalToConstant: 64), logo.heightAnchor.constraint(equalToConstant: 64),
            t.topAnchor.constraint(equalTo: logo.bottomAnchor, constant: 16), t.centerXAnchor.constraint(equalTo: c.centerXAnchor),
            v.topAnchor.constraint(equalTo: t.bottomAnchor, constant: 6), v.centerXAnchor.constraint(equalTo: c.centerXAnchor),
            d.topAnchor.constraint(equalTo: v.bottomAnchor, constant: 20), d.centerXAnchor.constraint(equalTo: c.centerXAnchor),
            cp.topAnchor.constraint(equalTo: d.bottomAnchor, constant: 30), cp.centerXAnchor.constraint(equalTo: c.centerXAnchor)
        ])
    }
}

extension MainWindowController: NSTableViewDelegate, NSTableViewDataSource {
    func numberOfRows(in tableView: NSTableView) -> Int { SidebarItem.allCases.count }
    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        let item = SidebarItem.allCases[row]
        let cell = NSView(); cell.wantsLayer = true
        let icon = NSImageView(); icon.translatesAutoresizingMaskIntoConstraints = false
        icon.image = NSImage(systemSymbolName: item.icon, accessibilityDescription: item.rawValue)
        icon.contentTintColor = .white; icon.symbolConfiguration = NSImage.SymbolConfiguration(pointSize: 14, weight: .medium); cell.addSubview(icon)
        let label = NSTextField(labelWithString: item.rawValue); label.translatesAutoresizingMaskIntoConstraints = false; label.font = .systemFont(ofSize: 13); label.textColor = .white; cell.addSubview(label)
        NSLayoutConstraint.activate([
            icon.leadingAnchor.constraint(equalTo: cell.leadingAnchor, constant: 12), icon.centerYAnchor.constraint(equalTo: cell.centerYAnchor), icon.widthAnchor.constraint(equalToConstant: 20), icon.heightAnchor.constraint(equalToConstant: 20),
            label.leadingAnchor.constraint(equalTo: icon.trailingAnchor, constant: 10), label.centerYAnchor.constraint(equalTo: cell.centerYAnchor)
        ])
        return cell
    }
    func tableViewSelectionDidChange(_ notification: Notification) {
        let row = sidebarTableView.selectedRow
        guard row >= 0, row < SidebarItem.allCases.count else { return }
        showContentForItem(SidebarItem.allCases[row])
    }
}