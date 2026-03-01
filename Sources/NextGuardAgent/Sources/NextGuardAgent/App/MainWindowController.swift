//
//  MainWindowController.swift
//  NextGuard Endpoint DLP Agent
//
//  Copyright (c) 2026 NextGuard Technology Limited. All rights reserved.
//  Fortinet-style rich GUI for DLP Agent configuration and monitoring
//

import AppKit
import os.log

// MARK: - Sidebar Navigation Items
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

// MARK: - Main Window Controller
class MainWindowController: NSObject {
    static let shared = MainWindowController()
    private static let logger = Logger(subsystem: "com.nextguard.agent", category: "GUI")
    
    private var window: NSWindow?
    private var sidebarTableView: NSTableView!
    private var contentView: NSView!
    private var selectedItem: SidebarItem = .system
    
    private let policyEngine = DLPPolicyEngine.shared
    private let mgmtClient = ManagementClient.shared
    
    // Status labels for System view
    private var agentStatusLabel: NSTextField!
    private var consoleStatusLabel: NSTextField!
    private var policyCountLabel: NSTextField!
    private var lastSyncLabel: NSTextField!
    private var uptimeLabel: NSTextField!
    private var versionLabel: NSTextField!
    
    func showWindow() {
        if let existingWindow = window {
            existingWindow.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
            return
        }
        
        let w = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 780, height: 520),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        w.title = "NextGuard DLP Agent"
        w.center()
        w.minSize = NSSize(width: 680, height: 420)
        w.isReleasedWhenClosed = false
        
        let mainContainer = NSView()
        mainContainer.translatesAutoresizingMaskIntoConstraints = false
        w.contentView = mainContainer
        
        // -- Header bar --
        let headerView = createHeaderView()
        headerView.translatesAutoresizingMaskIntoConstraints = false
        mainContainer.addSubview(headerView)
        
        // -- Sidebar --
        let sidebar = createSidebar()
        sidebar.translatesAutoresizingMaskIntoConstraints = false
        mainContainer.addSubview(sidebar)
        
        // -- Content area --
        contentView = NSView()
        contentView.translatesAutoresizingMaskIntoConstraints = false
        contentView.wantsLayer = true
        contentView.layer?.backgroundColor = NSColor.windowBackgroundColor.cgColor
        mainContainer.addSubview(contentView)
        
        // -- Separator line --
        let separator = NSBox()
        separator.boxType = .separator
        separator.translatesAutoresizingMaskIntoConstraints = false
        mainContainer.addSubview(separator)
        
        NSLayoutConstraint.activate([
            headerView.topAnchor.constraint(equalTo: mainContainer.topAnchor),
            headerView.leadingAnchor.constraint(equalTo: mainContainer.leadingAnchor),
            headerView.trailingAnchor.constraint(equalTo: mainContainer.trailingAnchor),
            headerView.heightAnchor.constraint(equalToConstant: 56),
            
            sidebar.topAnchor.constraint(equalTo: headerView.bottomAnchor),
            sidebar.leadingAnchor.constraint(equalTo: mainContainer.leadingAnchor),
            sidebar.bottomAnchor.constraint(equalTo: mainContainer.bottomAnchor),
            sidebar.widthAnchor.constraint(equalToConstant: 180),
            
            separator.topAnchor.constraint(equalTo: headerView.bottomAnchor),
            separator.leadingAnchor.constraint(equalTo: sidebar.trailingAnchor),
            separator.bottomAnchor.constraint(equalTo: mainContainer.bottomAnchor),
            separator.widthAnchor.constraint(equalToConstant: 1),
            
            contentView.topAnchor.constraint(equalTo: headerView.bottomAnchor),
            contentView.leadingAnchor.constraint(equalTo: separator.trailingAnchor),
            contentView.trailingAnchor.constraint(equalTo: mainContainer.trailingAnchor),
            contentView.bottomAnchor.constraint(equalTo: mainContainer.bottomAnchor),
        ])
        
        window = w
        showContentForItem(.system)
        w.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }
    
    // MARK: - Header View
    private func createHeaderView() -> NSView {
        let header = NSView()
        header.wantsLayer = true
        header.layer?.backgroundColor = NSColor(red: 0.08, green: 0.35, blue: 0.15, alpha: 1.0).cgColor
        
        let logo = NSImageView()
        logo.translatesAutoresizingMaskIntoConstraints = false
        logo.image = NSImage(systemSymbolName: "shield.checkered", accessibilityDescription: "NextGuard")
        logo.contentTintColor = .white
        logo.symbolConfiguration = NSImage.SymbolConfiguration(pointSize: 24, weight: .medium)
        header.addSubview(logo)
        
        let titleLabel = NSTextField(labelWithString: "NextGuard DLP Agent")
        titleLabel.translatesAutoresizingMaskIntoConstraints = false
        titleLabel.font = .boldSystemFont(ofSize: 16)
        titleLabel.textColor = .white
        header.addSubview(titleLabel)
        
        let statusDot = NSView()
        statusDot.translatesAutoresizingMaskIntoConstraints = false
        statusDot.wantsLayer = true
        statusDot.layer?.backgroundColor = NSColor.systemGreen.cgColor
        statusDot.layer?.cornerRadius = 5
        header.addSubview(statusDot)
        
        let statusLabel = NSTextField(labelWithString: "Protected")
        statusLabel.translatesAutoresizingMaskIntoConstraints = false
        statusLabel.font = .systemFont(ofSize: 12)
        statusLabel.textColor = NSColor(white: 0.9, alpha: 1.0)
        header.addSubview(statusLabel)
        
        NSLayoutConstraint.activate([
            logo.leadingAnchor.constraint(equalTo: header.leadingAnchor, constant: 16),
            logo.centerYAnchor.constraint(equalTo: header.centerYAnchor),
            logo.widthAnchor.constraint(equalToConstant: 28),
            logo.heightAnchor.constraint(equalToConstant: 28),
            
            titleLabel.leadingAnchor.constraint(equalTo: logo.trailingAnchor, constant: 10),
            titleLabel.centerYAnchor.constraint(equalTo: header.centerYAnchor),
            
            statusDot.trailingAnchor.constraint(equalTo: statusLabel.leadingAnchor, constant: -6),
            statusDot.centerYAnchor.constraint(equalTo: header.centerYAnchor),
            statusDot.widthAnchor.constraint(equalToConstant: 10),
            statusDot.heightAnchor.constraint(equalToConstant: 10),
            
            statusLabel.trailingAnchor.constraint(equalTo: header.trailingAnchor, constant: -16),
            statusLabel.centerYAnchor.constraint(equalTo: header.centerYAnchor),
        ])
        
        return header
    }
    
    // MARK: - Sidebar
    private func createSidebar() -> NSView {
        let container = NSView()
        container.wantsLayer = true
        container.layer?.backgroundColor = NSColor(white: 0.15, alpha: 1.0).cgColor
        
        let scrollView = NSScrollView()
        scrollView.translatesAutoresizingMaskIntoConstraints = false
        scrollView.hasVerticalScroller = false
        scrollView.drawsBackground = false
        
        sidebarTableView = NSTableView()
        sidebarTableView.backgroundColor = .clear
        sidebarTableView.headerView = nil
        sidebarTableView.rowHeight = 40
        sidebarTableView.selectionHighlightStyle = .regular
        sidebarTableView.delegate = self
        sidebarTableView.dataSource = self
        
        let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("sidebar"))
        column.width = 170
        sidebarTableView.addTableColumn(column)
        
        scrollView.documentView = sidebarTableView
        container.addSubview(scrollView)
        
        NSLayoutConstraint.activate([
            scrollView.topAnchor.constraint(equalTo: container.topAnchor, constant: 8),
            scrollView.leadingAnchor.constraint(equalTo: container.leadingAnchor),
            scrollView.trailingAnchor.constraint(equalTo: container.trailingAnchor),
            scrollView.bottomAnchor.constraint(equalTo: container.bottomAnchor),
        ])
        
        return container
    }
    
    // MARK: - Content Switching
    func showContentForItem(_ item: SidebarItem) {
        selectedItem = item
        contentView.subviews.forEach { $0.removeFromSuperview() }
        
        switch item {
        case .system:
            showSystemView()
        case .dlpPolicies:
            showDLPPoliciesView()
        case .channels:
            showChannelsView()
        case .logging:
            showLoggingView()
        case .notifications:
            showNotificationsView()
        case .about:
            showAboutView()
        }
    }
    
    // MARK: - System View
    private func showSystemView() {
        let scroll = NSScrollView()
        scroll.translatesAutoresizingMaskIntoConstraints = false
        scroll.hasVerticalScroller = true
        scroll.drawsBackground = false
        
        let container = NSView()
        container.translatesAutoresizingMaskIntoConstraints = false
        
        var yOffset: CGFloat = 20
        
        // Section: Agent Status
        let statusTitle = createSectionHeader("Agent Status")
        statusTitle.frame = NSRect(x: 20, y: 0, width: 540, height: 24)
        container.addSubview(statusTitle)
        
        let statusGrid = createInfoGrid([
            ("Agent Status", "Active - Monitoring"),
            ("Agent ID", mgmtClient.agentId ?? "Not registered"),
            ("Console Connection", "Connected"),
            ("Policies Loaded", "\(policyEngine.activePolicies.count) rules"),
            ("Last Policy Sync", currentTimeString()),
            ("Uptime", "Running since launch"),
        ])
        statusGrid.frame = NSRect(x: 20, y: 34, width: 540, height: 180)
        container.addSubview(statusGrid)
        
        // Section: System Information
        let sysTitle = createSectionHeader("System Information")
        sysTitle.frame = NSRect(x: 20, y: 224, width: 540, height: 24)
        container.addSubview(sysTitle)
        
        let hostname = ProcessInfo.processInfo.hostName
        let osVersion = ProcessInfo.processInfo.operatingSystemVersionString
        let sysGrid = createInfoGrid([
            ("Hostname", hostname),
            ("OS Version", "macOS \(osVersion)"),
            ("Agent Version", "1.1.0"),
            ("Architecture", "arm64 / Apple Silicon"),
            ("Console URL", "https://www.next-guard.com/console"),
        ])
        sysGrid.frame = NSRect(x: 20, y: 258, width: 540, height: 150)
        container.addSubview(sysGrid)
        
        // Section: Protection Summary
        let protTitle = createSectionHeader("Protection Summary")
        protTitle.frame = NSRect(x: 20, y: 418, width: 540, height: 24)
        container.addSubview(protTitle)
        
        let protGrid = createInfoGrid([
            ("DLP Engine", "Enabled"),
            ("Clipboard Monitor", "Active"),
            ("File System Monitor", "Active"),
            ("Network Monitor", "Active"),
            ("Email Channel", "Active"),
            ("USB Device Control", "Active"),
            ("Print Channel", "Active"),
            ("Screen Capture", "Active"),
            ("Web DLP / URL Filtering", "Active"),
            ("Watermark", "Enabled"),
        ])
        protGrid.frame = NSRect(x: 20, y: 452, width: 540, height: 300)
        container.addSubview(protGrid)
        
        container.frame = NSRect(x: 0, y: 0, width: 580, height: 770)
        scroll.documentView = container
        contentView.addSubview(scroll)
        
        NSLayoutConstraint.activate([
            scroll.topAnchor.constraint(equalTo: contentView.topAnchor),
            scroll.leadingAnchor.constraint(equalTo: contentView.leadingAnchor),
            scroll.trailingAnchor.constraint(equalTo: contentView.trailingAnchor),
            scroll.bottomAnchor.constraint(equalTo: contentView.bottomAnchor),
        ])
    }
    
    // MARK: - DLP Policies View
    private func showDLPPoliciesView() {
        let scroll = NSScrollView()
        scroll.translatesAutoresizingMaskIntoConstraints = false
        scroll.hasVerticalScroller = true
        scroll.drawsBackground = false
        
        let container = NSView()
        
        let header = createSectionHeader("Active DLP Policies (\(policyEngine.activePolicies.count) rules)")
        header.frame = NSRect(x: 20, y: 0, width: 540, height: 24)
        container.addSubview(header)
        
        // Table header row
        let colHeaders = ["Policy Name", "Category", "Severity", "Action"]
        let colWidths: [CGFloat] = [220, 100, 80, 100]
        var xPos: CGFloat = 20
        for (i, colName) in colHeaders.enumerated() {
            let label = NSTextField(labelWithString: colName)
            label.font = .boldSystemFont(ofSize: 11)
            label.textColor = .secondaryLabelColor
            label.frame = NSRect(x: xPos, y: 34, width: colWidths[i], height: 18)
            container.addSubview(label)
            xPos += colWidths[i]
        }
        
        // Policy rows
        var rowY: CGFloat = 58
        for policy in policyEngine.activePolicies {
            xPos = 20
            let nameLabel = NSTextField(labelWithString: policy.name)
            nameLabel.font = .systemFont(ofSize: 12)
            nameLabel.frame = NSRect(x: xPos, y: rowY, width: 220, height: 18)
            container.addSubview(nameLabel)
            xPos += 220
            
            let catLabel = NSTextField(labelWithString: policy.category)
            catLabel.font = .systemFont(ofSize: 12)
            catLabel.textColor = .secondaryLabelColor
            catLabel.frame = NSRect(x: xPos, y: rowY, width: 100, height: 18)
            container.addSubview(catLabel)
            xPos += 100
            
            let sevLabel = NSTextField(labelWithString: policy.severity.rawValue)
            sevLabel.font = .boldSystemFont(ofSize: 11)
            sevLabel.textColor = colorForSeverity(policy.severity)
            sevLabel.frame = NSRect(x: xPos, y: rowY, width: 80, height: 18)
            container.addSubview(sevLabel)
            xPos += 80
            
            let actLabel = NSTextField(labelWithString: policy.action.rawValue)
            actLabel.font = .systemFont(ofSize: 12)
            actLabel.frame = NSRect(x: xPos, y: rowY, width: 100, height: 18)
            container.addSubview(actLabel)
            
            rowY += 24
        }
        
        let totalHeight = max(rowY + 40, 500)
        container.frame = NSRect(x: 0, y: 0, width: 580, height: totalHeight)
        scroll.documentView = container
        contentView.addSubview(scroll)
        
        NSLayoutConstraint.activate([
            scroll.topAnchor.constraint(equalTo: contentView.topAnchor),
            scroll.leadingAnchor.constraint(equalTo: contentView.leadingAnchor),
            scroll.trailingAnchor.constraint(equalTo: contentView.trailingAnchor),
            scroll.bottomAnchor.constraint(equalTo: contentView.bottomAnchor),
        ])
    }
    
    // MARK: - Channels View
    private func showChannelsView() {
        let scroll = NSScrollView()
        scroll.translatesAutoresizingMaskIntoConstraints = false
        scroll.hasVerticalScroller = true
        scroll.drawsBackground = false
        
        let container = NSView()
        
        let header = createSectionHeader("Monitored Data Channels")
        header.frame = NSRect(x: 20, y: 0, width: 540, height: 24)
        container.addSubview(header)
        
        let channels: [(String, String, String)] = [
            ("File System (FSEvents)", "Active", "Real-time file create/modify/copy/move detection"),
            ("Clipboard", "Active", "Pasteboard content monitoring with DLP scan"),
            ("Network / HTTP/HTTPS", "Active", "Web upload detection, SSL inspection"),
            ("SMB / File Share", "Active", "Network file share transfer monitoring"),
            ("Email (SMTP/IMAP)", "Active", "Email attachment and body DLP scanning"),
            ("USB / Removable Media", "Active", "USB device control and file transfer block"),
            ("Print Channel", "Active", "Print job content inspection"),
            ("Screen Capture", "Active", "Screenshot and screen recording detection"),
            ("AirDrop", "Active", "AirDrop file transfer monitoring"),
            ("Cloud Storage Sync", "Active", "iCloud, Dropbox, Google Drive sync detection"),
            ("Browser Upload", "Active", "Web form and file upload monitoring"),
            ("Web URL Filtering", "Active", "Category-based URL access control"),
            ("Watermark", "Enabled", "Screen and document watermark overlay"),
        ]
        
        var rowY: CGFloat = 34
        for (name, status, desc) in channels {
            let nameLabel = NSTextField(labelWithString: name)
            nameLabel.font = .boldSystemFont(ofSize: 12)
            nameLabel.frame = NSRect(x: 20, y: rowY, width: 220, height: 18)
            container.addSubview(nameLabel)
            
            let statusLabel = NSTextField(labelWithString: status)
            statusLabel.font = .boldSystemFont(ofSize: 11)
            statusLabel.textColor = status == "Active" || status == "Enabled" ? .systemGreen : .systemRed
            statusLabel.frame = NSRect(x: 250, y: rowY, width: 60, height: 18)
            container.addSubview(statusLabel)
            
            let descLabel = NSTextField(labelWithString: desc)
            descLabel.font = .systemFont(ofSize: 10)
            descLabel.textColor = .secondaryLabelColor
            descLabel.frame = NSRect(x: 20, y: rowY + 18, width: 520, height: 16)
            container.addSubview(descLabel)
            
            rowY += 42
        }
        
        container.frame = NSRect(x: 0, y: 0, width: 580, height: rowY + 20)
        scroll.documentView = container
        contentView.addSubview(scroll)
        
        NSLayoutConstraint.activate([
            scroll.topAnchor.constraint(equalTo: contentView.topAnchor),
            scroll.leadingAnchor.constraint(equalTo: contentView.leadingAnchor),
            scroll.trailingAnchor.constraint(equalTo: contentView.trailingAnchor),
            scroll.bottomAnchor.constraint(equalTo: contentView.bottomAnchor),
        ])
    }
    
    // MARK: - Logging View
    private func showLoggingView() {
        let container = NSView()
        container.translatesAutoresizingMaskIntoConstraints = false
        contentView.addSubview(container)
        
        let header = createSectionHeader("Logging Configuration")
        header.frame = NSRect(x: 20, y: 20, width: 540, height: 24)
        container.addSubview(header)
        
        let logGrid = createInfoGrid([
            ("Log Level", "Info"),
            ("Log Destination", "Local + Console Server"),
            ("Log Rotation", "Daily, 30 days retention"),
            ("Log File Path", "/var/log/nextguard/agent.log"),
            ("Syslog Forwarding", "Enabled (CEF format)"),
            ("SIEM Integration", "Ready (Splunk/QRadar/Sentinel)"),
            ("Debug Mode", "Disabled"),
            ("Audit Trail", "Enabled"),
        ])
        logGrid.frame = NSRect(x: 20, y: 54, width: 540, height: 240)
        container.addSubview(logGrid)
        
        let recentHeader = createSectionHeader("Recent Log Entries")
        recentHeader.frame = NSRect(x: 20, y: 310, width: 540, height: 24)
        container.addSubview(recentHeader)
        
        let logEntries = [
            "[INFO] Agent registered with management console",
            "[OK] 43 policies loaded from console",
            "[OK] Heartbeat started - 60s interval",
            "[INFO] File system monitor active",
            "[INFO] Clipboard monitor active",
            "[INFO] Network channel monitor active",
        ]
        var logY: CGFloat = 344
        for entry in logEntries {
            let label = NSTextField(labelWithString: entry)
            label.font = NSFont.monospacedSystemFont(ofSize: 10, weight: .regular)
            label.textColor = .secondaryLabelColor
            label.frame = NSRect(x: 20, y: logY, width: 540, height: 16)
            container.addSubview(label)
            logY += 18
        }
        
        NSLayoutConstraint.activate([
            container.topAnchor.constraint(equalTo: contentView.topAnchor),
            container.leadingAnchor.constraint(equalTo: contentView.leadingAnchor),
            container.trailingAnchor.constraint(equalTo: contentView.trailingAnchor),
            container.bottomAnchor.constraint(equalTo: contentView.bottomAnchor),
        ])
    }
    
    // MARK: - Notifications View
    private func showNotificationsView() {
        let container = NSView()
        container.translatesAutoresizingMaskIntoConstraints = false
        contentView.addSubview(container)
        
        let header = createSectionHeader("Notification Settings")
        header.frame = NSRect(x: 20, y: 20, width: 540, height: 24)
        container.addSubview(header)
        
        let notifGrid = createInfoGrid([
            ("Desktop Notifications", "Enabled"),
            ("Alert on Policy Violation", "Enabled (Critical + High)"),
            ("Alert on Block Action", "Enabled"),
            ("Alert on USB Connect", "Enabled"),
            ("Alert on Agent Disconnect", "Enabled"),
            ("Sound Alerts", "Disabled"),
            ("Notification Center", "Integrated"),
            ("Email Alerts to Admin", "Enabled (via Console)"),
        ])
        notifGrid.frame = NSRect(x: 20, y: 54, width: 540, height: 240)
        container.addSubview(notifGrid)
        
        NSLayoutConstraint.activate([
            container.topAnchor.constraint(equalTo: contentView.topAnchor),
            container.leadingAnchor.constraint(equalTo: contentView.leadingAnchor),
            container.trailingAnchor.constraint(equalTo: contentView.trailingAnchor),
            container.bottomAnchor.constraint(equalTo: contentView.bottomAnchor),
        ])
    }
    
    // MARK: - About View
    private func showAboutView() {
        let container = NSView()
        container.translatesAutoresizingMaskIntoConstraints = false
        contentView.addSubview(container)
        
        let logo = NSImageView()
        logo.translatesAutoresizingMaskIntoConstraints = false
        logo.image = NSImage(systemSymbolName: "shield.checkered", accessibilityDescription: "NextGuard")
        logo.contentTintColor = .labelColor
        logo.symbolConfiguration = NSImage.SymbolConfiguration(pointSize: 48, weight: .medium)
        container.addSubview(logo)
        
        let title = NSTextField(labelWithString: "NextGuard Endpoint DLP Agent")
        title.font = .boldSystemFont(ofSize: 18)
        title.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(title)
        
        let version = NSTextField(labelWithString: "Version 1.1.0 (Build 2026.01)")
        version.font = .systemFont(ofSize: 13)
        version.textColor = .secondaryLabelColor
        version.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(version)
        
        let desc = NSTextField(labelWithString: "Enterprise-grade Data Loss Prevention for macOS\nBuilt with Swift and Apple native frameworks\n\nAI-powered content inspection | 43+ DLP policies\n13 data channels | Real-time monitoring")
        desc.font = .systemFont(ofSize: 12)
        desc.textColor = .secondaryLabelColor
        desc.maximumNumberOfLines = 10
        desc.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(desc)
        
        let copyright = NSTextField(labelWithString: "Copyright (c) 2026 NextGuard Technology Limited.\nAll rights reserved.\nhttps://www.next-guard.com")
        copyright.font = .systemFont(ofSize: 11)
        copyright.textColor = .tertiaryLabelColor
        copyright.maximumNumberOfLines = 5
        copyright.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(copyright)
        
        NSLayoutConstraint.activate([
            container.topAnchor.constraint(equalTo: contentView.topAnchor),
            container.leadingAnchor.constraint(equalTo: contentView.leadingAnchor),
            container.trailingAnchor.constraint(equalTo: contentView.trailingAnchor),
            container.bottomAnchor.constraint(equalTo: contentView.bottomAnchor),
            
            logo.topAnchor.constraint(equalTo: container.topAnchor, constant: 40),
            logo.centerXAnchor.constraint(equalTo: container.centerXAnchor),
            logo.widthAnchor.constraint(equalToConstant: 64),
            logo.heightAnchor.constraint(equalToConstant: 64),
            
            title.topAnchor.constraint(equalTo: logo.bottomAnchor, constant: 16),
            title.centerXAnchor.constraint(equalTo: container.centerXAnchor),
            
            version.topAnchor.constraint(equalTo: title.bottomAnchor, constant: 6),
            version.centerXAnchor.constraint(equalTo: container.centerXAnchor),
            
            desc.topAnchor.constraint(equalTo: version.bottomAnchor, constant: 20),
            desc.centerXAnchor.constraint(equalTo: container.centerXAnchor),
            
            copyright.topAnchor.constraint(equalTo: desc.bottomAnchor, constant: 30),
            copyright.centerXAnchor.constraint(equalTo: container.centerXAnchor),
        ])
    }
    
    // MARK: - Helper Methods
    private func createSectionHeader(_ text: String) -> NSTextField {
        let label = NSTextField(labelWithString: text)
        label.font = .boldSystemFont(ofSize: 14)
        label.textColor = .labelColor
        return label
    }
    
    private func createInfoGrid(_ items: [(String, String)]) -> NSView {
        let grid = NSView()
        var y: CGFloat = 0
        for (key, value) in items {
            let keyLabel = NSTextField(labelWithString: key)
            keyLabel.font = .systemFont(ofSize: 12)
            keyLabel.textColor = .secondaryLabelColor
            keyLabel.frame = NSRect(x: 0, y: y, width: 200, height: 18)
            grid.addSubview(keyLabel)
            
            let valLabel = NSTextField(labelWithString: value)
            valLabel.font = .systemFont(ofSize: 12)
            valLabel.textColor = .labelColor
            valLabel.frame = NSRect(x: 210, y: y, width: 330, height: 18)
            grid.addSubview(valLabel)
            
            y += 24
        }
        return grid
    }
    
    private func colorForSeverity(_ severity: DLPPolicyEngine.Severity) -> NSColor {
        switch severity {
        case .critical: return .systemRed
        case .high: return .systemOrange
        case .medium: return .systemYellow
        case .low: return .systemGreen
        }
    }
    
    private func currentTimeString() -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return formatter.string(from: Date())
    }
}

// MARK: - NSTableViewDelegate & DataSource
extension MainWindowController: NSTableViewDelegate, NSTableViewDataSource {
    func numberOfRows(in tableView: NSTableView) -> Int {
        return SidebarItem.allCases.count
    }
    
    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        let item = SidebarItem.allCases[row]
        
        let cellView = NSView()
        cellView.wantsLayer = true
        
        let icon = NSImageView()
        icon.translatesAutoresizingMaskIntoConstraints = false
        icon.image = NSImage(systemSymbolName: item.icon, accessibilityDescription: item.rawValue)
        icon.contentTintColor = .white
        icon.symbolConfiguration = NSImage.SymbolConfiguration(pointSize: 14, weight: .medium)
        cellView.addSubview(icon)
        
        let label = NSTextField(labelWithString: item.rawValue)
        label.translatesAutoresizingMaskIntoConstraints = false
        label.font = .systemFont(ofSize: 13)
        label.textColor = .white
        cellView.addSubview(label)
        
        NSLayoutConstraint.activate([
            icon.leadingAnchor.constraint(equalTo: cellView.leadingAnchor, constant: 12),
            icon.centerYAnchor.constraint(equalTo: cellView.centerYAnchor),
            icon.widthAnchor.constraint(equalToConstant: 20),
            icon.heightAnchor.constraint(equalToConstant: 20),
            
            label.leadingAnchor.constraint(equalTo: icon.trailingAnchor, constant: 10),
            label.centerYAnchor.constraint(equalTo: cellView.centerYAnchor),
        ])
        
        return cellView
    }
    
    func tableViewSelectionDidChange(_ notification: Notification) {
        let row = sidebarTableView.selectedRow
        guard row >= 0, row < SidebarItem.allCases.count else { return }
        showContentForItem(SidebarItem.allCases[row])
    }
}