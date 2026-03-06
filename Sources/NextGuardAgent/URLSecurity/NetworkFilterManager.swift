//
// NetworkFilterManager.swift
// NextGuardAgent
//
// Copyright (c) 2026 NextGuard Technology Limited. All rights reserved.
// Network Filter Manager - DNS-level URL blocking for blacklisted domains
// Uses /etc/hosts modification + NEFilterManager for enterprise URL filtering
// FIX: Persist filter state across launches; auto-enable on init if previously enabled
//

import Foundation
import NetworkExtension
import os.log
import Combine

// MARK: - Network Filter Manager
final class NetworkFilterManager: ObservableObject {
    static let shared = NetworkFilterManager()
    private let logger = Logger(subsystem: "com.nextguard.agent", category: "NetworkFilter")

    @Published var isFilterEnabled: Bool = false
    @Published var filterStatus: FilterStatus = .notConfigured
    @Published var blockedRequestsCount: Int = 0
    @Published var lastBlockedDomain: String = ""
    @Published var lastBlockedDate: Date? = nil

    private var blockedDomains: Set<String> = []
    private var cancellables = Set<AnyCancellable>()
    private let hostsFilePath = "/etc/hosts"
    private let markerStart = "# >>> NextGuard URL Security Blocked Domains"
    private let markerEnd = "# <<< NextGuard URL Security Blocked Domains"
    private let basePath = NSHomeDirectory() + "/Library/Application Support/NextGuard"
    private let filterEnabledKey = "com.nextguard.urlsecurity.filterEnabled"

    enum FilterStatus: String {
        case notConfigured = "Not Configured"
        case activating = "Activating..."
        case active = "Active"
        case error = "Error"
        case disabled = "Disabled"

        var color: String {
            switch self {
            case .active: return "green"
            case .activating: return "orange"
            case .error: return "red"
            case .disabled, .notConfigured: return "gray"
            }
        }

        var icon: String {
            switch self {
            case .active: return "shield.checkered"
            case .activating: return "arrow.triangle.2.circlepath"
            case .error: return "exclamationmark.shield.fill"
            case .disabled, .notConfigured: return "shield.slash"
            }
        }
    }

    private init() {
        loadBlockedDomains()
        syncWithScanner()
        // Restore filter state from UserDefaults
        let savedEnabled = UserDefaults.standard.bool(forKey: filterEnabledKey)
        if savedEnabled {
            logger.info("[Filter] Restoring previously enabled filter state")
            isFilterEnabled = true
            filterStatus = .activating
            applyDNSBlocking()
        }
    }

    // MARK: - Sync with URLSecurityScanner blacklist
    private func syncWithScanner() {
        let scanner = URLSecurityScanner.shared
        // Observe blacklist changes
        scanner.$blacklistedDomains
            .receive(on: DispatchQueue.main)
            .sink { [weak self] domains in
                self?.updateBlockedDomains(Set(domains))
            }
            .store(in: &cancellables)
        // Observe scanner DNS filter toggle
        scanner.$isDNSFilterEnabled
            .receive(on: DispatchQueue.main)
            .sink { [weak self] enabled in
                guard let self = self else { return }
                if enabled && !self.isFilterEnabled {
                    self.enableFilter()
                } else if !enabled && self.isFilterEnabled {
                    self.disableFilter()
                }
            }
            .store(in: &cancellables)
    }

    // MARK: - Domain Management
    func updateBlockedDomains(_ domains: Set<String>) {
        let newDomains = domains.subtracting(blockedDomains)
        let removedDomains = blockedDomains.subtracting(domains)
        blockedDomains = domains
        saveBlockedDomains()
        if !newDomains.isEmpty || !removedDomains.isEmpty {
            applyDNSBlocking()
            logger.info("[Filter] Updated: +\(newDomains.count) -\(removedDomains.count) domains. Total: \(domains.count)")
        }
    }

    func addBlockedDomain(_ domain: String) {
        let d = domain.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
        guard !d.isEmpty else { return }
        blockedDomains.insert(d)
        saveBlockedDomains()
        if isFilterEnabled { applyDNSBlocking() }
        logger.info("[Filter] Blocked: \(d)")
    }

    func removeBlockedDomain(_ domain: String) {
        blockedDomains.remove(domain)
        saveBlockedDomains()
        if isFilterEnabled { applyDNSBlocking() }
        logger.info("[Filter] Unblocked: \(domain)")
    }

    // MARK: - DNS-Level Blocking (/etc/hosts)
    func applyDNSBlocking() {
        guard isFilterEnabled else {
            removeDNSBlocking()
            return
        }
        DispatchQueue.global(qos: .userInitiated).async { [self] in
            do {
                var hostsContent = try String(contentsOfFile: hostsFilePath, encoding: .utf8)
                hostsContent = removeNextGuardEntries(from: hostsContent)
                if !blockedDomains.isEmpty {
                    var blockEntries = "\n\(markerStart)\n"
                    for domain in blockedDomains.sorted() {
                        blockEntries += "0.0.0.0 \(domain)\n"
                        if !domain.hasPrefix("www.") {
                            blockEntries += "0.0.0.0 www.\(domain)\n"
                        }
                    }
                    blockEntries += "\(markerEnd)\n"
                    hostsContent += blockEntries
                }
                let tempPath = basePath + "/hosts_update.tmp"
                try FileManager.default.createDirectory(atPath: basePath, withIntermediateDirectories: true)
                try hostsContent.write(toFile: tempPath, atomically: true, encoding: .utf8)
                let script = "do shell script \"cp \(tempPath) \(hostsFilePath) && dscacheutil -flushcache && killall -HUP mDNSResponder\" with administrator privileges"
                let appleScript = NSAppleScript(source: script)
                var error: NSDictionary?
                appleScript?.executeAndReturnError(&error)
                if let error = error {
                    logger.error("[Filter] Failed to apply DNS blocking: \(error)")
                    DispatchQueue.main.async {
                        self.filterStatus = .error
                    }
                } else {
                    try? FileManager.default.removeItem(atPath: tempPath)
                    logger.info("[Filter] DNS blocking applied: \(self.blockedDomains.count) domains")
                    DispatchQueue.main.async {
                        self.filterStatus = .active
                    }
                }
            } catch {
                logger.error("[Filter] DNS blocking error: \(error.localizedDescription)")
                DispatchQueue.main.async {
                    self.filterStatus = .error
                }
            }
        }
    }

    func removeDNSBlocking() {
        DispatchQueue.global(qos: .userInitiated).async { [self] in
            do {
                var hostsContent = try String(contentsOfFile: hostsFilePath, encoding: .utf8)
                hostsContent = removeNextGuardEntries(from: hostsContent)
                let tempPath = basePath + "/hosts_remove.tmp"
                try hostsContent.write(toFile: tempPath, atomically: true, encoding: .utf8)
                let script = "do shell script \"cp \(tempPath) \(hostsFilePath) && dscacheutil -flushcache && killall -HUP mDNSResponder\" with administrator privileges"
                let appleScript = NSAppleScript(source: script)
                var error: NSDictionary?
                appleScript?.executeAndReturnError(&error)
                try? FileManager.default.removeItem(atPath: tempPath)
                DispatchQueue.main.async {
                    self.filterStatus = .disabled
                }
                logger.info("[Filter] DNS blocking removed")
            } catch {
                logger.error("[Filter] Remove blocking error: \(error.localizedDescription)")
            }
        }
    }

    private func removeNextGuardEntries(from content: String) -> String {
        let lines = content.components(separatedBy: .newlines)
        var result: [String] = []
        var inBlock = false
        for line in lines {
            if line.trimmingCharacters(in: .whitespaces) == markerStart {
                inBlock = true
                continue
            }
            if line.trimmingCharacters(in: .whitespaces) == markerEnd {
                inBlock = false
                continue
            }
            if !inBlock {
                result.append(line)
            }
        }
        while result.last?.trimmingCharacters(in: .whitespaces).isEmpty == true {
            result.removeLast()
        }
        return result.joined(separator: "\n")
    }

    // MARK: - NEFilterManager (Content Filter)
    func enableContentFilter() {
        filterStatus = .activating
        NEFilterManager.shared().loadFromPreferences { [weak self] error in
            guard let self = self else { return }
            if let error = error {
                self.logger.error("[Filter] Load preferences error: \(error.localizedDescription)")
                DispatchQueue.main.async { self.filterStatus = .error }
                return
            }
            let filterConfig = NEFilterProviderConfiguration()
            filterConfig.filterSockets = true
            filterConfig.organization = "NextGuard Technology Limited"
            NEFilterManager.shared().providerConfiguration = filterConfig
            NEFilterManager.shared().isEnabled = true
            NEFilterManager.shared().localizedDescription = "NextGuard URL Security Filter"
            NEFilterManager.shared().saveToPreferences { error in
                DispatchQueue.main.async {
                    if let error = error {
                        self.logger.error("[Filter] Save preferences error: \(error.localizedDescription)")
                        self.filterStatus = .error
                    } else {
                        self.filterStatus = .active
                        self.isFilterEnabled = true
                        self.logger.info("[Filter] Content filter enabled")
                    }
                }
            }
        }
    }

    func disableContentFilter() {
        NEFilterManager.shared().loadFromPreferences { [weak self] _ in
            NEFilterManager.shared().isEnabled = false
            NEFilterManager.shared().saveToPreferences { _ in
                DispatchQueue.main.async {
                    self?.filterStatus = .disabled
                    self?.isFilterEnabled = false
                    self?.logger.info("[Filter] Content filter disabled")
                }
            }
        }
    }

    // MARK: - Enable/Disable Filter
    func enableFilter() {
        isFilterEnabled = true
        UserDefaults.standard.set(true, forKey: filterEnabledKey)
        applyDNSBlocking()
        enableContentFilter()
        logger.info("[Filter] Filter ENABLED - DNS blocking active")
    }

    func disableFilter() {
        isFilterEnabled = false
        UserDefaults.standard.set(false, forKey: filterEnabledKey)
        removeDNSBlocking()
        disableContentFilter()
        logger.info("[Filter] Filter DISABLED")
    }

    // MARK: - URL Check (called by browser monitor or scanner)
    func shouldBlockURL(_ urlString: String) -> Bool {
        guard isFilterEnabled else { return false }
        guard let url = URL(string: urlString.hasPrefix("http") ? urlString : "https://\(urlString)"),
              let host = url.host?.lowercased() else { return false }
        // Check exact match
        if blockedDomains.contains(host) {
            recordBlock(domain: host)
            return true
        }
        // Check parent domain match (e.g., sub.nba.com matches nba.com)
        for blocked in blockedDomains {
            if host.hasSuffix("." + blocked) || host == blocked {
                recordBlock(domain: host)
                return true
            }
        }
        // Also check URLSecurityScanner scan result
        let scanResult = URLSecurityScanner.shared.scanURL(urlString)
        if scanResult.threatLevel == .blocked || scanResult.threatLevel == .dangerous {
            if URLSecurityScanner.shared.blockMode == .warnAndBlock || URLSecurityScanner.shared.blockMode == .silentBlock {
                recordBlock(domain: host)
                return true
            }
        }
        return false
    }

    private func recordBlock(domain: String) {
        DispatchQueue.main.async {
            self.blockedRequestsCount += 1
            self.lastBlockedDomain = domain
            self.lastBlockedDate = Date()
        }
        logger.warning("[Filter] BLOCKED: \(domain)")
    }

    // MARK: - Persistence
    private func saveBlockedDomains() {
        let path = basePath + "/blocked_domains.json"
        try? FileManager.default.createDirectory(atPath: basePath, withIntermediateDirectories: true)
        if let data = try? JSONEncoder().encode(Array(blockedDomains)) {
            try? data.write(to: URL(fileURLWithPath: path))
        }
    }

    private func loadBlockedDomains() {
        let path = basePath + "/blocked_domains.json"
        if let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
           let domains = try? JSONDecoder().decode([String].self, from: data) {
            blockedDomains = Set(domains)
        }
    }

    // MARK: - Status
    var blockedDomainsCount: Int { blockedDomains.count }
    var blockedDomainsList: [String] { blockedDomains.sorted() }
}
