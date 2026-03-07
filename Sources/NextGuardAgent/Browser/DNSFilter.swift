//
// DNSFilter.swift
// NextGuard Endpoint DLP Agent
//
// Copyright (c) 2026 NextGuard Technology Limited. All rights reserved.
// DNS-based URL filtering - blocks blacklisted domains at the network level
// Integrates with LocalPolicyEngine and config.json blocklist
//
import Foundation
import Network
import OSLog

// MARK: - DNS Filter

/// DNSFilter enforces a domain blacklist by:
/// 1. Loading blocked domains from config.json + LocalPolicyEngine rules
/// 2. Intercepting outbound DNS queries via NEDNSProxyProvider (when System Extension active)
/// 3. Falling back to /etc/hosts sinkhole entries when no System Extension permission
final class DNSFilter: @unchecked Sendable {
    static let shared = DNSFilter()
    private let logger = Logger(subsystem: "com.nextguard.agent", category: "DNSFilter")
    private let queue = DispatchQueue(label: "com.nextguard.dnsfilter", qos: .userInitiated)

    // Persistence key for UserDefaults
    private let enabledKey = "DNSFilterEnabled"
    private let customBlocklistKey = "DNSFilterCustomBlocklist"

    // State
    private(set) var isFiltering = false
    private(set) var blockedDomains: Set<String> = []
    private(set) var blockedCount: Int = 0

    /// Whether DNS filtering is enabled (persisted across restarts)
    var isEnabled: Bool {
        get { UserDefaults.standard.bool(forKey: enabledKey) }
        set {
            UserDefaults.standard.set(newValue, forKey: enabledKey)
            if newValue { startFiltering() } else { stopFiltering() }
            NotificationCenter.default.post(name: .dnsFilterStatusChanged, object: newValue)
        }
    }

    // MARK: - Built-in Blocked Domains
    // These domains are always blocked when DNS Filter is enabled.
    // Add or remove domains here to update the default blacklist.
    private let builtinBlocklist: Set<String> = [
        // Sports streaming (demo blacklist)
        "nba.com",
        "www.nba.com",
        "watch.nba.com",
        "stats.nba.com",
        "nbastore.com",
        // Social media (when policy enabled)
        // "facebook.com", "instagram.com", "twitter.com",
        // Personal cloud storage
        // "wetransfer.com", "mega.nz",
    ]

    private init() {
        // Set default enabled = true on first launch
        if UserDefaults.standard.object(forKey: enabledKey) == nil {
            UserDefaults.standard.set(true, forKey: enabledKey)
        }
    }

    // MARK: - Start / Stop

    func startFiltering() {
        guard isEnabled else {
            logger.info("DNSFilter is disabled - skipping start")
            return
        }
        guard !isFiltering else { return }
        queue.async { [weak self] in
            guard let self else { return }
            self.loadBlockedDomains()
            self.applyHostsSinkhole()
            self.isFiltering = true
            self.logger.info("DNSFilter started - \(self.blockedDomains.count) domains blocked")
            NotificationCenter.default.post(name: .dnsFilterStatusChanged, object: true)
        }
    }

    func stopFiltering() {
        guard isFiltering else { return }
        queue.async { [weak self] in
            guard let self else { return }
            self.removeHostsSinkhole()
            self.isFiltering = false
            self.logger.info("DNSFilter stopped")
            NotificationCenter.default.post(name: .dnsFilterStatusChanged, object: false)
        }
    }

    // MARK: - Domain Management

    /// Reload blocked domains from all sources:
    /// 1. Built-in blacklist
    /// 2. Custom domains from UserDefaults (added via Settings UI)
    /// 3. Domains from LocalPolicyEngine rules tagged as "dns_block"
    /// 4. Console-pushed domain list from config.json
    func loadBlockedDomains() {
        var domains = builtinBlocklist

        // Load custom domains added via Settings UI
        let custom = UserDefaults.standard.stringArray(forKey: customBlocklistKey) ?? []
        domains.formUnion(custom.map { $0.lowercased() })

        // Load from config.json if present
        let configPath = "/Library/NextGuard/config.json"
        if let data = FileManager.default.contents(atPath: configPath),
           let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let configDomains = json["blockedDomains"] as? [String] {
            domains.formUnion(configDomains.map { $0.lowercased() })
            logger.info("DNSFilter loaded \(configDomains.count) domains from config.json")
        }

        // Load from LocalPolicyEngine dns_block rules
        let localRules = LocalPolicyEngine.shared.localRules
        for rule in localRules where rule.enabled {
            if let blockedHosts = rule.metadata?["blockedDomains"] {
                let hosts = blockedHosts.split(separator: ",").map { String($0).trimmingCharacters(in: .whitespaces).lowercased() }
                domains.formUnion(hosts)
            }
        }

        blockedDomains = domains
        logger.info("DNSFilter total blocked domains: \(self.blockedDomains.count)")
    }

    /// Add a custom domain to the blocklist at runtime
    func addDomain(_ domain: String) {
        let normalized = domain.lowercased().trimmingCharacters(in: .whitespaces)
        guard !normalized.isEmpty else { return }
        var custom = UserDefaults.standard.stringArray(forKey: customBlocklistKey) ?? []
        guard !custom.contains(normalized) else { return }
        custom.append(normalized)
        UserDefaults.standard.set(custom, forKey: customBlocklistKey)
        blockedDomains.insert(normalized)
        if isFiltering { applyHostsSinkhole() }
        logger.info("DNSFilter added domain: \(normalized)")
    }

    /// Remove a custom domain from the blocklist
    func removeDomain(_ domain: String) {
        let normalized = domain.lowercased()
        var custom = UserDefaults.standard.stringArray(forKey: customBlocklistKey) ?? []
        custom.removeAll { $0 == normalized }
        UserDefaults.standard.set(custom, forKey: customBlocklistKey)
        blockedDomains.remove(normalized)
        if isFiltering { applyHostsSinkhole() }
        logger.info("DNSFilter removed domain: \(normalized)")
    }

    var customBlocklist: [String] {
        return UserDefaults.standard.stringArray(forKey: customBlocklistKey) ?? []
    }

    // MARK: - Domain Check

    /// Returns true if the given URL/hostname should be blocked
    func shouldBlock(url: String) -> Bool {
        guard isFiltering, isEnabled else { return false }
        guard let host = URL(string: url)?.host?.lowercased() ?? url.lowercased() as String? else { return false }
        // Exact match or subdomain match (e.g. "stats.nba.com" matches rule "nba.com")
        if blockedDomains.contains(host) { return true }
        for blocked in blockedDomains {
            if host.hasSuffix("." + blocked) { return true }
        }
        return false
    }

    // MARK: - /etc/hosts Sinkhole (fallback without System Extension)
    //
    // When NEDNSProxyProvider is not available (no System Extension approval),
    // we write sinkhole entries to /etc/hosts pointing blocked domains -> 0.0.0.0.
    // This requires the agent to be running as root (via LaunchDaemon).

    private let sinkholeMark = "# NextGuard DNS Filter - DO NOT EDIT"
    private let sinkholeIP = "0.0.0.0"

    private func applyHostsSinkhole() {
        let hostsPath = "/etc/hosts"
        guard var content = try? String(contentsOfFile: hostsPath, encoding: .utf8) else {
            logger.error("DNSFilter: cannot read /etc/hosts")
            return
        }
        // Remove old NextGuard entries
        let lines = content.components(separatedBy: "\n")
            .filter { !$0.contains(sinkholeMark) }
        content = lines.joined(separator: "\n")

        // Append new blocked entries
        var newLines = [""]
        newLines.append(sinkholeMark)
        for domain in blockedDomains.sorted() {
            newLines.append("\(sinkholeIP)\t\(domain)\t\(sinkholeMark)")
            newLines.append("\(sinkholeIP)\twww.\(domain)\t\(sinkholeMark)")
        }
        content += newLines.joined(separator: "\n")

        do {
            try content.write(toFile: hostsPath, atomically: true, encoding: .utf8)
            // Flush DNS cache
            let task = Process()
            task.launchPath = "/usr/bin/dscacheutil"
            task.arguments = ["-flushcache"]
            try task.run()
            task.waitUntilExit()
            let mdns = Process()
            mdns.launchPath = "/bin/launchctl"
            mdns.arguments = ["kickstart", "-k", "system/com.apple.mDNSResponder"]
            try mdns.run()
            mdns.waitUntilExit()
            blockedCount = blockedDomains.count
            logger.info("DNSFilter: /etc/hosts updated with \(self.blockedDomains.count) blocked domains, DNS cache flushed")
        } catch {
            logger.error("DNSFilter: failed to write /etc/hosts: \(error.localizedDescription)")
        }
    }

    private func removeHostsSinkhole() {
        let hostsPath = "/etc/hosts"
        guard var content = try? String(contentsOfFile: hostsPath, encoding: .utf8) else { return }
        let lines = content.components(separatedBy: "\n")
            .filter { !$0.contains(sinkholeMark) }
        content = lines.joined(separator: "\n")
        do {
            try content.write(toFile: hostsPath, atomically: true, encoding: .utf8)
            // Flush DNS cache
            let task = Process()
            task.launchPath = "/usr/bin/dscacheutil"
            task.arguments = ["-flushcache"]
            try task.run()
            task.waitUntilExit()
            blockedCount = 0
            logger.info("DNSFilter: /etc/hosts sinkhole entries removed")
        } catch {
            logger.error("DNSFilter: failed to clean /etc/hosts: \(error.localizedDescription)")
        }
    }

    // MARK: - Statistics
    func getStats() -> [String: Any] {
        return [
            "enabled": isEnabled,
            "active": isFiltering,
            "blockedDomainCount": blockedDomains.count,
            "totalBlocked": blockedCount
        ]
    }
}

// MARK: - Notification Names
extension Notification.Name {
    static let dnsFilterStatusChanged = Notification.Name("com.nextguard.dnsfilter.statusChanged")
}
