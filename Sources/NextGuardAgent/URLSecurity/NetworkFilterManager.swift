//
// NetworkFilterManager.swift
// NextGuardAgent
//
// Copyright (c) 2026 NextGuard Technology Limited. All rights reserved.
// Network Filter Manager v2.5.0 - Production-grade URL blocking
// Uses NETransparentProxyProvider (no visible system proxy)
// Coordinates: TransparentProxyManager + DNSFilter + URLSecurityScanner
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

    private var cancellables = Set<AnyCancellable>()
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
        syncBlacklistWithScanner()
        let savedEnabled = UserDefaults.standard.bool(forKey: filterEnabledKey)
        if savedEnabled {
            logger.info("[Filter] Restoring previously enabled filter state")
            enableFilter()
        }
    }

    // MARK: - Sync blacklist with URLSecurityScanner
    private func syncBlacklistWithScanner() {
        let scanner = URLSecurityScanner.shared
        scanner.$blacklistedDomains
            .receive(on: DispatchQueue.main)
            .sink { [weak self] domains in
                self?.updateBlockedDomains(Set(domains))
            }
            .store(in: &cancellables)
    }

    // MARK: - Domain Management
    func updateBlockedDomains(_ domains: Set<String>) {
        // Update DNSFilter for local DNS-level blocking
        for domain in domains {
            DNSFilter.shared.addDomain(domain)
        }
        // Update TransparentProxy with new policy
        if isFilterEnabled {
            let allDomains = DNSFilter.shared.blockedDomains.sorted()
            let threats = ThreatIntelligenceService.shared.blockedDomains.sorted()
            TransparentProxyManager.shared.updatePolicy(
                domains: allDomains,
                patterns: [],
                threats: threats,
                version: "\(Date().timeIntervalSince1970)"
            )
            logger.info("[Filter] Updated policy: \(allDomains.count) domains, \(threats.count) threats")
        }
    }

    func addBlockedDomain(_ domain: String) {
        let d = domain.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
        guard !d.isEmpty else { return }
        DNSFilter.shared.addDomain(d)
        updateBlockedDomains(Set(DNSFilter.shared.blockedDomains))
        logger.info("[Filter] Blocked: \(d)")
    }

    func removeBlockedDomain(_ domain: String) {
        DNSFilter.shared.removeDomain(domain)
        updateBlockedDomains(Set(DNSFilter.shared.blockedDomains))
        logger.info("[Filter] Unblocked: \(domain)")
    }

    // MARK: - Enable/Disable Filter (v2.5.0: TransparentProxy + DNSFilter)
    func enableFilter() {
        filterStatus = .activating
        isFilterEnabled = true
        UserDefaults.standard.set(true, forKey: filterEnabledKey)

        // Start DNS-level filtering
        DNSFilter.shared.startFiltering()

        // Install & start transparent proxy
        let domains = DNSFilter.shared.blockedDomains.sorted()
        let threats = ThreatIntelligenceService.shared.blockedDomains.sorted()
        TransparentProxyManager.shared.installProxy(
            blockedDomains: domains,
            blockedURLPatterns: [],
            threatIntelDomains: threats,
            policyVersion: "\(Date().timeIntervalSince1970)"
        ) { [weak self] success in
            DispatchQueue.main.async {
                if success {
                    self?.filterStatus = .active
                    self?.logger.info("[Filter] ENABLED - TransparentProxy + DNS active")
                } else {
                    self?.filterStatus = .error
                    self?.logger.error("[Filter] Failed to start TransparentProxy")
                }
            }
        }
    }

    func disableFilter() {
        isFilterEnabled = false
        UserDefaults.standard.set(false, forKey: filterEnabledKey)
        DNSFilter.shared.stopFiltering()
        TransparentProxyManager.shared.stopProxy {
            DispatchQueue.main.async {
                self.filterStatus = .disabled
                self.logger.info("[Filter] DISABLED - all blocking stopped")
            }
        }
    }

    // MARK: - URL Check
    func shouldBlockURL(_ urlString: String) -> Bool {
        guard isFilterEnabled else { return false }
        if DNSFilter.shared.shouldBlock(url: urlString) {
            guard let url = URL(string: urlString.hasPrefix("http") ? urlString : "https://\(urlString)"),
                  let host = url.host?.lowercased() else { return true }
            recordBlock(domain: host)
            return true
        }
        let scanResult = URLSecurityScanner.shared.scanURL(urlString)
        if scanResult.threatLevel == .blocked || scanResult.threatLevel == .dangerous {
            if URLSecurityScanner.shared.blockMode == .warnAndBlock || URLSecurityScanner.shared.blockMode == .silentBlock {
                if let host = URL(string: urlString)?.host {
                    recordBlock(domain: host)
                }
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

    // MARK: - Status
    var blockedDomainsCount: Int { DNSFilter.shared.blockedDomains.count }
    var blockedDomainsList: [String] { DNSFilter.shared.blockedDomains.sorted() }
}