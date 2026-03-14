//
// NetworkFilterManager.swift
// NextGuardAgent
//
// Copyright (c) 2026 NextGuard Technology Limited. All rights reserved.
// Network Filter Manager - Unified URL blocking coordinator
// FIX v2.4.1: Removed duplicate /etc/hosts logic - now delegates to DNSFilter
// FIX v2.4.1: Single source of truth for domain blocking via DNSFilter + ProxyServer
// Uses NEFilterManager for content filter + DNSFilter for actual blocking
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
            isFilterEnabled = true
            filterStatus = .activating
            // FIX v2.4.1: Delegate to DNSFilter instead of duplicate /etc/hosts
            DNSFilter.shared.startFiltering()
            filterStatus = .active
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

    // MARK: - Domain Management (FIX v2.4.1: delegates to DNSFilter)
    func updateBlockedDomains(_ domains: Set<String>) {
        for domain in domains {
            DNSFilter.shared.addDomain(domain)
        }
        if isFilterEnabled {
            logger.info("[Filter] Updated domains via DNSFilter. Total: \(domains.count)")
        }
    }

    func addBlockedDomain(_ domain: String) {
        let d = domain.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
        guard !d.isEmpty else { return }
        DNSFilter.shared.addDomain(d)
        logger.info("[Filter] Blocked: \(d)")
    }

    func removeBlockedDomain(_ domain: String) {
        DNSFilter.shared.removeDomain(domain)
        logger.info("[Filter] Unblocked: \(domain)")
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

    // MARK: - Enable/Disable Filter (FIX v2.4.1: unified via DNSFilter)
    func enableFilter() {
        isFilterEnabled = true
        UserDefaults.standard.set(true, forKey: filterEnabledKey)
        DNSFilter.shared.startFiltering()
        enableContentFilter()
        logger.info("[Filter] Filter ENABLED - DNS + proxy blocking active")
    }

    func disableFilter() {
        isFilterEnabled = false
        UserDefaults.standard.set(false, forKey: filterEnabledKey)
        DNSFilter.shared.stopFiltering()
        disableContentFilter()
        logger.info("[Filter] Filter DISABLED")
    }

    // MARK: - URL Check
    func shouldBlockURL(_ urlString: String) -> Bool {
        guard isFilterEnabled else { return false }
        // Delegate domain check to DNSFilter
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