//
// ThreatIntelligenceService.swift
// NextGuardAgent
//
// Copyright (c) 2026 NextGuard Technology Limited. All rights reserved.
// Enterprise-grade Threat Intelligence Service - Multi-provider URL threat detection
// Supports: Google Safe Browsing, VirusTotal, PhishTank, URLhaus, OpenPhish,
//           AlienVault OTX, Cloudflare DNS
//

import Foundation
import os.log
import Combine

// MARK: - Provider Config Model (for UI & persistence)

class TIProviderConfig: ObservableObject, Identifiable {
    let id: String
    let name: String
    let description: String
    let requiresAPIKey: Bool
    @Published var isEnabled: Bool
    @Published var apiKey: String

    init(id: String, name: String, description: String, requiresAPIKey: Bool, isEnabled: Bool = false, apiKey: String = "") {
        self.id = id
        self.name = name
        self.description = description
        self.requiresAPIKey = requiresAPIKey
        self.isEnabled = isEnabled
        self.apiKey = apiKey
    }
}

// MARK: - Per-Provider Scan Result

struct TIProviderResult {
    let providerName: String
    let isMalicious: Bool
    let threatCategory: String?
    let confidence: Double
    let detail: String
}

// MARK: - Aggregated Threat Intel Summary

struct ThreatIntelSummary {
    let providerResults: [TIProviderResult]
    let positiveCount: Int
    let totalEngines: Int
    let combinedRiskScore: Int    // 0-100
    let confidence: Double        // 0.0-1.0
    let threatCategories: [String]
    let summary: String

    var isDefinitelyMalicious: Bool { positiveCount >= 2 || (positiveCount == 1 && confidence >= 0.90) }
    var isSuspicious: Bool { positiveCount >= 1 && !isDefinitelyMalicious }

    static let clean = ThreatIntelSummary(
        providerResults: [], positiveCount: 0, totalEngines: 0,
        combinedRiskScore: 0, confidence: 0, threatCategories: [], summary: ""
    )
}

// MARK: - Internal Provider Protocol

private protocol ThreatProvider {
    var name: String { get }
    func check(_ url: String) async -> TIProviderResult
}

// MARK: - 1. Google Safe Browsing

private struct GoogleSBProvider: ThreatProvider {
    let name = "Google Safe Browsing"
    let apiKey: String
    func check(_ url: String) async -> TIProviderResult {
        guard !apiKey.isEmpty else { return TIProviderResult(providerName: name, isMalicious: false, threatCategory: nil, confidence: 0, detail: "Not configured") }
        let endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=\(apiKey)"
        guard let reqURL = URL(string: endpoint) else { return TIProviderResult(providerName: name, isMalicious: false, threatCategory: nil, confidence: 0, detail: "Invalid endpoint") }
        var request = URLRequest(url: reqURL)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.timeoutInterval = 10
        let body: [String: Any] = [
            "client": ["clientId": "nextguard-agent", "clientVersion": "2.1.0"],
            "threatInfo": [
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [["url": url]]
            ]
        ]
        do {
            request.httpBody = try JSONSerialization.data(withJSONObject: body)
            let (data, resp) = try await URLSession.shared.data(for: request)
            guard let http = resp as? HTTPURLResponse, http.statusCode == 200 else {
                return TIProviderResult(providerName: name, isMalicious: false, threatCategory: nil, confidence: 0, detail: "API error")
            }
            if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let matches = json["matches"] as? [[String: Any]], !matches.isEmpty {
                let types = matches.compactMap { $0["threatType"] as? String }
                return TIProviderResult(providerName: name, isMalicious: true, threatCategory: types.first, confidence: 0.95, detail: "Google SB: \(types.joined(separator: ", "))")
            }
            return TIProviderResult(providerName: name, isMalicious: false, threatCategory: nil, confidence: 0, detail: "Clean")
        } catch {
            return TIProviderResult(providerName: name, isMalicious: false, threatCategory: nil, confidence: 0, detail: error.localizedDescription)
        }
    }
}

// MARK: - 2. VirusTotal

private struct VirusTotalProvider: ThreatProvider {
    let name = "VirusTotal"
    let apiKey: String
    func check(_ url: String) async -> TIProviderResult {
        guard !apiKey.isEmpty else { return TIProviderResult(providerName: name, isMalicious: false, threatCategory: nil, confidence: 0, detail: "Not configured") }
        let urlId = Data(url.utf8).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        guard let reqURL = URL(string: "https://www.virustotal.com/api/v3/urls/\(urlId)") else {
            return TIProviderResult(providerName: name, isMalicious: false, threatCategory: nil, confidence: 0, detail: "Invalid URL")
        }
        var request = URLRequest(url: reqURL)
        request.setValue(apiKey, forHTTPHeaderField: "x-apikey")
        request.timeoutInterval = 15
        do {
            let (data, resp) = try await URLSession.shared.data(for: request)
            guard let http = resp as? HTTPURLResponse, http.statusCode == 200 else {
                return TIProviderResult(providerName: name, isMalicious: false, threatCategory: nil, confidence: 0, detail: "API error")
            }
            if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let attrs = (json["data"] as? [String: Any])?["attributes"] as? [String: Any],
               let stats = attrs["last_analysis_stats"] as? [String: Int] {
                let malicious = stats["malicious"] ?? 0
                let total = (stats["harmless"] ?? 0) + malicious + (stats["suspicious"] ?? 0) + (stats["undetected"] ?? 0)
                if malicious > 0 {
                    return TIProviderResult(providerName: name, isMalicious: true, threatCategory: "Malware", confidence: min(1.0, Double(malicious) / Double(max(total, 1)) * 3.0), detail: "VT: \(malicious)/\(total) engines flagged")
                }
            }
            return TIProviderResult(providerName: name, isMalicious: false, threatCategory: nil, confidence: 0, detail: "Clean")
        } catch {
            return TIProviderResult(providerName: name, isMalicious: false, threatCategory: nil, confidence: 0, detail: error.localizedDescription)
        }
    }
}

// MARK: - 3. PhishTank

private struct PhishTankProvider: ThreatProvider {
    let name = "PhishTank"
    let apiKey: String
    func check(_ url: String) async -> TIProviderResult {
        guard let reqURL = URL(string: "https://checkurl.phishtank.com/checkurl/") else {
            return TIProviderResult(providerName: name, isMalicious: false, threatCategory: nil, confidence: 0, detail: "Invalid endpoint")
        }
        var request = URLRequest(url: reqURL)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.timeoutInterval = 10
        var body = "format=json&url=\(url.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? url)"
        if !apiKey.isEmpty { body += "&app_key=\(apiKey)" }
        request.httpBody = body.data(using: .utf8)
        do {
            let (data, resp) = try await URLSession.shared.data(for: request)
            guard let http = resp as? HTTPURLResponse, http.statusCode == 200 else {
                return TIProviderResult(providerName: name, isMalicious: false, threatCategory: nil, confidence: 0, detail: "API error")
            }
            if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let results = json["results"] as? [String: Any],
               let inDB = results["in_database"] as? Bool, inDB,
               let valid = results["valid"] as? Bool, valid {
                return TIProviderResult(providerName: name, isMalicious: true, threatCategory: "Phishing", confidence: 0.98, detail: "PhishTank: Confirmed phishing")
            }
            return TIProviderResult(providerName: name, isMalicious: false, threatCategory: nil, confidence: 0, detail: "Clean")
        } catch {
            return TIProviderResult(providerName: name, isMalicious: false, threatCategory: nil, confidence: 0, detail: error.localizedDescription)
        }
    }
}

// MARK: - 4. URLhaus (abuse.ch)

private struct URLhausProvider: ThreatProvider {
    let name = "URLhaus"
    func check(_ url: String) async -> TIProviderResult {
        guard let reqURL = URL(string: "https://urlhaus-api.abuse.ch/v1/url/") else {
            return TIProviderResult(providerName: name, isMalicious: false, threatCategory: nil, confidence: 0, detail: "Invalid endpoint")
        }
        var request = URLRequest(url: reqURL)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.httpBody = "url=\(url.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? url)".data(using: .utf8)
        request.timeoutInterval = 10
        do {
            let (data, resp) = try await URLSession.shared.data(for: request)
            guard let http = resp as? HTTPURLResponse, http.statusCode == 200 else {
                return TIProviderResult(providerName: name, isMalicious: false, threatCategory: nil, confidence: 0, detail: "API error")
            }
            if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let status = json["query_status"] as? String, status == "listed" {
                let threat = (json["threat"] as? String) ?? "malware"
                return TIProviderResult(providerName: name, isMalicious: true, threatCategory: threat, confidence: 0.92, detail: "URLhaus: \(threat)")
            }
            return TIProviderResult(providerName: name, isMalicious: false, threatCategory: nil, confidence: 0, detail: "Clean")
        } catch {
            return TIProviderResult(providerName: name, isMalicious: false, threatCategory: nil, confidence: 0, detail: error.localizedDescription)
        }
    }
}

// MARK: - 5. OpenPhish

private struct OpenPhishProvider: ThreatProvider {
    let name = "OpenPhish"
    func check(_ url: String) async -> TIProviderResult {
        // Query OpenPhish feed
        guard let feedURL = URL(string: "https://openphish.com/feed.txt") else {
            return TIProviderResult(providerName: name, isMalicious: false, threatCategory: nil, confidence: 0, detail: "Feed unavailable")
        }
        do {
            let (data, _) = try await URLSession.shared.data(from: feedURL)
            if let content = String(data: data, encoding: .utf8) {
                let normalized = url.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
                let urls = content.components(separatedBy: .newlines).map { $0.lowercased().trimmingCharacters(in: .whitespacesAndNewlines) }
                if urls.contains(normalized) {
                    return TIProviderResult(providerName: name, isMalicious: true, threatCategory: "Phishing", confidence: 0.90, detail: "OpenPhish: URL in phishing feed")
                }
                if let host = URL(string: normalized)?.host {
                    for u in urls where URL(string: u)?.host == host {
                        return TIProviderResult(providerName: name, isMalicious: true, threatCategory: "Phishing", confidence: 0.75, detail: "OpenPhish: Domain in feed")
                    }
                }
            }
            return TIProviderResult(providerName: name, isMalicious: false, threatCategory: nil, confidence: 0, detail: "Clean")
        } catch {
            return TIProviderResult(providerName: name, isMalicious: false, threatCategory: nil, confidence: 0, detail: error.localizedDescription)
        }
    }
}

// MARK: - 6. AlienVault OTX

private struct AlienVaultOTXProvider: ThreatProvider {
    let name = "AlienVault OTX"
    let apiKey: String
    func check(_ url: String) async -> TIProviderResult {
        guard !apiKey.isEmpty else { return TIProviderResult(providerName: name, isMalicious: false, threatCategory: nil, confidence: 0, detail: "Not configured") }
        guard let host = URL(string: url.hasPrefix("http") ? url : "https://\(url)")?.host else {
            return TIProviderResult(providerName: name, isMalicious: false, threatCategory: nil, confidence: 0, detail: "No host")
        }
        guard let reqURL = URL(string: "https://otx.alienvault.com/api/v1/indicators/domain/\(host)/general") else {
            return TIProviderResult(providerName: name, isMalicious: false, threatCategory: nil, confidence: 0, detail: "Invalid endpoint")
        }
        var request = URLRequest(url: reqURL)
        request.setValue(apiKey, forHTTPHeaderField: "X-OTX-API-KEY")
        request.timeoutInterval = 10
        do {
            let (data, resp) = try await URLSession.shared.data(for: request)
            guard let http = resp as? HTTPURLResponse, http.statusCode == 200 else {
                return TIProviderResult(providerName: name, isMalicious: false, threatCategory: nil, confidence: 0, detail: "API error")
            }
            if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let pulseInfo = json["pulse_info"] as? [String: Any],
               let count = pulseInfo["count"] as? Int, count > 0 {
                return TIProviderResult(providerName: name, isMalicious: true, threatCategory: "Threat Intelligence", confidence: min(1.0, Double(count) / 10.0), detail: "OTX: \(count) threat pulses")
            }
            return TIProviderResult(providerName: name, isMalicious: false, threatCategory: nil, confidence: 0, detail: "Clean")
        } catch {
            return TIProviderResult(providerName: name, isMalicious: false, threatCategory: nil, confidence: 0, detail: error.localizedDescription)
        }
    }
}

// MARK: - 7. Cloudflare DNS Security

private struct CloudflareDNSProvider: ThreatProvider {
    let name = "Cloudflare DNS"
    func check(_ url: String) async -> TIProviderResult {
        guard let host = URL(string: url.hasPrefix("http") ? url : "https://\(url)")?.host else {
            return TIProviderResult(providerName: name, isMalicious: false, threatCategory: nil, confidence: 0, detail: "No host")
        }
        guard let reqURL = URL(string: "https://security.cloudflare-dns.com/dns-query?name=\(host)&type=A") else {
            return TIProviderResult(providerName: name, isMalicious: false, threatCategory: nil, confidence: 0, detail: "Invalid endpoint")
        }
        var request = URLRequest(url: reqURL)
        request.setValue("application/dns-json", forHTTPHeaderField: "Accept")
        request.timeoutInterval = 5
        do {
            let (data, _) = try await URLSession.shared.data(for: request)
            if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let answers = json["Answer"] as? [[String: Any]] {
                for answer in answers {
                    if let addr = answer["data"] as? String, (addr == "0.0.0.0" || addr == "::") {
                        return TIProviderResult(providerName: name, isMalicious: true, threatCategory: "DNS Blocked", confidence: 0.85, detail: "Cloudflare: Domain blocked")
                    }
                }
            }
            return TIProviderResult(providerName: name, isMalicious: false, threatCategory: nil, confidence: 0, detail: "Clean")
        } catch {
            return TIProviderResult(providerName: name, isMalicious: false, threatCategory: nil, confidence: 0, detail: error.localizedDescription)
        }
    }
}

// MARK: - ThreatIntelligenceService (Main Orchestrator)

final class ThreatIntelligenceService: ObservableObject {
    static let shared = ThreatIntelligenceService()
    private let logger = Logger(subsystem: "com.nextguard.agent", category: "ThreatIntelligence")

    // Published properties for UI
    @Published var isEnabled: Bool = true
    @Published var providers: [TIProviderConfig] = []
    @Published var totalQueriesCount: Int = 0
    @Published var threatsFoundCount: Int = 0
    @Published var queryTimeout: TimeInterval = 10

    var enabledProviders: [TIProviderConfig] { providers.filter { $0.isEnabled } }

    // Cache
    private let cache = NSCache<NSString, CacheEntry>()
    private let cacheExpiration: TimeInterval = 3600

    private init() {
        cache.countLimit = 10000
        setupProviders()
    }

    private func setupProviders() {
        let defaults = UserDefaults.standard
        providers = [
            TIProviderConfig(id: "googleSB", name: "Google Safe Browsing", description: "Google's threat detection with 5B+ URLs daily", requiresAPIKey: true,
                isEnabled: defaults.bool(forKey: "ti.googleSB.enabled"), apiKey: defaults.string(forKey: "ti.googleSB.apiKey") ?? ""),
            TIProviderConfig(id: "virusTotal", name: "VirusTotal", description: "70+ antivirus engines multi-scan platform", requiresAPIKey: true,
                isEnabled: defaults.bool(forKey: "ti.virusTotal.enabled"), apiKey: defaults.string(forKey: "ti.virusTotal.apiKey") ?? ""),
            TIProviderConfig(id: "phishTank", name: "PhishTank", description: "Community-driven phishing URL database", requiresAPIKey: false,
                isEnabled: defaults.bool(forKey: "ti.phishTank.enabled")),
            TIProviderConfig(id: "urlhaus", name: "URLhaus", description: "abuse.ch malicious URL tracking (free)", requiresAPIKey: false,
                isEnabled: defaults.bool(forKey: "ti.urlhaus.enabled")),
            TIProviderConfig(id: "openPhish", name: "OpenPhish", description: "Real-time phishing intelligence feed", requiresAPIKey: false,
                isEnabled: defaults.bool(forKey: "ti.openPhish.enabled")),
            TIProviderConfig(id: "alienVault", name: "AlienVault OTX", description: "Open Threat Exchange community platform", requiresAPIKey: true,
                isEnabled: defaults.bool(forKey: "ti.alienVault.enabled"), apiKey: defaults.string(forKey: "ti.alienVault.apiKey") ?? ""),
            TIProviderConfig(id: "cloudflareDNS", name: "Cloudflare DNS", description: "Security DNS filtering via 1.1.1.2", requiresAPIKey: false,
                isEnabled: defaults.bool(forKey: "ti.cloudflareDNS.enabled")),
        ]
    }

    // MARK: - Check URL

    func checkURL(_ urlString: String) async -> ThreatIntelSummary {
        guard isEnabled else { return .clean }
        totalQueriesCount += 1

        // Check cache
        let key = NSString(string: urlString)
        if let cached = cache.object(forKey: key), Date().timeIntervalSince(cached.date) < cacheExpiration {
            return cached.summary
        }

        // Build active providers
        var activeProviders: [ThreatProvider] = []
        for cfg in providers where cfg.isEnabled {
            switch cfg.id {
            case "googleSB": activeProviders.append(GoogleSBProvider(apiKey: cfg.apiKey))
            case "virusTotal": activeProviders.append(VirusTotalProvider(apiKey: cfg.apiKey))
            case "phishTank": activeProviders.append(PhishTankProvider(apiKey: cfg.apiKey))
            case "urlhaus": activeProviders.append(URLhausProvider())
            case "openPhish": activeProviders.append(OpenPhishProvider())
            case "alienVault": activeProviders.append(AlienVaultOTXProvider(apiKey: cfg.apiKey))
            case "cloudflareDNS": activeProviders.append(CloudflareDNSProvider())
            default: break
            }
        }

        if activeProviders.isEmpty { return .clean }

        // Query all concurrently
        let results = await withTaskGroup(of: TIProviderResult.self) { group in
            for provider in activeProviders {
                group.addTask { await provider.check(urlString) }
            }
            var all: [TIProviderResult] = []
            for await result in group { all.append(result) }
            return all
        }

        // Aggregate
        let positives = results.filter { $0.isMalicious }
        let bestConf = positives.map { $0.confidence }.max() ?? 0
        let categories = Array(Set(positives.compactMap { $0.threatCategory }))
        let riskScore = min(100, Int(Double(positives.count) / Double(max(results.count, 1)) * 100 * (bestConf + 0.5)))
        let summaryText = positives.isEmpty ? "No threats found" : "\(positives.count)/\(results.count) providers flagged this URL"

        let summary = ThreatIntelSummary(
            providerResults: results,
            positiveCount: positives.count,
            totalEngines: results.count,
            combinedRiskScore: riskScore,
            confidence: bestConf,
            threatCategories: categories,
            summary: summaryText
        )

        if !positives.isEmpty {
            DispatchQueue.main.async { self.threatsFoundCount += 1 }
        }

        cache.setObject(CacheEntry(summary: summary), forKey: key)
        logger.info("[TI] \(urlString): \(positives.count)/\(results.count) positive (score: \(riskScore))")
        return summary
    }

    func clearCache() { cache.removeAllObjects() }

    func saveSettings() {
        let defaults = UserDefaults.standard
        for cfg in providers {
            defaults.set(cfg.isEnabled, forKey: "ti.\(cfg.id).enabled")
            if cfg.requiresAPIKey {
                defaults.set(cfg.apiKey, forKey: "ti.\(cfg.id).apiKey")
            }
        }
    }

    // Cache Entry
    private class CacheEntry: NSObject {
        let summary: ThreatIntelSummary
        let date: Date
        init(summary: ThreatIntelSummary, date: Date = Date()) {
            self.summary = summary
            self.date = date
        }
    }
}
