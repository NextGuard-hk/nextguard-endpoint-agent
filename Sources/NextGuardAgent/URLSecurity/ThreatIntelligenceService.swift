//
// ThreatIntelligenceService.swift
// NextGuardAgent
//
// Copyright (c) 2026 NextGuard Technology Limited. All rights reserved.
// Enterprise-grade Threat Intelligence Service - Multi-provider URL threat detection
// Supports: Google Safe Browsing, VirusTotal, PhishTank, URLhaus, OpenPhish,
//           AlienVault OTX, Cloudflare DNS filtering
//

import Foundation
import os.log

// MARK: - Threat Intelligence Protocol

protocol ThreatIntelligenceProvider {
  var name: String { get }
  var isConfigured: Bool { get }
  func checkURL(_ url: String) async -> ThreatIntelResult
}

// MARK: - Threat Intel Result

enum ThreatIntelResult {
  case safe(provider: String, name: String)
  case malicious(provider: String, url: String, types: [String], confidence: Double, details: String)
  case error(provider: String, message: String)

  var isMalicious: Bool {
    if case .malicious = self { return true }
    return false
  }
}

// MARK: - 1. Google Safe Browsing Provider

class GoogleSafeBrowsingProvider: ThreatIntelligenceProvider {
  let name = "Google Safe Browsing"
  private let apiKey: String
  private let logger = Logger(subsystem: "com.nextguard.agent", category: "GoogleSB")

  var isConfigured: Bool { !apiKey.isEmpty }

  init(apiKey: String) {
    self.apiKey = apiKey
  }

  func checkURL(_ url: String) async -> ThreatIntelResult {
    guard isConfigured else { return .error(provider: name, message: "API key not configured") }
    let endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=\(apiKey)"
    guard let requestURL = URL(string: endpoint) else {
      return .error(provider: name, message: "Invalid endpoint")
    }

    var request = URLRequest(url: requestURL)
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
      let (data, response) = try await URLSession.shared.data(for: request)
      guard let httpResponse = response as? HTTPURLResponse else {
        return .error(provider: name, message: "Invalid response")
      }

      if httpResponse.statusCode == 200 {
        if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let matches = json["matches"] as? [[String: Any]], !matches.isEmpty {
          var threatTypes: [String] = []
          for match in matches {
            if let tt = match["threatType"] as? String {
              threatTypes.append(tt)
            }
          }
          logger.warning("[GoogleSB] Threat found for: \(url)")
          return .malicious(
            provider: name, url: url,
            types: threatTypes,
            confidence: 0.95,
            details: "Google Safe Browsing: \(threatTypes.joined(separator: ", "))"
          )
        } else {
          return .safe(provider: name, name: url)
        }
      } else {
        return .error(provider: name, message: "HTTP \(httpResponse.statusCode)")
      }
    } catch {
      logger.error("[GoogleSB] Error: \(error.localizedDescription)")
      return .error(provider: name, message: error.localizedDescription)
    }
  }
}

// MARK: - 2. VirusTotal Provider

class VirusTotalProvider: ThreatIntelligenceProvider {
  let name = "VirusTotal"
  private let apiKey: String
  private let logger = Logger(subsystem: "com.nextguard.agent", category: "VirusTotal")

  var isConfigured: Bool { !apiKey.isEmpty }

  init(apiKey: String) {
    self.apiKey = apiKey
  }

  func checkURL(_ url: String) async -> ThreatIntelResult {
    guard isConfigured else { return .error(provider: name, message: "API key not configured") }
    let urlId = Data(url.utf8).base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
    let endpoint = "https://www.virustotal.com/api/v3/urls/\(urlId)"
    guard let requestURL = URL(string: endpoint) else {
      return .error(provider: name, message: "Invalid endpoint")
    }

    var request = URLRequest(url: requestURL)
    request.setValue(apiKey, forHTTPHeaderField: "x-apikey")
    request.timeoutInterval = 15

    do {
      let (data, response) = try await URLSession.shared.data(for: request)
      guard let httpResponse = response as? HTTPURLResponse else {
        return .error(provider: name, message: "Invalid response")
      }

      if httpResponse.statusCode == 200 {
        if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let attrs = (json["data"] as? [String: Any])?["attributes"] as? [String: Any],
           let stats = attrs["last_analysis_stats"] as? [String: Int] {
          let malicious = stats["malicious"] ?? 0
          let suspicious = stats["suspicious"] ?? 0
          let total = stats["harmless", default: 0] + malicious + suspicious + stats["undetected", default: 0]

          if malicious > 0 {
            let confidence = min(1.0, Double(malicious) / Double(max(total, 1)) * 3.0)
            logger.warning("[VT] \(malicious) engines flagged: \(url)")
            return .malicious(
              provider: name, url: url,
              types: ["VirusTotal: \(malicious)/\(total) engines"],
              confidence: confidence,
              details: "VirusTotal: \(malicious) malicious, \(suspicious) suspicious out of \(total) engines"
            )
          } else {
            return .safe(provider: name, name: url)
          }
        }
        return .safe(provider: name, name: url)
      } else if httpResponse.statusCode == 404 {
        return .safe(provider: name, name: url)
      } else {
        return .error(provider: name, message: "HTTP \(httpResponse.statusCode)")
      }
    } catch {
      logger.error("[VT] Error: \(error.localizedDescription)")
      return .error(provider: name, message: error.localizedDescription)
    }
  }

  // MARK: - 3. PhishTank Provider

class PhishTankProvider: ThreatIntelligenceProvider {
  let name = "PhishTank"
  private let apiKey: String
  private let logger = Logger(subsystem: "com.nextguard.agent", category: "PhishTank")

  var isConfigured: Bool { true } // Works without API key (rate limited)

  init(apiKey: String = "") {
    self.apiKey = apiKey
  }

  func checkURL(_ url: String) async -> ThreatIntelResult {
    let endpoint = "https://checkurl.phishtank.com/checkurl/"
    guard let requestURL = URL(string: endpoint) else {
      return .error(provider: name, message: "Invalid endpoint")
    }

    var request = URLRequest(url: requestURL)
    request.httpMethod = "POST"
    request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
    request.timeoutInterval = 10

    var bodyStr = "format=json&url=\(url.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? url)"
    if !apiKey.isEmpty { bodyStr += "&app_key=\(apiKey)" }
    request.httpBody = bodyStr.data(using: .utf8)

    do {
      let (data, response) = try await URLSession.shared.data(for: request)
      guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else {
        return .error(provider: name, message: "Invalid response")
      }

      if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
         let results = json["results"] as? [String: Any],
         let inDatabase = results["in_database"] as? Bool, inDatabase,
         let valid = results["valid"] as? Bool, valid {
        logger.warning("[PhishTank] Phishing URL confirmed: \(url)")
        return .malicious(
          provider: name, url: url,
          types: ["Phishing"],
          confidence: 0.98,
          details: "PhishTank: Confirmed phishing URL in database"
        )
      }
      return .safe(provider: name, name: url)
    } catch {
      logger.error("[PhishTank] Error: \(error.localizedDescription)")
      return .error(provider: name, message: error.localizedDescription)
    }
  }
}

// MARK: - 4. URLhaus Provider (abuse.ch)

class URLhausProvider: ThreatIntelligenceProvider {
  let name = "URLhaus"
  private let logger = Logger(subsystem: "com.nextguard.agent", category: "URLhaus")

  var isConfigured: Bool { true } // Free, no API key needed

  func checkURL(_ url: String) async -> ThreatIntelResult {
    let endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
    guard let requestURL = URL(string: endpoint) else {
      return .error(provider: name, message: "Invalid endpoint")
    }

    var request = URLRequest(url: requestURL)
    request.httpMethod = "POST"
    request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
    request.httpBody = "url=\(url.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? url)".data(using: .utf8)
    request.timeoutInterval = 10

    do {
      let (data, response) = try await URLSession.shared.data(for: request)
      guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else {
        return .error(provider: name, message: "Invalid response")
      }

      if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
         let status = json["query_status"] as? String {
        if status == "listed" {
          let threat = (json["threat"] as? String) ?? "malware"
          let tags = (json["tags"] as? [String]) ?? []
          logger.warning("[URLhaus] Listed: \(url) - \(threat)")
          return .malicious(
            provider: name, url: url,
            types: ["URLhaus: \(threat)"] + tags,
            confidence: 0.92,
            details: "URLhaus: Listed as \(threat). Tags: \(tags.joined(separator: ", "))"
          )
        }
      }
      return .safe(provider: name, name: url)
    } catch {
      logger.error("[URLhaus] Error: \(error.localizedDescription)")
      return .error(provider: name, message: error.localizedDescription)
    }
  }
}

// MARK: - 5. OpenPhish Provider

class OpenPhishProvider: ThreatIntelligenceProvider {
  let name = "OpenPhish"
  private let logger = Logger(subsystem: "com.nextguard.agent", category: "OpenPhish")
  private var phishingURLs: Set<String> = []
  private var lastFetchDate: Date? = nil
  private let feedURL = "https://openphish.com/feed.txt"
  private let refreshInterval: TimeInterval = 3600 // Refresh every hour

  var isConfigured: Bool { true } // Free feed

  func checkURL(_ url: String) async -> ThreatIntelResult {
    // Refresh feed if needed
    if phishingURLs.isEmpty || shouldRefresh() {
      await refreshFeed()
    }

    let normalizedURL = url.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
    if phishingURLs.contains(normalizedURL) {
      logger.warning("[OpenPhish] Phishing match: \(url)")
      return .malicious(
        provider: name, url: url,
        types: ["Phishing"],
        confidence: 0.90,
        details: "OpenPhish: URL found in active phishing feed"
      )
    }

    // Also check domain-level match
    if let urlObj = URL(string: normalizedURL), let host = urlObj.host {
      for phishURL in phishingURLs {
        if let phishObj = URL(string: phishURL), phishObj.host == host {
          logger.warning("[OpenPhish] Domain match: \(host)")
          return .malicious(
            provider: name, url: url,
            types: ["Phishing"],
            confidence: 0.75,
            details: "OpenPhish: Domain \(host) found in phishing feed"
          )
        }
      }
    }
    return .safe(provider: name, name: url)
  }

  private func shouldRefresh() -> Bool {
    guard let last = lastFetchDate else { return true }
    return Date().timeIntervalSince(last) > refreshInterval
  }

  private func refreshFeed() async {
    guard let url = URL(string: feedURL) else { return }
    do {
      let (data, _) = try await URLSession.shared.data(from: url)
      if let content = String(data: data, encoding: .utf8) {
        let urls = content.components(separatedBy: .newlines)
          .map { $0.lowercased().trimmingCharacters(in: .whitespacesAndNewlines) }
          .filter { !$0.isEmpty }
        phishingURLs = Set(urls)
        lastFetchDate = Date()
        logger.info("[OpenPhish] Feed refreshed: \(self.phishingURLs.count) URLs loaded")
      }
    } catch {
      logger.error("[OpenPhish] Feed refresh failed: \(error.localizedDescription)")
    }

    // MARK: - 6. AlienVault OTX Provider

class AlienVaultOTXProvider: ThreatIntelligenceProvider {
  let name = "AlienVault OTX"
  private let apiKey: String
  private let logger = Logger(subsystem: "com.nextguard.agent", category: "OTX")

  var isConfigured: Bool { !apiKey.isEmpty }

  init(apiKey: String) {
    self.apiKey = apiKey
  }

  func checkURL(_ url: String) async -> ThreatIntelResult {
    guard isConfigured else { return .error(provider: name, message: "API key not configured") }
    guard let host = URL(string: url.hasPrefix("http") ? url : "https://\(url)")?.host else {
      return .error(provider: name, message: "Cannot extract host")
    }

    let endpoint = "https://otx.alienvault.com/api/v1/indicators/domain/\(host)/general"
    guard let requestURL = URL(string: endpoint) else {
      return .error(provider: name, message: "Invalid endpoint")
    }

    var request = URLRequest(url: requestURL)
    request.setValue(apiKey, forHTTPHeaderField: "X-OTX-API-KEY")
    request.timeoutInterval = 10

    do {
      let (data, response) = try await URLSession.shared.data(for: request)
      guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else {
        return .error(provider: name, message: "Invalid response")
      }

      if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
         let pulseInfo = json["pulse_info"] as? [String: Any],
         let count = pulseInfo["count"] as? Int, count > 0 {
        let pulses = (pulseInfo["pulses"] as? [[String: Any]]) ?? []
        var tags: [String] = []
        for pulse in pulses.prefix(5) {
          if let pulseTags = pulse["tags"] as? [String] {
            tags.append(contentsOf: pulseTags)
          }
        }
        let uniqueTags = Array(Set(tags)).prefix(10)
        let confidence = min(1.0, Double(count) / 10.0)
        logger.warning("[OTX] \(count) pulses for: \(host)")
        return .malicious(
          provider: name, url: url,
          types: Array(uniqueTags),
          confidence: confidence,
          details: "AlienVault OTX: \(count) threat pulses. Tags: \(uniqueTags.joined(separator: ", "))"
        )
      }
      return .safe(provider: name, name: url)
    } catch {
      logger.error("[OTX] Error: \(error.localizedDescription)")
      return .error(provider: name, message: error.localizedDescription)
    }
  }
}

// MARK: - 7. Cloudflare DNS Provider (1.1.1.2 Family/Security)

class CloudflareDNSProvider: ThreatIntelligenceProvider {
  let name = "Cloudflare DNS"
  private let logger = Logger(subsystem: "com.nextguard.agent", category: "CloudflareDNS")

  var isConfigured: Bool { true } // Free, no API key needed

  func checkURL(_ url: String) async -> ThreatIntelResult {
    guard let host = URL(string: url.hasPrefix("http") ? url : "https://\(url)")?.host else {
      return .error(provider: name, message: "Cannot extract host")
    }

    // Use Cloudflare's security DNS (1.1.1.2) via DoH
    let endpoint = "https://security.cloudflare-dns.com/dns-query?name=\(host)&type=A"
    guard let requestURL = URL(string: endpoint) else {
      return .error(provider: name, message: "Invalid endpoint")
    }

    var request = URLRequest(url: requestURL)
    request.setValue("application/dns-json", forHTTPHeaderField: "Accept")
    request.timeoutInterval = 5

    do {
      let (data, response) = try await URLSession.shared.data(for: request)
      guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else {
        return .error(provider: name, message: "Invalid response")
      }

      if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
        let status = json["Status"] as? Int ?? 0
        let answers = json["Answer"] as? [[String: Any]] ?? []

        // Status 0 = NOERROR, check if blocked (0.0.0.0 or empty)
        if status == 0 {
          for answer in answers {
            if let addr = answer["data"] as? String {
              if addr == "0.0.0.0" || addr == "::" {
                logger.warning("[CloudflareDNS] Blocked domain: \(host)")
                return .malicious(
                  provider: name, url: url,
                  types: ["DNS Blocked"],
                  confidence: 0.85,
                  details: "Cloudflare Security DNS: Domain blocked (malware/phishing)"
                )
              }
            }
          }
          // If no answers at all, domain might be blocked
          if answers.isEmpty {
            // Check with regular DNS to see if it's actually blocked vs non-existent
            let regularEndpoint = "https://cloudflare-dns.com/dns-query?name=\(host)&type=A"
            if let regularURL = URL(string: regularEndpoint) {
              var regularReq = URLRequest(url: regularURL)
              regularReq.setValue("application/dns-json", forHTTPHeaderField: "Accept")
              regularReq.timeoutInterval = 5
              if let (regData, _) = try? await URLSession.shared.data(for: regularReq),
                 let regJson = try? JSONSerialization.jsonObject(with: regData) as? [String: Any],
                 let regAnswers = regJson["Answer"] as? [[String: Any]], !regAnswers.isEmpty {
                // Regular DNS resolves but security DNS doesn't = blocked
                logger.warning("[CloudflareDNS] Domain blocked by security filter: \(host)")
                return .malicious(
                  provider: name, url: url,
                  types: ["DNS Security Filter"],
                  confidence: 0.88,
                  details: "Cloudflare Security DNS: Domain filtered by security policy"
                )
              }
            }
          }
        }
      }
      return .safe(provider: name, name: url)
    } catch {
      logger.error("[CloudflareDNS] Error: \(error.localizedDescription)")
      return .error(provider: name, message: error.localizedDescription)
    }
  }

  // MARK: - ThreatIntelligenceService (Main Orchestrator)

class ThreatIntelligenceService {
  static let shared = ThreatIntelligenceService()

  private let logger = Logger(subsystem: "com.nextguard.agent", category: "ThreatIntelligence")
  private var providers: [ThreatIntelligenceProvider] = []
  private let cache = NSCache<NSString, ThreatIntelCacheEntry>()
  private let cacheExpiration: TimeInterval = 3600

  @Published var totalChecks: Int = 0
  @Published var totalThreatsFound: Int = 0

  private init() {
    cache.countLimit = 10000
    loadProviders()
  }

  func loadProviders() {
    providers.removeAll()
    let defaults = UserDefaults.standard

    // 1. Google Safe Browsing
    if let key = defaults.string(forKey: "threatIntel.googleSafeBrowsing.apiKey"), !key.isEmpty {
      providers.append(GoogleSafeBrowsingProvider(apiKey: key))
      logger.info("[TI] Google Safe Browsing loaded")
    }

    // 2. VirusTotal
    if let key = defaults.string(forKey: "threatIntel.virusTotal.apiKey"), !key.isEmpty {
      providers.append(VirusTotalProvider(apiKey: key))
      logger.info("[TI] VirusTotal loaded")
    }

    // 3. PhishTank
    if defaults.bool(forKey: "threatIntel.phishTank.enabled") {
      let key = defaults.string(forKey: "threatIntel.phishTank.apiKey") ?? ""
      providers.append(PhishTankProvider(apiKey: key))
      logger.info("[TI] PhishTank loaded")
    }

    // 4. URLhaus (free, no key)
    if defaults.bool(forKey: "threatIntel.urlhaus.enabled") {
      providers.append(URLhausProvider())
      logger.info("[TI] URLhaus loaded")
    }

    // 5. OpenPhish (free feed)
    if defaults.bool(forKey: "threatIntel.openPhish.enabled") {
      providers.append(OpenPhishProvider())
      logger.info("[TI] OpenPhish loaded")
    }

    // 6. AlienVault OTX
    if let key = defaults.string(forKey: "threatIntel.alienVaultOTX.apiKey"), !key.isEmpty {
      providers.append(AlienVaultOTXProvider(apiKey: key))
      logger.info("[TI] AlienVault OTX loaded")
    }

    // 7. Cloudflare DNS (free, no key)
    if defaults.bool(forKey: "threatIntel.cloudflareDNS.enabled") {
      providers.append(CloudflareDNSProvider())
      logger.info("[TI] Cloudflare DNS loaded")
    }

    logger.info("[TI] Total providers active: \(self.providers.count)")
  }

  func checkURL(_ url: String) async -> ThreatIntelResult {
    totalChecks += 1

    // Check cache
    let cacheKey = NSString(string: url)
    if let cached = cache.object(forKey: cacheKey),
       Date().timeIntervalSince(cached.timestamp) < cacheExpiration {
      return cached.result
    }

    if providers.isEmpty {
      return .safe(provider: "ThreatIntelligence", name: url)
    }

    // Query all providers concurrently
    let results = await withTaskGroup(of: ThreatIntelResult.self) { group in
      for provider in providers {
        group.addTask { await provider.checkURL(url) }
      }
      var all: [ThreatIntelResult] = []
      for await result in group { all.append(result) }
      return all
    }

    // Aggregate: any malicious = malicious (highest confidence wins)
    var bestMalicious: ThreatIntelResult? = nil
    var bestConfidence: Double = 0

    for result in results {
      if case .malicious(_, _, _, let conf, _) = result, conf > bestConfidence {
        bestMalicious = result
        bestConfidence = conf
      }
    }

    if let malResult = bestMalicious {
      totalThreatsFound += 1
      cache.setObject(ThreatIntelCacheEntry(result: malResult), forKey: cacheKey)
      return malResult
    }

    let safeResult = ThreatIntelResult.safe(provider: "ThreatIntelligence", name: url)
    cache.setObject(ThreatIntelCacheEntry(result: safeResult), forKey: cacheKey)
    return safeResult
  }

  var activeProviderCount: Int { providers.count }
  var activeProviderNames: [String] { providers.map { $0.name } }

  func clearCache() { cache.removeAllObjects() }
}

// MARK: - Cache Entry

private class ThreatIntelCacheEntry {
  let result: ThreatIntelResult
  let timestamp: Date
  init(result: ThreatIntelResult, timestamp: Date = Date()) {
    self.result = result
    self.timestamp = timestamp
  }
}
}
  }
}
}
