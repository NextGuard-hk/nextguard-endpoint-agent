//
// ThreatIntelligenceService.swift
// NextGuardAgent
//
// Copyright (c) 2026 NextGuard Technology Limited. All rights reserved.
// Threat Intelligence Service - Google Safe Browsing, VirusTotal, PhishTank, URLhaus
//
import Foundation
import os.log

// MARK: - Threat Intelligence Provider Protocol
protocol ThreatIntelligenceProvider {
    var name: String { get }
    var isConfigured: Bool { get }
    func checkURL(_ url: String) async -> ThreatIntelResult
}

// MARK: - Threat Intel Result
struct ThreatIntelResult: Codable {
    let provider: String
    let url: String
    let isMalicious: Bool
    let threatTypes: [String]
    let confidence: Double // 0.0 - 1.0
    let details: String
    let checkedAt: Date

    static func safe(provider: String, url: String) -> ThreatIntelResult {
        ThreatIntelResult(provider: provider, url: url, isMalicious: false, threatTypes: [], confidence: 1.0, details: "No threats found", checkedAt: Date())
    }

    static func malicious(provider: String, url: String, types: [String], confidence: Double, details: String) -> ThreatIntelResult {
        ThreatIntelResult(provider: provider, url: url, isMalicious: true, threatTypes: types, confidence: confidence, details: details, checkedAt: Date())
    }

    static func error(provider: String, url: String, details: String) -> ThreatIntelResult {
        ThreatIntelResult(provider: provider, url: url, isMalicious: false, threatTypes: [], confidence: 0.0, details: details, checkedAt: Date())
    }
}

// MARK: - Google Safe Browsing API v4
class GoogleSafeBrowsingProvider: ThreatIntelligenceProvider {
    let name = "Google Safe Browsing"
    private let logger = Logger(subsystem: "com.nextguard.agent", category: "GoogleSafeBrowsing")
    private var apiKey: String
    private let baseURL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    var isConfigured: Bool { !apiKey.isEmpty }

    init(apiKey: String = "") {
        self.apiKey = apiKey
    }

    func updateAPIKey(_ key: String) {
        self.apiKey = key
    }

    func checkURL(_ url: String) async -> ThreatIntelResult {
        guard isConfigured else {
            return .error(provider: name, url: url, details: "API key not configured")
        }

        let requestBody: [String: Any] = [
            "client": [
                "clientId": "nextguard-endpoint-agent",
                "clientVersion": "2.0.0"
            ],
            "threatInfo": [
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION", "THREAT_TYPE_UNSPECIFIED"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [
                    ["url": url]
                ]
            ]
        ]

        guard let jsonData = try? JSONSerialization.data(withJSONObject: requestBody),
              let requestURL = URL(string: "\(baseURL)?key=\(apiKey)") else {
            return .error(provider: name, url: url, details: "Failed to create request")
        }

        var request = URLRequest(url: requestURL)
        request.httpMethod = "POST"
        request.httpBody = jsonData
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.timeoutInterval = 10

        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let httpResponse = response as? HTTPURLResponse else {
                return .error(provider: name, url: url, details: "Invalid response")
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
                    logger.warning("[GoogleSB] THREAT DETECTED for \(url): \(threatTypes)")
                    return .malicious(
                        provider: name,
                        url: url,
                        types: threatTypes,
                        confidence: 0.95,
                        details: "Google Safe Browsing flagged: \(threatTypes.joined(separator: ", "))"
                    )
                } else {
                    // Empty response = safe
                    return .safe(provider: name, url: url)
                }
            } else {
                return .error(provider: name, url: url, details: "HTTP \(httpResponse.statusCode)")
            }
        } catch {
            logger.error("[GoogleSB] Error checking \(url): \(error.localizedDescription)")
            return .error(provider: name, url: url, details: error.localizedDescription)
        }
    }
}

// MARK: - VirusTotal API v3
class VirusTotalProvider: ThreatIntelligenceProvider {
    let name = "VirusTotal"
    private let logger = Logger(subsystem: "com.nextguard.agent", category: "VirusTotal")
    private var apiKey: String
    private let baseURL = "https://www.virustotal.com/api/v3/urls"

    var isConfigured: Bool { !apiKey.isEmpty }

    init(apiKey: String = "") {
        self.apiKey = apiKey
    }

    func updateAPIKey(_ key: String) {
        self.apiKey = key
    }

    func checkURL(_ url: String) async -> ThreatIntelResult {
        guard isConfigured else {
            return .error(provider: name, url: url, details: "API key not configured")
        }

        // VirusTotal uses base64-encoded URL (without padding) as identifier
        let urlId = Data(url.utf8).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")

        guard let requestURL = URL(string: "\(baseURL)/\(urlId)") else {
            return .error(provider: name, url: url, details: "Failed to create request")
        }

        var request = URLRequest(url: requestURL)
        request.httpMethod = "GET"
        request.setValue(apiKey, forHTTPHeaderField: "x-apikey")
        request.timeoutInterval = 15

        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let httpResponse = response as? HTTPURLResponse else {
                return .error(provider: name, url: url, details: "Invalid response")
            }

            if httpResponse.statusCode == 200 {
                if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                   let attrs = (json["data"] as? [String: Any])?["attributes"] as? [String: Any],
                   let stats = attrs["last_analysis_stats"] as? [String: Int] {
                    let malicious = stats["malicious"] ?? 0
                    let suspicious = stats["suspicious"] ?? 0
                    let total = stats.values.reduce(0, +)

                    if malicious > 0 || suspicious > 2 {
                        let detectionRate = Double(malicious + suspicious) / Double(max(total, 1))
                        logger.warning("[VT] THREAT: \(url) - \(malicious) malicious, \(suspicious) suspicious out of \(total)")
                        return .malicious(
                            provider: name,
                            url: url,
                            types: ["VirusTotal: \(malicious) engines flagged"],
                            confidence: min(detectionRate * 2.0, 1.0),
                            details: "\(malicious) malicious, \(suspicious) suspicious detections out of \(total) engines"
                        )
                    } else {
                        return .safe(provider: name, url: url)
                    }
                }
                return .safe(provider: name, url: url)
            } else if httpResponse.statusCode == 404 {
                // URL not in VT database - submit for scanning
                return .error(provider: name, url: url, details: "URL not yet analyzed by VirusTotal")
            } else {
                return .error(provider: name, url: url, details: "HTTP \(httpResponse.statusCode)")
            }
        } catch {
            logger.error("[VT] Error: \(error.localizedDescription)")
            return .error(provider: name, url: url, details: error.localizedDescription)
        }
    }
}

// MARK: - URLhaus (abuse.ch) - Free, no API key needed
class URLhausProvider: ThreatIntelligenceProvider {
    let name = "URLhaus"
    private let logger = Logger(subsystem: "com.nextguard.agent", category: "URLhaus")
    private let baseURL = "https://urlhaus-api.abuse.ch/v1/url/"

    var isConfigured: Bool { true } // No API key required

    func checkURL(_ url: String) async -> ThreatIntelResult {
        guard let requestURL = URL(string: baseURL) else {
            return .error(provider: name, url: url, details: "Invalid API URL")
        }

        var request = URLRequest(url: requestURL)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.httpBody = "url=\(url)".data(using: .utf8)
        request.timeoutInterval = 10

        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else {
                return .error(provider: name, url: url, details: "Invalid response")
            }

            if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let status = json["query_status"] as? String {
                if status == "listed" {
                    let threat = (json["threat"] as? String) ?? "malware"
                    let tags = (json["tags"] as? [String]) ?? []
                    logger.warning("[URLhaus] LISTED: \(url) - \(threat)")
                    return .malicious(
                        provider: name,
                        url: url,
                        types: ["URLhaus: \(threat)"] + tags,
                        confidence: 0.90,
                        details: "Listed in URLhaus database: \(threat). Tags: \(tags.joined(separator: ", "))"
                    )
                } else {
                    return .safe(provider: name, url: url)
                }
            }
            return .safe(provider: name, url: url)
        } catch {
            logger.error("[URLhaus] Error: \(error.localizedDescription)")
            return .error(provider: name, url: url, details: error.localizedDescription)
        }
    }

  // MARK: - ThreatIntelligenceService

class ThreatIntelligenceService {
  static let shared = ThreatIntelligenceService()
  
  private let logger = Logger(subsystem: "com.nextguard.agent", category: "ThreatIntelligence")
  private var providers: [ThreatIntelligenceProvider] = []
  private let cache = NSCache<NSString, ThreatIntelCacheEntry>()
  private let cacheExpiration: TimeInterval = 3600 // 1 hour
  
  private init() {
    cache.countLimit = 10000
    loadProviders()
  }
  
  func loadProviders() {
    providers.removeAll()
    
    let defaults = UserDefaults.standard
    
    // Google Safe Browsing
    if let gsbKey = defaults.string(forKey: "threatIntel.googleSafeBrowsing.apiKey"), !gsbKey.isEmpty {
      providers.append(GoogleSafeBrowsingProvider(apiKey: gsbKey))
      logger.info("[TI] Google Safe Browsing provider loaded")
    }
    
    // VirusTotal
    if let vtKey = defaults.string(forKey: "threatIntel.virusTotal.apiKey"), !vtKey.isEmpty {
      providers.append(VirusTotalProvider(apiKey: vtKey))
      logger.info("[TI] VirusTotal provider loaded")
    }
    
    // URLhaus (no API key needed)
    if defaults.bool(forKey: "threatIntel.urlhaus.enabled") {
      providers.append(URLhausProvider())
      logger.info("[TI] URLhaus provider loaded")
    }
    
    logger.info("[TI] Total providers loaded: \(self.providers.count)")
  }
  
  func checkURL(_ url: String) async -> ThreatIntelResult {
    // Check cache first
    let cacheKey = NSString(string: url)
    if let cached = cache.object(forKey: cacheKey), Date().timeIntervalSince(cached.timestamp) < cacheExpiration {
      logger.debug("[TI] Cache hit for: \(url)")
      return cached.result
    }
    
    if providers.isEmpty {
      return .safe(provider: "ThreatIntelligence", name: url)
    }
    
    // Query all providers concurrently
    let results = await withTaskGroup(of: ThreatIntelResult.self) { group in
      for provider in providers {
        group.addTask {
          await provider.checkURL(url)
        }
      }
      
      var allResults: [ThreatIntelResult] = []
      for await result in group {
        allResults.append(result)
      }
      return allResults
    }
    
    // If any provider reports malicious, return malicious
    for result in results {
      if case .malicious = result {
        cache.setObject(ThreatIntelCacheEntry(result: result), forKey: cacheKey)
        return result
      }
    }
    
    // All providers say safe
    let safeResult = ThreatIntelResult.safe(provider: "ThreatIntelligence", name: url)
    cache.setObject(ThreatIntelCacheEntry(result: safeResult), forKey: cacheKey)
    return safeResult
  }
  
  var activeProviderCount: Int {
    return providers.count
  }
  
  var activeProviderNames: [String] {
    return providers.map { $0.name }
  }
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
