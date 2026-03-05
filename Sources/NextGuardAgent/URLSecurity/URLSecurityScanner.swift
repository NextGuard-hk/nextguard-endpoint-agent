//
// URLSecurityScanner.swift
// NextGuardAgent
//
// Copyright (c) 2026 NextGuard Technology Limited. All rights reserved.
// URL Security Scanner - Phishing, scam, and malicious URL detection engine
//

import Foundation
import CryptoKit
import os.log
import AppKit

// MARK: - URL Threat Classification
enum URLThreatLevel: String, Codable, CaseIterable {
    case safe = "Safe"
    case suspicious = "Suspicious"
    case dangerous = "Dangerous"
    case blocked = "Blocked"

    var color: String {
        switch self {
        case .safe: return "green"
        case .suspicious: return "orange"
        case .dangerous: return "red"
        case .blocked: return "purple"
        }
    }

    var icon: String {
        switch self {
        case .safe: return "checkmark.shield.fill"
        case .suspicious: return "exclamationmark.triangle.fill"
        case .dangerous: return "xmark.shield.fill"
        case .blocked: return "hand.raised.fill"
        }
    }
}

enum URLThreatCategory: String, Codable, CaseIterable {
    case phishing = "Phishing"
    case scam = "Scam"
    case malware = "Malware Distribution"
    case cryptojacking = "Cryptojacking"
    case typosquatting = "Typosquatting"
    case homograph = "Homograph Attack"
    case redirectChain = "Suspicious Redirect"
    case dataHarvesting = "Data Harvesting"
    case fakeLogin = "Fake Login Page"
    case sslStripping = "SSL Stripping"
    case urlShortenerAbuse = "Shortened URL Abuse"
    case suspiciousTLD = "Suspicious TLD"
    case ipAddress = "Direct IP Access"
    case dga = "Domain Generation Algorithm"
    case clean = "Clean"
}

// MARK: - Scan Result
struct URLScanResult: Identifiable, Codable {
    let id: UUID
    let url: String
    let domain: String
    let threatLevel: URLThreatLevel
    let categories: [URLThreatCategory]
    let riskScore: Int // 0-100
    let details: [String]
    let scannedAt: Date
    let sslValid: Bool
    let redirectCount: Int
    var userAction: UserAction?

    enum UserAction: String, Codable {
        case allowed = "Allowed"
        case blocked = "Blocked"
        case ignored = "Ignored"
    }

    init(url: String, domain: String, threatLevel: URLThreatLevel, categories: [URLThreatCategory], riskScore: Int, details: [String], sslValid: Bool = true, redirectCount: Int = 0) {
        self.id = UUID()
        self.url = url
        self.domain = domain
        self.threatLevel = threatLevel
        self.categories = categories
        self.riskScore = min(100, max(0, riskScore))
        self.details = details
        self.scannedAt = Date()
        self.sslValid = sslValid
        self.redirectCount = redirectCount
        self.userAction = nil
    }
}

// MARK: - URL Security Scanner Engine
final class URLSecurityScanner: ObservableObject {
    static let shared = URLSecurityScanner()
    private let logger = Logger(subsystem: "com.nextguard.agent", category: "URLSecurity")

    @Published var isEnabled: Bool = true
    @Published var isRealTimeEnabled: Bool = true
    @Published var scanHistory: [URLScanResult] = []
    @Published var blockedCount: Int = 0
    @Published var scannedCount: Int = 0
    @Published var threatsDetected: Int = 0
    @Published var lastScanDate: Date? = nil
    @Published var whitelistedDomains: [String] = []
    @Published var blacklistedDomains: [String] = []
    @Published var blockMode: BlockMode = .warnAndBlock

    enum BlockMode: String, CaseIterable {
        case monitorOnly = "Monitor Only"
        case warnUser = "Warn User"
        case warnAndBlock = "Warn & Block"
        case silentBlock = "Silent Block"
    }

    // MARK: - Known Phishing Domains Database
    private let knownPhishingPatterns: [String] = [
        "login-secure", "account-verify", "signin-update",
        "security-alert", "confirm-identity", "verify-account",
        "update-billing", "suspended-account", "unusual-activity",
        "password-reset-confirm", "secure-login-portal",
        "banking-secure", "paypal-confirm", "apple-id-verify",
        "microsoft-365-login", "google-security-check",
        "amazon-order-confirm", "netflix-payment-update",
        "dhl-tracking-delivery", "fedex-package-notice",
    ]

    // Known malicious TLDs with higher risk scores
    private let suspiciousTLDs: Set<String> = [
        "tk", "ml", "ga", "cf", "gq",  // Free TLDs commonly abused
        "xyz", "top", "work", "click", "link",
        "buzz", "surf", "icu", "monster", "rest",
        "cam", "bar", "loan", "racing", "win",
        "bid", "stream", "gdn", "mom", "cyou",
    ]

    // Legitimate domains that are commonly impersonated
    private let highValueTargets: [String: [String]] = [
        "google.com": ["g00gle", "googie", "gooogle", "google-login", "google-verify"],
        "apple.com": ["appie", "apple-id", "apples-support", "icloud-verify"],
        "microsoft.com": ["micr0soft", "microsft", "microsoft-login", "office365-verify"],
        "amazon.com": ["amaz0n", "amazom", "amazon-order", "amazon-prime-verify"],
        "paypal.com": ["paypa1", "paypal-secure", "paypal-confirm", "paypal-verify"],
        "facebook.com": ["faceb00k", "facebook-login", "fb-security"],
        "netflix.com": ["netfIix", "netflix-billing", "netflix-update"],
        "bankofamerica.com": ["bankofamerica-secure", "boa-login", "bofa-verify"],
        "chase.com": ["chase-secure", "chase-verify", "chase-banking"],
        "wellsfargo.com": ["wellsfarg0", "wellsfargo-secure"],
        "hsbc.com": ["hsbc-secure", "hsbc-verify", "hsbc-online-banking"],
        "citibank.com": ["citibank-secure", "citi-verify"],
        "dhl.com": ["dhl-tracking", "dhl-delivery", "dhl-parcel"],
    ]

    // URL shortener services
    private let urlShorteners: Set<String> = [
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
        "is.gd", "buff.ly", "adf.ly", "bl.ink", "lnkd.in",
        "rb.gy", "cutt.ly", "shorturl.at", "tiny.cc",
    ]

    init() {
        loadWhitelist()
        loadBlacklist()
        loadScanHistory()
    }

    // MARK: - Main Scan Function
    func scanURL(_ urlString: String) -> URLScanResult {
        let cleanURL = urlString.trimmingCharacters(in: .whitespacesAndNewlines)
        scannedCount += 1
        lastScanDate = Date()

        guard let url = URL(string: cleanURL.hasPrefix("http") ? cleanURL : "https://\(cleanURL)"),
              let host = url.host?.lowercased() else {
            let result = URLScanResult(
                url: cleanURL, domain: "unknown",
                threatLevel: .dangerous,
                categories: [.phishing],
                riskScore: 85,
                details: ["Invalid or malformed URL"]
            )
            recordResult(result)
            return result
        }

        let domain = host
        var riskScore = 0
        var categories: [URLThreatCategory] = []
        var details: [String] = []
        let isHTTPS = url.scheme == "https"

        // Check whitelist first
        if whitelistedDomains.contains(where: { domain.hasSuffix($0) }) {
            let result = URLScanResult(
                url: cleanURL, domain: domain,
                threatLevel: .safe, categories: [.clean],
                riskScore: 0, details: ["Domain is whitelisted"]
            )
            recordResult(result)
            return result
        }

        // Check blacklist
        if blacklistedDomains.contains(where: { domain.hasSuffix($0) }) {
            let result = URLScanResult(
                url: cleanURL, domain: domain,
                threatLevel: .blocked, categories: [.phishing],
                riskScore: 100, details: ["Domain is blacklisted"]
            )
            recordResult(result)
            return result
        }

        // 1. SSL/HTTPS Check
        if !isHTTPS {
            riskScore += 20
            categories.append(.sslStripping)
            details.append("No HTTPS - connection is not encrypted")
        }

        // 2. Direct IP address access
        if isIPAddress(domain) {
            riskScore += 35
            categories.append(.ipAddress)
            details.append("URL uses direct IP address instead of domain name")
        }

        // 3. Suspicious TLD check
        let tld = domain.components(separatedBy: ".").last ?? ""
        if suspiciousTLDs.contains(tld) {
            riskScore += 25
            categories.append(.suspiciousTLD)
            details.append("Domain uses suspicious TLD: .\(tld)")
        }

        // 4. Typosquatting / Homograph detection
        let typoResult = checkTyposquatting(domain)
        if let target = typoResult {
            riskScore += 45
            categories.append(.typosquatting)
            details.append("Possible impersonation of \(target)")
        }

        // 5. Homograph attack (IDN / punycode)
        if domain.contains("xn--") || containsHomoglyphs(domain) {
            riskScore += 40
            categories.append(.homograph)
            details.append("Domain contains lookalike characters (homograph attack)")
        }

        // 6. Phishing pattern matching
        let phishingMatch = checkPhishingPatterns(domain, path: url.path)
        if !phishingMatch.isEmpty {
            riskScore += 35
            categories.append(.phishing)
            details.append(contentsOf: phishingMatch)
        }

        // 7. URL shortener check
        if urlShorteners.contains(domain) {
            riskScore += 15
            categories.append(.urlShortenerAbuse)
            details.append("URL uses a shortener service - final destination unknown")
        }

        // 8. Excessive subdomains (common in phishing)
        let subdomainCount = domain.components(separatedBy: ".").count - 2
        if subdomainCount > 3 {
            riskScore += 20
            categories.append(.phishing)
            details.append("Excessive subdomains (\(subdomainCount)) - common phishing pattern")
        }

        // 9. DGA detection (random-looking domain)
        if isDGADomain(domain) {
            riskScore += 30
            categories.append(.dga)
            details.append("Domain appears to be algorithmically generated")
        }

        // 10. Suspicious URL path patterns
        let pathRisk = analyzeURLPath(url.path, query: url.query)
        riskScore += pathRisk.score
        details.append(contentsOf: pathRisk.details)
        categories.append(contentsOf: pathRisk.categories)

        // 11. Domain age heuristic (very long domains)
        if domain.count > 40 {
            riskScore += 15
            details.append("Unusually long domain name (\(domain.count) chars)")
        }

        // 12. Multiple hyphens in domain
        let hyphenCount = domain.filter({ $0 == "-" }).count
        if hyphenCount > 3 {
            riskScore += 15
            details.append("Domain has excessive hyphens (\(hyphenCount)) - phishing indicator")
        }

        // Determine threat level
        let threatLevel: URLThreatLevel
        if riskScore >= 70 {
            threatLevel = .dangerous
            threatsDetected += 1
        } else if riskScore >= 40 {
            threatLevel = .suspicious
        } else {
            threatLevel = .safe
        }

        if categories.isEmpty { categories = [.clean] }

        let result = URLScanResult(
            url: cleanURL, domain: domain,
            threatLevel: threatLevel,
            categories: categories,
            riskScore: riskScore,
            details: details.isEmpty ? ["No threats detected"] : details,
            sslValid: isHTTPS
        )

        recordResult(result)
        logger.info("[URLSecurity] Scanned \(domain): \(threatLevel.rawValue) (score: \(riskScore))")
        return result
    }

    // MARK: - Detection Helpers
    private func isIPAddress(_ host: String) -> Bool {
        let ipv4 = "^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$"
        let ipv6 = ".*:.*:.*"
        return host.range(of: ipv4, options: .regularExpression) != nil ||
               host.range(of: ipv6, options: .regularExpression) != nil
    }

    private func checkTyposquatting(_ domain: String) -> String? {
        let domainLower = domain.lowercased()
        for (legitimate, typos) in highValueTargets {
            for typo in typos {
                if domainLower.contains(typo) {
                    return legitimate
                }
            }
            // Levenshtein distance check
            let baseDomain = domainLower.components(separatedBy: ".").dropLast().joined(separator: ".")
            let legitBase = legitimate.components(separatedBy: ".").first ?? legitimate
            if levenshteinDistance(baseDomain, legitBase) <= 2 && baseDomain != legitBase {
                return legitimate
            }
        }
        return nil
    }

    private func containsHomoglyphs(_ domain: String) -> Bool {
        // Check for common Unicode lookalikes
        let homoglyphs: [Character: Character] = [
            "\u{0430}": "a",  // Cyrillic а
            "\u{0435}": "e",  // Cyrillic е
            "\u{043E}": "o",  // Cyrillic о
            "\u{0440}": "p",  // Cyrillic р
            "\u{0441}": "c",  // Cyrillic с
            "\u{0443}": "y",  // Cyrillic у
            "\u{0445}": "x",  // Cyrillic х
            "\u{04BB}": "h",  // Cyrillic ћ
        ]
        for char in domain {
            if homoglyphs.keys.contains(char) {
                return true
            }
        }
        return false
    }

    private func checkPhishingPatterns(_ domain: String, path: String) -> [String] {
        var matches: [String] = []
        let combined = domain + path
        for pattern in knownPhishingPatterns {
            if combined.contains(pattern) {
                matches.append("Phishing pattern detected: \(pattern)")
            }
        }
        // Check for credential harvesting paths
        let dangerousPaths = ["login", "signin", "verify", "confirm", "secure", "account", "banking", "password", "credential", "authenticate"]
        let pathLower = path.lowercased()
        for dp in dangerousPaths {
            if pathLower.contains(dp) && !isKnownLegitimate(domain) {
                matches.append("Suspicious path contains '\(dp)' on unknown domain")
                break
            }
        }
        return matches
    }

    private func isDGADomain(_ domain: String) -> Bool {
        let baseDomain = domain.components(separatedBy: ".").first ?? domain
        if baseDomain.count < 8 { return false }
        // Consonant ratio check - DGA domains have unusual letter distributions
        let vowels: Set<Character> = ["a", "e", "i", "o", "u"]
        let consonants = baseDomain.filter { $0.isLetter && !vowels.contains($0) }
        let vowelCount = baseDomain.filter { vowels.contains($0) }.count
        if vowelCount == 0 { return true }
        let ratio = Double(consonants.count) / Double(vowelCount)
        if ratio > 5.0 { return true }
        // Digit ratio check
        let digitCount = baseDomain.filter { $0.isNumber }.count
        if Double(digitCount) / Double(baseDomain.count) > 0.4 { return true }
        // Entropy check
        let entropy = calculateEntropy(baseDomain)
        return entropy > 4.0
    }

    private func calculateEntropy(_ string: String) -> Double {
        var freq: [Character: Int] = [:]
        for char in string { freq[char, default: 0] += 1 }
        let len = Double(string.count)
        var entropy = 0.0
        for (_, count) in freq {
            let p = Double(count) / len
            if p > 0 { entropy -= p * log2(p) }
        }
        return entropy
    }

    private func analyzeURLPath(_ path: String, query: String?) -> (score: Int, details: [String], categories: [URLThreatCategory]) {
        var score = 0
        var details: [String] = []
        var categories: [URLThreatCategory] = []
        let combined = path + (query ?? "")

        // Data exfiltration patterns in query
        if let q = query {
            if q.contains("base64") || q.contains("encoded") {
                score += 15
                details.append("URL contains encoded data parameters")
                categories.append(.dataHarvesting)
            }
            if q.count > 500 {
                score += 10
                details.append("Unusually long query string (\(q.count) chars)")
            }
        }

        // Redirect patterns
        if combined.contains("redirect") || combined.contains("redir=") || combined.contains("url=") || combined.contains("goto=") {
            score += 15
            details.append("URL contains redirect parameters")
            categories.append(.redirectChain)
        }

        // File download triggers
        let dangerousExts = [".exe", ".scr", ".bat", ".cmd", ".msi", ".js", ".vbs", ".ps1"]
        for ext in dangerousExts {
            if path.lowercased().hasSuffix(ext) {
                score += 25
                details.append("URL points to potentially dangerous file type: \(ext)")
                categories.append(.malware)
                break
            }
        }

        return (score, details, categories)
    }

    private func isKnownLegitimate(_ domain: String) -> Bool {
        let legitimateDomains: Set<String> = [
            "google.com", "apple.com", "microsoft.com", "amazon.com",
            "facebook.com", "github.com", "stackoverflow.com",
            "paypal.com", "netflix.com", "linkedin.com", "twitter.com",
            "instagram.com", "youtube.com", "wikipedia.org",
            "bankofamerica.com", "chase.com", "wellsfargo.com",
            "hsbc.com", "citibank.com", "yahoo.com", "outlook.com",
        ]
        return legitimateDomains.contains(where: { domain.hasSuffix($0) })
    }

    private func levenshteinDistance(_ s1: String, _ s2: String) -> Int {
        let a = Array(s1)
        let b = Array(s2)
        var dist = [[Int]](repeating: [Int](repeating: 0, count: b.count + 1), count: a.count + 1)
        for i in 0...a.count { dist[i][0] = i }
        for j in 0...b.count { dist[0][j] = j }
        for i in 1...a.count {
            for j in 1...b.count {
                let cost = a[i-1] == b[j-1] ? 0 : 1
                dist[i][j] = min(dist[i-1][j] + 1, dist[i][j-1] + 1, dist[i-1][j-1] + cost)
            }
        }
        return dist[a.count][b.count]
    }

    // MARK: - Clipboard Monitoring
    func scanClipboardForURLs() {
        guard isRealTimeEnabled else { return }
        let pasteboard = NSPasteboard.general
        guard let content = pasteboard.string(forType: .string) else { return }
        let detector = try? NSDataDetector(types: NSTextCheckingResult.CheckingType.link.rawValue)
        let matches = detector?.matches(in: content, range: NSRange(content.startIndex..., in: content)) ?? []
        for match in matches {
            if let url = match.url {
                let result = scanURL(url.absoluteString)
                if result.threatLevel == .dangerous || result.threatLevel == .blocked {
                    logger.warning("[URLSecurity] Dangerous URL detected in clipboard: \(url.absoluteString)")
                }
            }
        }
    }

    // MARK: - Batch Scan
    func scanMultipleURLs(_ urls: [String]) -> [URLScanResult] {
        return urls.map { scanURL($0) }
    }

    // MARK: - Whitelist / Blacklist Management
    func addToWhitelist(_ domain: String) {
        let d = domain.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
        if !whitelistedDomains.contains(d) {
            whitelistedDomains.append(d)
            saveWhitelist()
        }
    }

    func removeFromWhitelist(_ domain: String) {
        whitelistedDomains.removeAll { $0 == domain }
        saveWhitelist()
    }

    func addToBlacklist(_ domain: String) {
        let d = domain.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
        if !blacklistedDomains.contains(d) {
            blacklistedDomains.append(d)
            saveBlacklist()
        }
    }

    func removeFromBlacklist(_ domain: String) {
        blacklistedDomains.removeAll { $0 == domain }
        saveBlacklist()
    }

    // MARK: - Persistence
    private let basePath = NSHomeDirectory() + "/Library/Application Support/NextGuard"

    private func recordResult(_ result: URLScanResult) {
        DispatchQueue.main.async {
            self.scanHistory.insert(result, at: 0)
            if self.scanHistory.count > 500 { self.scanHistory = Array(self.scanHistory.prefix(500)) }
        }
        saveScanHistory()
    }

    private func saveScanHistory() {
        let path = basePath + "/url_scan_history.json"
        try? FileManager.default.createDirectory(atPath: basePath, withIntermediateDirectories: true)
        if let data = try? JSONEncoder().encode(Array(scanHistory.prefix(200))) {
            try? data.write(to: URL(fileURLWithPath: path))
        }
    }

    private func loadScanHistory() {
        let path = basePath + "/url_scan_history.json"
        if let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
           let history = try? JSONDecoder().decode([URLScanResult].self, from: data) {
            scanHistory = history
        }
    }

    private func saveWhitelist() {
        let path = basePath + "/url_whitelist.json"
        try? FileManager.default.createDirectory(atPath: basePath, withIntermediateDirectories: true)
        if let data = try? JSONEncoder().encode(whitelistedDomains) {
            try? data.write(to: URL(fileURLWithPath: path))
        }
    }

    private func loadWhitelist() {
        let path = basePath + "/url_whitelist.json"
        if let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
           let list = try? JSONDecoder().decode([String].self, from: data) {
            whitelistedDomains = list
        }
    }

    private func saveBlacklist() {
        let path = basePath + "/url_blacklist.json"
        try? FileManager.default.createDirectory(atPath: basePath, withIntermediateDirectories: true)
        if let data = try? JSONEncoder().encode(blacklistedDomains) {
            try? data.write(to: URL(fileURLWithPath: path))
        }
    }

    private func loadBlacklist() {
        let path = basePath + "/url_blacklist.json"
        if let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
           let list = try? JSONDecoder().decode([String].self, from: data) {
            blacklistedDomains = list
        }
    }

    // MARK: - Clear History
    func clearHistory() {
        scanHistory.removeAll()
        scannedCount = 0
        threatsDetected = 0
        blockedCount = 0
        saveScanHistory()
    }
}
