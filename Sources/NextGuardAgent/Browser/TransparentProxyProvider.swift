import Foundation
import NetworkExtension
import os.log

/// NETransparentProxyProvider - Production-grade transparent proxy
/// Intercepts all TCP/UDP flows without setting visible system proxy.
/// Uses Network Extension framework for kernel-level traffic inspection.
class TransparentProxyProvider: NETransparentProxyProvider {

    private let logger = Logger(subsystem: "com.nextguard.agent", category: "TransparentProxy")
    private var blockedDomains: Set<String> = []
    private var blockedURLPatterns: [String] = []
    private var threatIntelDomains: Set<String> = []
    private var policyVersion: String = ""

    // MARK: - Lifecycle

    override func startProxy(options: [String: Any]?, completionHandler: @escaping (Error?) -> Void) {
        logger.info("TransparentProxy starting...")
        loadPolicyFromConfig()
        completionHandler(nil)
        logger.info("TransparentProxy started successfully. Policy v\(self.policyVersion)")
    }

    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        logger.info("TransparentProxy stopping. Reason: \(String(describing: reason))")
        completionHandler()
    }

    // MARK: - Flow Handling

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        if let tcpFlow = flow as? NEAppProxyTCPFlow {
            return handleTCPFlow(tcpFlow)
        } else if let udpFlow = flow as? NEAppProxyUDPFlow {
            return handleUDPFlow(udpFlow)
        }
        return false
    }

    // MARK: - TCP Flow Processing

    private func handleTCPFlow(_ flow: NEAppProxyTCPFlow) -> Bool {
        guard let remoteEndpoint = flow.remoteEndpoint as? NWHostEndpoint else {
            return false
        }
        let hostname = remoteEndpoint.hostname
        let port = remoteEndpoint.port

        // Check against blocked domains
        if shouldBlockDomain(hostname) {
            logger.warning("BLOCKED TCP: \(hostname):\(port)")
            flow.closeReadWithError(makeBlockedError(hostname))
            flow.closeWriteWithError(makeBlockedError(hostname))
            AuditLogger.shared.log(event: .urlBlocked, details: [
                "domain": hostname,
                "port": port,
                "protocol": "TCP",
                "action": "blocked"
            ])
            return true
        }

        // HTTPS (port 443) - Inspect CONNECT via SNI
        if port == "443" {
            return handleHTTPSFlow(flow, hostname: hostname)
        }

        // HTTP (port 80) - Inspect full URL
        if port == "80" {
            return handleHTTPFlow(flow, hostname: hostname)
        }

        // Allow other TCP flows to pass through
        flow.open(withLocalEndpoint: nil) { error in
            if let error = error {
                self.logger.error("TCP open error: \(error.localizedDescription)")
                return
            }
            self.relayTCPFlow(flow)
        }
        return true
    }

    // MARK: - HTTPS Flow (SNI-based blocking, no SSL interception)

    private func handleHTTPSFlow(_ flow: NEAppProxyTCPFlow, hostname: String) -> Bool {
        // For HTTPS we block at connection level using SNI hostname
        // No SSL interception needed - we inspect the destination only
        if shouldBlockDomain(hostname) {
            logger.warning("BLOCKED HTTPS: \(hostname):443")
            flow.closeReadWithError(makeBlockedError(hostname))
            flow.closeWriteWithError(makeBlockedError(hostname))
            AuditLogger.shared.log(event: .urlBlocked, details: [
                "domain": hostname,
                "port": "443",
                "protocol": "HTTPS",
                "action": "blocked"
            ])
            return true
        }
        // Allow - pass through transparently
        flow.open(withLocalEndpoint: nil) { error in
            if let error = error {
                self.logger.error("HTTPS open error: \(error.localizedDescription)")
                return
            }
            self.relayTCPFlow(flow)
        }
        return true
    }

    // MARK: - HTTP Flow (Full URL inspection)

    private func handleHTTPFlow(_ flow: NEAppProxyTCPFlow, hostname: String) -> Bool {
        flow.open(withLocalEndpoint: nil) { error in
            if let error = error {
                self.logger.error("HTTP open error: \(error.localizedDescription)")
                return
            }
            // Read initial data to inspect HTTP request
            flow.readData { data, error in
                if let error = error {
                    self.logger.error("HTTP read error: \(error.localizedDescription)")
                    return
                }
                guard let data = data, let request = String(data: data, encoding: .utf8) else {
                    self.relayTCPFlow(flow)
                    return
                }
                // Extract full URL from HTTP request line
                let fullURL = self.extractURLFromHTTPRequest(request, hostname: hostname)
                if self.shouldBlockURL(fullURL) || self.shouldBlockDomain(hostname) {
                    self.logger.warning("BLOCKED HTTP: \(fullURL)")
                    let blockPage = self.generateBlockPageResponse(fullURL)
                    flow.write(blockPage, withTag: 0) { _ in
                        flow.closeReadWithError(nil)
                        flow.closeWriteWithError(nil)
                    }
                    AuditLogger.shared.log(event: .urlBlocked, details: [
                        "url": fullURL,
                        "protocol": "HTTP",
                        "action": "blocked"
                    ])
                    return
                }
                // Write original data and continue relay
                flow.write(data, withTag: 0) { _ in
                    self.relayTCPFlow(flow)
                }
            }
        }
        return true
    }

    // MARK: - UDP Flow Processing (QUIC & DoH blocking)

    private func handleUDPFlow(_ flow: NEAppProxyUDPFlow) -> Bool {
        guard let remoteEndpoint = flow.localEndpoint as? NWHostEndpoint else {
            return false
        }
        let hostname = remoteEndpoint.hostname
        let port = remoteEndpoint.port

        // Block QUIC (UDP 443) for blocked domains
        if port == "443" && shouldBlockDomain(hostname) {
            logger.warning("BLOCKED QUIC: \(hostname):443")
            flow.closeReadWithError(makeBlockedError(hostname))
            flow.closeWriteWithError(makeBlockedError(hostname))
            AuditLogger.shared.log(event: .urlBlocked, details: [
                "domain": hostname,
                "port": "443",
                "protocol": "QUIC",
                "action": "blocked"
            ])
            return true
        }

        // Block DNS-over-HTTPS / DNS-over-QUIC to known providers
        let dohProviders = ["dns.google", "cloudflare-dns.com", "dns.quad9.net",
                            "doh.opendns.com", "dns.adguard.com", "1.1.1.1", "8.8.8.8"]
        if (port == "443" || port == "853") && dohProviders.contains(hostname) {
            logger.info("BLOCKED DoH/DoQ: \(hostname):\(port)")
            flow.closeReadWithError(makeBlockedError(hostname))
            flow.closeWriteWithError(makeBlockedError(hostname))
            return true
        }

        // Allow other UDP traffic
        flow.open(withLocalEndpoint: nil) { error in
            if let error = error {
                self.logger.error("UDP open error: \(error.localizedDescription)")
                return
            }
            self.relayUDPFlow(flow)
        }
        return true
    }

    // MARK: - Relay Functions

    private func relayTCPFlow(_ flow: NEAppProxyTCPFlow) {
        flow.readData { data, error in
            if let error = error {
                flow.closeReadWithError(error)
                return
            }
            guard let data = data, !data.isEmpty else {
                flow.closeReadWithError(nil)
                return
            }
            flow.write(data, withTag: 0) { error in
                if let error = error {
                    flow.closeWriteWithError(error)
                    return
                }
                self.relayTCPFlow(flow)
            }
        }
    }

    private func relayUDPFlow(_ flow: NEAppProxyUDPFlow) {
        flow.readDatagrams { datagrams, endpoints, error in
            if let error = error {
                flow.closeReadWithError(error)
                return
            }
            guard let datagrams = datagrams, let endpoints = endpoints else {
                return
            }
            flow.writeDatagrams(datagrams, sentBy: endpoints) { error in
                if let error = error {
                    flow.closeWriteWithError(error)
                    return
                }
                self.relayUDPFlow(flow)
            }
        }
    }

    // MARK: - Domain & URL Matching

    private func shouldBlockDomain(_ domain: String) -> Bool {
        let normalizedDomain = domain.lowercased()
        // Exact match
        if blockedDomains.contains(normalizedDomain) || threatIntelDomains.contains(normalizedDomain) {
            return true
        }
        // Wildcard subdomain match
        for blocked in blockedDomains {
            if normalizedDomain.hasSuffix("." + blocked) {
                return true
            }
        }
        for threat in threatIntelDomains {
            if normalizedDomain.hasSuffix("." + threat) {
                return true
            }
        }
        return false
    }

    private func shouldBlockURL(_ url: String) -> Bool {
        let normalizedURL = url.lowercased()
        for pattern in blockedURLPatterns {
            if normalizedURL.contains(pattern.lowercased()) {
                return true
            }
        }
        return false
    }

    private func extractURLFromHTTPRequest(_ request: String, hostname: String) -> String {
        guard let firstLine = request.components(separatedBy: "\r\n").first else {
            return hostname
        }
        let parts = firstLine.components(separatedBy: " ")
        guard parts.count >= 2 else { return hostname }
        let path = parts[1]
        return "http://\(hostname)\(path)"
    }

    // MARK: - Policy Loading

    private func loadPolicyFromConfig() {
        guard let config = (self.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration else {
            logger.error("No provider configuration found")
            return
        }
        if let domains = config["blockedDomains"] as? [String] {
            blockedDomains = Set(domains.map { $0.lowercased() })
        }
        if let patterns = config["blockedURLPatterns"] as? [String] {
            blockedURLPatterns = patterns
        }
        if let threats = config["threatIntelDomains"] as? [String] {
            threatIntelDomains = Set(threats.map { $0.lowercased() })
        }
        if let version = config["policyVersion"] as? String {
            policyVersion = version
        }
        logger.info("Policy loaded: \(self.blockedDomains.count) domains, \(self.blockedURLPatterns.count) patterns, \(self.threatIntelDomains.count) threat domains")
    }

    /// Update policy at runtime without restarting proxy
    func updatePolicy(domains: [String], patterns: [String], threats: [String], version: String) {
        blockedDomains = Set(domains.map { $0.lowercased() })
        blockedURLPatterns = patterns
        threatIntelDomains = Set(threats.map { $0.lowercased() })
        policyVersion = version
        logger.info("Policy updated to v\(version): \(domains.count) domains")
    }

    // MARK: - Helpers

    private func makeBlockedError(_ domain: String) -> Error {
        NSError(domain: "com.nextguard.proxy", code: 403, userInfo: [
            NSLocalizedDescriptionKey: "Blocked by NextGuard: \(domain)"
        ])
    }

    private func generateBlockPageResponse(_ url: String) -> Data {
        let html = """
        HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n
        <!DOCTYPE html><html><head><title>NextGuard - Blocked</title>
        <style>body{font-family:-apple-system,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#f5f5f5}
        .card{background:#fff;padding:40px;border-radius:12px;box-shadow:0 2px 20px rgba(0,0,0,0.1);text-align:center;max-width:500px}
        h1{color:#e74c3c}p{color:#666}</style></head>
        <body><div class="card"><h1>Access Blocked</h1>
        <p>This website has been blocked by your organization's security policy.</p>
        <p style="font-size:12px;color:#999">\(url)</p>
        <p style="font-size:12px;color:#999">NextGuard Endpoint Protection</p></div></body></html>
        """
        return html.data(using: .utf8) ?? Data()
    }
}

// MARK: - Proxy Manager (installs/manages the transparent proxy)

class TransparentProxyManager {
    static let shared = TransparentProxyManager()
    private let logger = Logger(subsystem: "com.nextguard.agent", category: "ProxyManager")
    private var manager: NETunnelProviderManager?

    func installProxy(blockedDomains: [String], blockedURLPatterns: [String], threatIntelDomains: [String], policyVersion: String, completion: @escaping (Bool) -> Void) {
        NETunnelProviderManager.loadAllFromPreferences { managers, error in
            if let error = error {
                self.logger.error("Load managers error: \(error.localizedDescription)")
                completion(false)
                return
            }
            let manager = managers?.first ?? NETunnelProviderManager()
            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = "com.nextguard.agent.transparent-proxy"
            proto.serverAddress = "NextGuard"
            proto.providerConfiguration = [
                "blockedDomains": blockedDomains,
                "blockedURLPatterns": blockedURLPatterns,
                "threatIntelDomains": threatIntelDomains,
                "policyVersion": policyVersion
            ]
            manager.protocolConfiguration = proto
            manager.localizedDescription = "NextGuard URL Filter"
            manager.isEnabled = true

            manager.saveToPreferences { error in
                if let error = error {
                    self.logger.error("Save proxy error: \(error.localizedDescription)")
                    completion(false)
                    return
                }
                self.manager = manager
                self.startProxy(manager: manager, completion: completion)
            }
        }
    }

    private func startProxy(manager: NETunnelProviderManager, completion: @escaping (Bool) -> Void) {
        do {
            try (manager.connection as? NETunnelProviderSession)?.startTunnel(options: nil)
            logger.info("Transparent proxy started")
            completion(true)
        } catch {
            logger.error("Start proxy error: \(error.localizedDescription)")
            completion(false)
        }
    }

    func stopProxy(completion: @escaping () -> Void) {
        manager?.connection.stopVPNTunnel()
        logger.info("Transparent proxy stopped")
        completion()
    }

    func updatePolicy(domains: [String], patterns: [String], threats: [String], version: String) {
        guard let manager = manager else { return }
        guard let proto = manager.protocolConfiguration as? NETunnelProviderProtocol else { return }
        proto.providerConfiguration = [
            "blockedDomains": domains,
            "blockedURLPatterns": patterns,
            "threatIntelDomains": threats,
            "policyVersion": version
        ]
        manager.protocolConfiguration = proto
        manager.saveToPreferences { error in
            if let error = error {
                self.logger.error("Update policy error: \(error.localizedDescription)")
            }
        }
    }
}