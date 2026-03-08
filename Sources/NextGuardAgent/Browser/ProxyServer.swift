//
//  ProxyServer.swift
//  NextGuard Endpoint DLP Agent
//
//  Local HTTP/HTTPS proxy server for URL filtering.
//  Like Zscaler, intercepts browser traffic via system proxy settings.
//  Blocked domains get a custom block page; allowed traffic is forwarded.
//
import Foundation
import OSLog
import Darwin

final class ProxyServer: @unchecked Sendable {
    static let shared = ProxyServer()
    private let logger = Logger(subsystem: "com.nextguard.agent", category: "ProxyServer")
    private var isRunning = false
    let port: UInt16 = 8999
    private let networkInterface = "Wi-Fi"

    private init() {}

    // MARK: - Start / Stop
    func start() {
        guard !isRunning else { return }
        isRunning = true
        Thread.detachNewThread { self.runProxyServer() }
        enableSystemProxy()
        logger.info("ProxyServer started on port \(self.port)")
    }

    func stop() {
        guard isRunning else { return }
        isRunning = false
        disableSystemProxy()
        logger.info("ProxyServer stopped")
    }

    // MARK: - System Proxy Configuration
    private func enableSystemProxy() {
        setProxy(enabled: true)
    }

    private func disableSystemProxy() {
        setProxy(enabled: false)
    }

    private func setProxy(enabled: Bool) {
        // Detect active network interface
        let interfaces = getActiveInterfaces()
        for iface in interfaces {
            if enabled {
                runCommand("/usr/sbin/networksetup", ["-setwebproxy", iface, "127.0.0.1", "\(port)"])
                runCommand("/usr/sbin/networksetup", ["-setsecurewebproxy", iface, "127.0.0.1", "\(port)"])
                runCommand("/usr/sbin/networksetup", ["-setwebproxystate", iface, "on"])
                runCommand("/usr/sbin/networksetup", ["-setsecurewebproxystate", iface, "on"])
                logger.info("ProxyServer: enabled system proxy on \(iface)")
            } else {
                runCommand("/usr/sbin/networksetup", ["-setwebproxystate", iface, "off"])
                runCommand("/usr/sbin/networksetup", ["-setsecurewebproxystate", iface, "off"])
                logger.info("ProxyServer: disabled system proxy on \(iface)")
            }
        }
    }

    private func getActiveInterfaces() -> [String] {
        var result: [String] = []
        let pipe = Pipe()
        let proc = Process()
        proc.launchPath = "/usr/sbin/networksetup"
        proc.arguments = ["-listallnetworkservices"]
        proc.standardOutput = pipe
        proc.standardError = FileHandle.nullDevice
        try? proc.run()
        proc.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        for line in output.components(separatedBy: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || trimmed.hasPrefix("An asterisk") || trimmed.hasPrefix("*") { continue }
            // Only add common interfaces
            if trimmed == "Wi-Fi" || trimmed == "Ethernet" || trimmed == "USB 10/100/1000 LAN" || trimmed.contains("Thunderbolt") {
                result.append(trimmed)
            }
        }
        if result.isEmpty { result.append("Wi-Fi") }
        return result
    }

    private func runCommand(_ path: String, _ args: [String]) {
        let proc = Process()
        proc.launchPath = path
        proc.arguments = args
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = FileHandle.nullDevice
        try? proc.run()
        proc.waitUntilExit()
    }

    // MARK: - Proxy Server
    private func runProxyServer() {
        let serverFd = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        guard serverFd >= 0 else {
            logger.error("ProxyServer: socket() failed")
            return
        }
        defer { Darwin.close(serverFd) }

        var yes: Int32 = 1
        setsockopt(serverFd, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        addr.sin_zero = (0,0,0,0,0,0,0,0)

        let bindOk = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(serverFd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindOk == 0 else {
            logger.error("ProxyServer: bind failed: \(String(cString: strerror(errno)))")
            return
        }
        guard listen(serverFd, 128) == 0 else {
            logger.error("ProxyServer: listen failed")
            return
        }

        print("[ProxyServer] Listening on 127.0.0.1:\(port)")

        while isRunning {
            var ca = sockaddr_in()
            var cl = socklen_t(MemoryLayout<sockaddr_in>.size)
            let cfd = withUnsafeMutablePointer(to: &ca) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    accept(serverFd, $0, &cl)
                }
            }
            guard cfd >= 0 else { continue }
            Thread.detachNewThread { self.handleProxyClient(cfd) }
        }
    }

    // MARK: - Handle Proxy Client
    private func handleProxyClient(_ cfd: Int32) {
        defer { Darwin.close(cfd) }

        var tv = timeval(tv_sec: 10, tv_usec: 0)
        setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        var buf = [UInt8](repeating: 0, count: 8192)
        let n = Darwin.read(cfd, &buf, buf.count)
        guard n > 0 else { return }

        let request = String(bytes: buf[0..<n], encoding: .utf8) ?? ""
        let firstLine = request.components(separatedBy: "\r\n").first ?? ""
        let parts = firstLine.components(separatedBy: " ")
        guard parts.count >= 3 else { return }

        let method = parts[0].uppercased()
        let target = parts[1]

        // CONNECT method = HTTPS tunnel
        if method == "CONNECT" {
            handleConnect(cfd: cfd, target: target, request: request)
            return
        }

        // Regular HTTP proxy request
        handleHTTPProxy(cfd: cfd, method: method, target: target, request: request, rawBytes: Array(buf[0..<n]))
    }

    // MARK: - HTTP Proxy (GET/POST etc)
    private func handleHTTPProxy(cfd: Int32, method: String, target: String, request: String, rawBytes: [UInt8]) {
        // Extract host from URL or Host header
        guard let url = URL(string: target) else { return }
        let host = url.host?.lowercased() ?? extractHostHeader(from: request)?.lowercased() ?? ""
        let port = url.port ?? 80

        // Check if blocked
        if DNSFilter.shared.shouldBlock(url: "http://\(host)") {
            logger.info("ProxyServer: BLOCKED http://\(host)")
            let html = BlockPageServer.shared.buildBlockPage(domain: host)
            let resp = buildHTTPResponse(html: html)
            _ = resp.withUnsafeBytes { Darwin.write(cfd, $0.baseAddress!, resp.count) }
            return
        }

        // Forward request to real server
        guard let remoteFd = connectToRemote(host: host, port: UInt16(port)) else { return }
        defer { Darwin.close(remoteFd) }

        // Rewrite request: convert absolute URL to relative path
        let path = url.path.isEmpty ? "/" : url.path + (url.query.map { "?\($0)" } ?? "")
        var rewritten = "\(method) \(path) HTTP/1.1\r\n"
        let lines = request.components(separatedBy: "\r\n")
        for i in 1..<lines.count {
            // Skip proxy-specific headers
            let lower = lines[i].lowercased()
            if lower.hasPrefix("proxy-connection") || lower.hasPrefix("proxy-auth") { continue }
            rewritten += lines[i] + "\r\n"
        }

        if let data = rewritten.data(using: .utf8) {
            _ = data.withUnsafeBytes { Darwin.write(remoteFd, $0.baseAddress!, data.count) }
        }

        // Relay response back
        relayData(from: remoteFd, to: cfd)
    }

    // MARK: - HTTPS CONNECT Tunnel
    private func handleConnect(cfd: Int32, target: String, request: String) {
        let components = target.components(separatedBy: ":")
        let host = components[0].lowercased()
        let port = UInt16(components.count > 1 ? components[1] : "443") ?? 443

        // Check if blocked
        if DNSFilter.shared.shouldBlock(url: "https://\(host)") {
            logger.info("ProxyServer: BLOCKED https://\(host)")
            // Send 200 Connection Established, then send block page as HTML
            let established = "HTTP/1.1 200 Connection Established\r\n\r\n"
            _ = established.utf8.withContiguousStorageIfAvailable {
                Darwin.write(cfd, $0.baseAddress!, $0.count)
            }
            // Wait for client TLS ClientHello, then just send block page
            // For HTTPS blocks, we send an HTTP response directly
            // Safari will show a connection error, but this is expected
            // The block is effective because the connection goes nowhere
            var dummy = [UInt8](repeating: 0, count: 1024)
            _ = Darwin.read(cfd, &dummy, dummy.count)
            // Can't send HTML over TLS without cert, just close
            // The user sees "connection reset" which indicates blocked
            return
        }

        // Allowed: tunnel through
        guard let remoteFd = connectToRemote(host: host, port: port) else {
            let err = "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n"
            _ = err.utf8.withContiguousStorageIfAvailable {
                Darwin.write(cfd, $0.baseAddress!, $0.count)
            }
            return
        }

        // Send 200 to client
        let ok = "HTTP/1.1 200 Connection Established\r\n\r\n"
        _ = ok.utf8.withContiguousStorageIfAvailable {
            Darwin.write(cfd, $0.baseAddress!, $0.count)
        }

        // Bidirectional tunnel
        let remoteFdCopy = remoteFd
        let cfdCopy = cfd
        let t1 = Thread { self.relayData(from: cfdCopy, to: remoteFdCopy) }
        t1.start()
        relayData(from: remoteFdCopy, to: cfdCopy)
        Darwin.close(remoteFd)
    }

    // MARK: - Connect to Remote
    private func connectToRemote(host: String, port: UInt16) -> Int32? {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM
        var res: UnsafeMutablePointer<addrinfo>?
        let rc = getaddrinfo(host, "\(port)", &hints, &res)
        guard rc == 0, let addrList = res else { return nil }
        defer { freeaddrinfo(addrList) }

        let remoteFd = Darwin.socket(addrList.pointee.ai_family, addrList.pointee.ai_socktype, addrList.pointee.ai_protocol)
        guard remoteFd >= 0 else { return nil }

        let connectResult = Darwin.connect(remoteFd, addrList.pointee.ai_addr, addrList.pointee.ai_addrlen)
        guard connectResult == 0 else {
            Darwin.close(remoteFd)
            return nil
        }

        return remoteFd
    }

    // MARK: - Relay Data
    private func relayData(from src: Int32, to dst: Int32) {
        var buf = [UInt8](repeating: 0, count: 16384)
        while true {
            let n = Darwin.read(src, &buf, buf.count)
            if n <= 0 { break }
            var written = 0
            while written < n {
                let w = Darwin.write(dst, &buf + written, n - written)
                if w <= 0 { return }
                written += w
            }
        }
    }

    // MARK: - Helpers
    private func extractHostHeader(from request: String) -> String? {
        for line in request.components(separatedBy: "\r\n") {
            if line.lowercased().hasPrefix("host:") {
                return line.dropFirst(5).trimmingCharacters(in: .whitespaces)
                    .components(separatedBy: ":").first
            }
        }
        return nil
    }

    private func buildHTTPResponse(html: String) -> Data {
        let body = html.data(using: .utf8) ?? Data()
        let header = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: \(body.count)\r\nConnection: close\r\n\r\n"
        var response = header.data(using: .utf8) ?? Data()
        response.append(body)
        return response
    }
}
