//
//  BlockPageServer.swift
//  NextGuard Endpoint DLP Agent
//
//  Simplified approach: HTTP-only block page server on port 80.
//  For HTTPS blocked domains, Safari will show a connection error
//  (which is the expected behavior for a DNS sinkhole).
//  The block page is served when the browser falls back to HTTP.
//
import Foundation
import OSLog
import Darwin

final class BlockPageServer: @unchecked Sendable {
    static let shared = BlockPageServer()
    private let logger = Logger(subsystem: "com.nextguard.agent", category: "BlockPageServer")
    private var isRunning = false
    private let messagePath = "/tmp/nextguard_block_message"

    // MARK: - Custom Block Message
    var customBlockMessage: String {
        get {
            let raw = (try? String(contentsOfFile: messagePath, encoding: .utf8)) ?? ""
            return raw.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        set {
            try? newValue.write(toFile: messagePath, atomically: true, encoding: .utf8)
        }
    }

    private init() {}

    // MARK: - Start
    func start() {
        guard !isRunning else { return }
        isRunning = true

        // Start HTTP on port 80
        Thread.detachNewThread {
            self.runHTTPServer(port: 80)
        }
        // Start a simple HTTPS redirect-to-block on port 443
        // Just accept and immediately send an HTTP block page
        // (Safari will show cert warning but curl -k will work)
        Thread.detachNewThread {
            self.runHTTPServer(port: 443)
        }
        logger.info("BlockPageServer: started on ports 80 and 443")
    }

    func stop() {
        isRunning = false
    }

    // MARK: - Run POSIX Socket Server (HTTP)
    private func runHTTPServer(port: UInt16) {
        let serverFd = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        guard serverFd >= 0 else {
            logger.error("BlockPageServer: socket() failed on port \(port)")
            return
        }
        defer { Darwin.close(serverFd) }

        var yes: Int32 = 1
        setsockopt(serverFd, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))
        setsockopt(serverFd, SOL_SOCKET, SO_REUSEPORT, &yes, socklen_t(MemoryLayout<Int32>.size))

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        addr.sin_zero = (0,0,0,0,0,0,0,0)

        let bindResult = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(serverFd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindResult == 0 else {
            logger.error("BlockPageServer: bind failed on port \(port): \(String(cString: strerror(errno)))")
            return
        }

        guard listen(serverFd, 10) == 0 else {
            logger.error("BlockPageServer: listen failed on port \(port)")
            return
        }

        print("[BlockPageServer] Listening on 127.0.0.1:\(port)")

        while isRunning {
            var clientAddr = sockaddr_in()
            var clientLen = socklen_t(MemoryLayout<sockaddr_in>.size)
            let clientFd = withUnsafeMutablePointer(to: &clientAddr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    accept(serverFd, $0, &clientLen)
                }
            }
            guard clientFd >= 0 else { continue }

            Thread.detachNewThread {
                self.handleClient(clientFd, port: port)
            }
        }
    }

    // MARK: - Handle Client Connection
    private func handleClient(_ cfd: Int32, port: UInt16) {
        defer { Darwin.close(cfd) }

        // Set a read timeout so we don't hang forever
        var tv = timeval(tv_sec: 3, tv_usec: 0)
        setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        var buf = [UInt8](repeating: 0, count: 4096)
        let n = Darwin.read(cfd, &buf, buf.count)

        // For port 443: the first byte will be 0x16 (TLS ClientHello)
        // In that case, we can't do a proper TLS handshake without certs,
        // so just close the connection. Safari will show "can't establish secure connection"
        // which is acceptable for a blocked site.
        if port == 443 && n > 0 && buf[0] == 0x16 {
            // This is a TLS ClientHello - we can't respond without valid certs
            // Just close - Safari shows connection error for blocked HTTPS sites
            logger.info("BlockPageServer: TLS ClientHello on 443, closing (blocked site)")
            return
        }

        // For HTTP requests (port 80, or non-TLS on 443)
        if n > 0 {
            let request = String(bytes: buf[0..<n], encoding: .utf8) ?? ""
            let domain = extractHost(from: request) ?? "blocked.site"
            logger.info("BlockPageServer: HTTP request for \(domain)")

            let html = buildBlockPage(domain: domain)
            let response = buildHTTPResponse(html: html)
            _ = response.withUnsafeBytes {
                Darwin.write(cfd, $0.baseAddress!, response.count)
            }
        }
    }

    // MARK: - Extract Host Header
    private func extractHost(from request: String) -> String? {
        for line in request.components(separatedBy: "\r\n") {
            if line.lowercased().hasPrefix("host:") {
                return line.dropFirst(5).trimmingCharacters(in: .whitespaces)
                    .components(separatedBy: ":").first
            }
        }
        return nil
    }

    // MARK: - Build HTTP Response
    private func buildHTTPResponse(html: String) -> Data {
        let body = html.data(using: .utf8) ?? Data()
        let header = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: \(body.count)\r\nConnection: close\r\n\r\n"
        var response = header.data(using: .utf8) ?? Data()
        response.append(body)
        return response
    }

    // MARK: - Build Block Page HTML
    private func buildBlockPage(domain: String) -> String {
        let adminMessage = customBlockMessage.isEmpty
            ? "This website has been blocked by your organization's security policy."
            : customBlockMessage

        return """
        <!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
        <title>Access Blocked - NextGuard DLP</title>
        <style>
        *{margin:0;padding:0;box-sizing:border-box}
        body{font-family:-apple-system,BlinkMacSystemFont,'SF Pro Display',sans-serif;background:#0a0a0f;color:#e0e0e0;display:flex;align-items:center;justify-content:center;min-height:100vh}
        .container{text-align:center;max-width:560px;padding:48px 32px;background:#12121a;border-radius:20px;border:1px solid #ff3b3022;box-shadow:0 0 60px rgba(255,59,48,0.08)}
        .shield{width:80px;height:80px;margin:0 auto 24px;background:linear-gradient(135deg,#1a1a2e,#16213e);border-radius:50%;display:flex;align-items:center;justify-content:center;border:2px solid #ff3b30;box-shadow:0 0 24px rgba(255,59,48,0.3)}
        .shield svg{width:36px;height:36px}
        .brand{font-size:13px;font-weight:600;color:#636366;letter-spacing:2px;text-transform:uppercase;margin-bottom:16px}
        h1{font-size:28px;font-weight:700;color:#ff3b30;margin-bottom:8px}
        .domain{font-size:16px;color:#8e8e93;margin-bottom:24px;font-family:'SF Mono',Monaco,monospace;background:#1c1c2e;padding:8px 16px;border-radius:8px;display:inline-block}
        .message{font-size:15px;line-height:1.6;color:#aeaeb2;margin-bottom:32px;padding:16px;background:#1c1c2e;border-radius:12px;border-left:3px solid #ff9500;text-align:left}
        .footer{font-size:12px;color:#48484a;margin-top:24px}
        .footer span{color:#636366}
        .policy-badge{display:inline-flex;align-items:center;gap:6px;background:#1c1c2e;border:1px solid #2c2c3e;border-radius:20px;padding:6px 14px;font-size:12px;color:#636366;margin-bottom:20px}
        .dot{width:6px;height:6px;border-radius:50%;background:#ff3b30}
        </style></head><body>
        <div class="container">
        <div class="shield"><svg viewBox="0 0 24 24" fill="none" stroke="#ff3b30" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg></div>
        <div class="brand">NextGuard DLP</div>
        <h1>Access Blocked</h1>
        <div class="domain">\(domain)</div>
        <div class="policy-badge"><div class="dot"></div>DNS Filter Policy Active</div>
        <div class="message">\(adminMessage)</div>
        <div class="footer">Protected by <span>NextGuard Endpoint DLP Agent v2.4.0</span><br>Contact your IT administrator if you believe this is an error.</div>
        </div></body></html>
        """
    }
}
