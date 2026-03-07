//
// BlockPageServer.swift
// NextGuard Endpoint DLP Agent
//
// Uses raw POSIX sockets (not NWListener) to reliably bind port 80 and 8080.
// NWListener silently fails to bind on macOS even as root - POSIX sockets work.
// Custom message stored in /tmp/nextguard_block_message.txt
//
import Foundation
import OSLog
import Darwin

final class BlockPageServer: @unchecked Sendable {
    static let shared = BlockPageServer()
    private let logger = Logger(subsystem: "com.nextguard.agent", category: "BlockPageServer")
    private var isRunning = false
    private let messagePath = "/tmp/nextguard_block_message.txt"

    // MARK: - Custom Block Message
    var customBlockMessage: String {
        get {
            let raw = (try? String(contentsOfFile: messagePath, encoding: .utf8)) ?? ""
            return raw.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        set {
            try? newValue.write(toFile: messagePath, atomically: true, encoding: .utf8)
            chmod(messagePath, 0o666)
        }
    }

    private init() {}

    // MARK: - Start
    func start() {
        guard !isRunning else { return }
        isRunning = true
        // Start on both port 80 and 8080
        Thread.detachNewThread { self.runServer(port: 80) }
        Thread.detachNewThread { self.runServer(port: 8080) }
    }

    // MARK: - Stop
    func stop() {
        isRunning = false
    }

    // MARK: - POSIX Socket Server
    private func runServer(port: UInt16) {
        // Create TCP socket
        let serverFd = socket(AF_INET, SOCK_STREAM, 0)
        guard serverFd >= 0 else {
            logger.error("BlockPageServer: socket() failed for port \(port)")
            return
        }
        defer { Darwin.close(serverFd) }

        // Allow reuse of port immediately after restart
        var yes: Int32 = 1
        setsockopt(serverFd, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))
        setsockopt(serverFd, SOL_SOCKET, SO_REUSEPORT, &yes, socklen_t(MemoryLayout<Int32>.size))

        // Bind to 127.0.0.1:port
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
            logger.error("BlockPageServer: bind() failed port \(port): \(String(cString: strerror(errno)))")
            return
        }

        guard listen(serverFd, 10) == 0 else {
            logger.error("BlockPageServer: listen() failed port \(port)")
            return
        }

        logger.info("BlockPageServer: listening on 127.0.0.1:\(port) via POSIX socket")
        print("[BlockPageServer] Listening on port \(port)")

        while isRunning {
            var clientAddr = sockaddr_in()
            var clientAddrLen = socklen_t(MemoryLayout<sockaddr_in>.size)
            let clientFd = withUnsafeMutablePointer(to: &clientAddr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    accept(serverFd, $0, &clientAddrLen)
                }
            }
            guard clientFd >= 0 else { continue }
            // Handle each connection in a new thread
            Thread.detachNewThread {
                self.handleClient(fd: clientFd)
            }
        }
    }

    private func handleClient(fd: Int32) {
        defer { Darwin.close(fd) }

        // Read HTTP request
        var buf = [UInt8](repeating: 0, count: 4096)
        let n = recv(fd, &buf, buf.count - 1, 0)
        guard n > 0 else { return }
        let request = String(bytes: buf.prefix(Int(n)), encoding: .utf8) ?? ""
        let domain = extractHost(from: request) ?? "this website"

        // Send HTTP response with block page
        let html = buildBlockPage(domain: domain)
        let body = html.data(using: .utf8) ?? Data()
        let header = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: \(body.count)\r\nConnection: close\r\n\r\n"
        var response = (header.data(using: .utf8) ?? Data()) + body
        response.withUnsafeBytes { ptr in
            _ = send(fd, ptr.baseAddress!, response.count, 0)
        }
    }

    private func extractHost(from request: String) -> String? {
        for line in request.components(separatedBy: "\r\n") {
            if line.lowercased().hasPrefix("host:") {
                return line.dropFirst(5).trimmingCharacters(in: .whitespaces)
                    .components(separatedBy: ":").first
            }
        }
        return nil
    }

    private func buildBlockPage(domain: String) -> String {
        let msg = customBlockMessage.isEmpty
            ? "This website has been blocked by your organization\u{2019}s security policy."
            : customBlockMessage
        return """
        <!DOCTYPE html>
        <html lang="en">
        <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Access Blocked - NextGuard DLP</title>
        <style>
        *{margin:0;padding:0;box-sizing:border-box}
        body{font-family:-apple-system,BlinkMacSystemFont,'SF Pro Display',sans-serif;background:#0a0a0f;color:#e0e0e0;display:flex;align-items:center;justify-content:center;min-height:100vh}
        .container{text-align:center;max-width:560px;padding:48px 32px;background:#12121a;border-radius:20px;border:1px solid #ff3b3022;box-shadow:0 0 60px rgba(255,59,48,.08)}
        .shield{width:80px;height:80px;margin:0 auto 24px;background:linear-gradient(135deg,#1a1a2e,#16213e);border-radius:50%;display:flex;align-items:center;justify-content:center;border:2px solid #ff3b30;box-shadow:0 0 24px rgba(255,59,48,.3)}
        .shield svg{width:36px;height:36px}
        .brand{font-size:13px;font-weight:600;color:#636366;letter-spacing:2px;text-transform:uppercase;margin-bottom:16px}
        h1{font-size:28px;font-weight:700;color:#ff3b30;margin-bottom:8px}
        .domain{font-size:16px;color:#8e8e93;margin-bottom:24px;font-family:'SF Mono',Monaco,monospace;background:#1c1c2e;padding:8px 16px;border-radius:8px;display:inline-block}
        .message{font-size:15px;line-height:1.6;color:#aeaeb2;margin-bottom:32px;padding:16px;background:#1c1c2e;border-radius:12px;border-left:3px solid #ff9500;text-align:left}
        .footer{font-size:12px;color:#48484a;margin-top:24px}
        .footer span{color:#636366}
        .badge{display:inline-flex;align-items:center;gap:6px;background:#1c1c2e;border:1px solid #2c2c3e;border-radius:20px;padding:6px 14px;font-size:12px;color:#636366;margin-bottom:20px}
        .dot{width:6px;height:6px;border-radius:50%;background:#ff3b30}
        </style>
        </head>
        <body>
        <div class="container">
            <div class="shield"><svg viewBox="0 0 24 24" fill="none" stroke="#ff3b30" stroke-width="2"><path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg></div>
            <div class="brand">NextGuard DLP</div>
            <h1>Access Blocked</h1>
            <div class="domain">\(domain)</div>
            <div class="badge"><div class="dot"></div>DNS Filter Policy Active</div>
            <div class="message">\(msg)</div>
            <div class="footer">Protected by <span>NextGuard Endpoint DLP Agent v2.4.0</span><br>Contact your IT administrator if you believe this is an error.</div>
        </div>
        </body>
        </html>
        """
    }
}
