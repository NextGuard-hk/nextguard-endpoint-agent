//
// BlockPageServer.swift
// NextGuard Endpoint DLP Agent
//
// Listens on BOTH port 80 (HTTP) and port 8080 (HTTP fallback).
// For HTTPS blocked sites: /etc/hosts redirects the domain to 127.0.0.1,
// browser hits port 80 first (for http://) or gets a connection refused
// for https:// (port 443 needs a TLS cert - handled separately).
// Custom message stored in /tmp/nextguard_block_message.txt
//
import Foundation
import Network
import OSLog

final class BlockPageServer: @unchecked Sendable {
    static let shared = BlockPageServer()
    private let logger = Logger(subsystem: "com.nextguard.agent", category: "BlockPageServer")
    private var listener80: NWListener?
    private var listener8080: NWListener?
    private let queue = DispatchQueue(label: "com.nextguard.blockpage", qos: .background)

    // Shared file - readable/writable by root process AND user UI process
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
        startListener(port: 80, store: &listener80)
        startListener(port: 8080, store: &listener8080)
    }

    private func startListener(port: UInt16, store: inout NWListener?) {
        do {
            let params = NWParameters.tcp
            let nwPort = NWEndpoint.Port(rawValue: port)!
            let listener = try NWListener(using: params, on: nwPort)
            listener.newConnectionHandler = { [weak self] connection in
                self?.handleConnection(connection)
            }
            listener.stateUpdateHandler = { [weak self] state in
                switch state {
                case .ready:
                    self?.logger.info("BlockPageServer listening on :\(port)")
                case .failed(let error):
                    self?.logger.warning("BlockPageServer port \(port) failed: \(error.localizedDescription)")
                default: break
                }
            }
            listener.start(queue: queue)
            store = listener
        } catch {
            logger.warning("BlockPageServer: cannot bind port \(port): \(error.localizedDescription)")
        }
    }

    // MARK: - Stop
    func stop() {
        listener80?.cancel()
        listener80 = nil
        listener8080?.cancel()
        listener8080 = nil
    }

    // MARK: - Handle Connection
    private func handleConnection(_ connection: NWConnection) {
        connection.start(queue: queue)
        connection.receive(minimumIncompleteLength: 1, maximumLength: 4096) { [weak self] data, _, _, _ in
            guard let self else { connection.cancel(); return }
            let request = data.flatMap { String(data: $0, encoding: .utf8) } ?? ""
            let domain = self.extractHost(from: request) ?? "this website"
            let html = self.buildBlockPage(domain: domain)
            let response = self.buildHTTPResponse(html: html)
            connection.send(content: response, completion: .contentProcessed { _ in
                connection.cancel()
            })
        }
    }

    // MARK: - Extract Host
    private func extractHost(from request: String) -> String? {
        for line in request.components(separatedBy: "\r\n") {
            if line.lowercased().hasPrefix("host:") {
                return line.dropFirst(5).trimmingCharacters(in: .whitespaces)
                    .components(separatedBy: ":").first
            }
        }
        return nil
    }

    // MARK: - HTTP Response
    private func buildHTTPResponse(html: String) -> Data {
        let body = html.data(using: .utf8) ?? Data()
        let header = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: \(body.count)\r\nConnection: close\r\n\r\n"
        var r = header.data(using: .utf8) ?? Data()
        r.append(body)
        return r
    }

    // MARK: - Block Page HTML
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
        <meta http-equiv="refresh" content="0">
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
