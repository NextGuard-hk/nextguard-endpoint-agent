//
// BlockPageServer.swift
// NextGuard Endpoint DLP Agent
//
// Uses raw POSIX sockets (not NWListener which silently fails to bind on some macOS configs)
// NWListener silently fails to bind on some macOS configurations
// Custom message stored in /tmp/nextguard_block_message
//

import Foundation
import OSLog
import Darwin
import Security

final class BlockPageServer: @unchecked Sendable {
    static let shared = BlockPageServer()
    private let logger = Logger(subsystem: "com.nextguard.agent", category: "BlockPageServer")
    private var isRunning = false
    private let messagePath = "/tmp/nextguard_block_message"
    private let certCachePath = "/tmp/nextguard_certs"

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
        // Ensure cert cache directory exists
        try? FileManager.default.createDirectory(atPath: certCachePath, withIntermediateDirectories: true)
        // Start HTTP on port 80
        Thread.detachNewThread { self.runServer(port: 80, tls: false) }
        // Start HTTPS on port 443
        Thread.detachNewThread { self.runServer(port: 443, tls: true) }
    }

    func stop() { isRunning = false }

    // MARK: - Generate per-domain cert signed by Root CA
    private func generateCert(forDomain domain: String) -> (String, String)? {
        let safeDomain = domain.replacingOccurrences(of: "*", with: "wildcard")
        let domainKey = "\(certCachePath)/\(safeDomain).key"
        let domainCert = "\(certCachePath)/\(safeDomain).pem"
        if FileManager.default.fileExists(atPath: domainCert),
           FileManager.default.fileExists(atPath: domainKey) {
            return (domainCert, domainKey)
        }
        guard FileManager.default.fileExists(atPath: "\(certCachePath)/rootCA.pem"),
              FileManager.default.fileExists(atPath: "\(certCachePath)/rootCA.key") else {
            logger.error("BlockPageServer: Root CA not found. Run setup-ca.sh first.")
            return nil
        }

        // Generate domain key
        let genKey = Process()
        genKey.launchPath = "/usr/bin/openssl"
        genKey.arguments = ["genrsa", "-out", domainKey, "2048"]
        genKey.standardOutput = FileHandle.nullDevice
        genKey.standardError = FileHandle.nullDevice
        try? genKey.run(); genKey.waitUntilExit()

        // Create CSR
        let csrPath = "\(certCachePath)/\(safeDomain).csr"
        let genCSR = Process()
        genCSR.launchPath = "/usr/bin/openssl"
        genCSR.arguments = ["req", "-new", "-key", domainKey, "-out", csrPath, "-subj", "/CN=\(domain)"]
        genCSR.standardOutput = FileHandle.nullDevice
        genCSR.standardError = FileHandle.nullDevice
        try? genCSR.run(); genCSR.waitUntilExit()

        // Create SAN extension file
        let extPath = "\(certCachePath)/\(safeDomain).ext"
        let extContent = "authorityKeyIdentifier=keyid,issuer\nbasicConstraints=CA:FALSE\nsubjectAltName=DNS:\(domain)\n"
        try? extContent.write(toFile: extPath, atomically: true, encoding: .utf8)

        // Sign with Root CA
        let signCert = Process()
        signCert.launchPath = "/usr/bin/openssl"
        signCert.arguments = [
            "x509", "-req", "-in", csrPath,
            "-CA", "\(certCachePath)/rootCA.pem",
            "-CAkey", "\(certCachePath)/rootCA.key",
            "-CAcreateserial",
            "-out", domainCert,
            "-days", "365",
            "-sha256",
            "-extfile", extPath
        ]
        signCert.standardOutput = FileHandle.nullDevice
        signCert.standardError = FileHandle.nullDevice
        try? signCert.run(); signCert.waitUntilExit()

        if FileManager.default.fileExists(atPath: domainCert) {
            return (domainCert, domainKey)
        }
        return nil
    }

    // MARK: - Run POSIX Socket Server
    private func runServer(port: UInt16, tls: Bool) {
        let serverFd = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        guard serverFd >= 0 else { return }
        defer { Darwin.close(serverFd) }
        var yes: Int32 = 1
        setsockopt(serverFd, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))
        setsockopt(serverFd, SOL_SOCKET, SO_REUSEPORT, &yes, socklen_t(MemoryLayout<Int32>.size))
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        addr.sin_zero = (0,0,0,0,0,0,0,0)
        let ok = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(serverFd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }

        guard ok == 0 else {
            logger.error("BlockPageServer: bind failed on port \(port): \(String(cString: strerror(errno)))")
            return
        }
        guard listen(serverFd, 10) == 0 else { return }
        print("[BlockPageServer] Listening on 127.0.0.1:\(port) tls=\(tls)")
        while isRunning {
            var ca = sockaddr_in()
            var cl = socklen_t(MemoryLayout<sockaddr_in>.size)
            let cfd = withUnsafeMutablePointer(to: &ca) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    accept(serverFd, $0, &cl)
                }
            }
            guard cfd >= 0 else { continue }
            if tls {
                Thread.detachNewThread { self.handleTLSClient(cfd) }
            } else {
                Thread.detachNewThread { self.handleHTTPClient(cfd) }
            }
        }
    }

    // MARK: - Handle TLS Client (HTTPS)
    private func handleTLSClient(_ cfd: Int32) {
        defer { Darwin.close(cfd) }

        // Read ClientHello to extract SNI (Server Name Indication)
        var buf = [UInt8](repeating: 0, count: 8192)
        let n = Darwin.read(cfd, &buf, buf.count)
        guard n > 5 else { return }

        let domain = extractSNI(from: buf, length: n) ?? "blocked.site"
        logger.info("BlockPageServer TLS: SNI=\(domain)")

        // Generate per-domain cert
        guard let (certPath, keyPath) = generateCert(forDomain: domain) else {
            // Fallback: send HTTP block page without TLS
            let html = buildBlockPage(domain: domain)
            let resp = buildHTTPResponse(html: html)
            _ = resp.withUnsafeBytes { Darwin.write(cfd, $0.baseAddress!, resp.count) }
            return
        }

        // Use openssl s_server style: spawn openssl s_client to do TLS handshake
        // Alternative: use Security.framework SecIdentity - but openssl is simpler
        // We use a pipe-based approach: create a connected socket pair, 
        // spawn openssl s_server on one end, forward data on the other
        
        // For simplicity and reliability, use Security.framework SSLContext
        // (deprecated but still functional on macOS 14)
        handleTLSWithSecFramework(cfd: cfd, certPath: certPath, keyPath: keyPath, domain: domain)
    }

    // MARK: - TLS via Security.framework
    private func handleTLSWithSecFramework(cfd: Int32, certPath: String, keyPath: String, domain: String) {
        // Read the PKCS12 or use SecIdentity from PEM files
        // Convert PEM cert+key to PKCS12 for import
        let p12Path = certPath.replacingOccurrences(of: ".pem", with: ".p12")
        if !FileManager.default.fileExists(atPath: p12Path) {
            let convert = Process()
            convert.launchPath = "/usr/bin/openssl"
            convert.arguments = ["pkcs12", "-export", "-out", p12Path,
                                 "-inkey", keyPath, "-in", certPath,
                                 "-passout", "pass:nextguard"]
            convert.standardOutput = FileHandle.nullDevice
            convert.standardError = FileHandle.nullDevice
            try? convert.run(); convert.waitUntilExit()
        }

        guard let p12Data = try? Data(contentsOf: URL(fileURLWithPath: p12Path)) else {
            sendPlainBlockPage(cfd: cfd, domain: domain)
            return
        }

        let options: [String: Any] = [kSecImportExportPassphrase as String: "nextguard"]
        var items: CFArray?
        let status = SecPKCS12Import(p12Data as CFData, options as CFDictionary, &items)
        guard status == errSecSuccess,
              let itemArray = items as? [[String: Any]],
              let firstItem = itemArray.first,
              let identity = firstItem[kSecImportItemIdentity as String] else {
            sendPlainBlockPage(cfd: cfd, domain: domain)
            return
        }

        let secIdentity = identity as! SecIdentity
        var certRef: SecCertificate?
        SecIdentityCopyCertificate(secIdentity, &certRef)

        guard let sslContext = SSLCreateContext(nil, .serverSide, .streamType) else {
            sendPlainBlockPage(cfd: cfd, domain: domain)
            return
        }
        defer { /* context is ARC managed */ }

        let certs = certRef.map { [secIdentity, $0] as CFArray } ?? [secIdentity] as CFArray
        SSLSetCertificate(sslContext, certs)

        // Set I/O callbacks using the raw fd
        var fdCopy = cfd
        SSLSetIOFuncs(sslContext, BlockPageServer.sslReadCallback, BlockPageServer.sslWriteCallback)
        SSLSetConnection(sslContext, UnsafeMutableRawPointer(bitPattern: Int(cfd)))

        // Perform TLS handshake
        var handshakeResult = SSLHandshake(sslContext)
        while handshakeResult == errSSLWouldBlock {
            handshakeResult = SSLHandshake(sslContext)
        }
        guard handshakeResult == errSecSuccess else {
            logger.error("BlockPageServer: TLS handshake failed for \(domain): \(handshakeResult)")
            sendPlainBlockPage(cfd: cfd, domain: domain)
            return
        }

        // Read HTTP request over TLS
        var reqBuf = [UInt8](repeating: 0, count: 4096)
        var bytesRead: Int = 0
        SSLRead(sslContext, &reqBuf, reqBuf.count, &bytesRead)

        // Send block page response over TLS
        let html = buildBlockPage(domain: domain)
        let response = buildHTTPResponse(html: html)
        var bytesWritten: Int = 0
        response.withUnsafeBytes { ptr in
            SSLWrite(sslContext, ptr.baseAddress!, response.count, &bytesWritten)
        }

        SSLClose(sslContext)
    }

    // MARK: - SSL I/O Callbacks
    private static let sslReadCallback: SSLReadFunc = { connection, data, dataLength in
        let fd = Int32(Int(bitPattern: connection))
        let bytesRead = Darwin.read(fd, data, dataLength.pointee)
        if bytesRead > 0 {
            dataLength.pointee = bytesRead
            return errSecSuccess
        } else if bytesRead == 0 {
            dataLength.pointee = 0
            return errSSLClosedGraceful
        } else {
            dataLength.pointee = 0
            return errSSLClosedAbort
        }
    }

    private static let sslWriteCallback: SSLWriteFunc = { connection, data, dataLength in
        let fd = Int32(Int(bitPattern: connection))
        let bytesWritten = Darwin.write(fd, data, dataLength.pointee)
        if bytesWritten > 0 {
            dataLength.pointee = bytesWritten
            return errSecSuccess
        } else {
            dataLength.pointee = 0
            return errSSLClosedAbort
        }
    }

    // MARK: - Send plain HTTP block page (fallback)
    private func sendPlainBlockPage(cfd: Int32, domain: String) {
        let html = buildBlockPage(domain: domain)
        let resp = buildHTTPResponse(html: html)
        _ = resp.withUnsafeBytes { Darwin.write(cfd, $0.baseAddress!, resp.count) }
    }

    // MARK: - Extract SNI from TLS ClientHello
    private func extractSNI(from data: [UInt8], length: Int) -> String? {
        // TLS record: type(1) + version(2) + length(2) + handshake
        guard length > 5, data[0] == 0x16 else { return nil } // 0x16 = Handshake
        let hsStart = 5
        guard hsStart < length, data[hsStart] == 0x01 else { return nil } // ClientHello
        // Skip: handshake type(1) + length(3) + client version(2) + random(32)
        var pos = hsStart + 1 + 3 + 2 + 32
        guard pos < length else { return nil }
        // Session ID
        let sessionIdLen = Int(data[pos])
        pos += 1 + sessionIdLen
        guard pos + 2 <= length else { return nil }
        // Cipher suites
        let cipherLen = Int(data[pos]) << 8 | Int(data[pos+1])
        pos += 2 + cipherLen
        guard pos + 1 <= length else { return nil }
        // Compression methods
        let compLen = Int(data[pos])
        pos += 1 + compLen
        guard pos + 2 <= length else { return nil }
        // Extensions
        let extTotalLen = Int(data[pos]) << 8 | Int(data[pos+1])
        pos += 2
        let extEnd = min(pos + extTotalLen, length)
        while pos + 4 <= extEnd {
            let extType = Int(data[pos]) << 8 | Int(data[pos+1])
            let extLen = Int(data[pos+2]) << 8 | Int(data[pos+3])
            pos += 4
            if extType == 0 { // SNI extension
                guard pos + 5 <= extEnd else { break }
                let nameListLen = Int(data[pos]) << 8 | Int(data[pos+1])
                let nameType = data[pos+2]
                let nameLen = Int(data[pos+3]) << 8 | Int(data[pos+4])
                if nameType == 0, pos + 5 + nameLen <= extEnd {
                    return String(bytes: data[(pos+5)..<(pos+5+nameLen)], encoding: .utf8)
                }
            }
            pos += extLen
        }
        return nil
    }

    // MARK: - Handle plain HTTP Client
    private func handleHTTPClient(_ cfd: Int32) {
        defer { Darwin.close(cfd) }
        var buf = [UInt8](repeating: 0, count: 4096)
        let n = Darwin.read(cfd, &buf, buf.count)
        guard n > 0 else { return }
        let request = String(bytes: buf[0..<n], encoding: .utf8) ?? ""
        let domain = extractHost(from: request) ?? "this website"
        let html = buildBlockPage(domain: domain)
        let resp = buildHTTPResponse(html: html)
        _ = resp.withUnsafeBytes { Darwin.write(cfd, $0.baseAddress!, resp.count) }
    }

    // MARK: - Extract Host from HTTP request
    private func extractHost(from request: String) -> String? {
        let lines = request.components(separatedBy: "\r\n")
        for line in lines {
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
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Access Blocked - NextGuard DLP</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body {
                    font-family: -apple-system, BlinkMacSystemFont, 'SF Pro Display', sans-serif;
                    background: #0a0a0f;
                    color: #e0e0e0;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    min-height: 100vh;
                }
                .container {
                    text-align: center;
                    max-width: 560px;
                    padding: 48px 32px;
                    background: #12121a;
                    border-radius: 20px;
                    border: 1px solid #ff3b3022;
                    box-shadow: 0 0 60px rgba(255,59,48,0.08);
                }
                .shield {
                    width: 80px; height: 80px;
                    margin: 0 auto 24px;
                    background: linear-gradient(135deg, #1a1a2e, #16213e);
                    border-radius: 50%;
                    display: flex; align-items: center; justify-content: center;
                    border: 2px solid #ff3b30;
                    box-shadow: 0 0 24px rgba(255,59,48,0.3);
                }
                .shield svg { width: 36px; height: 36px; }
                .brand { font-size: 13px; font-weight: 600; color: #636366; letter-spacing: 2px; text-transform: uppercase; margin-bottom: 16px; }
                h1 { font-size: 28px; font-weight: 700; color: #ff3b30; margin-bottom: 8px; }
                .domain { font-size: 16px; color: #8e8e93; margin-bottom: 24px; font-family: 'SF Mono', Monaco, monospace; background: #1c1c2e; padding: 8px 16px; border-radius: 8px; display: inline-block; }
                .message { font-size: 15px; line-height: 1.6; color: #aeaeb2; margin-bottom: 32px; padding: 16px; background: #1c1c2e; border-radius: 12px; border-left: 3px solid #ff9500; text-align: left; }
                .footer { font-size: 12px; color: #48484a; margin-top: 24px; }
                .footer span { color: #636366; }
                .policy-badge { display: inline-flex; align-items: center; gap: 6px; background: #1c1c2e; border: 1px solid #2c2c3e; border-radius: 20px; padding: 6px 14px; font-size: 12px; color: #636366; margin-bottom: 20px; }
                .dot { width: 6px; height: 6px; border-radius: 50%; background: #ff3b30; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="shield">
                    <svg viewBox="0 0 24 24" fill="none" stroke="#ff3b30" stroke-width="2">
                        <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z"/>
                        <line x1="12" y1="8" x2="12" y2="12"/>
                        <line x1="12" y1="16" x2="12.01" y2="16"/>
                    </svg>
                </div>
                <div class="brand">NextGuard DLP</div>
                <h1>Access Blocked</h1>
                <div class="domain">\(domain)</div>
                <div class="policy-badge"><div class="dot"></div>DNS Filter Policy Active</div>
                <div class="message">\(adminMessage)</div>
                <div class="footer">
                    Protected by <span>NextGuard Endpoint DLP Agent v2.4.0</span><br>
                    Contact your IT administrator if you believe this is an error.
                </div>
            </div>
        </body>
        </html>
        """
    }
}
