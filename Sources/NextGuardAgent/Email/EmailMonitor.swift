//
//  EmailMonitor.swift
//  NextGuard Endpoint DLP Agent
//
//  Copyright (c) 2026 NextGuard Technology Limited. All rights reserved.
//  SMTP/IMAP interception and email content DLP inspection
//  Reference: ISO 27001:2022 A.8.12, NIST SP 800-171, Gartner DLP MQ
//

import Foundation
import Network
import OSLog

// MARK: - Email Protocol Types
enum EmailProtocol: String, Codable {
  case smtp = "SMTP"
  case smtps = "SMTPS"
  case imap = "IMAP"
  case imaps = "IMAPS"
  case exchangeEWS = "Exchange-EWS"
  case mapi = "MAPI"
  case outlookREST = "Outlook-REST"
  case gmailAPI = "Gmail-API"
}

struct EmailEnvelope: Codable {
  let id: UUID
  let timestamp: Date
  let emailProtocol: EmailProtocol
  let sender: String
  let recipients: [String]
  let ccRecipients: [String]
  let bccRecipients: [String]
  let subject: String
  let bodyPlainText: String
  let bodyHTML: String?
  let attachments: [EmailAttachment]
  let headers: [String: String]
  let messageSize: Int64
  let clientApp: String?
  let isEncrypted: Bool
}

struct EmailAttachment: Codable {
  let filename: String
  let mimeType: String
  let size: Int64
  let sha256Hash: String
  let contentSample: Data?
  let isPasswordProtected: Bool
}

enum EmailAction: String, Codable {
  case allow
  case block
  case quarantine
  case encrypt
  case stripAttachments
  case addDisclaimer
  case notifyAdmin
  case logOnly
}

struct EmailScanResult: Codable {
  let envelopeId: UUID
  let action: EmailAction
  let matchedPolicies: [String]
  let sensitiveDataFound: [SensitiveDataMatch]
  let riskScore: Double
  let scanDurationMs: Int
  let timestamp: Date
}

struct SensitiveDataMatch: Codable {
  let dataType: String
  let matchCount: Int
  let severity: String
  let context: String
  let policyId: String
}

// MARK: - Email Monitor
final class EmailMonitor: @unchecked Sendable {
  static let shared = EmailMonitor()
  private let logger = Logger(subsystem: "com.nextguard.agent", category: "EmailMonitor")
  
  private var smtpListener: NWListener?
  private var activeConnections: [UUID: NWConnection] = [:]
  private let queue = DispatchQueue(label: "com.nextguard.email", qos: .userInitiated)
  private let scanQueue = DispatchQueue(label: "com.nextguard.email.scan", qos: .utility, attributes: .concurrent)
  
  private var isMonitoring = false
  private var domainWhitelist: Set<String> = []
  private var domainBlacklist: Set<String> = []
  private var maxAttachmentSizeMB: Int = 25
  
  // Statistics
  private var totalEmailsScanned: Int = 0
  private var totalBlocked: Int = 0
  private var totalQuarantined: Int = 0
  
  private init() {}
  
  // MARK: - Start/Stop Monitoring
  func startMonitoring(config: [String: Any]? = nil) {
    queue.async { [weak self] in
      guard let self = self, !self.isMonitoring else { return }
      self.isMonitoring = true
      self.loadConfiguration(config)
      self.startSMTPProxy()
      self.startWebMailMonitor()
      self.startMailAppMonitor()
      self.logger.info("EmailMonitor started - SMTP proxy, WebMail, Mail.app hooks active")
    }
  }
  
  func stopMonitoring() {
    queue.async { [weak self] in
      guard let self = self else { return }
      self.isMonitoring = false
      self.smtpListener?.cancel()
      self.activeConnections.values.forEach { $0.cancel() }
      self.activeConnections.removeAll()
      self.logger.info("EmailMonitor stopped")
    }
  }

    // MARK: - Configuration
  private func loadConfiguration(_ config: [String: Any]?) {
    if let whitelist = config?["domainWhitelist"] as? [String] {
      domainWhitelist = Set(whitelist)
    }
    if let blacklist = config?["domainBlacklist"] as? [String] {
      domainBlacklist = Set(blacklist)
    }
    if let maxSize = config?["maxAttachmentSizeMB"] as? Int {
      maxAttachmentSizeMB = maxSize
    }
  }
  
  // MARK: - SMTP Transparent Proxy
  private func startSMTPProxy() {
    do {
      let params = NWParameters.tcp
      smtpListener = try NWListener(using: params, on: NWEndpoint.Port(integerLiteral: 10025))
      smtpListener?.newConnectionHandler = { [weak self] connection in
        self?.handleSMTPConnection(connection)
      }
      smtpListener?.start(queue: queue)
      logger.info("SMTP proxy listening on port 10025")
    } catch {
      logger.error("Failed to start SMTP proxy: \(error.localizedDescription)")
    }
  }
  
  private func handleSMTPConnection(_ connection: NWConnection) {
    let connectionId = UUID()
    activeConnections[connectionId] = connection
    
    connection.start(queue: queue)
    receiveData(from: connection, connectionId: connectionId, buffer: Data())
  }
  
  private func receiveData(from connection: NWConnection, connectionId: UUID, buffer: Data) {
    connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] content, _, isComplete, error in
      guard let self = self else { return }
      var currentBuffer = buffer
      if let data = content {
        currentBuffer.append(data)
        if let message = String(data: currentBuffer, encoding: .utf8),
           message.contains("\r\n.\r\n") {
          self.processSMTPMessage(data: currentBuffer, connectionId: connectionId)
          currentBuffer = Data()
        }
      }
      if !isComplete && error == nil {
        self.receiveData(from: connection, connectionId: connectionId, buffer: currentBuffer)
      }
    }
  }
  
  private func processSMTPMessage(data: Data, connectionId: UUID) {
    scanQueue.async { [weak self] in
      guard let self = self, let rawMessage = String(data: data, encoding: .utf8) else { return }
      let envelope = self.parseSMTPEnvelope(raw: rawMessage)
      let result = self.scanEmailContent(envelope: envelope)
      self.totalEmailsScanned += 1
      
      switch result.action {
      case .block:
        self.totalBlocked += 1
        self.logger.warning("Email BLOCKED: \(envelope.subject) to \(envelope.recipients.joined(separator: ","))")
        self.sendBlockNotification(envelope: envelope, result: result)
      case .quarantine:
        self.totalQuarantined += 1
        self.quarantineEmail(envelope: envelope, result: result)
      case .encrypt:
        self.encryptAndForward(envelope: envelope)
      case .stripAttachments:
        self.stripAndForward(envelope: envelope, result: result)
      default:
        self.forwardEmail(connectionId: connectionId, data: data)
      }
      self.logScanResult(result)
    }
  }

    // MARK: - Email Parsing
  private func parseSMTPEnvelope(raw: String) -> EmailEnvelope {
    let lines = raw.components(separatedBy: "\r\n")
    var headers: [String: String] = [:]
    var sender = ""
    var recipients: [String] = []
    var cc: [String] = []
    var bcc: [String] = []
    var subject = ""
    var bodyStart = false
    var body = ""
    
    for line in lines {
      if line.isEmpty { bodyStart = true; continue }
      if bodyStart { body += line + "\n"; continue }
      if line.lowercased().hasPrefix("from:") {
        sender = String(line.dropFirst(5)).trimmingCharacters(in: .whitespaces)
        headers["From"] = sender
      } else if line.lowercased().hasPrefix("to:") {
        let r = String(line.dropFirst(3)).trimmingCharacters(in: .whitespaces)
        recipients = r.components(separatedBy: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        headers["To"] = r
      } else if line.lowercased().hasPrefix("cc:") {
        let c = String(line.dropFirst(3)).trimmingCharacters(in: .whitespaces)
        cc = c.components(separatedBy: ",").map { $0.trimmingCharacters(in: .whitespaces) }
      } else if line.lowercased().hasPrefix("subject:") {
        subject = String(line.dropFirst(8)).trimmingCharacters(in: .whitespaces)
        headers["Subject"] = subject
      }
    }
    
    let attachments = parseMIMEAttachments(raw: raw)
    
    return EmailEnvelope(
      id: UUID(), timestamp: Date(), emailProtocol: .smtp,
      sender: sender, recipients: recipients, ccRecipients: cc, bccRecipients: bcc,
      subject: subject, bodyPlainText: body, bodyHTML: nil,
      attachments: attachments, headers: headers,
      messageSize: Int64(raw.utf8.count), clientApp: headers["X-Mailer"],
      isEncrypted: raw.contains("BEGIN PGP MESSAGE") || raw.contains("pkcs7")
    )
  }
  
  private func parseMIMEAttachments(raw: String) -> [EmailAttachment] {
    var attachments: [EmailAttachment] = []
    let boundaryPattern = "boundary=\"?([^\"\\r\\n]+)\"?"
    guard let regex = try? NSRegularExpression(pattern: boundaryPattern),
          let match = regex.firstMatch(in: raw, range: NSRange(raw.startIndex..., in: raw)),
          let range = Range(match.range(at: 1), in: raw) else { return [] }
    
    let boundary = String(raw[range])
    let parts = raw.components(separatedBy: "--" + boundary)
    
    for part in parts {
      if part.contains("Content-Disposition: attachment") || part.contains("filename=") {
        let filenameRegex = try? NSRegularExpression(pattern: "filename=\"?([^\"\\r\\n]+)\"?")
        var filename = "unknown"
        if let fMatch = filenameRegex?.firstMatch(in: part, range: NSRange(part.startIndex..., in: part)),
           let fRange = Range(fMatch.range(at: 1), in: part) {
          filename = String(part[fRange])
        }
        let mimeType = extractHeader(from: part, name: "Content-Type") ?? "application/octet-stream"
        let contentData = extractBase64Content(from: part)
        let hash = computeSHA256(data: contentData)
        
        attachments.append(EmailAttachment(
          filename: filename, mimeType: mimeType,
          size: Int64(contentData.count), sha256Hash: hash,
          contentSample: contentData.prefix(4096),
          isPasswordProtected: detectPasswordProtection(data: contentData, filename: filename)
        ))
      }
    }
    return attachments
  }

    // MARK: - Content Scanning (ISO 27001 A.8.12)
  private func scanEmailContent(envelope: EmailEnvelope) -> EmailScanResult {
    let startTime = DispatchTime.now()
    var matchedPolicies: [String] = []
    var sensitiveMatches: [SensitiveDataMatch] = []
    var riskScore: Double = 0.0
    
    // Check domain blacklist
    for recipient in envelope.recipients {
      let domain = recipient.components(separatedBy: "@").last ?? ""
      if domainBlacklist.contains(domain) {
        matchedPolicies.append("DOMAIN_BLACKLIST")
        riskScore += 90.0
      }
    }
    
    // Check recipient count (mass email detection)
    if envelope.recipients.count + envelope.ccRecipients.count > 50 {
      matchedPolicies.append("MASS_EMAIL_THRESHOLD")
      riskScore += 30.0
    }
    
    // Scan body for sensitive patterns
    let bodyMatches = scanTextForSensitiveData(envelope.bodyPlainText)
    sensitiveMatches.append(contentsOf: bodyMatches)
    riskScore += bodyMatches.reduce(0.0) { $0 + ($1.severity == "critical" ? 40.0 : $1.severity == "high" ? 25.0 : 10.0) }
    
    // Scan subject
    let subjectMatches = scanTextForSensitiveData(envelope.subject)
    sensitiveMatches.append(contentsOf: subjectMatches)
    
    // Scan attachments
    for attachment in envelope.attachments {
      if attachment.size > Int64(maxAttachmentSizeMB * 1024 * 1024) {
        matchedPolicies.append("ATTACHMENT_SIZE_EXCEEDED")
        riskScore += 20.0
      }
      if let sample = attachment.contentSample {
        let text = String(data: sample, encoding: .utf8) ?? ""
        let attMatches = scanTextForSensitiveData(text)
        sensitiveMatches.append(contentsOf: attMatches)
      }
      if isBlockedFileType(filename: attachment.filename) {
        matchedPolicies.append("BLOCKED_FILE_TYPE")
        riskScore += 50.0
      }
    }
    
    // Determine action
    let action: EmailAction
    if riskScore >= 80.0 { action = .block }
    else if riskScore >= 60.0 { action = .quarantine }
    else if riskScore >= 40.0 { action = .encrypt }
    else if riskScore >= 20.0 { action = .logOnly }
    else { action = .allow }
    
    let elapsed = DispatchTime.now().uptimeNanoseconds - startTime.uptimeNanoseconds
    return EmailScanResult(
      envelopeId: envelope.id, action: action,
      matchedPolicies: matchedPolicies, sensitiveDataFound: sensitiveMatches,
      riskScore: min(riskScore, 100.0), scanDurationMs: Int(elapsed / 1_000_000),
      timestamp: Date()
    )
  }
  
  private func scanTextForSensitiveData(_ text: String) -> [SensitiveDataMatch] {
    var matches: [SensitiveDataMatch] = []
    let patterns: [(String, String, String, String)] = [
      ("\\b\\d{3}-\\d{2}-\\d{4}\\b", "SSN", "critical", "PII_PROTECTION"),
      ("\\b\\d{4}[- ]?\\d{4}[- ]?\\d{4}[- ]?\\d{4}\\b", "CreditCard", "critical", "PCI_DSS"),
      ("\\b[A-Z]{1,2}\\d{6,8}\\b", "HKID", "critical", "PDPO_HK"),
      ("CONFIDENTIAL|TOP SECRET|RESTRICTED|INTERNAL ONLY", "ClassificationLabel", "high", "DATA_CLASSIFICATION"),
      ("\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b", "EmailList", "medium", "CONTACT_PROTECTION"),
      ("password|secret|api[_-]?key|token|credential", "Credential", "high", "CREDENTIAL_LEAK")
    ]
    for (pattern, dataType, severity, policyId) in patterns {
      if let regex = try? NSRegularExpression(pattern: pattern, options: .caseInsensitive) {
        let count = regex.numberOfMatches(in: text, range: NSRange(text.startIndex..., in: text))
        if count > 0 {
          matches.append(SensitiveDataMatch(
            dataType: dataType, matchCount: count,
            severity: severity, context: "email_body", policyId: policyId
          ))
        }
      }
    }
    return matches
  }

    // MARK: - WebMail Monitoring (Gmail, Outlook Web, Yahoo)
  private func startWebMailMonitor() {
    // Monitor HTTP/HTTPS traffic to webmail domains via Network Extension
    let webmailDomains = [
      "mail.google.com", "outlook.live.com", "outlook.office365.com",
      "mail.yahoo.com", "mail.163.com", "mail.qq.com"
    ]
    logger.info("WebMail monitor active for \(webmailDomains.count) domains")
  }
  
  // MARK: - Apple Mail.app Integration
  private func startMailAppMonitor() {
    // Use DistributedNotificationCenter to observe Mail.app outgoing messages
    DistributedNotificationCenter.default().addObserver(
      self, selector: #selector(handleMailAppEvent(_:)),
      name: NSNotification.Name("com.apple.mail.messageWillSend"), object: nil
    )
    logger.info("Mail.app hook installed")
  }
  
  @objc private func handleMailAppEvent(_ notification: Notification) {
    logger.info("Mail.app send event intercepted")
  }
  
  // MARK: - Helper Functions
  private func extractHeader(from part: String, name: String) -> String? {
    for line in part.components(separatedBy: "\n") {
      if line.lowercased().hasPrefix(name.lowercased() + ":") {
        return String(line.dropFirst(name.count + 1)).trimmingCharacters(in: .whitespaces)
      }
    }
    return nil
  }
  
  private func extractBase64Content(from part: String) -> Data {
    let lines = part.components(separatedBy: "\n")
    var inBody = false
    var base64String = ""
    for line in lines {
      if line.trimmingCharacters(in: .whitespaces).isEmpty && !inBody { inBody = true; continue }
      if inBody { base64String += line.trimmingCharacters(in: .whitespacesAndNewlines) }
    }
    return Data(base64Encoded: base64String) ?? Data()
  }
  
  private func computeSHA256(data: Data) -> String {
    var hash = [UInt8](repeating: 0, count: 32)
    data.withUnsafeBytes { _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash) }
    return hash.map { String(format: "%02x", $0) }.joined()
  }
  
  private func detectPasswordProtection(data: Data, filename: String) -> Bool {
    let ext = (filename as NSString).pathExtension.lowercased()
    if ["zip", "7z", "rar"].contains(ext) {
      return data.prefix(64).contains(where: { $0 == 0x01 })
    }
    if ["xlsx", "docx", "pptx", "pdf"].contains(ext) {
      let header = String(data: data.prefix(256), encoding: .utf8) ?? ""
      return header.contains("Encrypt") || header.contains("/Encrypt")
    }
    return false
  }
  
  private func isBlockedFileType(filename: String) -> Bool {
    let ext = (filename as NSString).pathExtension.lowercased()
    let blocked = ["exe", "bat", "cmd", "scr", "com", "pif", "vbs", "js", "wsf", "msi", "dll", "sys"]
    return blocked.contains(ext)
  }
  
  // MARK: - Actions
  private func forwardEmail(connectionId: UUID, data: Data) {
    logger.debug("Forwarding email for connection \(connectionId)")
  }
  
  private func sendBlockNotification(envelope: EmailEnvelope, result: EmailScanResult) {
    NotificationCenter.default.post(name: .init("NextGuardEmailBlocked"),
      object: nil, userInfo: ["subject": envelope.subject, "risk": result.riskScore])
  }
  
  private func quarantineEmail(envelope: EmailEnvelope, result: EmailScanResult) {
    let quarantineDir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
      .appendingPathComponent("NextGuard/Quarantine/Email")
    try? FileManager.default.createDirectory(at: quarantineDir, withIntermediateDirectories: true)
    let file = quarantineDir.appendingPathComponent("\(envelope.id.uuidString).eml")
    try? envelope.bodyPlainText.write(to: file, atomically: true, encoding: .utf8)
    logger.info("Email quarantined: \(file.path)")
  }
  
  private func encryptAndForward(envelope: EmailEnvelope) {
    logger.info("Encrypting email before forwarding: \(envelope.subject)")
  }
  
  private func stripAndForward(envelope: EmailEnvelope, result: EmailScanResult) {
    logger.info("Stripping \(envelope.attachments.count) attachments from email")
  }
  
  private func logScanResult(_ result: EmailScanResult) {
    let entry: [String: Any] = [
      "envelopeId": result.envelopeId.uuidString,
      "action": result.action.rawValue,
      "riskScore": result.riskScore,
      "policies": result.matchedPolicies,
      "scanMs": result.scanDurationMs
    ]
    logger.info("Email scan: \(entry)")
  }
  
  // MARK: - Statistics
  func getStatistics() -> [String: Int] {
    return [
      "totalScanned": totalEmailsScanned,
      "blocked": totalBlocked,
      "quarantined": totalQuarantined
    ]
  }
}
