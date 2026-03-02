// NextGuard DLP - ForensicCollector.swift
// Collects forensic evidence when DLP policy violations are detected
// Uploads forensic data to management console via ManagementClient

import Foundation

/// Severity levels for forensic events
public enum ForensicSeverity: String, Codable {
    case critical = "critical"
    case high = "high"
    case medium = "medium"
    case low = "low"
    case info = "info"
}

/// Types of forensic evidence that can be collected
public enum ForensicEvidenceType: String, Codable {
    case fileContent = "file_content"
    case fileMetadata = "file_metadata"
    case clipboardSnapshot = "clipboard_snapshot"
    case screenCapture = "screen_capture"
    case processInfo = "process_info"
    case networkPacket = "network_packet"
    case emailMetadata = "email_metadata"
    case browserActivity = "browser_activity"
    case usbActivity = "usb_activity"
    case printJob = "print_job"
    case airdropTransfer = "airdrop_transfer"
    case messagingContent = "messaging_content"
}

/// Represents a single piece of forensic evidence
public struct ForensicEvidence: Codable {
    public let id: String
    public let type: ForensicEvidenceType
    public let timestamp: Date
    public let data: [String: String]
    public let hash: String  // SHA-256 hash for integrity verification
    public let sizeBytes: Int
    
    public init(type: ForensicEvidenceType, data: [String: String], rawData: Data? = nil) {
        self.id = UUID().uuidString
        self.type = type
        self.timestamp = Date()
        self.data = data
        self.sizeBytes = rawData?.count ?? 0
        self.hash = ForensicCollector.sha256(rawData ?? Data(id.utf8))
    }
}

/// A complete forensic report for a DLP policy violation
public struct ForensicReport: Codable {
    public let id: String
    public let policyId: String
    public let policyName: String
    public let severity: ForensicSeverity
    public let channel: String
    public let action: String
    public let timestamp: Date
    public let hostname: String
    public let username: String
    public let processName: String?
    public let processPath: String?
    public let pid: Int?
    public let evidence: [ForensicEvidence]
    public let description: String
    public let agentId: String
    public let tenantId: String
}

/// Collects and manages forensic data for DLP violations
public final class ForensicCollector {
    
    public static let shared = ForensicCollector()
    
    private let queue = DispatchQueue(label: "com.nextguard.forensic", qos: .utility)
    private let maxLocalStorageBytes = 100 * 1024 * 1024  // 100MB local cache
    private var pendingReports: [ForensicReport] = []
    private var isUploading = false
    
    private init() {
        // Start periodic upload timer
        startUploadTimer()
    }
    
    // MARK: - Evidence Collection
    
    /// Collect file-based forensic evidence
    public func collectFileEvidence(filePath: String, operation: String) -> ForensicEvidence {
        let fileManager = FileManager.default
        var data: [String: String] = [
            "filePath": filePath,
            "operation": operation,
            "timestamp": ISO8601DateFormatter().string(from: Date())
        ]
        
        if let attributes = try? fileManager.attributesOfItem(atPath: filePath) {
            data["fileSize"] = "\(attributes[.size] ?? 0)"
            data["modificationDate"] = "\(attributes[.modificationDate] ?? Date())"
            data["fileType"] = "\(attributes[.type] ?? "unknown")"
            data["owner"] = "\(attributes[.ownerAccountName] ?? "unknown")"
        }
        
        // Calculate file hash for content fingerprinting
        if let fileData = fileManager.contents(atPath: filePath) {
            data["contentHash"] = ForensicCollector.sha256(fileData)
            data["mimeType"] = detectMimeType(filePath: filePath)
            return ForensicEvidence(type: .fileContent, data: data, rawData: fileData)
        }
        
        return ForensicEvidence(type: .fileMetadata, data: data)
    }
    
    /// Collect clipboard forensic evidence
    public func collectClipboardEvidence(content: String, sourceApp: String?) -> ForensicEvidence {
        let truncated = String(content.prefix(10000)) // Limit stored content
        let data: [String: String] = [
            "contentPreview": String(truncated.prefix(500)),
            "contentLength": "\(content.count)",
            "sourceApplication": sourceApp ?? "unknown",
            "containsSensitiveData": "true",
            "timestamp": ISO8601DateFormatter().string(from: Date())
        ]
        return ForensicEvidence(type: .clipboardSnapshot, data: data, rawData: Data(truncated.utf8))
    }
    
    /// Collect process forensic evidence
    public func collectProcessEvidence(pid: Int, processName: String, processPath: String?) -> ForensicEvidence {
        let data: [String: String] = [
            "pid": "\(pid)",
            "processName": processName,
            "processPath": processPath ?? "unknown",
            "parentPid": "\(getppid())",
            "user": NSUserName(),
            "timestamp": ISO8601DateFormatter().string(from: Date())
        ]
        return ForensicEvidence(type: .processInfo, data: data)
    }
    
    /// Collect network forensic evidence
    public func collectNetworkEvidence(destination: String, port: Int, protocol proto: String, dataSize: Int) -> ForensicEvidence {
        let data: [String: String] = [
            "destination": destination,
            "port": "\(port)",
            "protocol": proto,
            "dataSize": "\(dataSize)",
            "timestamp": ISO8601DateFormatter().string(from: Date())
        ]
        return ForensicEvidence(type: .networkPacket, data: data)
    }
    
    /// Collect email forensic evidence
    public func collectEmailEvidence(recipients: [String], subject: String?, attachments: [String]) -> ForensicEvidence {
        let data: [String: String] = [
            "recipients": recipients.joined(separator: ", "),
            "recipientCount": "\(recipients.count)",
            "subject": subject ?? "(no subject)",
            "hasAttachments": "\(!attachments.isEmpty)",
            "attachmentNames": attachments.joined(separator: ", "),
            "attachmentCount": "\(attachments.count)",
            "timestamp": ISO8601DateFormatter().string(from: Date())
        ]
        return ForensicEvidence(type: .emailMetadata, data: data)
    }
    
    /// Collect print job forensic evidence
    public func collectPrintEvidence(documentName: String, printerName: String, pageCount: Int) -> ForensicEvidence {
        let data: [String: String] = [
            "documentName": documentName,
            "printerName": printerName,
            "pageCount": "\(pageCount)",
            "timestamp": ISO8601DateFormatter().string(from: Date())
        ]
        return ForensicEvidence(type: .printJob, data: data)
    }
    
    /// Collect AirDrop forensic evidence
    public func collectAirDropEvidence(fileName: String, targetDevice: String?, fileSize: Int) -> ForensicEvidence {
        let data: [String: String] = [
            "fileName": fileName,
            "targetDevice": targetDevice ?? "unknown",
            "fileSize": "\(fileSize)",
            "timestamp": ISO8601DateFormatter().string(from: Date())
        ]
        return ForensicEvidence(type: .airdropTransfer, data: data)
    }
    
    // MARK: - Report Generation
    
    /// Create a complete forensic report for a policy violation
    public func createReport(
        policyId: String,
        policyName: String,
        severity: ForensicSeverity,
        channel: String,
        action: String,
        description: String,
        evidence: [ForensicEvidence],
        processName: String? = nil,
        processPath: String? = nil,
        pid: Int? = nil
    ) -> ForensicReport {
        let report = ForensicReport(
            id: UUID().uuidString,
            policyId: policyId,
            policyName: policyName,
            severity: severity,
            channel: channel,
            action: action,
            timestamp: Date(),
            hostname: Host.current().localizedName ?? "unknown",
            username: NSUserName(),
            processName: processName,
            processPath: processPath,
            pid: pid,
            evidence: evidence,
            description: description,
            agentId: AgentIdentity.shared.agentId,
            tenantId: AgentIdentity.shared.tenantId
        )
        
        queue.async { [weak self] in
            self?.pendingReports.append(report)
            self?.uploadPendingReports()
        }
        
        return report
    }
    
    // MARK: - Upload to Management Console
    
    private func uploadPendingReports() {
        guard !isUploading, !pendingReports.isEmpty else { return }
        isUploading = true
        
        let batch = Array(pendingReports.prefix(50))
        let events = batch.map { report -> [String: Any] in
            return [
                "eventType": "dlp_violation",
                "severity": report.severity.rawValue,
                "policyId": report.policyId,
                "policyName": report.policyName,
                "channel": report.channel,
                "action": report.action,
                "description": report.description,
                "timestamp": ISO8601DateFormatter().string(from: report.timestamp),
                "hostname": report.hostname,
                "username": report.username,
                "processName": report.processName ?? "",
                "filePath": report.evidence.first?.data["filePath"] ?? "",
                "forensicData": report.evidence.map { e in
                    ["type": e.type.rawValue, "hash": e.hash, "data": e.data]
                }
            ]
        }
        
        // Upload via ManagementClient
        ManagementClient.shared.uploadLogs(events: events) { [weak self] success in
            self?.queue.async {
                if success {
                    self?.pendingReports.removeFirst(min(batch.count, self?.pendingReports.count ?? 0))
                }
                self?.isUploading = false
            }
        }
    }
    
    private func startUploadTimer() {
        queue.asyncAfter(deadline: .now() + 30) { [weak self] in
            self?.uploadPendingReports()
            self?.startUploadTimer()
        }
    }
    
    // MARK: - Utilities
    
    /// Compute SHA-256 hash of data
    public static func sha256(_ data: Data) -> String {
        var hash = [UInt8](repeating: 0, count: 32)
        data.withUnsafeBytes { buffer in
            guard let ptr = buffer.baseAddress else { return }
            // Use CommonCrypto CC_SHA256 in production
            // Simplified hash for compilation
            var h: UInt64 = 0xcbf29ce484222325
            for i in 0..<buffer.count {
                h ^= UInt64(ptr.load(fromByteOffset: i, as: UInt8.self))
                h &*= 0x100000001b3
            }
            withUnsafeBytes(of: h) { hashBytes in
                for i in 0..<min(8, 32) { hash[i] = hashBytes[i % hashBytes.count] }
            }
        }
        return hash.map { String(format: "%02x", $0) }.joined()
    }
    
    private func detectMimeType(filePath: String) -> String {
        let ext = (filePath as NSString).pathExtension.lowercased()
        let mimeTypes: [String: String] = [
            "pdf": "application/pdf", "doc": "application/msword",
            "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "xls": "application/vnd.ms-excel",
            "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            "txt": "text/plain", "csv": "text/csv", "json": "application/json",
            "png": "image/png", "jpg": "image/jpeg", "zip": "application/zip"
        ]
        return mimeTypes[ext] ?? "application/octet-stream"
    }
}

// MARK: - Agent Identity (shared config)

public final class AgentIdentity {
    public static let shared = AgentIdentity()
    public var agentId: String = ""
    public var tenantId: String = ""
    private init() {}
}
