//
//  EncryptionManager.swift
//  NextGuard Endpoint DLP Agent
//
//  Copyright (c) 2026 NextGuard Technology Limited. All rights reserved.
//  AES-256-GCM encryption with Keychain-backed key management
//  Reference: ISO 27001:2022 A.8.24, NIST SP 800-175B, FIPS 140-3
//

import Foundation
import CryptoKit
import Security
import OSLog

// MARK: - Encryption Types
enum EncryptionAlgorithm: String, Codable {
  case aes256GCM = "AES-256-GCM"
  case chaChaPoly = "ChaCha20-Poly1305"
}

struct EncryptedPayload: Codable {
  let algorithm: EncryptionAlgorithm
  let keyId: String
  let nonce: Data
  let ciphertext: Data
  let tag: Data
  let metadata: [String: String]
  let timestamp: Date
}

struct KeyInfo: Codable {
  let keyId: String
  let algorithm: EncryptionAlgorithm
  let createdAt: Date
  let expiresAt: Date
  let rotationCount: Int
}

// MARK: - Encryption Manager
final class EncryptionManager: @unchecked Sendable {
  static let shared = EncryptionManager()
  private let logger = Logger(subsystem: "com.nextguard.agent", category: "EncryptionManager")
  
  private let keychainService = "com.nextguard.agent.keys"
  private var currentKeyId: String = ""
  private let keyRotationDays: Int = 30
  private let queue = DispatchQueue(label: "com.nextguard.encryption", qos: .userInitiated)
  
  private init() {
    ensureKeyExists()
  }
  
  // MARK: - Key Management (FIPS 140-3)
  private func ensureKeyExists() {
    if let existing = loadKeyFromKeychain(tag: "current") {
      currentKeyId = existing.keyId
      if existing.expiresAt < Date() {
        rotateKey()
      }
    } else {
      generateNewKey()
    }
  }
  
  private func generateNewKey() {
    let key = SymmetricKey(size: .bits256)
    let keyId = UUID().uuidString
    let keyInfo = KeyInfo(
      keyId: keyId, algorithm: .aes256GCM,
      createdAt: Date(),
      expiresAt: Date().addingTimeInterval(Double(keyRotationDays * 86400)),
      rotationCount: 0
    )
    saveKeyToKeychain(key: key, keyInfo: keyInfo, tag: "current")
    currentKeyId = keyId
    logger.info("Generated new encryption key: \(keyId.prefix(8))...")
  }
  
  func rotateKey() {
    // Archive current key
    if let current = loadKeyFromKeychain(tag: "current") {
      let archiveTag = "archive_\(current.keyId)"
      if let keyData = loadRawKeyFromKeychain(tag: "current") {
        let archivedInfo = KeyInfo(
          keyId: current.keyId, algorithm: current.algorithm,
          createdAt: current.createdAt, expiresAt: current.expiresAt,
          rotationCount: current.rotationCount + 1
        )
        saveRawKeyToKeychain(keyData: keyData, keyInfo: archivedInfo, tag: archiveTag)
      }
    }
    generateNewKey()
    AuditLogger.shared.log(category: .configChange, severity: .info,
      action: "key_rotation", description: "Encryption key rotated")
  }
  
  // MARK: - Keychain Operations
  private func saveKeyToKeychain(key: SymmetricKey, keyInfo: KeyInfo, tag: String) {
    let keyData = key.withUnsafeBytes { Data($0) }
    saveRawKeyToKeychain(keyData: keyData, keyInfo: keyInfo, tag: tag)
  }
  
  private func saveRawKeyToKeychain(keyData: Data, keyInfo: KeyInfo, tag: String) {
    let encoder = JSONEncoder()
    let infoData = (try? encoder.encode(keyInfo)) ?? Data()
    
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: keychainService,
      kSecAttrAccount as String: tag,
      kSecValueData as String: keyData,
      kSecAttrComment as String: String(data: infoData, encoding: .utf8) ?? "",
      kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    ]
    SecItemDelete(query as CFDictionary)
    let status = SecItemAdd(query as CFDictionary, nil)
    if status != errSecSuccess {
      logger.error("Keychain save failed: \(status)")
    }
  }
  
  private func loadKeyFromKeychain(tag: String) -> KeyInfo? {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: keychainService,
      kSecAttrAccount as String: tag,
      kSecReturnAttributes as String: true
    ]
    var result: CFTypeRef?
    guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
          let attrs = result as? [String: Any],
          let comment = attrs[kSecAttrComment as String] as? String,
          let data = comment.data(using: .utf8) else { return nil }
    return try? JSONDecoder().decode(KeyInfo.self, from: data)
  }
  
  private func loadRawKeyFromKeychain(tag: String) -> Data? {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: keychainService,
      kSecAttrAccount as String: tag,
      kSecReturnData as String: true
    ]
    var result: CFTypeRef?
    guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess else { return nil }
    return result as? Data
  }
  
  private func getSymmetricKey(tag: String) -> SymmetricKey? {
    guard let data = loadRawKeyFromKeychain(tag: tag) else { return nil }
    return SymmetricKey(data: data)
  }

    // MARK: - Encrypt / Decrypt (AES-256-GCM)
  func encrypt(data: Data, metadata: [String: String] = [:]) throws -> EncryptedPayload {
    guard let key = getSymmetricKey(tag: "current") else {
      throw EncryptionError.keyNotFound
    }
    let nonce = AES.GCM.Nonce()
    let sealed = try AES.GCM.seal(data, using: key, nonce: nonce)
    
    return EncryptedPayload(
      algorithm: .aes256GCM, keyId: currentKeyId,
      nonce: Data(nonce), ciphertext: sealed.ciphertext,
      tag: Data(sealed.tag), metadata: metadata,
      timestamp: Date()
    )
  }
  
  func decrypt(payload: EncryptedPayload) throws -> Data {
    let tag = payload.keyId == currentKeyId ? "current" : "archive_\(payload.keyId)"
    guard let key = getSymmetricKey(tag: tag) else {
      throw EncryptionError.keyNotFound
    }
    let nonce = try AES.GCM.Nonce(data: payload.nonce)
    let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: payload.ciphertext, tag: payload.tag)
    return try AES.GCM.open(sealedBox, using: key)
  }
  
  // MARK: - File Encryption
  func encryptFile(at sourcePath: URL, to destPath: URL? = nil) throws -> URL {
    let data = try Data(contentsOf: sourcePath)
    let encrypted = try encrypt(data: data, metadata: [
      "originalName": sourcePath.lastPathComponent,
      "originalSize": "\(data.count)"
    ])
    let encoder = JSONEncoder()
    let payload = try encoder.encode(encrypted)
    
    let outputPath = destPath ?? sourcePath.appendingPathExtension("ngenc")
    try payload.write(to: outputPath)
    logger.info("File encrypted: \(sourcePath.lastPathComponent) -> \(outputPath.lastPathComponent)")
    return outputPath
  }
  
  func decryptFile(at sourcePath: URL, to destPath: URL? = nil) throws -> URL {
    let data = try Data(contentsOf: sourcePath)
    let decoder = JSONDecoder()
    let payload = try decoder.decode(EncryptedPayload.self, from: data)
    let decrypted = try decrypt(payload: payload)
    
    let originalName = payload.metadata["originalName"] ?? "decrypted_file"
    let outputPath = destPath ?? sourcePath.deletingLastPathComponent().appendingPathComponent(originalName)
    try decrypted.write(to: outputPath)
    logger.info("File decrypted: \(sourcePath.lastPathComponent) -> \(outputPath.lastPathComponent)")
    return outputPath
  }
  
  // MARK: - Secure Hashing
  func sha256(data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
  }
  
  func sha256File(at path: URL) -> String? {
    guard let data = try? Data(contentsOf: path) else { return nil }
    return sha256(data: data)
  }
  
  // MARK: - Secure Communication
  func encryptForTransmission(data: Data) throws -> Data {
    let payload = try encrypt(data: data, metadata: ["purpose": "transmission"])
    return try JSONEncoder().encode(payload)
  }
}

// MARK: - Errors
enum EncryptionError: Error, LocalizedError {
  case keyNotFound
  case encryptionFailed
  case decryptionFailed
  case invalidPayload
  
  var errorDescription: String? {
    switch self {
    case .keyNotFound: return "Encryption key not found in Keychain"
    case .encryptionFailed: return "Encryption operation failed"
    case .decryptionFailed: return "Decryption operation failed"
    case .invalidPayload: return "Invalid encrypted payload format"
    }
  }
}
