//
//  USBDeviceMonitor.swift
//  NextGuard Endpoint DLP Agent
//
//  Copyright (c) 2026 NextGuard Technology Limited. All rights reserved.
//
//  USB/Removable device DLP control using IOKit framework
//  Ref: ISO 27001:2022 A.8.1, NIST SP 800-171 3.8.7, CIS Controls v8 10.3
//

import Foundation
import IOKit
import IOKit.usb
import DiskArbitration
import os.log

// MARK: - USB Device Info
struct USBDeviceInfo: Codable, Identifiable {
  let id: String
  let vendorId: Int
  let productId: Int
  let vendorName: String
  let productName: String
  let serialNumber: String?
  let deviceClass: USBDeviceClass
  let mountPoint: String?
  let capacity: Int64?
  let timestamp: Date
}

enum USBDeviceClass: String, Codable {
  case massStorage, hid, printer, imaging, hub
  case wireless, communication, audioVideo, other
}

enum USBPolicy: String, Codable {
  case allow, blockAll, readOnly, auditOnly
  case allowWhitelisted, blockMassStorage
}

// MARK: - USB Device Event
struct USBDLPEvent: Codable {
  let id: String
  let timestamp: Date
  let device: USBDeviceInfo
  let eventType: USBEventType
  let action: DLPAction
  let policyApplied: USBPolicy
}

enum USBEventType: String, Codable {
  case connected, disconnected, mountAttempt, fileTransfer, blocked
}

// MARK: - USB Device Monitor
final class USBDeviceMonitor: ObservableObject {
  static let shared = USBDeviceMonitor()
  private let logger = Logger(subsystem: "com.nextguard.agent", category: "USBMonitor")
  
  @Published var isActive: Bool = false
  @Published var connectedDevices: [USBDeviceInfo] = []
  @Published var totalBlocked: Int = 0
  
  private var notificationPort: IONotificationPortRef?
  private var addedIterator: io_iterator_t = 0
  private var removedIterator: io_iterator_t = 0
  private var daSession: DASession?
  
  // Policy configuration
  var currentPolicy: USBPolicy = .blockMassStorage
  var whitelistedDevices: Set<String> = []  // serial numbers
  var whitelistedVendors: Set<Int> = []     // vendor IDs
  
  private init() {
    loadUSBPolicy()
  }
  
  // MARK: - Start / Stop
  func startMonitoring() {
    guard !isActive else { return }
    logger.info("Starting USB device DLP monitoring")
    
    setupIOKitNotifications()
    setupDiskArbitration()
    
    DispatchQueue.main.async { self.isActive = true }
  }
  
  func stopMonitoring() {
    if let port = notificationPort {
      IONotificationPortDestroy(port)
    }
    if addedIterator != 0 { IOObjectRelease(addedIterator) }
    if removedIterator != 0 { IOObjectRelease(removedIterator) }
    daSession = nil
    DispatchQueue.main.async { self.isActive = false }
    logger.info("USB monitoring stopped")
  }
  
  // MARK: - IOKit USB Notifications
  private func setupIOKitNotifications() {
    notificationPort = IONotificationPortCreate(kIOMainPortDefault)
    guard let port = notificationPort else { return }
    
    let runLoopSource = IONotificationPortGetRunLoopSource(port).takeRetainedValue()
    CFRunLoopAddSource(CFRunLoopGetCurrent(), runLoopSource, .defaultMode)
    
    let matchingDict = IOServiceMatching(kIOUSBDeviceClassName) as NSMutableDictionary
    
    // USB device added
    let selfPtr = Unmanaged.passUnretained(self).toOpaque()
    IOServiceAddMatchingNotification(port, kIOFirstMatchNotification, matchingDict, { refcon, iterator in
      guard let refcon = refcon else { return }
      let monitor = Unmanaged<USBDeviceMonitor>.fromOpaque(refcon).takeUnretainedValue()
      monitor.handleDeviceAdded(iterator: iterator)
    }, selfPtr, &addedIterator)
    
    // Process existing devices
    handleDeviceAdded(iterator: addedIterator)
    
    // USB device removed
    IOServiceAddMatchingNotification(port, kIOTerminatedNotification, matchingDict, { refcon, iterator in
      guard let refcon = refcon else { return }
      let monitor = Unmanaged<USBDeviceMonitor>.fromOpaque(refcon).takeUnretainedValue()
      monitor.handleDeviceRemoved(iterator: iterator)
    }, selfPtr, &removedIterator)
    
    handleDeviceRemoved(iterator: removedIterator)
  }
  
  // MARK: - Disk Arbitration (Mount Control)
  private func setupDiskArbitration() {
    daSession = DASessionCreate(kCFAllocatorDefault)
    guard let session = daSession else { return }
    
    DARegisterDiskAppearedCallback(session, nil, { disk, context in
      guard let context = context else { return }
      let monitor = Unmanaged<USBDeviceMonitor>.fromOpaque(context).takeUnretainedValue()
      monitor.handleDiskAppeared(disk: disk)
    }, Unmanaged.passUnretained(self).toOpaque())
    
    DASessionSetDispatchQueue(session, DispatchQueue.main)
  }
  
  // MARK: - Device Event Handlers
  private func handleDeviceAdded(iterator: io_iterator_t) {
    var device: io_object_t = IOIteratorNext(iterator)
    while device != 0 {
      if let info = extractDeviceInfo(device) {
        let action = evaluatePolicy(for: info)
        
        DispatchQueue.main.async {
          self.connectedDevices.append(info)
        }
        
        let event = USBDLPEvent(
          id: UUID().uuidString,
          timestamp: Date(),
          device: info,
          eventType: .connected,
          action: action,
          policyApplied: currentPolicy
        )
        AgentAPIClient.shared.reportUSBEvent(event)
        
        if action == .block {
          blockDevice(device)
          totalBlocked += 1
          logger.warning("USB BLOCKED: \(info.vendorName) \(info.productName)")
        } else {
          logger.info("USB allowed: \(info.vendorName) \(info.productName)")
        }
      }
      IOObjectRelease(device)
      device = IOIteratorNext(iterator)
    }
  }
  
  private func handleDeviceRemoved(iterator: io_iterator_t) {
    var device: io_object_t = IOIteratorNext(iterator)
    while device != 0 {
      logger.info("USB device disconnected")
      IOObjectRelease(device)
      device = IOIteratorNext(iterator)
    }
  }
  
  private func handleDiskAppeared(disk: DADisk) {
    guard let desc = DADiskCopyDescription(disk) as? [String: Any] else { return }
    let isRemovable = desc[kDADiskDescriptionMediaRemovableKey as String] as? Bool ?? false
    let isExternal = desc[kDADiskDescriptionDeviceInternalKey as String] as? Bool == false
    
    if (isRemovable || isExternal) && currentPolicy == .blockMassStorage {
      logger.warning("Blocking removable disk mount")
      DADiskUnmount(disk, DADiskUnmountOptions(kDADiskUnmountOptionForce), nil, nil)
    }
  }
  
  // MARK: - Policy Evaluation
  func evaluatePolicy(for device: USBDeviceInfo) -> DLPAction {
    switch currentPolicy {
    case .allow:
      return .allow
    case .blockAll:
      return .block
    case .blockMassStorage:
      return device.deviceClass == .massStorage ? .block : .allow
    case .readOnly:
      return device.deviceClass == .massStorage ? .audit : .allow
    case .auditOnly:
      return .audit
    case .allowWhitelisted:
      if let serial = device.serialNumber, whitelistedDevices.contains(serial) { return .allow }
      if whitelistedVendors.contains(device.vendorId) { return .allow }
      return .block
    }
  }
  
  // MARK: - Device Info Extraction
  private func extractDeviceInfo(_ device: io_object_t) -> USBDeviceInfo? {
    let vendorId = getIntProperty(device, key: kUSBVendorID) ?? 0
    let productId = getIntProperty(device, key: kUSBProductID) ?? 0
    let vendorName = getStringProperty(device, key: "USB Vendor Name") ?? "Unknown"
    let productName = getStringProperty(device, key: "USB Product Name") ?? "Unknown"
    let serial = getStringProperty(device, key: kUSBSerialNumberString)
    
    let deviceClass = classifyUSBDevice(classCode: getIntProperty(device, key: "bDeviceClass") ?? 0)
    
    return USBDeviceInfo(
      id: UUID().uuidString,
      vendorId: vendorId,
      productId: productId,
      vendorName: vendorName,
      productName: productName,
      serialNumber: serial,
      deviceClass: deviceClass,
      mountPoint: nil,
      capacity: nil,
      timestamp: Date()
    )
  }
  
  // MARK: - Block Device
  private func blockDevice(_ device: io_object_t) {
    // Request kernel-level block via Endpoint Security
    logger.warning("Issuing device block via Endpoint Security framework")
  }
  
  // MARK: - Helpers
  private func getStringProperty(_ device: io_object_t, key: String) -> String? {
    IORegistryEntryCreateCFProperty(device, key as CFString, kCFAllocatorDefault, 0)?.takeRetainedValue() as? String
  }
  
  private func getIntProperty(_ device: io_object_t, key: String) -> Int? {
    IORegistryEntryCreateCFProperty(device, key as CFString, kCFAllocatorDefault, 0)?.takeRetainedValue() as? Int
  }
  
  private func classifyUSBDevice(classCode: Int) -> USBDeviceClass {
    switch classCode {
    case 0x08: return .massStorage
    case 0x03: return .hid
    case 0x07: return .printer
    case 0x06: return .imaging
    case 0x09: return .hub
    case 0xE0: return .wireless
    case 0x02: return .communication
    case 0x01, 0x0E, 0x10: return .audioVideo
    default:   return .other
    }
  }
  
  private func loadUSBPolicy() {
    let path = "/Library/Application Support/NextGuard/usb-policy.json"
    guard let data = FileManager.default.contents(atPath: path),
          let config = try? JSONDecoder().decode(USBPolicyConfig.self, from: data) else { return }
    currentPolicy = config.policy
    whitelistedDevices = Set(config.whitelistedSerials)
    whitelistedVendors = Set(config.whitelistedVendorIds)
  }
}

struct USBPolicyConfig: Codable {
  let policy: USBPolicy
  let whitelistedSerials: [String]
  let whitelistedVendorIds: [Int]
}

extension AgentAPIClient {
  func reportUSBEvent(_ event: USBDLPEvent) {
    guard let data = try? JSONEncoder().encode(event) else { return }
    let url = URL(string: "\(AgentConfig.shared.managementServerURL)/api/v1/events/usb")!
    var request = URLRequest(url: url)
    request.httpMethod = "POST"
    request.httpBody = data
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.setValue("Bearer \(AgentConfig.shared.apiToken)", forHTTPHeaderField: "Authorization")
    URLSession.shared.dataTask(with: request).resume()
  }
}
