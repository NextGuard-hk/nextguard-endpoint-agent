// swift-tools-version: 5.9
// NextGuard Endpoint DLP Agent
// Copyright (c) 2026 NextGuard Technology Limited. All rights reserved.

import PackageDescription

let package = Package(
  name: "NextGuardAgent",
  platforms: [
    .macOS(.v14)
  ],
  products: [
    .executable(
      name: "NextGuardAgent",
      targets: ["NextGuardAgent"]
    )
  ],
  dependencies: [],
  targets: [
    .executableTarget(
      name: "NextGuardAgent",
      dependencies: [],
      path: "Sources/NextGuardAgent",
      exclude: ["MacApps"],
      sources: [
        "App/NextGuardApp.swift",
        "DLP/DLPPolicyEngine.swift",
        "DLP/LocalPolicyEngine.swift",
        "Clipboard/ClipboardMonitor.swift",
        "FileSystem/FileSystemWatcher.swift",
        "USB/USBDeviceMonitor.swift",
        "Network/NetworkMonitor.swift",
        "Print/PrintMonitor.swift",
        "AirDrop/AirDropMonitor.swift",
        "ScreenCapture/ScreenCaptureMonitor.swift",
        "GUI/GUIManager.swift",
        "GUI/MenuBarController.swift",
        "GUI/StatusBarIconHelper.swift",
        "GUI/IncidentStoreManager.swift",
        "GUI/PolicyStore.swift",
        "Management/ManagementClient.swift",
        "Management/AgentAPIClient.swift",
        "Audit/AuditLogger.swift",
        "Browser/BrowserMonitor.swift"
      ],
      linkerSettings: [
        .linkedFramework("AppKit"),
        .linkedFramework("SwiftUI"),
        .linkedFramework("Combine"),
        .linkedFramework("UserNotifications"),
        .linkedFramework("SystemExtensions"),
        .linkedFramework("NetworkExtension"),
        .linkedFramework("IOKit"),
        .linkedFramework("DiskArbitration"),
        .linkedFramework("Security"),
        .linkedFramework("CoreServices"),
        .linkedFramework("NaturalLanguage")
      ]
    )
  ]
)
