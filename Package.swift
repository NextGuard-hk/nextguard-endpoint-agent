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
      exclude: ["MacApps", "Sources"],
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
