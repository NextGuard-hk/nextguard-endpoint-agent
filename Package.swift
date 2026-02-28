// swift-tools-version: 5.9
// NextGuard Endpoint DLP Agent
// Copyright (c) 2026 NextGuard Technology Limited. All rights reserved.

import PackageDescription

let package = Package(
  name: "NextGuardAgent",
  platforms: [
    .macOS(.v14)  // macOS 14 Sonoma minimum, supports macOS 15 Sequoia+
  ],
  products: [
    .executable(
      name: "NextGuardAgent",
      targets: ["NextGuardAgent"]
    )
  ],
  dependencies: [
    // No external dependencies - uses Apple frameworks only for security
  ],
  targets: [
    .executableTarget(
      name: "NextGuardAgent",
      dependencies: [],
      path: "Sources/NextGuardAgent",
      linkerSettings: [
        .linkedFramework("AppKit"),
        .linkedFramework("SystemExtensions"),
        .linkedFramework("NetworkExtension"),
        .linkedFramework("IOKit"),
        .linkedFramework("DiskArbitration"),
        .linkedFramework("Security"),
        .linkedFramework("CoreServices"),
        .linkedFramework("NaturalLanguage"),
        .unsafeFlags(["-F/System/Library/PrivateFrameworks"])
      ]
    ),
    .testTarget(
      name: "NextGuardAgentTests",
      dependencies: ["NextGuardAgent"],
      path: "Tests/NextGuardAgentTests"
    )
  ]
)
