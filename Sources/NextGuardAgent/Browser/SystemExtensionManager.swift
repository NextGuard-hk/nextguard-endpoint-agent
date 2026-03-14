//
// SystemExtensionManager.swift
// NextGuardAgent
//
// Copyright (c) 2026 NextGuard Technology Limited. All rights reserved.
// Manages the lifecycle of the Network Extension system extension.
// Handles activation, deactivation, and user approval flow.
//

import Foundation
import SystemExtensions
import NetworkExtension
import os.log

/// Manages the transparent proxy system extension lifecycle.
/// The system extension must be activated before the proxy can be started.
/// On first activation, macOS will prompt the user for approval in
/// System Settings > Privacy & Security.
class SystemExtensionManager: NSObject, ObservableObject {
    static let shared = SystemExtensionManager()
    private let logger = Logger(subsystem: "com.nextguard.agent", category: "SystemExtension")

    @Published var extensionStatus: ExtensionStatus = .unknown

    enum ExtensionStatus: String {
        case unknown = "Unknown"
        case activating = "Activating..."
        case activated = "Activated"
        case needsApproval = "Needs User Approval"
        case failed = "Failed"
        case deactivating = "Deactivating..."
    }

    /// Activate the transparent proxy system extension.
    /// This embeds the extension into the system and triggers user approval.
    func activateExtension() {
        logger.info("Requesting system extension activation...")
        extensionStatus = .activating

        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: "com.nextguard.agent.transparent-proxy",
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    /// Deactivate the system extension (e.g., on uninstall).
    func deactivateExtension() {
        logger.info("Requesting system extension deactivation...")
        extensionStatus = .deactivating

        let request = OSSystemExtensionRequest.deactivationRequest(
            forExtensionWithIdentifier: "com.nextguard.agent.transparent-proxy",
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }
}

// MARK: - OSSystemExtensionRequestDelegate
extension SystemExtensionManager: OSSystemExtensionRequestDelegate {

    func request(_ request: OSSystemExtensionRequest,
                 didFinishWithResult result: OSSystemExtensionRequest.Result) {
        switch result {
        case .completed:
            logger.info("System extension activated successfully")
            DispatchQueue.main.async {
                self.extensionStatus = .activated
            }
        case .willCompleteAfterReboot:
            logger.info("System extension will complete after reboot")
            DispatchQueue.main.async {
                self.extensionStatus = .needsApproval
            }
        @unknown default:
            logger.warning("Unknown result: \(result.rawValue)")
        }
    }

    func request(_ request: OSSystemExtensionRequest,
                 didFailWithError error: Error) {
        logger.error("System extension request failed: \(error.localizedDescription)")
        DispatchQueue.main.async {
            self.extensionStatus = .failed
        }
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        logger.info("System extension needs user approval in System Settings")
        DispatchQueue.main.async {
            self.extensionStatus = .needsApproval
        }
    }

    func request(_ request: OSSystemExtensionRequest,
                 actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        logger.info("Replacing existing extension v\(existing.bundleShortVersion) with v\(ext.bundleShortVersion)")
        return .replace
    }
}