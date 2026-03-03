//
//  PolicyEnforcer.swift
//  NextGuardAgent
//
//  Bridge between DLPPolicyEngine (core DLP) and PolicyStore (GUI layer)
//  Intercepts DLP scan results and updates GUI counters + shows alerts
//

import Foundation
import AppKit

// MARK: - Policy Enforcer
// Singleton bridge: DLPPolicyEngine -> PolicyStore (GUI)
// Also handles user-facing enforcement (block dialog, audit notification)
class PolicyEnforcer {
    static let shared = PolicyEnforcer()
    private init() {}

    // Called by DLP scanners after a policy match is found
    // Returns true if transfer should be blocked
    func enforcePolicy(
        result: DLPScanResult,
        channel: String,
        fileName: String? = nil
    ) -> Bool {
        let shouldBlock = result.action == .block

        // Update GUI counters
        let guiAction: RuleAction = result.action == .block ? .block :
            result.action == .audit ? .audit : .allow
        PolicyStore.shared.recordIncident(action: guiAction)
        GUIManager.shared.notifyIncident(policyName: result.ruleName, action: guiAction)

        // Show user notification
        DispatchQueue.main.async {
            if shouldBlock {
                self.showBlockAlert(policyName: result.ruleName, channel: channel, fileName: fileName)
                DLPNotificationHelper.showBlockAlert(policyName: result.ruleName, channel: channel)
            } else if result.action == .audit {
                DLPNotificationHelper.showAuditAlert(policyName: result.ruleName, channel: channel)
            }
        }

        return shouldBlock
    }

    // Enforce multiple scan results at once (returns true if ANY rule blocks)
    func enforceAll(
        results: [DLPScanResult],
        channel: String,
        fileName: String? = nil
    ) -> Bool {
        var blocked = false
        for result in results {
            if enforcePolicy(result: result, channel: channel, fileName: fileName) {
                blocked = true
            }
        }
        return blocked
    }

    // MARK: - Block Alert Dialog
    @MainActor
    private func showBlockAlert(policyName: String, channel: String, fileName: String?) {
        let alert = NSAlert()
        alert.messageText = "Transfer Blocked by NextGuard DLP"
        var info = "Policy: \(policyName)\nChannel: \(channel)"
        if let fileName = fileName { info += "\nFile: \(fileName)" }
        info += "\n\nThis transfer has been blocked and logged."
        alert.informativeText = info
        alert.alertStyle = .critical
        alert.icon = NSImage(systemSymbolName: "shield.slash.fill", accessibilityDescription: nil)
        alert.addButton(withTitle: "OK")
        alert.addButton(withTitle: "View Dashboard")
        let response = alert.runModal()
        if response == .alertSecondButtonReturn {
            if let url = URL(string: "https://next-guard.com/console") {
                NSWorkspace.shared.open(url)
            }
        }
    }

    // MARK: - Policy Sync Helper
    // Converts DLPPolicyEngine rules to PolicyStore format for GUI display
    func syncPoliciesToGUI(from engine: DLPPolicyEngine) {
        let engineRules = engine.activePolicies

        // Only sync if GUI has default/empty policies
        guard PolicyStore.shared.policies.isEmpty || isDefaultPolicies() else { return }

        let guiRules: [GUIPolicyRule] = engineRules.map { rule in
            GUIPolicyRule(
                id: UUID(uuidString: rule.id) ?? UUID(),
                name: rule.name,
                description: rule.description ?? "",
                enabled: rule.enabled,
                action: rule.action == "block" ? .block : rule.action == "audit" ? .audit : .allow,
                keywords: rule.keywords ?? [],
                fileTypes: rule.fileTypes ?? [],
                destinations: rule.channels ?? []
            )
        }

        if !guiRules.isEmpty {
            DispatchQueue.main.async {
                PolicyStore.shared.policies = guiRules
            }
        }
    }

    private func isDefaultPolicies() -> Bool {
        let defaultNames = ["Credit Card Data", "Personal Identifiable Information", "Confidential Documents", "Source Code"]
        return PolicyStore.shared.policies.allSatisfy { defaultNames.contains($0.name) }
    }
}
