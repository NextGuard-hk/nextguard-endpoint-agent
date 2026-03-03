//
//  PolicyManagementView.swift
//  NextGuardAgent
//
//  Local policy management - Block/Audit/Allow rule configuration
//

import SwiftUI

struct PolicyManagementView: View {
    @EnvironmentObject var policyStore: PolicyStore
    @State private var showingAddPolicy = false
    @State private var editingPolicy: GUIPolicyRule?

    var body: some View {
        VStack(spacing: 0) {
            // Toolbar
            HStack {
                Text("\(policyStore.policies.count) rules")
                    .font(.system(size: 11))
                    .foregroundColor(.secondary)
                Spacer()
                Button(action: { showingAddPolicy = true }) {
                    Label("Add Rule", systemImage: "plus")
                        .font(.system(size: 11))
                }
                .buttonStyle(.bordered)
                .controlSize(.mini)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .background(Color(NSColor.controlBackgroundColor))

            Divider()

            // Policy List
            if policyStore.policies.isEmpty {
                emptyState
            } else {
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(policyStore.policies) { policy in
                            PolicyRowView(policy: policy) {
                                editingPolicy = policy
                            }
                            Divider().padding(.leading, 12)
                        }
                    }
                }
            }
        }
        .sheet(isPresented: $showingAddPolicy) {
            PolicyEditView(policy: nil) { newPolicy in
                policyStore.addPolicy(newPolicy)
            }
        }
        .sheet(item: $editingPolicy) { policy in
            PolicyEditView(policy: policy) { updated in
                policyStore.updatePolicy(updated)
            }
        }
    }

    var emptyState: some View {
        VStack(spacing: 10) {
            Image(systemName: "doc.text.magnifyingglass")
                .font(.system(size: 32))
                .foregroundColor(.secondary)
            Text("No Policies")
                .font(.system(size: 13, weight: .medium))
            Text("Add rules to control data movement")
                .font(.system(size: 11))
                .foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

// MARK: - Policy Row
struct PolicyRowView: View {
    let policy: GUIPolicyRule
    let onEdit: () -> Void
    @EnvironmentObject var policyStore: PolicyStore

    var actionColor: Color {
        switch policy.action {
        case .block: return .red
        case .audit: return .orange
        case .allow: return .green
        }
    }

    var body: some View {
        HStack(spacing: 10) {
            // Toggle
            Toggle("", isOn: Binding(
                get: { policy.enabled },
                set: { _ in policyStore.togglePolicy(policy) }
            ))
            .toggleStyle(.switch)
            .controlSize(.mini)
            .labelsHidden()

            // Info
            VStack(alignment: .leading, spacing: 2) {
                Text(policy.name)
                    .font(.system(size: 12, weight: .medium))
                    .foregroundColor(policy.enabled ? .primary : .secondary)
                HStack(spacing: 6) {
                    // Action Badge
                    Text(policy.action.displayName.uppercased())
                        .font(.system(size: 9, weight: .bold))
                        .foregroundColor(actionColor)
                        .padding(.horizontal, 5)
                        .padding(.vertical, 2)
                        .background(RoundedRectangle(cornerRadius: 3).fill(actionColor.opacity(0.12)))
                    if !policy.keywords.isEmpty {
                        Text("\(policy.keywords.count) keywords")
                            .font(.system(size: 10))
                            .foregroundColor(.secondary)
                    }
                    if !policy.fileTypes.isEmpty {
                        Text("\(policy.fileTypes.count) types")
                            .font(.system(size: 10))
                            .foregroundColor(.secondary)
                    }
                }
            }

            Spacer()

            // Edit
            Button(action: onEdit) {
                Image(systemName: "pencil")
                    .font(.system(size: 11))
                    .foregroundColor(.secondary)
            }
            .buttonStyle(.plain)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(policy.enabled ? Color.clear : Color(NSColor.controlBackgroundColor).opacity(0.5))
        .contentShape(Rectangle())
    }
}

// MARK: - Policy Edit Sheet
struct PolicyEditView: View {
    let existingPolicy: GUIPolicyRule?
    let onSave: (GUIPolicyRule) -> Void

    @State private var name: String
    @State private var description: String
    @State private var enabled: Bool
    @State private var action: RuleAction
    @State private var keywordsText: String
    @State private var fileTypesText: String
    @State private var destinationsText: String
    @Environment(\.dismiss) private var dismiss

    init(policy: GUIPolicyRule?, onSave: @escaping (GUIPolicyRule) -> Void) {
        self.existingPolicy = policy
        self.onSave = onSave
        _name = State(initialValue: policy?.name ?? "")
        _description = State(initialValue: policy?.description ?? "")
        _enabled = State(initialValue: policy?.enabled ?? true)
        _action = State(initialValue: policy?.action ?? .audit)
        _keywordsText = State(initialValue: policy?.keywords.joined(separator: ", ") ?? "")
        _fileTypesText = State(initialValue: policy?.fileTypes.joined(separator: ", ") ?? "")
        _destinationsText = State(initialValue: policy?.destinations.joined(separator: ", ") ?? "")
    }

    var body: some View {
        VStack(spacing: 0) {
            // Sheet Header
            HStack {
                Text(existingPolicy == nil ? "New Policy Rule" : "Edit Rule")
                    .font(.system(size: 14, weight: .bold))
                Spacer()
                Button("Cancel") { dismiss() }
                    .buttonStyle(.plain)
                    .foregroundColor(.secondary)
            }
            .padding(14)
            .background(Color(NSColor.controlBackgroundColor))

            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    // Name
                    fieldLabel("Rule Name")
                    TextField("e.g. Credit Card Detection", text: $name)
                        .textFieldStyle(.roundedBorder)

                    // Description
                    fieldLabel("Description")
                    TextField("Optional description", text: $description)
                        .textFieldStyle(.roundedBorder)

                    // Action
                    fieldLabel("Action When Matched")
                    Picker("", selection: $action) {
                        ForEach(RuleAction.allCases, id: \.self) { act in
                            HStack {
                                Circle()
                                    .fill(act == .block ? Color.red : act == .audit ? Color.orange : Color.green)
                                    .frame(width: 8, height: 8)
                                Text(act.displayName)
                            }
                            .tag(act)
                        }
                    }
                    .pickerStyle(.segmented)

                    // Action Description
                    actionDescription

                    // Keywords
                    fieldLabel("Keywords (comma-separated)")
                    TextField("e.g. confidential, secret, internal", text: $keywordsText)
                        .textFieldStyle(.roundedBorder)

                    // File Types
                    fieldLabel("File Types (comma-separated)")
                    TextField("e.g. .pdf, .docx, .xlsx", text: $fileTypesText)
                        .textFieldStyle(.roundedBorder)

                    // Destinations
                    fieldLabel("Destinations (comma-separated)")
                    TextField("e.g. email, usb, cloud, web", text: $destinationsText)
                        .textFieldStyle(.roundedBorder)

                    // Enabled
                    Toggle("Enable this rule", isOn: $enabled)
                        .font(.system(size: 12))
                }
                .padding(14)
            }

            Divider()

            // Footer
            HStack {
                if existingPolicy != nil {
                    Button("Delete Rule") {
                        dismiss()
                    }
                    .foregroundColor(.red)
                    .buttonStyle(.plain)
                }
                Spacer()
                Button("Save Rule") { save() }
                    .buttonStyle(.borderedProminent)
                    .disabled(name.isEmpty)
            }
            .padding(14)
        }
        .frame(width: 360, height: 520)
    }

    var actionDescription: some View {
        Group {
            switch action {
            case .block:
                Label("File transfer will be blocked and user notified", systemImage: "xmark.shield")
                    .foregroundColor(.red)
            case .audit:
                Label("Transfer allowed but incident will be logged", systemImage: "eye")
                    .foregroundColor(.orange)
            case .allow:
                Label("Transfer always allowed, no logging", systemImage: "checkmark.shield")
                    .foregroundColor(.green)
            }
        }
        .font(.system(size: 11))
        .padding(8)
        .background(RoundedRectangle(cornerRadius: 6).fill(Color.secondary.opacity(0.08)))
    }

    func fieldLabel(_ text: String) -> some View {
        Text(text)
            .font(.system(size: 11, weight: .medium))
            .foregroundColor(.secondary)
    }

    func save() {
        let keywords = keywordsText.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        let fileTypes = fileTypesText.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        let destinations = destinationsText.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }

        var policy = existingPolicy ?? GUIPolicyRule(name: name)
        policy.name = name
        policy.description = description
        policy.enabled = enabled
        policy.action = action
        policy.keywords = keywords
        policy.fileTypes = fileTypes
        policy.destinations = destinations

        onSave(policy)
        dismiss()
    }
}
