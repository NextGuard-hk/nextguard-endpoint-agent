//
// LocalPolicyManagementView.swift
// NextGuardAgent
//
// Full CRUD GUI for local policy management using LocalPolicyEngine
// Allows admin to create, edit, toggle, delete local DLP rules
// Respects AgentModeManager lock state (greyed out when managed+locked)
//

import SwiftUI

// MARK: - Local Policy Management View
struct LocalPolicyManagementView: View {
    @StateObject private var engine = LocalPolicyEngine.shared
    @StateObject private var modeManager = AgentModeManager.shared
    @State private var showAddSheet = false
    @State private var editingRule: LocalPolicyRule? = nil
    @State private var searchText = ""

    private var isLocked: Bool {
        modeManager.mode == .managed && modeManager.managedSettingsLocked
    }

    private var filteredRules: [LocalPolicyRule] {
        let rules = engine.localRules
        if searchText.isEmpty { return rules }
        return rules.filter { $0.name.localizedCaseInsensitiveContains(searchText) ||
            $0.description.localizedCaseInsensitiveContains(searchText) }
    }

    var body: some View {
        VStack(spacing: 0) {
            // Header
            headerBar
            Divider()
            if isLocked {
                lockedBanner
            }
            // Rule List
            if filteredRules.isEmpty {
                emptyState
            } else {
                ruleList
            }
        }
        .sheet(isPresented: $showAddSheet) {
            PolicyRuleEditorSheet(rule: nil) { newRule in
                engine.addLocalRule(
                    name: newRule.name,
                    description: newRule.description,
                    action: newRule.action,
                    category: newRule.category,
                    conditions: newRule.conditions,
                    priority: newRule.priority
                )
            }
        }
        .sheet(item: $editingRule) { rule in
            PolicyRuleEditorSheet(rule: rule) { updated in
                engine.updateLocalRule(updated)
            }
        }
    }

    // MARK: - Header
    private var headerBar: some View {
        HStack(spacing: 12) {
            Image(systemName: "doc.text.fill").foregroundColor(.blue)
            Text("Local Policies").font(.title2.bold())
            Spacer()
            TextField("Search...", text: $searchText)
                .textFieldStyle(.roundedBorder)
                .frame(width: 180)
            Button(action: { showAddSheet = true }) {
                Label("Add Rule", systemImage: "plus.circle.fill")
            }
            .disabled(isLocked)
            Menu {
                Button("Install Default Policies") {
                    engine.installDefaultPolicies()
                }
            } label: {
                Image(systemName: "ellipsis.circle")
            }
            .disabled(isLocked)
        }
        .padding(16)
    }

    // MARK: - Locked Banner
    private var lockedBanner: some View {
        HStack(spacing: 8) {
            Image(systemName: "lock.fill").foregroundColor(.orange)
            Text("Local policies are locked by your organisation.")
                .font(.caption).foregroundColor(.orange)
        }
        .padding(10)
        .frame(maxWidth: .infinity)
        .background(Color.orange.opacity(0.08))
    }

    // MARK: - Empty State
    private var emptyState: some View {
        VStack(spacing: 12) {
            Image(systemName: "doc.text.magnifyingglass")
                .font(.system(size: 44))
                .foregroundColor(.secondary.opacity(0.5))
            Text("No Local Policies")
                .font(.title3.bold())
            Text("Add custom DLP rules or install defaults.")
                .font(.subheadline).foregroundColor(.secondary)
            if !isLocked {
                Button("Install Default Policies") {
                    engine.installDefaultPolicies()
                }
                .buttonStyle(.bordered)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: - Rule List
    private var ruleList: some View {
        List {
            ForEach(filteredRules) { rule in
                ruleRow(rule)
                    .contextMenu {
                        if !isLocked {
                            Button("Edit") { editingRule = rule }
                            Button("Duplicate") { duplicateRule(rule) }
                            Divider()
                            Button(rule.isEnabled ? "Disable" : "Enable") {
                                engine.toggleRule(id: rule.id)
                            }
                            Divider()
                            Button("Delete", role: .destructive) {
                                engine.deleteLocalRule(id: rule.id)
                            }
                        }
                    }
            }
        }
    }

    private func ruleRow(_ rule: LocalPolicyRule) -> some View {
        HStack(spacing: 10) {
            // Action color dot
            Circle()
                .fill(colorForAction(rule.action))
                .frame(width: 8, height: 8)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(rule.name).font(.body.bold())
                    Text(rule.category.rawValue)
                        .font(.caption2)
                        .padding(.horizontal, 6).padding(.vertical, 2)
                        .background(Capsule().fill(Color.blue.opacity(0.12)))
                        .foregroundColor(.blue)
                    if rule.source == .server {
                        Text("Server")
                            .font(.caption2)
                            .padding(.horizontal, 6).padding(.vertical, 2)
                            .background(Capsule().fill(Color.purple.opacity(0.12)))
                            .foregroundColor(.purple)
                    }
                }
                Text(rule.description)
                    .font(.caption).foregroundColor(.secondary).lineLimit(1)
                Text("\(rule.conditions.count) condition(s) \u{2022} Priority \(rule.priority)")
                    .font(.caption2).foregroundColor(.secondary)
            }
            Spacer()
            // Action badge
            Text(rule.action.rawValue)
                .font(.caption).fontWeight(.medium)
                .padding(.horizontal, 8).padding(.vertical, 3)
                .background(Capsule().fill(colorForAction(rule.action).opacity(0.15)))
                .foregroundColor(colorForAction(rule.action))
            // Toggle
            Toggle("", isOn: Binding(
                get: { rule.isEnabled },
                set: { _ in engine.toggleRule(id: rule.id) }
            ))
            .labelsHidden()
            .disabled(isLocked)
        }
        .padding(.vertical, 4)
        .opacity(rule.isEnabled ? 1.0 : 0.5)
    }

    // MARK: - Helpers
    private func colorForAction(_ action: DLPAction) -> Color {
        switch action {
        case .block: return .red
        case .audit: return .orange
        case .allow: return .green
        case .encrypt: return .blue
        case .quarantine: return .purple
        }
    }

    private func duplicateRule(_ rule: LocalPolicyRule) {
        engine.addLocalRule(
            name: rule.name + " (Copy)",
            description: rule.description,
            action: rule.action,
            category: rule.category,
            conditions: rule.conditions,
            priority: rule.priority
        )
    }
}

// MARK: - Policy Rule Editor Sheet
struct PolicyRuleEditorSheet: View {
    let rule: LocalPolicyRule?
    let onSave: (LocalPolicyRule) -> Void

    @Environment(\.dismiss) private var dismiss

    @State private var name: String = ""
    @State private var description: String = ""
    @State private var action: DLPAction = .audit
    @State private var category: LocalPolicyRule.PolicyCategory = .custom
    @State private var priority: Int = 50
    @State private var isEnabled: Bool = true
    @State private var conditions: [PolicyCondition] = []
    @State private var showAddCondition = false

    var body: some View {
        VStack(spacing: 0) {
            // Title Bar
            HStack {
                Text(rule == nil ? "New Policy Rule" : "Edit Policy Rule")
                    .font(.headline)
                Spacer()
                Button("Cancel") { dismiss() }
                    .buttonStyle(.bordered)
                Button("Save") { saveRule() }
                    .buttonStyle(.borderedProminent)
                    .disabled(name.isEmpty)
            }
            .padding(16)
            Divider()

            // Form
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    formField("Name") {
                        TextField("Rule name", text: $name)
                            .textFieldStyle(.roundedBorder)
                    }
                    formField("Description") {
                        TextField("Optional description", text: $description)
                            .textFieldStyle(.roundedBorder)
                    }
                    HStack(spacing: 20) {
                        formField("Action") {
                            Picker("", selection: $action) {
                                ForEach(DLPAction.allCases, id: \.self) { a in
                                    Text(a.rawValue).tag(a)
                                }
                            }.labelsHidden()
                        }
                        formField("Category") {
                            Picker("", selection: $category) {
                                ForEach(LocalPolicyRule.PolicyCategory.allCases, id: \.self) { c in
                                    Text(c.rawValue).tag(c)
                                }
                            }.labelsHidden()
                        }
                        formField("Priority") {
                            Stepper("\(priority)", value: $priority, in: 1...100)
                        }
                    }
                    Toggle("Enabled", isOn: $isEnabled)
                    Divider()

                    // Conditions
                    HStack {
                        Text("Conditions").font(.subheadline.bold())
                        Spacer()
                        Button(action: { addEmptyCondition() }) {
                            Label("Add", systemImage: "plus")
                        }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                    }
                    if conditions.isEmpty {
                        Text("No conditions. Add at least one condition for this rule to match.")
                            .font(.caption).foregroundColor(.secondary)
                            .padding(.vertical, 8)
                    } else {
                        ForEach(Array(conditions.enumerated()), id: \.element.id) { index, condition in
                            conditionRow(index: index)
                        }
                    }
                }
                .padding(16)
            }
        }
        .frame(width: 560, height: 520)
        .onAppear { loadExisting() }
    }

    private func conditionRow(index: Int) -> some View {
        VStack(spacing: 6) {
            HStack {
                Picker("Type", selection: $conditions[index].type) {
                    ForEach(PolicyCondition.ConditionType.allCases, id: \.self) { t in
                        Text(t.rawValue).tag(t)
                    }
                }
                .frame(width: 160)
                TextField("Pattern / Value", text: $conditions[index].pattern)
                    .textFieldStyle(.roundedBorder)
                Toggle("Regex", isOn: $conditions[index].isRegex)
                    .toggleStyle(.checkbox)
                Button(role: .destructive, action: { conditions.remove(at: index) }) {
                    Image(systemName: "trash")
                }
                .buttonStyle(.borderless)
            }
        }
        .padding(8)
        .background(RoundedRectangle(cornerRadius: 6).fill(Color(NSColor.controlBackgroundColor)))
    }

    private func addEmptyCondition() {
        conditions.append(PolicyCondition(
            id: UUID(),
            type: .contentMatch,
            pattern: "",
            isRegex: false,
            caseSensitive: false
        ))
    }

    private func loadExisting() {
        guard let r = rule else { return }
        name = r.name
        description = r.description
        action = r.action
        category = r.category
        priority = r.priority
        isEnabled = r.isEnabled
        conditions = r.conditions
    }

    private func saveRule() {
        let saved = LocalPolicyRule(
            id: rule?.id ?? UUID(),
            name: name,
            description: description,
            isEnabled: isEnabled,
            action: action,
            priority: priority,
            category: category,
            conditions: conditions,
            source: .local,
            createdAt: rule?.createdAt ?? Date(),
            updatedAt: Date()
        )
        onSave(saved)
        dismiss()
    }

    private func formField<Content: View>(_ label: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).font(.system(size: 11, weight: .medium)).foregroundColor(.secondary)
            content()
        }
    }
}
