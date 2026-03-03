//
//  IncidentLogView.swift
//  NextGuardAgent
//
//  Incident log view - displays DLP violations and audit events
//

import SwiftUI

// MARK: - Incident Log Content View

struct IncidentLogContentView: View {
  @ObservedObject var store: IncidentStoreManager
  @State private var searchText = ""
  @State private var selectedSeverity: IncidentStoreManager.Severity?
  @State private var selectedIncident: IncidentStoreManager.DLPIncident?
  @State private var showDetail = false

  var filteredIncidents: [IncidentStoreManager.DLPIncident] {
    store.incidents.filter { incident in
      let matchesSearch = searchText.isEmpty ||
        incident.policyName.localizedCaseInsensitiveContains(searchText) ||
        incident.filePath.localizedCaseInsensitiveContains(searchText) ||
        incident.destination.localizedCaseInsensitiveContains(searchText)
      let matchesSeverity = selectedSeverity == nil || incident.severity == selectedSeverity
      return matchesSearch && matchesSeverity
    }
  }

  var body: some View {
    VStack(spacing: 0) {
      // Header
      headerBar

      Divider()

      if store.isLoading {
        ProgressView("Loading incidents...")
          .frame(maxWidth: .infinity, maxHeight: .infinity)
      } else if filteredIncidents.isEmpty {
        emptyState
      } else {
        incidentTable
      }
    }
    .frame(maxWidth: .infinity, maxHeight: .infinity)
    .background(Color(nsColor: .windowBackgroundColor))
    .onAppear { store.loadIncidents() }
    .sheet(isPresented: $showDetail) {
      if let incident = selectedIncident {
        IncidentDetailView(incident: incident)
      }
    }
  }

  // MARK: - Header

  private var headerBar: some View {
    HStack(spacing: 12) {
      Image(systemName: "exclamationmark.triangle.fill")
        .foregroundColor(.orange)
      Text("Incident Log")
        .font(.title2.bold())

      Spacer()

      // Severity Filter
      Picker("Severity", selection: $selectedSeverity) {
        Text("All").tag(nil as IncidentStoreManager.Severity?)
        ForEach(IncidentStoreManager.Severity.allCases, id: \.self) { severity in
          Label(severity.rawValue, systemImage: "circle.fill")
            .tag(severity as IncidentStoreManager.Severity?)
        }
      }
      .pickerStyle(.menu)
      .frame(width: 120)

      // Search
      TextField("Search incidents...", text: $searchText)
        .textFieldStyle(.roundedBorder)
        .frame(width: 200)

      Button(action: { store.loadIncidents() }) {
        Image(systemName: "arrow.clockwise")
      }
      .help("Refresh")

      Button("Export") {
        exportIncidents()
      }
    }
    .padding(16)
  }

  // MARK: - Empty State

  private var emptyState: some View {
    VStack(spacing: 12) {
      Image(systemName: "checkmark.shield")
        .font(.system(size: 48))
        .foregroundColor(.green)
      Text("No Incidents Found")
        .font(.title3.bold())
      Text(searchText.isEmpty ? "Your endpoint is clean. No DLP violations detected." : "No incidents match your search criteria.")
        .foregroundColor(.secondary)
    }
    .frame(maxWidth: .infinity, maxHeight: .infinity)
  }

  // MARK: - Incident Table

  private var incidentTable: some View {
    Table(filteredIncidents) {
      TableColumn("Severity") { incident in
        HStack(spacing: 4) {
          Circle()
            .fill(incident.severity.color)
            .frame(width: 8, height: 8)
          Text(incident.severity.rawValue)
            .font(.caption)
        }
      }
      .width(min: 70, ideal: 80)

      TableColumn("Time") { incident in
        Text(incident.timestamp, style: .relative)
          .font(.caption)
      }
      .width(min: 80, ideal: 100)

      TableColumn("Policy") { incident in
        Text(incident.policyName)
          .font(.caption)
          .fontWeight(.medium)
      }
      .width(min: 120, ideal: 160)

      TableColumn("Action") { incident in
        Text(incident.action)
          .font(.caption)
          .padding(.horizontal, 6)
          .padding(.vertical, 2)
          .background(
            Capsule().fill(
              incident.action == "Block" ? Color.red.opacity(0.15) :
              incident.action == "Audit" ? Color.orange.opacity(0.15) :
              Color.gray.opacity(0.15)
            )
          )
      }
      .width(min: 70, ideal: 80)

      TableColumn("File") { incident in
        Text(incident.filePath)
          .font(.caption)
          .lineLimit(1)
          .truncationMode(.middle)
      }
      .width(min: 150, ideal: 200)

      TableColumn("Destination") { incident in
        Text(incident.destination)
          .font(.caption)
          .lineLimit(1)
      }
      .width(min: 100, ideal: 140)
    }
  }

  // MARK: - Export

  private func exportIncidents() {
    let panel = NSSavePanel()
    panel.allowedContentTypes = [.commaSeparatedText]
    panel.nameFieldStringValue = "nextguard_incidents_\(Date().ISO8601Format()).csv"
    panel.begin { response in
      guard response == .OK, let url = panel.url else { return }
      var csv = "Timestamp,Severity,Policy,Action,File,Destination,Details\n"
      for incident in filteredIncidents {
        csv += "\(incident.timestamp),\(incident.severity.rawValue),\(incident.policyName),\(incident.action),\(incident.filePath),\(incident.destination),\(incident.details)\n"
      }
      try? csv.write(to: url, atomically: true, encoding: .utf8)
    }
  }
}

// MARK: - Incident Detail View

struct IncidentDetailView: View {
  let incident: IncidentStoreManager.DLPIncident
  @Environment(\.dismiss) private var dismiss

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      HStack {
        Circle()
          .fill(incident.severity.color)
          .frame(width: 12, height: 12)
        Text(incident.policyName)
          .font(.title2.bold())
        Spacer()
        Button("Close") { dismiss() }
      }

      Divider()

      LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 12) {
        DetailField(label: "Severity", value: incident.severity.rawValue)
        DetailField(label: "Action Taken", value: incident.action)
        DetailField(label: "Timestamp", value: incident.timestamp.formatted())
        DetailField(label: "File Path", value: incident.filePath)
        DetailField(label: "Destination", value: incident.destination)
        DetailField(label: "Acknowledged", value: incident.isAcknowledged ? "Yes" : "No")
      }

      GroupBox("Details") {
        Text(incident.details)
          .font(.body)
          .frame(maxWidth: .infinity, alignment: .leading)
          .padding(8)
      }

      Spacer()
    }
    .padding(24)
    .frame(width: 560, height: 420)
  }
}

// MARK: - Detail Field

struct DetailField: View {
  let label: String
  let value: String

  var body: some View {
    VStack(alignment: .leading, spacing: 4) {
      Text(label)
        .font(.caption)
        .foregroundColor(.secondary)
      Text(value)
        .font(.body)
    }
    .frame(maxWidth: .infinity, alignment: .leading)
  }
}
