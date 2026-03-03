//
//  IncidentStoreManager.swift
//  NextGuardAgent
//
//  Manages DLP incident storage, retrieval, and persistence
//  Used by IncidentLogContentView for the incident log UI
//

import SwiftUI
import AppKit

// MARK: - Incident Store Manager

class IncidentStoreManager: ObservableObject {
  static let shared = IncidentStoreManager()

  @Published var incidents: [DLPIncident] = []
  @Published var isLoading = false

  // MARK: - Severity Enum
  enum Severity: String, CaseIterable, Codable {
    case critical = "Critical"
    case high = "High"
    case medium = "Medium"
    case low = "Low"
    case info = "Info"

    var color: Color {
      switch self {
      case .critical: return .red
      case .high: return .orange
      case .medium: return .yellow
      case .low: return .blue
      case .info: return .gray
      }
    }
  }

  // MARK: - DLP Incident Model
  struct DLPIncident: Identifiable, Codable {
    let id: UUID
    var timestamp: Date
    var policyName: String
    var action: String
    var filePath: String
    var destination: String
    var details: String
    var severity: Severity
    var isAcknowledged: Bool

    init(
      id: UUID = UUID(),
      timestamp: Date = Date(),
      policyName: String,
      action: String,
      filePath: String = "",
      destination: String = "",
      details: String = "",
      severity: Severity = .medium,
      isAcknowledged: Bool = false
    ) {
      self.id = id
      self.timestamp = timestamp
      self.policyName = policyName
      self.action = action
      self.filePath = filePath
      self.destination = destination
      self.details = details
      self.severity = severity
      self.isAcknowledged = isAcknowledged
    }
  }

  // MARK: - Persistence Path
  private var storagePath: URL {
    let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
    let dir = support.appendingPathComponent("NextGuard", isDirectory: true)
    try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    return dir.appendingPathComponent("incidents.json")
  }

  // MARK: - Load
  func loadIncidents() {
    isLoading = true
    DispatchQueue.global(qos: .userInitiated).async { [weak self] in
      guard let self = self else { return }
      var loaded: [DLPIncident] = []
      if let data = try? Data(contentsOf: self.storagePath) {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        loaded = (try? decoder.decode([DLPIncident].self, from: data)) ?? []
      }
      DispatchQueue.main.async {
        self.incidents = loaded.sorted { $0.timestamp > $1.timestamp }
        self.isLoading = false
      }
    }
  }

  // MARK: - Save
  private func persist() {
    DispatchQueue.global(qos: .utility).async { [weak self] in
      guard let self = self else { return }
      let encoder = JSONEncoder()
      encoder.dateEncodingStrategy = .iso8601
      encoder.outputFormatting = .prettyPrinted
      if let data = try? encoder.encode(self.incidents) {
        try? data.write(to: self.storagePath, options: .atomic)
      }
    }
  }

  // MARK: - Add Incident
  func addIncident(
    policyName: String,
    action: String,
    filePath: String = "",
    destination: String = "",
    details: String = "",
    severity: Severity = .medium
  ) {
    let incident = DLPIncident(
      policyName: policyName,
      action: action,
      filePath: filePath,
      destination: destination,
      details: details,
      severity: severity
    )
    DispatchQueue.main.async {
      self.incidents.insert(incident, at: 0)
      self.persist()
    }
  }

  // MARK: - Acknowledge
  func acknowledge(id: UUID) {
    if let index = incidents.firstIndex(where: { $0.id == id }) {
      incidents[index].isAcknowledged = true
      persist()
    }
  }

  // MARK: - Clear All
  func clearAll() {
    incidents.removeAll()
    persist()
  }

  // MARK: - Stats
  var todayIncidents: [DLPIncident] {
    incidents.filter { Calendar.current.isDateInToday($0.timestamp) }
  }

  var blockedToday: Int {
    todayIncidents.filter { $0.action == "Block" }.count
  }

  var auditedToday: Int {
    todayIncidents.filter { $0.action == "Audit" }.count
  }
}
