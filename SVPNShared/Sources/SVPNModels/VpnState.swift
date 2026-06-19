import Foundation

/// Coarse connection lifecycle stage. The app drives its connect toggle and
/// status pill off this; the extension writes it to the shared `state.json`
/// (via ``SharedStore``) and posts a Darwin notification so the app refreshes.
public enum VpnStage: String, Codable, Sendable, CaseIterable {
    case disconnected
    case connecting
    case connected
    case error

    /// Whether a connection attempt is in flight or established — used to drive
    /// the toggle's "on" appearance.
    public var isActive: Bool {
        self == .connecting || self == .connected
    }
}

/// The connection state shared from the extension to the app. Written to the
/// App Group container as JSON; a missing or malformed file is treated as
/// ``VpnStage/disconnected``.
public struct VpnState: Codable, Sendable, Equatable {
    public var stage: VpnStage
    /// Identifier of the ``Profile`` the tunnel was started with, if any.
    public var profileID: String?
    /// Human-readable name of that profile, for display without a profile lookup.
    public var profileName: String?
    /// Populated when ``stage`` is ``VpnStage/error``.
    public var message: String?
    /// When the tunnel reached ``VpnStage/connected``; drives the uptime label.
    public var startedAt: Date?

    public init(
        stage: VpnStage = .disconnected,
        profileID: String? = nil,
        profileName: String? = nil,
        message: String? = nil,
        startedAt: Date? = nil,
    ) {
        self.stage = stage
        self.profileID = profileID
        self.profileName = profileName
        self.message = message
        self.startedAt = startedAt
    }

    /// Convenience for the common disconnected baseline.
    public static let disconnected = VpnState(stage: .disconnected)
}

/// Cumulative traffic counters the extension publishes for the home screen.
/// `*Bytes` are running totals (from `svpn_engine_traffic`), `*Rate` are the
/// per-second deltas the NE host computes between samples. The app reads the
/// latest snapshot from the shared `traffic.json` after each `traffic` Darwin
/// notification.
public struct TrafficSnapshot: Codable, Sendable, Equatable {
    /// Cumulative bytes sent through the tunnel (up).
    public var uploadBytes: Int64
    /// Cumulative bytes received through the tunnel (down).
    public var downloadBytes: Int64
    /// Instantaneous upload rate, bytes/second.
    public var uploadRate: Int64
    /// Instantaneous download rate, bytes/second.
    public var downloadRate: Int64
    /// When this snapshot was taken; used to compute display rates / staleness.
    public var timestamp: Date
    /// Resident physical footprint of the extension in MB (`svpn_resident_bytes`
    /// scaled), so the app can show the NE's memory headroom against the 50 MB
    /// budget. `0` when unavailable (non-Apple platforms).
    public var footprintMB: Int64

    public init(
        uploadBytes: Int64 = 0,
        downloadBytes: Int64 = 0,
        uploadRate: Int64 = 0,
        downloadRate: Int64 = 0,
        timestamp: Date = Date(),
        footprintMB: Int64 = 0,
    ) {
        self.uploadBytes = uploadBytes
        self.downloadBytes = downloadBytes
        self.uploadRate = uploadRate
        self.downloadRate = downloadRate
        self.timestamp = timestamp
        self.footprintMB = footprintMB
    }

    /// The zero snapshot shown before any data arrives.
    public static let empty = TrafficSnapshot()
}
