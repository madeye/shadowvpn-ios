import Foundation
import SVPNModels

/// Reads and writes JSON-encoded state to the App Group container. Both the app
/// and the extension consume this — the writer writes atomically and posts the
/// matching Darwin notification; the reader treats a missing or malformed file
/// as "no data yet" and returns `nil`.
///
/// The `write*` helpers fire the corresponding ``SVPNNotification`` after a
/// successful write so the peer process refreshes without polling.
public enum SharedStore {
    private static let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .secondsSince1970
        return e
    }()

    private static let decoder: JSONDecoder = {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .secondsSince1970
        return d
    }()

    // MARK: VpnState

    /// Persist ``VpnState`` and notify observers (``SVPNNotification/state``).
    public static func writeState(_ state: VpnState) throws {
        let data = try encoder.encode(state)
        try write(data, to: AppGroup.stateURL)
        DarwinBridge.post(.state)
    }

    /// Latest persisted ``VpnState``, or `nil` if none has been written yet.
    public static func readState() -> VpnState? {
        guard let data = try? Data(contentsOf: AppGroup.stateURL) else { return nil }
        return try? decoder.decode(VpnState.self, from: data)
    }

    // MARK: TrafficSnapshot

    /// Persist ``TrafficSnapshot`` and notify (``SVPNNotification/traffic``).
    public static func writeTraffic(_ traffic: TrafficSnapshot) throws {
        let data = try encoder.encode(traffic)
        try write(data, to: AppGroup.trafficURL)
        DarwinBridge.post(.traffic)
    }

    /// Latest persisted ``TrafficSnapshot``, or `nil` if none yet.
    public static func readTraffic() -> TrafficSnapshot? {
        guard let data = try? Data(contentsOf: AppGroup.trafficURL) else { return nil }
        return try? decoder.decode(TrafficSnapshot.self, from: data)
    }

    // MARK: Profile

    /// Persist the active ``Profile`` to the shared `UserDefaults` suite. The
    /// app edits and saves it; the extension reads it at start time to build
    /// the `config_json` for `svpn_tun_start`.
    public static func writeProfile(_ profile: Profile) throws {
        let data = try encoder.encode(profile)
        AppGroup.defaults.set(data, forKey: PreferenceKey.profile)
    }

    /// The persisted active ``Profile``, or `nil` if the user hasn't created one.
    public static func readProfile() -> Profile? {
        guard let data = AppGroup.defaults.data(forKey: PreferenceKey.profile) else { return nil }
        return try? decoder.decode(Profile.self, from: data)
    }

    // MARK: -

    /// Atomically write `data` to `url`, creating the parent directory first
    /// (the `logs/` subtree may not exist on a clean install).
    private static func write(_ data: Data, to url: URL) throws {
        let dir = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try data.write(to: url, options: [.atomic])
    }
}
