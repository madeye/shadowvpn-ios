import Foundation
import NetworkExtension
import Observation
import SVPNIPC
import SVPNModels

/// Thin observable wrapper around `NETunnelProviderManager` that the SwiftUI
/// layer watches for connect/disconnect, the live ``VpnStage`` and the running
/// traffic counters. A trimmed cousin of meow's `VpnManager`: ShadowVPN has a
/// single PSK tunnel, so there's no proxy-group replay, no REST control plane
/// and no on-demand subtleties beyond the basic reconnect rule.
///
/// Two data sources feed the UI:
///   * `NEVPNStatusDidChange` → ``stage`` (the authoritative connection state
///     from the NE host), with ``connectedDate`` captured on the connected edge
///     for the uptime label.
///   * a Darwin `traffic` notification → re-read ``SharedStore/readTraffic()``
///     into ``traffic`` (the cumulative up/down + per-second rates the
///     extension's traffic pump publishes).
@MainActor
@Observable
final class VpnManager {
    /// Coarse lifecycle stage mirrored from `connection.status`. Drives the
    /// Home toggle and status pill.
    private(set) var stage: VpnStage = .disconnected

    /// Last user-visible error, surfaced as a banner on Home. Either the
    /// localized `NEVPNManagerError` from a failed save/start, or the Rust
    /// failure the extension wrote into shared `state.json` before bailing.
    private(set) var lastError: String?

    /// When the tunnel last reached `.connected`, for the uptime label. `nil`
    /// while disconnected/connecting. Sourced from the extension's persisted
    /// `state.json` when available (survives an app relaunch into a live
    /// tunnel), else captured locally on the connected edge.
    private(set) var connectedDate: Date?

    /// Latest cumulative traffic + per-second rates published by the extension.
    /// Reset to ``TrafficSnapshot/empty`` on disconnect so the Home tiles don't
    /// show a stale total after the tunnel goes down.
    private(set) var traffic: TrafficSnapshot = .empty

    /// Clear the error banner — on user dismissal or at the start of a new
    /// connect attempt.
    func clearError() {
        lastError = nil
    }

    /// Convenience the UI reads for the toggle's "on" state.
    var isConnected: Bool { stage == .connected }

    /// True while a connect/disconnect transition is in flight (toggle spins,
    /// taps are debounced).
    var isInFlight: Bool { stage == .connecting }

    private var manager: NETunnelProviderManager?

    // nonisolated(unsafe): written only from `attach()` on the MainActor, read
    // from `deinit` (nonisolated). NotificationCenter.removeObserver is
    // thread-safe, so a torn read of the pointer here is harmless.
    private nonisolated(unsafe) var statusObserver: NSObjectProtocol?

    /// Retained Darwin observers for the cross-process traffic/state nudges.
    /// Held for the manager's lifetime; torn down in `deinit`.
    ///
    /// `nonisolated(unsafe)`: assigned only from `startObserving()` on the
    /// MainActor, read from the nonisolated `deinit`. `DarwinObserver` is
    /// `Sendable` and `DarwinBridge.removeObserver` is thread-safe, so reading
    /// the reference off-actor at teardown is safe (mirrors `statusObserver`).
    private nonisolated(unsafe) var trafficObserver: DarwinObserver?
    private nonisolated(unsafe) var stateObserver: DarwinObserver?

    /// Bundle identifier of the packet-tunnel extension. Must match the
    /// `PRODUCT_BUNDLE_IDENTIFIER` of the `PacketTunnel` target in `project.yml`.
    private static let providerBundleID = "com.tangzixiang.shadowvpn.PacketTunnel"

    deinit {
        if let statusObserver {
            NotificationCenter.default.removeObserver(statusObserver)
        }
        // DarwinObserver removes itself in its own deinit, but unregister
        // explicitly through the public bridge API so teardown is
        // deterministic and doesn't rely on dealloc timing.
        if let trafficObserver {
            DarwinBridge.removeObserver(trafficObserver)
        }
        if let stateObserver {
            DarwinBridge.removeObserver(stateObserver)
        }
    }

    // MARK: - Lifecycle wiring

    /// Begin observing the shared traffic/state files. Called once from
    /// `AppModel.bootstrap()`. Reads the current persisted snapshots so the UI
    /// is populated immediately on launch (e.g. relaunch into a live tunnel)
    /// rather than waiting for the next notification.
    func startObserving() {
        if let snapshot = SharedStore.readTraffic() {
            traffic = snapshot
        }
        if let state = SharedStore.readState() {
            applyExtensionState(state)
        }
        trafficObserver = DarwinBridge.addObserver(for: .traffic) { [weak self] in
            // CFNotificationCenter delivers on the main run loop here, but hop
            // to the MainActor explicitly to satisfy strict concurrency and to
            // keep all model mutation on the one actor.
            Task { @MainActor in self?.refreshTraffic() }
        }
        stateObserver = DarwinBridge.addObserver(for: .state) { [weak self] in
            Task { @MainActor in
                guard let state = SharedStore.readState() else { return }
                self?.applyExtensionState(state)
            }
        }
    }

    /// Re-read the latest ``TrafficSnapshot`` from the App Group. Cheap JSON
    /// read; runs on every `traffic` Darwin notification (~1 Hz).
    private func refreshTraffic() {
        guard let snapshot = SharedStore.readTraffic() else { return }
        traffic = snapshot
    }

    // MARK: - Manager load / install

    /// Load (or create) the packet-tunnel configuration. Called on app launch
    /// and after the user edits the profile.
    ///
    /// Critical (same rule meow documents): when an existing profile is found,
    /// attach without re-saving. iOS allows only one VPN profile in the active
    /// slot — calling `saveToPreferences()` with `isEnabled = true` re-claims
    /// that slot, deactivating whatever other VPN app held it. Doing that on
    /// every cold launch is how "opening ShadowVPN disconnects my other VPN"
    /// regressions appear. The slot is claimed only by explicit user actions
    /// (`connect()`, or the first-install branch here).
    func refresh() async {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            if let existing = managers.first {
                attach(existing)
            } else {
                let mgr = NETunnelProviderManager()
                configure(mgr, with: SharedStore.readProfile())
                try await mgr.saveToPreferences()
                try await mgr.loadFromPreferences()
                attach(mgr)
            }
        } catch {
            lastError = error.localizedDescription
            stage = .error
        }
    }

    /// Push the current ``Profile`` into the live NE configuration without
    /// starting the tunnel. Called after the user saves edits in Settings so
    /// the next connect (or an on-demand reconnect) uses the new server/cipher.
    /// No-op until a manager has been loaded.
    func updateConfiguration(with profile: Profile) async {
        if manager == nil { await refresh() }
        guard let manager else { return }
        configure(manager, with: profile)
        do {
            try await manager.saveToPreferences()
            try await manager.loadFromPreferences()
        } catch {
            lastError = error.localizedDescription
        }
    }

    // MARK: - Connect / disconnect

    /// Bring the tunnel up with the supplied ``Profile``. Persists the profile
    /// into both the App Group (so the extension can read it at start) and the
    /// `providerConfiguration`, claims the active VPN slot, then starts.
    func connect(profile: Profile) async {
        lastError = nil
        // Persist so the extension reads the freshest profile at start time —
        // providerConfiguration carries it too, but writing the App Group copy
        // keeps the two in lock-step and is what an on-demand restart reads.
        try? SharedStore.writeProfile(profile)

        if manager == nil { await refresh() }
        guard let manager else { return }
        configure(manager, with: profile)
        do {
            manager.isEnabled = true
            // A connect rule lets iOS resurrect the tunnel after it reclaims
            // the NE under memory/CPU pressure — invisible to the user.
            if (manager.onDemandRules ?? []).isEmpty {
                manager.onDemandRules = [NEOnDemandRuleConnect()]
            }
            let prefs = Preferences.load(from: AppGroup.defaults)
            manager.isOnDemandEnabled = prefs.onDemand
            try await manager.saveToPreferences()
            try await manager.loadFromPreferences()
            try manager.connection.startVPNTunnel()
        } catch {
            lastError = error.localizedDescription
            stage = .error
        }
    }

    /// Tear the tunnel down. Disables on-demand first so iOS doesn't
    /// immediately auto-reconnect when the user deliberately turns the VPN off.
    func disconnect() async {
        guard let manager else { return }
        if manager.isOnDemandEnabled {
            manager.isOnDemandEnabled = false
            try? await manager.saveToPreferences()
        }
        manager.connection.stopVPNTunnel()
    }

    // MARK: - Private

    /// Stamp the `NETunnelProviderProtocol` from a ``Profile``. The
    /// `serverAddress` carries the real `host:port` (ShadowVPN, unlike meow,
    /// connects to a concrete UDP endpoint), and the whole profile is mirrored
    /// into `providerConfiguration` so the extension can rebuild `config_json`
    /// for `svpn_tun_start` even if the App Group copy is somehow absent.
    private func configure(_ mgr: NETunnelProviderManager, with profile: Profile?) {
        let proto = (mgr.protocolConfiguration as? NETunnelProviderProtocol) ?? NETunnelProviderProtocol()
        proto.providerBundleIdentifier = Self.providerBundleID
        // ShadowVPN dials a concrete UDP server; use the profile's host:port as
        // the remote address. Fall back to an RFC 5737 TEST-NET placeholder
        // when no profile exists yet — iOS rejects an empty/invalid remote
        // address at NEPacketTunnelNetworkSettings construction time.
        proto.serverAddress = (profile?.server.isEmpty == false)
            ? profile!.serverAddress
            : "192.0.2.1"
        // Mirror every Profile field the extension needs. Values are plain
        // strings/ints so the dictionary round-trips through the NE keychain
        // store cleanly. The extension prefers the App Group Profile JSON but
        // can reconstruct from these as a fallback.
        var config: [String: Any] = ["appGroup": AppGroup.identifier]
        if let profile {
            config["server"] = profile.serverAddress
            config["password"] = profile.password
            config["cipher"] = profile.cipher.rawValue
            config["mode"] = profile.mode.rawValue
            config["mtu"] = profile.mtu
            config["dns_local"] = profile.dnsLocal
            config["dns_remote"] = profile.dnsRemote
            config["profileID"] = profile.id.uuidString
            config["profileName"] = profile.name
        }
        proto.providerConfiguration = config
        // Keep the tunnel alive across screen lock; iOS defaults this to false
        // for packet-tunnel providers, so set it explicitly.
        proto.disconnectOnSleep = false
        mgr.protocolConfiguration = proto
        mgr.localizedDescription = profile?.name ?? "ShadowVPN"
        mgr.isEnabled = true
    }

    /// Adopt a manager: record the initial status (a relaunch into an
    /// already-connected tunnel is NOT an observed `.NEVPNStatusDidChange`
    /// edge, so seed from `connection.status` directly) and subscribe to status
    /// changes.
    private func attach(_ mgr: NETunnelProviderManager) {
        manager = mgr
        applyConnectionStatus(mgr.connection.status)
        if let statusObserver { NotificationCenter.default.removeObserver(statusObserver) }
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: mgr.connection,
            queue: .main,
        ) { [weak self] _ in
            guard let self else { return }
            let status = mgr.connection.status
            Task { @MainActor in
                // When the extension aborts startup (svpn_tun_start fails) the
                // connection drops to .disconnected with no thrown NE error —
                // the provider wrote the Rust reason into state.json first, so
                // surface it here instead of a silently reverting toggle.
                if status == .disconnected,
                   let msg = SharedStore.readState()?.message, !msg.isEmpty {
                    self.lastError = msg
                }
                self.applyConnectionStatus(status)
            }
        }
    }

    /// Map a raw `NEVPNStatus` onto ``stage`` and maintain ``connectedDate`` /
    /// reset ``traffic`` across edges.
    private func applyConnectionStatus(_ status: NEVPNStatus) {
        let next = Self.map(status)
        let wasConnected = stage == .connected
        stage = next
        switch next {
        case .connected:
            if !wasConnected {
                // Prefer the extension's persisted start time (accurate across
                // a relaunch into a live tunnel); fall back to now.
                connectedDate = SharedStore.readState()?.startedAt ?? Date()
            }
        case .disconnected, .error:
            connectedDate = nil
            traffic = .empty
        case .connecting:
            break
        }
    }

    /// Reflect a state snapshot the extension wrote (carries the authoritative
    /// stage, error message and start time across processes).
    private func applyExtensionState(_ state: VpnState) {
        stage = state.stage
        if let started = state.startedAt {
            connectedDate = started
        }
        if let msg = state.message, !msg.isEmpty {
            lastError = msg
        }
        if state.stage == .disconnected || state.stage == .error {
            connectedDate = nil
        }
    }

    /// Pure mapping from the NE status enum to our coarse ``VpnStage``.
    /// `nonisolated static` so it has no actor affinity — it touches no state.
    private nonisolated static func map(_ status: NEVPNStatus) -> VpnStage {
        switch status {
        case .invalid, .disconnected: .disconnected
        case .connecting, .reasserting, .disconnecting: .connecting
        case .connected: .connected
        @unknown default: .disconnected
        }
    }
}
