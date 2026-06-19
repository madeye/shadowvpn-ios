import Foundation
import Observation
import os
import SVPNIPC
import SVPNModels

/// Top-level observable that wires the app's long-lived state together and runs
/// first-launch setup. ShadowVPN's model is small: it owns the single editable
/// ``Profile`` and the ``VpnManager`` that drives the packet-tunnel extension.
/// There is no SwiftData store, no subscription service and no REST control
/// plane — the profile is a single Codable value persisted in the App Group.
@MainActor
@Observable
final class AppModel {
    /// The single connection profile the user edits in Settings and connects
    /// with from Home. Loaded from the App Group on launch (or a fresh default
    /// for a clean install). Mutations route through ``updateProfile(_:)`` so
    /// every edit is persisted and pushed into the NE configuration.
    private(set) var profile: Profile

    /// Drives the tunnel and publishes connection state + live traffic.
    let vpnManager: VpnManager

    private let log = Logger(subsystem: "com.tangzixiang.shadowvpn.app", category: "app-model")
    private var didBootstrap = false

    init() {
        // Restore the persisted profile, or seed a fresh ChinaDNS-ready default
        // (the Profile initializer already mirrors the Rust config defaults, so
        // a new profile only needs a server + password filled in).
        profile = SharedStore.readProfile() ?? Profile()
        vpnManager = VpnManager()
    }

    /// One-shot async setup. Idempotent — the `.task` modifier can re-invoke it
    /// across scene rebuilds, so the `didBootstrap` guard makes the body run at
    /// most once per process.
    func bootstrap() async {
        guard !didBootstrap else { return }
        didBootstrap = true

        // Mark the persistent profile store as backup-eligible and exclude the
        // transient state/traffic/log/chnroute files (mirrors meow).
        AppGroup.configureBackup()
        // Stage chnroute.txt into the App Group so the extension can read the
        // China CIDR set from a stable shared path.
        ChnrouteStager.stageIfNeeded()
        // Persist the (possibly defaulted) profile so the extension always has
        // a copy to read at start time even on a brand-new install.
        try? SharedStore.writeProfile(profile)

        // Load (or install) the NE configuration and seed the initial stage.
        await vpnManager.refresh()
        // Begin watching the shared traffic/state files for live updates.
        vpnManager.startObserving()

        log.notice("bootstrap complete — profile=\(self.profile.name, privacy: .public)")
    }

    /// Apply an edited profile: update the in-memory copy, persist it to the
    /// App Group, and push it into the live NE configuration so the next
    /// connect (or on-demand restart) uses the new settings. Called from the
    /// Settings form's save path.
    func updateProfile(_ newProfile: Profile) {
        profile = newProfile
        do {
            try SharedStore.writeProfile(newProfile)
        } catch {
            log.error("persist profile failed: \(error.localizedDescription, privacy: .public)")
        }
        Task { await vpnManager.updateConfiguration(with: newProfile) }
    }

    /// Connect using the current profile. No-op (with a surfaced error) when
    /// the profile is incomplete — Home keeps the toggle disabled in that case,
    /// but guard here too so a programmatic call can't start an empty tunnel.
    func connect() async {
        guard profile.isComplete else {
            vpnManager.clearError()
            log.error("connect blocked — profile incomplete")
            return
        }
        await vpnManager.connect(profile: profile)
    }

    /// Disconnect the tunnel.
    func disconnect() async {
        await vpnManager.disconnect()
    }
}
