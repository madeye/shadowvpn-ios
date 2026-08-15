import Foundation

/// Shared App Group identifier and the file/`UserDefaults` layout both the app
/// and the packet-tunnel extension use to talk to each other. ShadowVPN's
/// container is far smaller than meow's: there's no Clash YAML, no effective
/// config and no REST-API credentials — just the active state, the traffic
/// snapshot and the tunnel's own log file.
public enum AppGroup {
    public static let identifier = "group.com.tangzixiang.shadowvpn"

    /// The shared container both processes can read and write. Force-unwrap is
    /// intentional: a missing container means the App Group entitlement is not
    /// wired, which is a build/provisioning bug that should fail loudly.
    public static var containerURL: URL {
        guard let url = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: identifier,
        ) else {
            fatalError("App Group container unavailable — entitlements missing '\(identifier)'")
        }
        return url
    }

    /// Latest ``VpnState`` JSON, written by the extension and read by the app.
    public static var stateURL: URL {
        containerURL.appending(path: "state.json")
    }

    /// Latest ``TrafficSnapshot`` JSON, written by the extension's traffic pump.
    public static var trafficURL: URL {
        containerURL.appending(path: "traffic.json")
    }

    /// Always-on log file the Rust core writes via `svpn_core_log` (the engine
    /// derives this same path from `svpn_core_set_home_dir(containerURL)` +
    /// `logs/svpn-tunnel.log`). The app can't read the extension's `OSLogStore`,
    /// so this shared file is how `LogsView` tails the tunnel's own output. A
    /// `.1`-suffixed sibling holds the previous rotation.
    public static var tunnelLogURL: URL {
        containerURL.appending(path: "logs", directoryHint: .isDirectory)
            .appending(path: "svpn-tunnel.log")
    }

    /// Directory where the extension caches each country's extracted bypass-CIDR
    /// file (`chnroute-<COUNTRY>-<mmdbLen>.txt`), written by the core's
    /// `svpn_country_cidrs_file` on first use and reused thereafter. Excluded
    /// from backup — it's a regenerable derivative of the bundled mmdb.
    public static var cidrCacheURL: URL {
        containerURL.appending(path: "cidr-cache")
    }

    /// Shared-defaults key holding the flow-diagnostics deadline (epoch
    /// seconds, `Double`). While the deadline is in the future the tunnel logs
    /// per-flow destinations (DNS name / TLS SNI / HTTP host) for debugging;
    /// past or absent means ordinary operation never records them. The app
    /// writes it and posts ``SVPNNotification/diagnostics``; the extension
    /// reads it. Must match `kFlowDiagnosticsUntilKey` in the ObjC provider.
    public static let flowDiagnosticsUntilKey = "flowDiagnosticsUntil"

    /// UserDefaults suite shared between app and extension. Force-unwrap is safe
    /// once entitlements are wired — a missing suite indicates a config bug that
    /// should fail loudly.
    public static var defaults: UserDefaults {
        guard let d = UserDefaults(suiteName: identifier) else {
            fatalError("Shared UserDefaults unavailable for suite '\(identifier)'")
        }
        return d
    }

    /// Mark the persistent profile store as backup-eligible and exclude the
    /// transient files that are regenerated on every tunnel start (state,
    /// traffic, the per-country CIDR cache and the diagnostic log ring).
    public static func configureBackup() {
        setBackupExclusion(containerURL, excluded: false)
        setBackupExclusion(stateURL, excluded: true)
        setBackupExclusion(trafficURL, excluded: true)
        setBackupExclusion(cidrCacheURL, excluded: true)
        setBackupExclusion(tunnelLogURL, excluded: true)
        setBackupExclusion(tunnelLogURL.appendingPathExtension("1"), excluded: true)
    }

    private static func setBackupExclusion(_ url: URL, excluded: Bool) {
        var u = url
        var values = URLResourceValues()
        values.isExcludedFromBackup = excluded
        try? u.setResourceValues(values)
    }
}
