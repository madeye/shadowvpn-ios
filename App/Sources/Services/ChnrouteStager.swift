import Foundation
import os
import SVPNModels

/// Copies the bundled `chnroute.txt` (the ~5.5k China CIDR set) into the App
/// Group container on launch so the packet-tunnel extension can read it from a
/// stable, shared path — handed to the Rust core as `chnroute_path` in
/// `config_json`. Mirrors meow's `GeoAssetStager`, trimmed to a single asset.
///
/// The extension *also* bundles its own copy of `chnroute.txt` (see
/// `project.yml`), so split-route excludedRoutes work even before the app has
/// ever launched. Staging into the App Group is what lets the Rust core read
/// the same CIDR set without re-reading the NE bundle path, and it's where the
/// app reads from for any future route-count display.
///
/// Existing files are left in place unless the bundled copy is newer (by size
/// or modification date) — re-running the stager never clobbers a hand-edited
/// or already-current copy, but a shipped chnroute refresh does propagate.
enum ChnrouteStager {
    private static let log = Logger(
        subsystem: "com.tangzixiang.shadowvpn.app",
        category: "chnroute-stager",
    )

    /// Bundled resource file name. Must match the resource added to both the
    /// app and the PacketTunnel targets in `project.yml`.
    private static let resourceName = "chnroute.txt"

    /// Stage `chnroute.txt` into ``AppGroup/chnrouteURL`` if the destination is
    /// missing or stale relative to the bundled copy. Best-effort: every
    /// failure is logged and swallowed so a staging hiccup never blocks launch
    /// (the extension can still fall back to its own bundled copy).
    static func stageIfNeeded() {
        guard let src = Bundle.main.url(forResource: "chnroute", withExtension: "txt") else {
            log.error("bundle missing \(resourceName, privacy: .public)")
            return
        }
        let dest = AppGroup.chnrouteURL
        let fm = FileManager.default

        // Skip the copy when the staged file already matches the bundled one.
        // Comparing size + mtime is cheap and avoids rewriting 5.5k lines on
        // every cold launch (and the backup-exclusion churn that follows).
        if let srcAttrs = try? fm.attributesOfItem(atPath: src.path),
           let destAttrs = try? fm.attributesOfItem(atPath: dest.path) {
            let srcSize = (srcAttrs[.size] as? Int) ?? -1
            let destSize = (destAttrs[.size] as? Int) ?? -2
            let srcDate = (srcAttrs[.modificationDate] as? Date) ?? .distantFuture
            let destDate = (destAttrs[.modificationDate] as? Date) ?? .distantPast
            if srcSize == destSize, destDate >= srcDate {
                return
            }
        }

        do {
            try fm.createDirectory(
                at: dest.deletingLastPathComponent(),
                withIntermediateDirectories: true,
            )
            if fm.fileExists(atPath: dest.path) {
                try fm.removeItem(at: dest)
            }
            try fm.copyItem(at: src, to: dest)
            log.notice("staged \(resourceName, privacy: .public) -> App Group")
        } catch {
            log.error(
                "stage \(resourceName, privacy: .public) failed: \(error.localizedDescription, privacy: .public)",
            )
        }
    }
}
