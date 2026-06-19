import SVPNModels
import SwiftUI

/// The ShadowVPN app entry point. Deliberately tiny compared with meow's
/// `MeowApp`: there is no Firebase, no SwiftData model container and no
/// subscription service — ShadowVPN is a single pre-shared-key UDP tunnel, so
/// the only long-lived state is the active ``Profile`` plus the
/// ``VpnManager`` that drives the packet-tunnel extension.
@main
struct ShadowVPNApp: App {
    /// The single source of truth for the app. `@State` keeps it alive for the
    /// process lifetime; it is injected into the environment below so any view
    /// can read the model and the manager it owns.
    @State private var appModel = AppModel()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environment(appModel)
                .environment(appModel.vpnManager)
                // One-shot async bootstrap: stage chnroute.txt into the App
                // Group, load (or create) the NE configuration, and start
                // observing the shared state/traffic files. `.task` runs once
                // when the window first appears and is cancelled on teardown.
                .task { await appModel.bootstrap() }
        }
    }
}
