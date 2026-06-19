import SwiftUI

/// Top-level tabs. ShadowVPN's shell is three screens — Home (connect),
/// Settings (the single profile), Logs (the tunnel's shared file). No
/// subscriptions, traffic charts or connections list like meow.
enum ContentTab: String {
    case home, settings, logs
}

/// The app's root view: a tabbed shell tinted with the app accent. Each tab
/// owns its own `NavigationStack` so titles and any pushed detail views behave
/// independently.
struct ContentView: View {
    @State private var selectedTab: ContentTab = .home

    var body: some View {
        TabView(selection: $selectedTab) {
            NavigationStack { HomeView() }
                .tabItem { Label("tabs.home", systemImage: "house.fill") }
                .accessibilityIdentifier("Home")
                .tag(ContentTab.home)
            NavigationStack { SettingsView() }
                .tabItem { Label("tabs.settings", systemImage: "gearshape.fill") }
                .accessibilityIdentifier("Settings")
                .tag(ContentTab.settings)
            NavigationStack { LogsView() }
                .tabItem { Label("tabs.logs", systemImage: "list.bullet.rectangle.fill") }
                .accessibilityIdentifier("Logs")
                .tag(ContentTab.logs)
        }
        .tint(AppTheme.accent)
    }
}
