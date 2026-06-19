import SwiftUI

/// Shared palette + background styles for the app. Adapted from meow's
/// `AppTheme`; the accent matches the `AccentColor` asset (a slightly deeper
/// blue than meow's) so SwiftUI's `.tint` and the asset agree.
enum AppTheme {
    static let accent = Color(red: 0.10, green: 0.43, blue: 0.86)
    static let connected = Color(red: 0.18, green: 0.64, blue: 0.38)
    static let warning = Color(red: 0.86, green: 0.52, blue: 0.18)
    static let danger = Color(red: 0.86, green: 0.24, blue: 0.24)

    /// Subtle top-to-bottom wash used behind scrollable screens so the
    /// material cards read against a faintly tinted backdrop in both
    /// appearances.
    static var screenBackground: some ShapeStyle {
        LinearGradient(
            colors: [
                Color(uiColor: .systemBackground),
                Color(uiColor: .secondarySystemBackground).opacity(0.72),
            ],
            startPoint: .top,
            endPoint: .bottom,
        )
    }

    /// Accent-tinted fill for the status glyph circle on Home.
    static var iconBackground: some ShapeStyle {
        LinearGradient(
            colors: [
                accent.opacity(0.18),
                accent.opacity(0.07),
            ],
            startPoint: .topLeading,
            endPoint: .bottomTrailing,
        )
    }
}

/// Material container for the app's card surfaces. Mirrors meow's `GlassCard`:
/// `.regularMaterial` with a hairline stroke and a soft shadow so every card
/// renders consistently from iOS 17 up. The API is intentionally a single
/// `@ViewBuilder` slot so call sites (Home tiles, the primary card) stay terse.
struct GlassCard<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        content
            .padding(16)
            .background(
                .regularMaterial,
                in: RoundedRectangle(cornerRadius: 18, style: .continuous),
            )
            .overlay(
                RoundedRectangle(cornerRadius: 18, style: .continuous)
                    .strokeBorder(Color.primary.opacity(0.08), lineWidth: 0.5),
            )
            .shadow(color: .black.opacity(0.045), radius: 8, y: 2)
    }
}
