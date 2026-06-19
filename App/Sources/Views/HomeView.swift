import SVPNModels
import SwiftUI

/// The connect screen. A single primary card (status glyph, profile name, the
/// up/down totals and the connect toggle) sits above the live traffic tiles and
/// a server/mode summary. Reads the model's ``Profile`` and the manager's stage
/// + traffic; all mutation goes back through ``AppModel``.
struct HomeView: View {
    @Environment(AppModel.self) private var appModel
    @Environment(VpnManager.self) private var vpnManager

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                if let message = vpnManager.lastError {
                    errorBanner(message)
                }
                primaryCard
                trafficRow
                summaryCard
            }
            .padding(16)
        }
        .background(AppTheme.screenBackground)
        .scrollContentBackground(.hidden)
        .navigationTitle("home.nav.title")
    }

    // MARK: - Error banner

    private func errorBanner(_ message: String) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text("home.error.tunnelFailed.title")
                    .font(.subheadline.weight(.semibold))
                Text(message)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
            .accessibilityElement(children: .combine)
            Spacer(minLength: 8)
            Button {
                vpnManager.clearError()
            } label: {
                Image(systemName: "xmark.circle.fill")
                    .foregroundStyle(.secondary)
                    .frame(minWidth: 44, minHeight: 44)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel("home.error.dismiss")
            .accessibilityIdentifier("home.error.dismiss")
        }
        .padding(12)
        .background(.regularMaterial, in: .rect(cornerRadius: 12))
        .accessibilityIdentifier("home.error.banner")
    }

    // MARK: - Primary card

    private var primaryCard: some View {
        GlassCard {
            VStack(alignment: .leading, spacing: 18) {
                HStack(alignment: .center, spacing: 14) {
                    StatusGlyph(stage: vpnManager.stage)
                    VStack(alignment: .leading, spacing: 4) {
                        Text(stageBadgeText)
                            .font(.title2.weight(.semibold))
                            .accessibilityIdentifier("home.badge.state")
                        Text(profileName)
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                            .accessibilityIdentifier("home.profile.name")
                    }
                    Spacer()
                }

                if vpnManager.isConnected, let started = vpnManager.connectedDate {
                    // Live-updating uptime; `Text(_:style:)` ticks itself.
                    Label {
                        Text(started, style: .timer)
                            .font(.subheadline.monospacedDigit())
                    } icon: {
                        Image(systemName: "clock")
                    }
                    .foregroundStyle(.secondary)
                    .accessibilityIdentifier("home.uptime")
                }

                vpnToggle
            }
        }
    }

    private var vpnToggle: some View {
        Button(action: toggle) {
            HStack(spacing: 8) {
                if vpnManager.isInFlight {
                    ProgressView().controlSize(.small).tint(.white)
                        .accessibilityHidden(true)
                }
                Image(systemName: vpnManager.isConnected ? "power.circle.fill" : "power.circle")
                    .imageScale(.large)
                    .accessibilityHidden(true)
                Text(toggleTitle)
                    .font(.headline)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 14)
        }
        .buttonStyle(.borderedProminent)
        .buttonBorderShape(.capsule)
        .tint(toggleTint)
        .disabled(toggleDisabled)
        .accessibilityIdentifier("home.toggle.vpn")
    }

    // MARK: - Traffic row

    private var trafficRow: some View {
        HStack(spacing: 12) {
            TrafficTile(
                title: "home.traffic.upload",
                bytes: vpnManager.traffic.uploadBytes,
                rate: vpnManager.traffic.uploadRate,
                systemImage: "arrow.up",
            )
            TrafficTile(
                title: "home.traffic.download",
                bytes: vpnManager.traffic.downloadBytes,
                rate: vpnManager.traffic.downloadRate,
                systemImage: "arrow.down",
            )
        }
    }

    // MARK: - Server / mode summary

    private var summaryCard: some View {
        GlassCard {
            VStack(spacing: 0) {
                SummaryRow(
                    systemImage: "server.rack",
                    title: "home.summary.server",
                    value: serverSummary,
                    identifier: "home.summary.server",
                )
                Divider().padding(.leading, 42)
                SummaryRow(
                    systemImage: "arrow.triangle.swap",
                    title: "home.summary.mode",
                    value: Text(appModel.profile.mode.displayName),
                    identifier: "home.summary.mode",
                )
                Divider().padding(.leading, 42)
                SummaryRow(
                    systemImage: "lock.shield",
                    title: "home.summary.cipher",
                    value: Text(appModel.profile.cipher.displayName),
                    identifier: "home.summary.cipher",
                )
            }
        }
    }

    private var serverSummary: Text {
        let p = appModel.profile
        if p.server.isEmpty {
            return Text("home.summary.noServer")
        }
        return Text(verbatim: p.serverAddress)
    }

    // MARK: - Derived state

    private var profileName: String {
        let name = appModel.profile.name
        return name.isEmpty ? String(localized: "home.profile.none") : name
    }

    private var stageBadgeText: LocalizedStringKey {
        switch vpnManager.stage {
        case .disconnected, .error: "home.badge.disconnected"
        case .connecting: "home.badge.connecting"
        case .connected: "home.badge.connected"
        }
    }

    private var toggleTitle: LocalizedStringKey {
        switch vpnManager.stage {
        case .connected: "home.toggle.disconnect"
        case .connecting: "home.toggle.connecting"
        default: "home.toggle.connect"
        }
    }

    private var toggleTint: Color {
        switch vpnManager.stage {
        case .connected, .error: AppTheme.danger
        case .connecting: AppTheme.warning
        case .disconnected: AppTheme.accent
        }
    }

    private var toggleDisabled: Bool {
        if vpnManager.isInFlight { return true }
        if vpnManager.isConnected { return false }
        // Can't connect an incomplete profile — nudge the user to Settings.
        return !appModel.profile.isComplete
    }

    // MARK: - Actions

    private func toggle() {
        if vpnManager.isConnected {
            Task { await appModel.disconnect() }
        } else {
            Task { await appModel.connect() }
        }
    }
}

// MARK: - Subviews

/// Circular status icon with a small colored dot indicating the live stage.
private struct StatusGlyph: View {
    let stage: VpnStage

    var body: some View {
        ZStack {
            Circle()
                .fill(AppTheme.iconBackground)
                .frame(width: 54, height: 54)
            Image(systemName: symbol)
                .font(.title3.weight(.semibold))
                .foregroundStyle(color)
        }
        .overlay(alignment: .bottomTrailing) {
            StageDot(stage: stage)
                .background(.background, in: Circle())
        }
        .accessibilityHidden(true)
    }

    private var symbol: String {
        switch stage {
        case .connected: "checkmark.shield.fill"
        case .connecting: "bolt.horizontal.circle.fill"
        case .error: "exclamationmark.triangle.fill"
        case .disconnected: "shield"
        }
    }

    private var color: Color {
        switch stage {
        case .connected: AppTheme.connected
        case .connecting: AppTheme.warning
        case .error: AppTheme.danger
        case .disconnected: AppTheme.accent
        }
    }
}

/// Small glowing dot for the status glyph's corner badge.
private struct StageDot: View {
    let stage: VpnStage

    var body: some View {
        Circle()
            .fill(color)
            .frame(width: 10, height: 10)
            .shadow(color: color.opacity(0.6), radius: 6)
    }

    private var color: Color {
        switch stage {
        case .disconnected: .secondary
        case .connecting: AppTheme.warning
        case .connected: AppTheme.connected
        case .error: AppTheme.danger
        }
    }
}

/// A traffic tile: the per-second rate big, the cumulative total small beneath.
private struct TrafficTile: View {
    let title: LocalizedStringKey
    let bytes: Int64
    let rate: Int64
    let systemImage: String

    var body: some View {
        GlassCard {
            VStack(alignment: .leading, spacing: 6) {
                Label(title, systemImage: systemImage)
                    .font(.caption.smallCaps())
                    .foregroundStyle(.secondary)
                Text(ByteCountFormatter.string(fromByteCount: rate, countStyle: .binary) + "/s")
                    .font(.title3.bold())
                    .monospacedDigit()
                Text(
                    "home.traffic.total \(ByteCountFormatter.string(fromByteCount: bytes, countStyle: .binary))",
                    comment: "Total bytes label under the rate display; %@ = formatted byte count",
                )
                .font(.caption)
                .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.updatesFrequently)
    }
}

/// A labeled summary row inside the server/mode card.
private struct SummaryRow: View {
    let systemImage: String
    let title: LocalizedStringKey
    let value: Text
    let identifier: String

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: systemImage)
                .foregroundStyle(AppTheme.accent)
                .frame(width: 30, height: 30)
                .background(AppTheme.accent.opacity(0.10), in: Circle())
                .accessibilityHidden(true)
            Text(title)
                .font(.subheadline)
                .foregroundStyle(.primary)
            Spacer(minLength: 8)
            value
                .font(.subheadline.monospacedDigit())
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
        }
        .frame(minHeight: 44)
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier(identifier)
    }
}
