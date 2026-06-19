import SVPNModels
import SwiftUI

/// The diagnostics screen. The packet-tunnel extension lives in its own process
/// whose `OSLogStore` the app can't read, so the Rust core mirrors every
/// `svpn_core_log` line into a shared App-Group file
/// (``AppGroup/tunnelLogURL``). This view tails that file: it reads the tail on
/// appear, re-reads on a light timer while visible, and offers copy / share /
/// clear actions. There's no live streaming socket — a periodic re-read of a
/// small rotating log is plenty for a hand-held diagnostics pane and keeps the
/// app fully decoupled from the extension's lifecycle.
struct LogsView: View {
    /// How many trailing bytes of the log file to surface. The core rotates the
    /// file well under this, so in practice we read the whole current segment;
    /// the cap only guards against an unexpectedly large file.
    private static let tailByteLimit = 256 * 1024

    /// Re-read cadence while the screen is on-screen. Slow enough to be free,
    /// fast enough that a fresh connect/disconnect shows up promptly.
    private static let refreshInterval: TimeInterval = 2

    @State private var lines: [LogLine] = []
    @State private var isEmpty = true
    /// Drives the periodic re-read; only fires while the view is visible.
    @State private var ticker = Timer.publish(
        every: refreshInterval,
        on: .main,
        in: .common,
    ).autoconnect()

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 0) {
                    if isEmpty {
                        emptyState
                    } else {
                        ForEach(lines) { line in
                            LogRow(line: line)
                                .id(line.id)
                        }
                        // Anchor the auto-scroll-to-bottom on a trailing marker.
                        Color.clear
                            .frame(height: 1)
                            .id(Self.bottomAnchor)
                    }
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .background(AppTheme.screenBackground)
            .scrollContentBackground(.hidden)
            .onChange(of: lines.count) { _, _ in
                // Keep the newest line in view as the tail grows.
                guard !lines.isEmpty else { return }
                withAnimation(.easeOut(duration: 0.2)) {
                    proxy.scrollTo(Self.bottomAnchor, anchor: .bottom)
                }
            }
        }
        .navigationTitle("logs.nav.title")
        .toolbar { toolbarContent }
        .onAppear {
            reload()
            // Restart the publisher each time the tab becomes visible so we're
            // not burning a timer while the user sits on Home or Settings.
            ticker = Timer.publish(every: Self.refreshInterval, on: .main, in: .common)
                .autoconnect()
        }
        .onReceive(ticker) { _ in reload() }
    }

    // MARK: - Empty state

    private var emptyState: some View {
        VStack(spacing: 12) {
            Image(systemName: "doc.text.magnifyingglass")
                .font(.system(size: 40, weight: .light))
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            Text("logs.empty.title")
                .font(.headline)
            Text("logs.empty.subtitle")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity)
        .padding(.top, 64)
        .padding(.horizontal, 24)
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("logs.empty")
    }

    // MARK: - Toolbar

    @ToolbarContentBuilder
    private var toolbarContent: some ToolbarContent {
        ToolbarItemGroup(placement: .topBarTrailing) {
            if !isEmpty {
                // Share the full file (not just the rendered tail) so a bug
                // report carries the complete current segment.
                ShareLink(item: AppGroup.tunnelLogURL) {
                    Image(systemName: "square.and.arrow.up")
                }
                .accessibilityIdentifier("logs.action.share")

                Button(role: .destructive, action: clear) {
                    Image(systemName: "trash")
                }
                .accessibilityLabel("logs.action.clear")
                .accessibilityIdentifier("logs.action.clear")
            }
        }
    }

    // MARK: - File I/O

    /// Read the tail of the shared log file and split it into rows. Cheap enough
    /// to run on the main actor: the file is small and capped by
    /// ``tailByteLimit``. A missing file (tunnel never started) is the normal
    /// empty state, not an error.
    private func reload() {
        let url = AppGroup.tunnelLogURL
        guard let data = try? Data(contentsOf: url, options: .mappedIfSafe),
              !data.isEmpty
        else {
            if !isEmpty { isEmpty = true }
            if !lines.isEmpty { lines = [] }
            return
        }

        // Keep only the trailing window so a long-lived tunnel doesn't blow the
        // view up; drop a partial first line after truncation.
        let window = data.count > Self.tailByteLimit
            ? data.suffix(Self.tailByteLimit)
            : data
        let text = String(decoding: window, as: UTF8.self)
        var rows = text
            .split(separator: "\n", omittingEmptySubsequences: false)
            .map(String.init)
        if data.count > Self.tailByteLimit, rows.count > 1 {
            rows.removeFirst()
        }
        // Drop a trailing empty element from a final newline.
        if rows.last?.isEmpty == true {
            rows.removeLast()
        }

        let parsed = rows.enumerated().map { LogLine(index: $0.offset, raw: $0.element) }
        if parsed != lines { lines = parsed }
        let empty = parsed.isEmpty
        if empty != isEmpty { isEmpty = empty }
    }

    /// Truncate the shared log file in place. Writing empty `Data` keeps the
    /// path stable so the extension's next `svpn_core_log` append still lands
    /// in the file the app is tailing.
    private func clear() {
        try? Data().write(to: AppGroup.tunnelLogURL, options: .atomic)
        lines = []
        isEmpty = true
    }

    /// Stable id for the trailing scroll anchor.
    private static let bottomAnchor = "logs.bottom"
}

// MARK: - Model

/// One rendered log line. The core writes `LEVEL  message`-style lines; we keep
/// the raw text but sniff a leading severity token so rows can be tinted without
/// imposing a strict format on the Rust side.
private struct LogLine: Identifiable, Equatable {
    let id: Int
    let raw: String
    let level: LogLevel

    init(index: Int, raw: String) {
        id = index
        self.raw = raw
        level = LogLevel(sniffing: raw)
    }
}

/// Coarse severity inferred from the line text, used only for the dot color.
private enum LogLevel {
    case error, warn, info, debug

    init(sniffing line: String) {
        let upper = line.uppercased()
        if upper.contains("ERROR") || upper.contains(" ERR ") {
            self = .error
        } else if upper.contains("WARN") {
            self = .warn
        } else if upper.contains("DEBUG") || upper.contains("TRACE") {
            self = .debug
        } else {
            self = .info
        }
    }

    var color: Color {
        switch self {
        case .error: AppTheme.danger
        case .warn: AppTheme.warning
        case .info: AppTheme.accent
        case .debug: .secondary
        }
    }
}

// MARK: - Row

/// A single monospaced log row with a leading severity dot. Selectable so the
/// user can copy individual lines; the whole file is also shareable from the
/// toolbar.
private struct LogRow: View {
    let line: LogLine

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Circle()
                .fill(line.level.color)
                .frame(width: 6, height: 6)
                .padding(.top, 5)
                .accessibilityHidden(true)
            Text(verbatim: line.raw)
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(.primary)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.vertical, 2)
    }
}
