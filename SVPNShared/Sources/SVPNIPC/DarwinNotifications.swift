import Foundation

/// Named Darwin notifications (`CFNotificationCenter`) used as the IPC channel
/// between the main app and the packet-tunnel extension. Both processes can post
/// and observe them; the payload itself lives in the shared App Group container
/// (``SharedStore`` JSON files and `UserDefaults`). A notification is just a
/// "go read the container" nudge — there is no inline data.
public enum SVPNNotification: String, Sendable {
    /// The app asked the extension to (re)load its state — used sparingly.
    case command = "com.tangzixiang.shadowvpn.command"
    /// The extension wrote a fresh ``VpnState`` to `state.json`.
    case state = "com.tangzixiang.shadowvpn.state"
    /// The extension wrote a fresh ``TrafficSnapshot`` to `traffic.json`.
    case traffic = "com.tangzixiang.shadowvpn.traffic"

    public var cfName: CFNotificationName {
        CFNotificationName(rawValue as CFString)
    }
}

public enum DarwinBridge {
    /// Post a Darwin notification with no payload. Receivers must read the
    /// shared container (or `UserDefaults`) to obtain the associated data.
    public static func post(_ notification: SVPNNotification) {
        let center = CFNotificationCenterGetDarwinNotifyCenter()
        CFNotificationCenterPostNotification(
            center,
            notification.cfName,
            nil,
            nil,
            true,
        )
    }

    /// Observe a Darwin notification. The closure is invoked when the
    /// notification fires. Returns an opaque ``DarwinObserver`` — retain it
    /// until you no longer want notifications, then pass it to
    /// ``removeObserver(_:)`` (or just let it deallocate).
    @discardableResult
    public static func addObserver(
        for notification: SVPNNotification,
        handler: @escaping @Sendable () -> Void,
    ) -> DarwinObserver {
        let observer = DarwinObserver(notification: notification, handler: handler)
        observer.start()
        return observer
    }

    public static func removeObserver(_ observer: DarwinObserver) {
        observer.stop()
    }
}

/// A live registration with the Darwin notify center. `@unchecked Sendable`
/// because the only mutable state (`token`) is an opaque pointer set once at
/// `start()` and cleared once at `stop()`; the C callback merely re-enters
/// `handler`, which is itself `@Sendable`.
public final class DarwinObserver: @unchecked Sendable {
    private let notification: SVPNNotification
    private let handler: @Sendable () -> Void
    private var token: UnsafeMutableRawPointer?

    init(notification: SVPNNotification, handler: @escaping @Sendable () -> Void) {
        self.notification = notification
        self.handler = handler
    }

    func start() {
        let center = CFNotificationCenterGetDarwinNotifyCenter()
        let unmanaged = Unmanaged.passUnretained(self).toOpaque()
        token = unmanaged
        CFNotificationCenterAddObserver(
            center,
            unmanaged,
            { _, observer, _, _, _ in
                guard let observer else { return }
                let this = Unmanaged<DarwinObserver>.fromOpaque(observer).takeUnretainedValue()
                this.handler()
            },
            notification.rawValue as CFString,
            nil,
            .deliverImmediately,
        )
    }

    func stop() {
        guard let token else { return }
        let center = CFNotificationCenterGetDarwinNotifyCenter()
        CFNotificationCenterRemoveObserver(center, token, notification.cfName, nil)
        self.token = nil
    }

    deinit { stop() }
}
