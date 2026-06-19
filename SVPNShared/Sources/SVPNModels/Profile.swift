import Foundation

/// AEAD cipher used for the shadowsocks UDP wire scheme. The raw values are the
/// exact shadowsocks names the Rust core parses with `Cipher::from_name`
/// (`crypto.rs`), so a `Profile` serializes straight into the `config_json` the
/// NE hands to `svpn_tun_start` without any name translation.
public enum Cipher: String, Codable, Sendable, CaseIterable, Identifiable {
    case aes128gcm = "aes-128-gcm"
    case aes256gcm = "aes-256-gcm"
    case chacha20poly1305 = "chacha20-poly1305"

    public var id: String { rawValue }

    /// Short, user-facing label for the Settings picker.
    public var displayName: String {
        switch self {
        case .aes128gcm: "AES-128-GCM"
        case .aes256gcm: "AES-256-GCM"
        case .chacha20poly1305: "ChaCha20-Poly1305"
        }
    }
}

/// Split-routing policy for the tunnel. Mirrors `policy::Mode` in the Rust
/// reference; the raw values are the strings `svpn_tun_start` expects in
/// `config_json["mode"]`.
///
///  * ``full`` — everything is tunneled (LAN excepted). No China split.
///  * ``chnroute`` — China CIDRs (`chnroute.txt`) bypass the tunnel; the rest is
///    tunneled. The load-bearing feature; implemented entirely in Swift via
///    `NEPacketTunnelNetworkSettings.excludedRoutes`.
///  * ``chinadns`` — `chnroute` plus the in-FFI split-DNS interceptor that picks
///    a domestic or clean answer per query (`dns_intercept.rs`).
public enum TunnelMode: String, Codable, Sendable, CaseIterable, Identifiable {
    case full
    case chnroute
    case chinadns

    public var id: String { rawValue }

    public var displayName: String {
        switch self {
        case .full: "Full"
        case .chnroute: "China Route"
        case .chinadns: "ChinaDNS"
        }
    }

    /// Whether this mode runs the in-FFI split-DNS interceptor (i.e. needs the
    /// `dns_local` / `dns_remote` upstreams). Only ``chinadns`` does.
    public var usesSplitDNS: Bool { self == .chinadns }
}

/// The user-editable connection profile. Persisted in the App Group via
/// ``SharedStore`` (and `UserDefaults`) and pushed to the NE through
/// `NETunnelProviderProtocol.providerConfiguration`. Defaults match the Rust
/// reference's `config.rs` constants so a freshly created profile is already a
/// valid ChinaDNS setup once a server/password are filled in.
public struct Profile: Codable, Sendable, Equatable, Identifiable {
    /// Stable identifier; survives renames and edits. Used as the persisted
    /// selected-profile key and echoed back in `VpnState.profileID`.
    public var id: UUID

    /// User-visible name shown in the app shell.
    public var name: String

    /// Server hostname or IP (without the port — see ``port``).
    public var server: String

    /// Server UDP port.
    public var port: Int

    /// Pre-shared password; the AEAD master key is derived from it by the core
    /// (`evp_bytes_to_key`). Stored as-is here; the app uses a `SecureField`.
    public var password: String

    /// AEAD cipher.
    public var cipher: Cipher

    /// Split-routing policy.
    public var mode: TunnelMode

    /// Domestic / direct DNS upstream (`host:port`), reached outside the tunnel.
    /// Only meaningful in ``TunnelMode/chinadns``.
    public var dnsLocal: String

    /// Clean DNS upstream (`host:port`), reached through the tunnel. Only
    /// meaningful in ``TunnelMode/chinadns``.
    public var dnsRemote: String

    /// Tunnel MTU. Defaults to 1400 (leaves headroom for the AEAD salt + tag and
    /// the UDP/IP outer headers, matching the Rust default).
    public var mtu: Int

    public init(
        id: UUID = UUID(),
        name: String = "ShadowVPN",
        server: String = "",
        port: Int = 8388,
        password: String = "",
        cipher: Cipher = .chacha20poly1305,
        mode: TunnelMode = .chnroute,
        dnsLocal: String = Profile.defaultDNSLocal,
        dnsRemote: String = Profile.defaultDNSRemote,
        mtu: Int = Profile.defaultMTU,
    ) {
        self.id = id
        self.name = name
        self.server = server
        self.port = port
        self.password = password
        self.cipher = cipher
        self.mode = mode
        self.dnsLocal = dnsLocal
        self.dnsRemote = dnsRemote
        self.mtu = mtu
    }

    // MARK: Defaults (mirror `config.rs`)

    /// 114DNS — the domestic upstream used in ChinaDNS mode.
    public static let defaultDNSLocal = "114.114.114.114:53"
    /// Google DNS — the clean upstream reached through the tunnel.
    public static let defaultDNSRemote = "8.8.8.8:53"
    /// Tunnel MTU default (`DEFAULT_TUN_MTU` in the Rust reference).
    public static let defaultMTU = 1400

    /// `server:port` as the NE expects it (and as `config_json["server"]`).
    public var serverAddress: String {
        "\(server):\(port)"
    }

    /// `true` once the profile has the minimum fields a connection needs.
    public var isComplete: Bool {
        !server.isEmpty && port > 0 && !password.isEmpty
    }
}

public extension Profile {
    /// Build the `config_json` dictionary the NE serializes and passes to
    /// `svpn_tun_start`. The shape matches the C-ABI contract documented in
    /// `DESIGN.md` / `shadowvpn_core.h`:
    ///
    /// ```json
    /// {"server":"host:port","password":"...","cipher":"chacha20-poly1305",
    ///  "mode":"full|chnroute|chinadns","mtu":1400,
    ///  "dns_local":"114.114.114.114:53","dns_remote":"8.8.8.8:53",
    ///  "chnroute_path":"/abs/chnroute.txt"}
    /// ```
    ///
    /// `chnroutePath` is the staged App-Group (or extension-bundle) path to
    /// `chnroute.txt`; pass it only when the mode needs it (`chnroute` /
    /// `chinadns`). Keys are emitted unconditionally except `chnroute_path`, so
    /// the JSON stays stable and predictable for the Rust `serde` deserializer.
    func configJSON(chnroutePath: String? = nil) -> [String: Any] {
        var dict: [String: Any] = [
            "server": serverAddress,
            "password": password,
            "cipher": cipher.rawValue,
            "mode": mode.rawValue,
            "mtu": mtu,
            "dns_local": dnsLocal,
            "dns_remote": dnsRemote,
        ]
        if let chnroutePath, mode != .full {
            dict["chnroute_path"] = chnroutePath
        }
        return dict
    }

    /// Serialize ``configJSON(chnroutePath:)`` to a UTF-8 JSON string, ready to
    /// hand to `svpn_tun_start(_:_:config_json:)`. Sorted keys keep the output
    /// deterministic (useful for logging and tests).
    func configJSONString(chnroutePath: String? = nil) throws -> String {
        let dict = configJSON(chnroutePath: chnroutePath)
        let data = try JSONSerialization.data(
            withJSONObject: dict,
            options: [.sortedKeys],
        )
        guard let string = String(data: data, encoding: .utf8) else {
            throw ProfileError.encodingFailed
        }
        return string
    }
}

/// Errors raised while turning a ``Profile`` into wire form.
public enum ProfileError: Error, Sendable {
    /// The serialized `config_json` was not valid UTF-8 (should never happen).
    case encodingFailed
}
