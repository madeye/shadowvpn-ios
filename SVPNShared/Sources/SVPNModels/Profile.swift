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

/// Split-routing policy for the tunnel. The raw values are the strings
/// `svpn_tun_start` expects in `config_json["mode"]`.
///
///  * ``full`` — everything is tunneled (LAN + the server itself excepted). No
///    China split.
///  * ``chinadns`` — China CIDRs (`chnroute.txt`) bypass the tunnel and the rest
///    is tunneled, plus the in-FFI split-DNS interceptor that picks a domestic or
///    clean answer per query (`dns_intercept.rs`).
///
/// The standalone "China Route" mode (split routing without DNS handling) was
/// removed; ChinaDNS is the split option. Profiles persisted with the old
/// `chnroute` raw value migrate to ``full`` via ``Profile``'s tolerant decoder.
public enum TunnelMode: String, Codable, Sendable, CaseIterable, Identifiable {
    case full
    case chinadns

    public var id: String { rawValue }

    public var displayName: String {
        switch self {
        case .full: "Full"
        case .chinadns: "ChinaDNS"
        }
    }

    /// Whether this mode runs the in-FFI split-DNS interceptor (i.e. needs the
    /// `dns_local` / `dns_remote` upstreams). Only ``chinadns`` does.
    public var usesSplitDNS: Bool { self == .chinadns }
}

/// Carrier obfuscation applied to each UDP datagram on the wire. The raw values
/// are the strings `svpn_tun_start` expects in `config_json["obfs"]`.
///
///  * ``none`` — the bare `salt ++ AEAD` envelope (default).
///  * ``quic`` — wrap each datagram so it looks like a QUIC 1-RTT (HTTP/3)
///    short-header packet, to evade naive UDP/protocol classification. **The
///    server must apply the matching de-obfuscation** (see DESIGN.md "QUIC obfs")
///    or the tunnel won't pass traffic.
public enum Obfuscation: String, Codable, Sendable, CaseIterable, Identifiable {
    case none
    case quic
    case base64

    public var id: String { rawValue }

    public var displayName: String {
        switch self {
        case .none: "None"
        case .quic: "HTTP/3 (QUIC)"
        case .base64: "Base64 (plain text)"
        }
    }
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

    /// ISO 3166-1 alpha-2 country code whose IP ranges **bypass** the tunnel in
    /// ``TunnelMode/chnroute`` / ``TunnelMode/chinadns``. Derived at runtime from
    /// the bundled MaxMind GeoLite2 Country mmdb (`svpn_country_cidrs_file`,
    /// cached per country), so any country can be the "direct" set — not just
    /// China. Defaults to ``defaultBypassCountry`` (`CN`). Ignored in
    /// ``TunnelMode/full``.
    public var bypassCountry: String

    /// Carrier obfuscation applied to every datagram on the wire (see
    /// ``Obfuscation``). Defaults to ``Obfuscation/none``.
    public var obfuscation: Obfuscation

    /// The tunnel's inner client IPv4 address — what the NE assigns the TUN and
    /// what the server sees as the packet source. **Must equal the server's
    /// `peer_ip`** so the server's `peer_ip/24` route can deliver return traffic
    /// back down the tunnel. Defaults to ``defaultPeerIP`` (`10.9.0.2`), matching
    /// the reference server config. Ignored when ``autoIP`` is on (the server
    /// leases an address instead).
    public var peerIP: String

    /// Whether to let the server **auto-assign** the tunnel IP instead of using
    /// the static ``peerIP`` (upstream PR #20's in-band control channel). When
    /// on, the NE performs a `Control::Request` → `Control::Assign` handshake at
    /// connect time and uses the leased address for the TUN — so one config can
    /// be shared across devices. Requires a server running with `auto_assign`.
    /// Defaults to `false` (static ``peerIP``).
    public var autoIP: Bool

    public init(
        id: UUID = UUID(),
        name: String = "ShadowVPN",
        server: String = "",
        port: Int = 8388,
        password: String = "",
        cipher: Cipher = .chacha20poly1305,
        mode: TunnelMode = .full,
        dnsLocal: String = Profile.defaultDNSLocal,
        dnsRemote: String = Profile.defaultDNSRemote,
        mtu: Int = Profile.defaultMTU,
        bypassCountry: String = Profile.defaultBypassCountry,
        obfuscation: Obfuscation = .none,
        peerIP: String = Profile.defaultPeerIP,
        autoIP: Bool = false,
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
        self.bypassCountry = bypassCountry
        self.obfuscation = obfuscation
        self.peerIP = peerIP
        self.autoIP = autoIP
    }

    /// Tolerant decoder: every field falls back to its default when absent, so a
    /// profile persisted by an older build (before `bypassCountry` existed, say)
    /// still loads instead of throwing on the missing key. Only a type mismatch
    /// fails.
    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d = Profile()
        id = try c.decodeIfPresent(UUID.self, forKey: .id) ?? d.id
        name = try c.decodeIfPresent(String.self, forKey: .name) ?? d.name
        server = try c.decodeIfPresent(String.self, forKey: .server) ?? d.server
        port = try c.decodeIfPresent(Int.self, forKey: .port) ?? d.port
        password = try c.decodeIfPresent(String.self, forKey: .password) ?? d.password
        cipher = try c.decodeIfPresent(Cipher.self, forKey: .cipher) ?? d.cipher
        // Tolerant on `mode`: a missing key OR an unknown raw value (e.g. a
        // profile saved with the removed `chnroute` mode) both fall back to the
        // default rather than throwing and losing the whole profile.
        mode = (try? c.decode(TunnelMode.self, forKey: .mode)) ?? d.mode
        dnsLocal = try c.decodeIfPresent(String.self, forKey: .dnsLocal) ?? d.dnsLocal
        dnsRemote = try c.decodeIfPresent(String.self, forKey: .dnsRemote) ?? d.dnsRemote
        mtu = try c.decodeIfPresent(Int.self, forKey: .mtu) ?? d.mtu
        bypassCountry = try c.decodeIfPresent(String.self, forKey: .bypassCountry) ?? d.bypassCountry
        // Tolerant like `mode`: missing or unknown obfuscation falls back to the
        // default so an older/newer profile still loads.
        obfuscation = (try? c.decode(Obfuscation.self, forKey: .obfuscation)) ?? d.obfuscation
        peerIP = try c.decodeIfPresent(String.self, forKey: .peerIP) ?? d.peerIP
        autoIP = try c.decodeIfPresent(Bool.self, forKey: .autoIP) ?? d.autoIP
    }

    // MARK: Defaults (mirror `config.rs`)

    /// 114DNS — the domestic upstream used in ChinaDNS mode.
    public static let defaultDNSLocal = "114.114.114.114:53"
    /// Google DNS — the clean upstream reached through the tunnel.
    public static let defaultDNSRemote = "8.8.8.8:53"
    /// Tunnel MTU default (`DEFAULT_TUN_MTU` in the Rust reference).
    public static let defaultMTU = 1400
    /// Default bypass country: China (the classic chnroute split-tunnel).
    public static let defaultBypassCountry = "CN"
    /// Default tunnel inner client IP — matches the reference server's `peer_ip`
    /// so return routing works out of the box.
    public static let defaultPeerIP = "10.9.0.2"

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
    ///
    /// Note: the optional `gfwlist_path` (a chinadns force-tunnel override) is
    /// *not* set here — it points at the NE's bundled `gfwlist.txt`, a fixed
    /// resource rather than a profile field, so the extension injects it directly
    /// in `buildConfigJSONFromConfig` at start time.
    func configJSON(chnroutePath: String? = nil) -> [String: Any] {
        var dict: [String: Any] = [
            "server": serverAddress,
            "password": password,
            "cipher": cipher.rawValue,
            "mode": mode.rawValue,
            "mtu": mtu,
            "dns_local": dnsLocal,
            "dns_remote": dnsRemote,
            "obfs": obfuscation.rawValue,
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
