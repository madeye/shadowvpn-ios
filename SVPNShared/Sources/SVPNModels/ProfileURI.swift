import Foundation

/// Decoder for the `shadowvpn://` configuration URI defined by upstream
/// `madeye/shadowvpn` (`src/uri.rs`, PR #19). The URI is **opaque**: the scheme
/// `shadowvpn://` immediately followed by the URL-safe, unpadded Base64 of the
/// client configuration's JSON (the upstream `FileConfig`):
///
/// ```text
/// shadowvpn://<base64url( FileConfig as JSON )>[#label]
/// ```
///
/// Encoding the whole JSON keeps the format lossless across the CLI and the app.
/// On iOS we only consume the client-relevant subset of `FileConfig` and map it
/// onto a ``Profile`` (the app's own model); server-only and host-specific path
/// fields — `tun_*`, `dns_listen`, `gfwlist`, `chnroute`, `geoip`, `cache_file`,
/// … — are intentionally ignored. A trailing `#fragment`, if present, is used as
/// the new profile's name (upstream treats it as a human label).
///
/// This mirrors upstream `uri::decode`, deliberately reimplemented in Swift
/// rather than vendored through the Rust FFI: the work is a Base64 + JSON decode,
/// and the upstream module pulls in `qrcode`/`rqrr`/`image` (camera scanning is
/// the platform's job on iOS via `AVFoundation`).
public enum ProfileURI {
    /// The URI scheme prefix, including the `://` separator. Matches upstream
    /// `uri::SCHEME`.
    public static let scheme = "shadowvpn://"

    /// Decode a `shadowvpn://` URI into a ``Profile``.
    ///
    /// Surrounding whitespace is tolerated, as is a trailing `#fragment` (some QR
    /// tools append one), so the payload is taken up to the first whitespace or
    /// `#` — matching upstream's tolerant parser.
    public static func profile(from uri: String) throws -> Profile {
        let trimmed = uri.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let body = trimmed.stripping(prefix: scheme) else {
            throw ProfileURIError.scheme
        }

        // Split the Base64 payload from an optional `#label`, stopping at the
        // first whitespace or `#` so stray trailing bytes don't poison decoding.
        let payloadEnd = body.firstIndex { $0 == "#" || $0.isWhitespace } ?? body.endIndex
        let payload = String(body[..<payloadEnd])
        let label = fragment(in: body, after: payloadEnd)

        guard let data = Data(base64URLEncoded: payload) else {
            throw ProfileURIError.base64
        }
        let config: FileConfig
        do {
            config = try JSONDecoder().decode(FileConfig.self, from: data)
        } catch {
            throw ProfileURIError.json(error)
        }
        return config.makeProfile(name: label)
    }

    /// Pull the `#label` fragment (up to the next whitespace) out of `body`,
    /// where `hashStart` is the index of the `#` (or `endIndex` if none).
    private static func fragment(in body: String, after hashStart: String.Index) -> String? {
        guard hashStart < body.endIndex, body[hashStart] == "#" else { return nil }
        let start = body.index(after: hashStart)
        let end = body[start...].firstIndex(where: \.isWhitespace) ?? body.endIndex
        let raw = String(body[start ..< end])
        let decoded = raw.removingPercentEncoding ?? raw
        let cleaned = decoded.trimmingCharacters(in: .whitespacesAndNewlines)
        return cleaned.isEmpty ? nil : cleaned
    }
}

/// Errors raised while decoding a `shadowvpn://` URI. Mirrors the variants of
/// upstream `uri::UriError`.
public enum ProfileURIError: Error, Sendable {
    /// The string did not start with the `shadowvpn://` scheme.
    case scheme
    /// The Base64 payload could not be decoded.
    case base64
    /// The decoded payload was not valid JSON for a configuration.
    case json(any Error)
}

/// The client-relevant subset of upstream's `FileConfig` JSON schema. All fields
/// are optional (upstream omits `None` on serialization), so any subset present
/// in the URI decodes and the rest falls back to ``Profile`` defaults. Unknown
/// keys (server-only fields, local paths) are ignored by `JSONDecoder`.
private struct FileConfig: Decodable {
    /// Server `host:port`.
    var server: String?
    var password: String?
    /// AEAD cipher name (e.g. `"aes-256-gcm"`).
    var cipher: String?
    /// Carrier obfuscation (`"none"` / `"quic"` / `"base64"`).
    var obfs: String?
    /// Policy-routing mode (`"full"` / `"gfwlist"` / `"chinadns"`).
    var mode: String?
    var dnsLocal: String?
    var dnsRemote: String?
    /// Inner tunnel peer IP, serialized by upstream as a dotted-quad string.
    var peerIP: String?
    var mtu: Int?
    /// ISO 3166-1 alpha-2 country selected from the GeoIP database.
    var geoipCountry: String?
    /// Whether the server auto-assigns the tunnel IP (upstream PR #20).
    var autoIP: Bool?

    enum CodingKeys: String, CodingKey {
        case server, password, cipher, obfs, mode, mtu
        case dnsLocal = "dns_local"
        case dnsRemote = "dns_remote"
        case peerIP = "peer_ip"
        case geoipCountry = "geoip_country"
        case autoIP = "auto_ip"
    }

    /// Map the decoded config onto a fresh ``Profile``. Every field is tolerant:
    /// an absent or unrecognized value falls back to the ``Profile`` default, so
    /// a URI from a newer/older or server-flavored config still imports as a
    /// usable client profile. `name` is the URI's `#label`, if any.
    func makeProfile(name: String?) -> Profile {
        let defaults = Profile()
        let (host, port) = Self.splitHostPort(server)

        // iOS supports only `full` and `chinadns`; `gfwlist` (and any unknown
        // mode) falls back to the default, matching Profile's own tolerant
        // decoder.
        let resolvedMode = mode.flatMap(TunnelMode.init(rawValue:)) ?? defaults.mode
        let resolvedCipher = cipher.flatMap { Cipher(rawValue: $0.lowercased()) } ?? defaults.cipher
        let resolvedObfs = obfs.flatMap { Obfuscation(rawValue: $0.lowercased()) } ?? defaults.obfuscation

        let resolvedName = name?.nonEmpty
            ?? host?.nonEmpty
            ?? defaults.name

        return Profile(
            name: resolvedName,
            server: host ?? defaults.server,
            port: port ?? defaults.port,
            password: password ?? defaults.password,
            cipher: resolvedCipher,
            mode: resolvedMode,
            dnsLocal: dnsLocal?.nonEmpty ?? defaults.dnsLocal,
            dnsRemote: dnsRemote?.nonEmpty ?? defaults.dnsRemote,
            mtu: mtu ?? defaults.mtu,
            bypassCountry: geoipCountry?.nonEmpty.map { $0.uppercased() } ?? defaults.bypassCountry,
            obfuscation: resolvedObfs,
            peerIP: peerIP?.nonEmpty ?? defaults.peerIP,
            autoIP: autoIP ?? defaults.autoIP,
        )
    }

    /// Split an upstream `host:port` string into its host and port. Handles a
    /// bracketed IPv6 literal (`[::1]:443`) and a bare host with no port.
    static func splitHostPort(_ server: String?) -> (host: String?, port: Int?) {
        guard let server = server?.trimmingCharacters(in: .whitespaces).nonEmpty else {
            return (nil, nil)
        }
        if server.hasPrefix("["), let close = server.firstIndex(of: "]") {
            let host = String(server[server.index(after: server.startIndex) ..< close])
            let after = server[server.index(after: close)...]
            let port = after.hasPrefix(":") ? Int(after.dropFirst()) : nil
            return (host.nonEmpty, port)
        }
        guard let colon = server.lastIndex(of: ":") else { return (server, nil) }
        let host = String(server[..<colon])
        let port = Int(server[server.index(after: colon)...])
        return (host.nonEmpty ?? server, port)
    }
}

private extension String {
    /// Self with `prefix` removed, or `nil` if it doesn't have that prefix.
    func stripping(prefix: String) -> String? {
        hasPrefix(prefix) ? String(dropFirst(prefix.count)) : nil
    }

    /// `nil` when empty, otherwise self — for chaining default fallbacks.
    var nonEmpty: String? {
        isEmpty ? nil : self
    }
}

private extension Data {
    /// Decode URL-safe, optionally unpadded Base64 (RFC 4648 §5) — the alphabet
    /// upstream emits (`URL_SAFE_NO_PAD`). Translates `-`/`_` back to `+`/`/`,
    /// strips any stray whitespace, and restores the `=` padding Foundation's
    /// strict decoder requires.
    init?(base64URLEncoded string: String) {
        var s = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
            .filter { !$0.isWhitespace }
        let remainder = s.count % 4
        if remainder > 0 {
            s.append(String(repeating: "=", count: 4 - remainder))
        }
        self.init(base64Encoded: s)
    }
}
