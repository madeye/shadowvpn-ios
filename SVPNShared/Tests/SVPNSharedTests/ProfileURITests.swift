import Foundation
@testable import SVPNModels
import Testing

@Suite("shadowvpn:// URI decoding")
struct ProfileURITests {
    /// Build a `shadowvpn://` URI from a config JSON object the way upstream
    /// does: URL-safe, unpadded Base64 of the JSON, prefixed with the scheme.
    private func makeURI(_ json: [String: Any], fragment: String? = nil) throws -> String {
        let data = try JSONSerialization.data(withJSONObject: json)
        var b64 = data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
        b64 = b64.replacingOccurrences(of: "=", with: "") // unpadded
        var uri = "shadowvpn://\(b64)"
        if let fragment { uri += "#\(fragment)" }
        return uri
    }

    @Test
    func `decodes a full client config into a profile`() throws {
        let uri = try makeURI([
            "server": "sf1.maxlv.net:443",
            "password": "pYGmRwycA/vVnoNlXg5aK2in5Tamsw4K",
            "cipher": "chacha20-poly1305",
            "obfs": "quic",
            "mode": "chinadns",
            "dns_local": "223.5.5.5:53",
            "dns_remote": "1.1.1.1:53",
            "peer_ip": "10.9.0.2",
            "mtu": 1380,
            "geoip_country": "CN",
            // server-only / host-specific keys must be ignored, not rejected:
            "tun_ip": "10.9.0.1",
            "geoip": "/opt/svpn/GeoLite2-Country.mmdb",
            "set_dns": true,
        ], fragment: "sf1-chinadns")

        let profile = try ProfileURI.profile(from: uri)
        #expect(profile.server == "sf1.maxlv.net")
        #expect(profile.port == 443)
        #expect(profile.password == "pYGmRwycA/vVnoNlXg5aK2in5Tamsw4K")
        #expect(profile.cipher == .chacha20poly1305)
        #expect(profile.obfuscation == .quic)
        #expect(profile.mode == .chinadns)
        #expect(profile.dnsLocal == "223.5.5.5:53")
        #expect(profile.dnsRemote == "1.1.1.1:53")
        #expect(profile.peerIP == "10.9.0.2")
        #expect(profile.mtu == 1380)
        #expect(profile.bypassCountry == "CN")
        // The `#fragment` becomes the profile name.
        #expect(profile.name == "sf1-chinadns")
    }

    @Test
    func `missing fields fall back to profile defaults`() throws {
        let uri = try makeURI(["server": "example.com:8388", "password": "pw"])
        let profile = try ProfileURI.profile(from: uri)
        let defaults = Profile()
        #expect(profile.server == "example.com")
        #expect(profile.port == 8388)
        #expect(profile.password == "pw")
        #expect(profile.cipher == defaults.cipher)
        #expect(profile.mode == defaults.mode)
        #expect(profile.obfuscation == defaults.obfuscation)
        #expect(profile.dnsLocal == defaults.dnsLocal)
        #expect(profile.peerIP == defaults.peerIP)
        // No fragment → name derived from the host.
        #expect(profile.name == "example.com")
    }

    @Test
    func `auto_ip maps to the profile autoIP flag`() throws {
        let on = try ProfileURI.profile(from: makeURI([
            "server": "h:443", "password": "p", "auto_ip": true,
        ]))
        #expect(on.autoIP == true)

        // Absent → the Profile default (false).
        let off = try ProfileURI.profile(from: makeURI(["server": "h:443", "password": "p"]))
        #expect(off.autoIP == false)
    }

    @Test
    func `gfwlist mode falls back to the default since iOS lacks it`() throws {
        let uri = try makeURI(["server": "h:1", "password": "p", "mode": "gfwlist"])
        let profile = try ProfileURI.profile(from: uri)
        #expect(profile.mode == Profile().mode)
    }

    @Test
    func `tolerates surrounding whitespace and a trailing fragment`() throws {
        let base = try makeURI(["server": "h:443", "password": "p"])
        let messy = "  \(base)#label with space\n"
        let profile = try ProfileURI.profile(from: messy)
        #expect(profile.server == "h")
        #expect(profile.port == 443)
        // Fragment is taken up to the first whitespace.
        #expect(profile.name == "label")
    }

    @Test
    func `a server without a port keeps the default port`() throws {
        let uri = try makeURI(["server": "bare-host", "password": "p"])
        let profile = try ProfileURI.profile(from: uri)
        #expect(profile.server == "bare-host")
        #expect(profile.port == Profile().port)
    }

    @Test
    func `a bracketed IPv6 server splits host and port`() throws {
        let uri = try makeURI(["server": "[2001:db8::1]:8443", "password": "p"])
        let profile = try ProfileURI.profile(from: uri)
        #expect(profile.server == "2001:db8::1")
        #expect(profile.port == 8443)
    }

    @Test
    func `rejects a non-shadowvpn scheme`() {
        #expect(throws: ProfileURIError.self) {
            _ = try ProfileURI.profile(from: "ss://whatever")
        }
    }

    @Test
    func `rejects a malformed base64 payload`() {
        #expect(throws: ProfileURIError.self) {
            _ = try ProfileURI.profile(from: "shadowvpn://!!!not-base64!!!")
        }
    }

    @Test
    func `decodes a payload that lacks Base64 padding`() throws {
        // "{}" is 2 bytes → Base64 "e30=" (one pad char); upstream emits it
        // unpadded as "e30". The decoder must restore the padding.
        let profile = try ProfileURI.profile(from: "shadowvpn://e30")
        #expect(profile.server == Profile().server)
    }
}
