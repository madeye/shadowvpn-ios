import Foundation
@testable import SVPNModels
import Testing

@Suite("Profile codable + config_json")
struct ProfileTests {
    @Test
    func `Codable round-trip preserves every field`() throws {
        let profile = Profile(
            name: "HK",
            server: "example.com",
            port: 9999,
            password: "correct horse battery staple",
            cipher: .aes256gcm,
            mode: .chinadns,
            dnsLocal: "223.5.5.5:53",
            dnsRemote: "1.1.1.1:53",
            mtu: 1380,
            autoIP: true,
        )

        let data = try JSONEncoder().encode(profile)
        let decoded = try JSONDecoder().decode(Profile.self, from: data)

        #expect(decoded == profile)
        #expect(decoded.cipher == .aes256gcm)
        #expect(decoded.mode == .chinadns)
        #expect(decoded.autoIP == true)
        #expect(decoded.serverAddress == "example.com:9999")
    }

    @Test
    func `cipher raw values match the shadowsocks names`() {
        #expect(Cipher.aes128gcm.rawValue == "aes-128-gcm")
        #expect(Cipher.aes256gcm.rawValue == "aes-256-gcm")
        #expect(Cipher.chacha20poly1305.rawValue == "chacha20-poly1305")
    }

    @Test
    func `a profile saved with the removed chnroute mode migrates to full`() throws {
        // The `chnroute` mode was removed; a profile persisted by an older build
        // must still decode (falling back to the default) rather than throw.
        let json = #"{"id":"00000000-0000-0000-0000-000000000000","server":"h","port":8388,"password":"p","mode":"chnroute"}"#
        let decoded = try JSONDecoder().decode(Profile.self, from: Data(json.utf8))
        #expect(decoded.mode == .full)
        #expect(decoded.server == "h")
        #expect(decoded.password == "p")
    }

    @Test
    func `mode raw values match the policy names`() {
        #expect(TunnelMode.full.rawValue == "full")
        #expect(TunnelMode.chinadns.rawValue == "chinadns")
    }

    @Test
    func `config_json has the expected shape for chinadns`() throws {
        let profile = Profile(
            server: "1.2.3.4",
            port: 8388,
            password: "pw",
            cipher: .chacha20poly1305,
            mode: .chinadns,
            dnsLocal: "114.114.114.114:53",
            dnsRemote: "8.8.8.8:53",
            mtu: 1400,
        )

        let dict = profile.configJSON(chnroutePath: "/tmp/chnroute.txt")

        #expect(dict["server"] as? String == "1.2.3.4:8388")
        #expect(dict["password"] as? String == "pw")
        #expect(dict["cipher"] as? String == "chacha20-poly1305")
        #expect(dict["mode"] as? String == "chinadns")
        #expect(dict["mtu"] as? Int == 1400)
        #expect(dict["dns_local"] as? String == "114.114.114.114:53")
        #expect(dict["dns_remote"] as? String == "8.8.8.8:53")
        #expect(dict["chnroute_path"] as? String == "/tmp/chnroute.txt")
    }

    @Test
    func `config_json omits chnroute_path in full mode`() {
        let profile = Profile(server: "h", port: 1, password: "p", mode: .full)
        let dict = profile.configJSON(chnroutePath: "/tmp/chnroute.txt")
        #expect(dict["chnroute_path"] == nil)
        #expect(dict["mode"] as? String == "full")
    }

    @Test
    func `config_json string is valid sorted-key JSON`() throws {
        let profile = Profile(server: "h", port: 53, password: "p", mode: .chinadns)
        let json = try profile.configJSONString(chnroutePath: "/abs/chnroute.txt")

        // Re-parse to confirm it's well-formed and the values survived.
        let parsed = try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any]
        let dict = try #require(parsed)
        #expect(dict["server"] as? String == "h:53")
        #expect(dict["chnroute_path"] as? String == "/abs/chnroute.txt")

        // `.sortedKeys` => "cipher" precedes "server" lexicographically.
        let cipherIdx = try #require(json.range(of: "\"cipher\"")).lowerBound
        let serverIdx = try #require(json.range(of: "\"server\"")).lowerBound
        #expect(cipherIdx < serverIdx)
    }
}
