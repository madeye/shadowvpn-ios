import Foundation
import SVPNModels

/// A mutable, field-by-field view model backing the Settings form. The wire
/// ``Profile`` keeps `port` and `mtu` as `Int`s, but `TextField` binds most
/// naturally to `String`s — so the form edits strings and validates/coerces
/// them back into a `Profile` only on save. This keeps a half-typed port ("80")
/// from momentarily reading as the integer `80` and triggering a reconnect.
///
/// `@Observable` so SwiftUI re-renders as the user types; the conditional
/// ChinaDNS fields key their visibility off ``mode``.
@Observable
final class EditableProfile {
    /// Carried through unchanged so a save round-trips the same identity.
    var id: UUID
    var name: String
    var server: String
    /// String-backed port; coerced to `Int` in ``makeProfile()``.
    var portText: String
    var password: String
    var cipher: Cipher
    var mode: TunnelMode
    var dnsLocal: String
    var dnsRemote: String
    /// ISO alpha-2 country code whose CIDRs bypass the tunnel (split modes).
    var bypassCountry: String
    /// String-backed MTU; coerced to `Int` in ``makeProfile()``.
    var mtuText: String
    /// Carrier obfuscation applied to every datagram on the wire.
    var obfuscation: Obfuscation
    /// Tunnel inner client IP (must match the server's `peer_ip`). Ignored when
    /// ``autoIP`` is on.
    var peerIP: String
    /// Whether the server auto-assigns the tunnel IP (upstream PR #20).
    var autoIP: Bool

    /// Seed the form from an existing ``Profile``.
    init(_ profile: Profile) {
        id = profile.id
        name = profile.name
        server = profile.server
        portText = String(profile.port)
        password = profile.password
        cipher = profile.cipher
        mode = profile.mode
        dnsLocal = profile.dnsLocal
        dnsRemote = profile.dnsRemote
        bypassCountry = profile.bypassCountry
        mtuText = String(profile.mtu)
        obfuscation = profile.obfuscation
        peerIP = profile.peerIP
        autoIP = profile.autoIP
    }

    /// Parsed port, or the wire default when the field is blank/garbage. Never
    /// throws — a bad value just falls back so the form can't wedge on save.
    var port: Int {
        Int(portText.trimmingCharacters(in: .whitespaces)) ?? 8388
    }

    /// Parsed MTU, clamped to a sane floor; defaults to the wire constant.
    var mtu: Int {
        let parsed = Int(mtuText.trimmingCharacters(in: .whitespaces)) ?? Profile.defaultMTU
        return max(576, parsed)
    }

    /// Whether the ChinaDNS upstream rows should be shown — only ``TunnelMode``
    /// ``TunnelMode/chinadns`` consults `dns_local` / `dns_remote`.
    var showsDNSFields: Bool {
        mode.usesSplitDNS
    }

    /// True once the minimum connection fields are present (server + password +
    /// a positive port). Drives the save button's enabled state.
    var isComplete: Bool {
        !server.trimmingCharacters(in: .whitespaces).isEmpty
            && port > 0
            && !password.isEmpty
    }

    /// Materialize the edited fields back into an immutable wire ``Profile``.
    /// Trims whitespace from the address-ish fields (a trailing space in a host
    /// or DNS upstream is a common paste artifact that breaks `host:port`
    /// parsing in the Rust core).
    func makeProfile() -> Profile {
        Profile(
            id: id,
            name: name.trimmingCharacters(in: .whitespaces).isEmpty
                ? "ShadowVPN"
                : name.trimmingCharacters(in: .whitespaces),
            server: server.trimmingCharacters(in: .whitespaces),
            port: port,
            password: password,
            cipher: cipher,
            mode: mode,
            dnsLocal: dnsLocal.trimmingCharacters(in: .whitespaces),
            dnsRemote: dnsRemote.trimmingCharacters(in: .whitespaces),
            mtu: mtu,
            bypassCountry: bypassCountry.trimmingCharacters(in: .whitespaces).uppercased(),
            obfuscation: obfuscation,
            peerIP: peerIP.trimmingCharacters(in: .whitespaces).isEmpty
                ? Profile.defaultPeerIP
                : peerIP.trimmingCharacters(in: .whitespaces),
            autoIP: autoIP,
        )
    }

    /// Whether the form differs from `other` — used to gate the save button so
    /// it's only enabled when there's something to persist.
    func differs(from other: Profile) -> Bool {
        makeProfile() != other
    }
}
