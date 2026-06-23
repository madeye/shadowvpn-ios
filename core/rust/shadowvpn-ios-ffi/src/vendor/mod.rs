//! Vendored, iOS-safe subset of the upstream `madeye/shadowvpn` library.
//!
//! # Why vendored instead of a git dependency
//!
//! `DESIGN.md` ("Dependency on upstream shadowvpn") asks us to first try
//! `shadowvpn = { git = ".../shadowvpn" }` and fall back to vendoring only if
//! the whole crate fails to cross-compile to `aarch64-apple-ios`. The upstream
//! library is not cross-compilable for iOS as-is: its `Cargo.toml` unconditionally
//! pulls
//!
//! * `tun-rs` (used by `tun_device.rs`) — opens a real OS `utun`/TUN device;
//! * `maxminddb` + `ipnetwork` (used by `policy::geoip` / `policy::route`) — a
//!   runtime MMDB reader and the user-mode route programmer;
//! * `windows-sys` IP-Helper bindings on Windows.
//!
//! and its `lib.rs` declares `pub mod tun_device;` + `pub mod policy;` at the
//! crate root, so the whole tree is type-checked even if we only touch
//! `crypto`/`protocol`. None of `tun_device` / `policy::{route,dnsconf,geoip}`
//! belong inside a NetworkExtension — Swift owns `NEPacketTunnelFlow`, and on
//! iOS `chnroute` is a plain bundled text file, never an MMDB. So we vendor ONLY
//! the four OS-agnostic modules the data plane actually needs and drop the git
//! dependency entirely. Each vendored file keeps the upstream MIT header plus a
//! `// vendored from madeye/shadowvpn` provenance note.
//!
//! The vendored set is deliberately minimal:
//!
//! * [`crypto`] — `Cipher`, `evp_bytes_to_key`, `encrypt_packet`,
//!   `decrypt_packet` (the shadowsocks AEAD UDP scheme).
//! * [`protocol`] — framing/sizing constants (`MAX_IP_PACKET`,
//!   `max_datagram_size`, `crypto_overhead`).
//! * [`chnroute`] — the `ChnRoute` China-IPv4 range set used by chinadns mode.
//! * [`gfwlist`] — the `GfwList` domain-suffix set used as a chinadns
//!   force-tunnel override (upstream PR #17).
//! * [`dns`] — read-only DNS wire helpers (`question`, `a_records`, `min_ttl`).
//! * [`control`] — in-band control frames (`Control`, `is_control`, `parse`) for
//!   the auto-IP assignment handshake (upstream PR #20).

// These modules are kept VERBATIM from upstream so they track its crypto/DNS
// wire behavior; the data plane only calls a subset of their public API
// (`encrypt_packet`/`decrypt_packet`, `question`/`a_records`, `ChnRoute::load`/
// `contains`/`from_lines`). The unused upstream helpers (`build_query`,
// `min_ttl`, `from_ranges`, …) are intentionally retained rather than deleted —
// `allow(dead_code)` silences the warnings without diverging from upstream.
#[allow(dead_code)]
pub mod control;
#[allow(dead_code)]
pub mod crypto;
#[allow(dead_code)]
pub mod dns;
#[allow(dead_code)]
pub mod protocol;

/// The `policy::*` sub-namespace, re-created so the vendored `chnroute` /
/// `gfwlist` modules keep their upstream import path
/// (`shadowvpn::policy::{chnroute,gfwlist}`) intact and so future iOS-safe
/// policy helpers slot in here without churn.
pub mod policy {
    #[allow(dead_code)]
    pub mod chnroute;
    #[allow(dead_code)]
    pub mod gfwlist;
}
