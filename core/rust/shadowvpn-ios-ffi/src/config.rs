//! Runtime configuration for the ShadowVPN data plane.
//!
//! Swift hands the FFI a single UTF-8 JSON blob at `svpn_tun_start`; this module
//! deserializes it into a [`RuntimeConfig`] and derives the shadowsocks master
//! key from the password so the hot path never re-runs the KDF. The JSON shape
//! is fixed by `DESIGN.md` ("C ABI", config_json):
//!
//! ```json
//! {
//!   "server": "host:port",
//!   "password": "...",
//!   "cipher": "chacha20-poly1305",
//!   "mode": "full|chnroute|chinadns",
//!   "mtu": 1400,
//!   "dns_local": "114.114.114.114:53",
//!   "dns_remote": "8.8.8.8:53",
//!   "chnroute_path": "/abs/chnroute.txt",
//!   "gfwlist_path": "/abs/gfwlist.txt"
//! }
//! ```
//!
//! Only `server`, `password`, and `cipher` are strictly required. `mode`
//! defaults to `full`; `mtu` to the upstream [`DEFAULT_TUN_MTU`]. The DNS
//! fields and `chnroute_path` are only consulted in `chinadns` mode (see
//! [`crate::dns_intercept`]); they are optional everywhere else. `gfwlist_path`
//! is an *optional* chinadns force-tunnel override (mirrors upstream PR #17):
//! when present, names matching the bundled gfwlist always resolve via the clean
//! tunneled upstream regardless of the local-vs-clean race. It is ignored in
//! every other mode and absent by default.

use serde::Deserialize;

use crate::vendor::crypto::{evp_bytes_to_key, Cipher};
use crate::vendor::protocol::DEFAULT_TUN_MTU;

/// The split-routing / DNS mode the tunnel runs in.
///
/// On iOS the *routing* split (full vs chnroute) is enforced by Swift's
/// `NEPacketTunnelNetworkSettings` (included/excluded routes), so the data
/// plane only distinguishes `Chinadns` — the one mode that changes what the
/// FFI does with an ingested packet (DNS interception). `Full` and `Chnroute`
/// are otherwise identical here: encrypt-and-forward everything Swift routes
/// into the tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Everything Swift routes in is tunneled; no DNS interception.
    #[default]
    Full,
    /// China CIDRs are excluded from the tunnel by Swift; the FFI still just
    /// encrypts-and-forwards whatever reaches it. No DNS interception.
    Chnroute,
    /// Split DNS: A/IN queries to `dns_local` go direct, a clean copy goes
    /// through the tunnel to `dns_remote`, and [`crate::dns_intercept`] picks
    /// the answer by `ChnRoute::contains`.
    Chinadns,
}

/// Carrier obfuscation applied to each UDP datagram on the wire (see
/// [`crate::obfs`]). Both ends must agree; the server applies the inverse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Obfs {
    /// No obfuscation — the datagram is the bare `salt ++ AEAD` envelope.
    #[default]
    None,
    /// Wrap each datagram to look like a QUIC 1-RTT (HTTP/3) short-header packet.
    Quic,
    /// Base64-encode each datagram so the UDP payload is printable ASCII text.
    Base64,
}

/// Raw, as-deserialized config. Kept private; callers get the validated
/// [`RuntimeConfig`] from [`RuntimeConfig::from_json`].
#[derive(Debug, Deserialize)]
struct RawConfig {
    /// `host:port` of the ShadowVPN server. Passed verbatim to
    /// `UdpSocket::connect`, which resolves a hostname if needed.
    server: String,
    /// Pre-shared password; the master key is `EVP_BytesToKey(password)`.
    password: String,
    /// shadowsocks cipher name (`aes-128-gcm` / `aes-256-gcm` /
    /// `chacha20-poly1305`).
    cipher: String,
    /// Routing/DNS mode. Defaults to [`Mode::Full`].
    #[serde(default)]
    mode: Mode,
    /// Tunnel MTU. Defaults to [`DEFAULT_TUN_MTU`]. Informational on the FFI
    /// side (Swift sizes the tun); carried so logs and buffer sizing agree.
    #[serde(default)]
    mtu: Option<u16>,
    /// Domestic resolver `ip:port` for chinadns mode (queried direct).
    #[serde(default)]
    dns_local: Option<String>,
    /// Clean upstream resolver `ip:port` for chinadns mode (queried through the
    /// tunnel).
    #[serde(default)]
    dns_remote: Option<String>,
    /// Absolute path to the bundled/staged `chnroute.txt` for chinadns mode.
    #[serde(default)]
    chnroute_path: Option<String>,
    /// Absolute path to the bundled/staged `gfwlist.txt` — an optional
    /// force-tunnel override consulted only in chinadns mode.
    #[serde(default)]
    gfwlist_path: Option<String>,
    /// Carrier obfuscation. Defaults to [`Obfs::None`].
    #[serde(default)]
    obfs: Obfs,
}

/// Validated, hot-path-ready runtime configuration.
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    /// `host:port` of the server, used by `UdpSocket::connect`.
    pub server: String,
    /// Negotiated AEAD cipher.
    pub cipher: Cipher,
    /// `EVP_BytesToKey`-derived master key; its length already equals
    /// `cipher.key_len()`.
    pub master_key: Vec<u8>,
    /// Routing/DNS mode.
    pub mode: Mode,
    /// Effective tunnel MTU (default applied).
    pub mtu: u16,
    /// Domestic resolver `ip:port` (chinadns mode).
    pub dns_local: Option<String>,
    /// Clean upstream resolver `ip:port` (chinadns mode).
    pub dns_remote: Option<String>,
    /// Path to `chnroute.txt` (chinadns mode).
    pub chnroute_path: Option<String>,
    /// Path to `gfwlist.txt` — optional chinadns force-tunnel override. `None`
    /// disables the override (plain chinadns race behavior).
    pub gfwlist_path: Option<String>,
    /// Carrier obfuscation applied to every datagram.
    pub obfs: Obfs,
}

impl RuntimeConfig {
    /// Parse and validate the `config_json` blob from `svpn_tun_start`.
    ///
    /// Returns a human-readable error string (surfaced through
    /// `svpn_core_last_error`) on malformed JSON, an unknown cipher, or — in
    /// `chinadns` mode — missing DNS endpoints / chnroute path.
    pub fn from_json(json: &str) -> Result<Self, String> {
        let raw: RawConfig =
            serde_json::from_str(json).map_err(|e| format!("invalid config_json: {e}"))?;

        if raw.server.trim().is_empty() {
            return Err("config_json: `server` is empty".to_string());
        }

        let cipher = Cipher::from_name(&raw.cipher)
            .map_err(|e| format!("config_json: unsupported cipher: {e}"))?;

        // Derive the master key once here; the hot path borrows it per packet.
        let master_key = evp_bytes_to_key(raw.password.as_bytes(), cipher.key_len());

        let mtu = raw.mtu.unwrap_or(DEFAULT_TUN_MTU);

        // chinadns mode is the only mode that needs the DNS endpoints + chnroute
        // table. Validate them up front so a misconfigured profile fails at
        // start with a clear message instead of silently degrading mid-session.
        if raw.mode == Mode::Chinadns {
            if raw.dns_local.as_deref().unwrap_or("").trim().is_empty() {
                return Err("config_json: chinadns mode requires `dns_local`".to_string());
            }
            if raw.dns_remote.as_deref().unwrap_or("").trim().is_empty() {
                return Err("config_json: chinadns mode requires `dns_remote`".to_string());
            }
            if raw.chnroute_path.as_deref().unwrap_or("").trim().is_empty() {
                return Err("config_json: chinadns mode requires `chnroute_path`".to_string());
            }
        }

        Ok(RuntimeConfig {
            server: raw.server,
            cipher,
            master_key,
            mode: raw.mode,
            mtu,
            dns_local: raw.dns_local,
            dns_remote: raw.dns_remote,
            chnroute_path: raw.chnroute_path,
            gfwlist_path: raw.gfwlist_path,
            obfs: raw.obfs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_full_config() {
        let json = r#"{"server":"1.2.3.4:443","password":"pw","cipher":"chacha20-poly1305"}"#;
        let cfg = RuntimeConfig::from_json(json).expect("parse");
        assert_eq!(cfg.server, "1.2.3.4:443");
        assert_eq!(cfg.cipher, Cipher::ChaCha20Poly1305);
        assert_eq!(cfg.mode, Mode::Full);
        assert_eq!(cfg.mtu, DEFAULT_TUN_MTU);
        // 32-byte key for chacha20-poly1305.
        assert_eq!(cfg.master_key.len(), 32);
    }

    #[test]
    fn master_key_matches_evp_bytes_to_key() {
        let json = r#"{"server":"h:1","password":"test","cipher":"aes-128-gcm"}"#;
        let cfg = RuntimeConfig::from_json(json).expect("parse");
        // aes-128-gcm => 16-byte key == MD5("test").
        assert_eq!(cfg.master_key, evp_bytes_to_key(b"test", 16));
        assert_eq!(cfg.master_key.len(), 16);
    }

    #[test]
    fn rejects_unknown_cipher() {
        let json = r#"{"server":"h:1","password":"p","cipher":"rc4-md5"}"#;
        assert!(RuntimeConfig::from_json(json).is_err());
    }

    #[test]
    fn rejects_empty_server() {
        let json = r#"{"server":"","password":"p","cipher":"aes-256-gcm"}"#;
        assert!(RuntimeConfig::from_json(json).is_err());
    }

    #[test]
    fn chinadns_requires_dns_and_chnroute() {
        // Missing dns_local/dns_remote/chnroute_path.
        let bad = r#"{"server":"h:1","password":"p","cipher":"aes-256-gcm","mode":"chinadns"}"#;
        assert!(RuntimeConfig::from_json(bad).is_err());

        let good = r#"{
            "server":"h:1","password":"p","cipher":"aes-256-gcm","mode":"chinadns",
            "dns_local":"114.114.114.114:53","dns_remote":"8.8.8.8:53",
            "chnroute_path":"/tmp/chnroute.txt"
        }"#;
        let cfg = RuntimeConfig::from_json(good).expect("parse");
        assert_eq!(cfg.mode, Mode::Chinadns);
        assert_eq!(cfg.dns_local.as_deref(), Some("114.114.114.114:53"));
        assert_eq!(cfg.dns_remote.as_deref(), Some("8.8.8.8:53"));
        // gfwlist_path is optional: absent here.
        assert_eq!(cfg.gfwlist_path, None);
    }

    #[test]
    fn chinadns_accepts_optional_gfwlist_path() {
        let json = r#"{
            "server":"h:1","password":"p","cipher":"aes-256-gcm","mode":"chinadns",
            "dns_local":"114.114.114.114:53","dns_remote":"8.8.8.8:53",
            "chnroute_path":"/tmp/chnroute.txt","gfwlist_path":"/tmp/gfwlist.txt"
        }"#;
        let cfg = RuntimeConfig::from_json(json).expect("parse");
        assert_eq!(cfg.gfwlist_path.as_deref(), Some("/tmp/gfwlist.txt"));
    }

    #[test]
    fn honors_explicit_mtu_and_mode() {
        let json = r#"{"server":"h:1","password":"p","cipher":"aes-256-gcm","mode":"chnroute","mtu":1280}"#;
        let cfg = RuntimeConfig::from_json(json).expect("parse");
        assert_eq!(cfg.mode, Mode::Chnroute);
        assert_eq!(cfg.mtu, 1280);
    }
}
