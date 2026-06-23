//! Rust half of the ShadowVPN iOS native stack — a single C ABI that the
//! PacketTunnel extension and the main app both link against via
//! `ShadowVPNCore.xcframework` (`libshadowvpn_ios_ffi.a`).
//!
//! # Dependency path taken: VENDORED (not the git dep)
//!
//! `DESIGN.md` asks us to first try `shadowvpn = { git = ".../shadowvpn" }` and
//! fall back to vendoring only the iOS-safe modules if the whole upstream crate
//! fails to cross-compile to `aarch64-apple-ios`. It does fail: upstream's
//! `Cargo.toml` unconditionally pulls `tun-rs`, `maxminddb`, and `ipnetwork`
//! (used by `tun_device.rs` / `policy::{route,geoip,dnsconf}`), and its
//! `lib.rs` declares those modules at the crate root, so the entire tree is
//! type-checked even though the data plane only needs crypto + DNS parsing.
//! None of that belongs in a NetworkExtension — Swift owns `NEPacketTunnelFlow`
//! and iOS chnroute is a plain bundled text file, never an MMDB.
//!
//! So we **vendored** the four OS-agnostic modules into [`vendor`]
//! (`crypto`, `protocol`, `policy::chnroute`, `dns`), each carrying the upstream
//! MIT header + a provenance note, and dropped the git dependency entirely. See
//! [`vendor`] for the full rationale.
//!
//! # Data-plane topology (no OS TUN inside the NE)
//!
//! ```text
//!  readPackets ──svpn_tun_ingest──▶ ingress ──encrypt──▶ UDP socket ⇆ server
//!                                                              │
//!  writePackets ◀──SvpnWritePacket── egress ◀──decrypt── UDP socket
//! ```
//!
//! A multi-thread tokio runtime drives one `connect()`ed UDP socket, a 25 s
//! keepalive (1-byte `0x00`), an ingress task (encrypt + send), and an egress
//! task (recv + decrypt + write callback). See [`engine`] for the lifecycle and
//! the [`svpn_tun_stop_blocking`] join contract that prevents the writer-`ctx`
//! use-after-free meow documents.

mod config;
mod country;
mod dns_intercept;
mod engine;
mod inspect;
mod logging;
mod obfs;
pub mod rss;
mod vendor;

use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};

// ---------------------------------------------------------------------------
// Thread-local last-error + small helpers
// ---------------------------------------------------------------------------

thread_local! {
    static LAST_ERROR: RefCell<CString> = RefCell::new(CString::new("").unwrap());
}

/// Store `msg` as this thread's last error, readable via [`svpn_core_last_error`].
fn set_error(msg: String) {
    let cstr = CString::new(msg).unwrap_or_else(|_| CString::new("error").unwrap());
    LAST_ERROR.with(|e| *e.borrow_mut() = cstr);
}

/// Borrow a `*const c_char` as a `&str`, or `None` if null / not UTF-8.
///
/// # Safety
/// `p` must be NUL-terminated and valid for reads, or null.
unsafe fn cstr_to_str<'a>(p: *const c_char) -> Option<&'a str> {
    if p.is_null() {
        None
    } else {
        CStr::from_ptr(p).to_str().ok()
    }
}

// ---------------------------------------------------------------------------
// Lifecycle / logging (shared surface)
// ---------------------------------------------------------------------------

/// Initialize logging (os_log bridge + panic hook). Safe to call more than once.
#[no_mangle]
pub extern "C" fn svpn_core_init() {
    logging::init_os_logger();
    logging::install_panic_hook();
    logging::bridge_log("svpn_core_init: os_log initialized");
}

/// Emit a log line from the NetworkExtension host (ObjC) into the same os_log
/// pipeline the data plane uses, so NE lifecycle events — start/stop,
/// sleep/wake, errors — interleave with engine output on one timeline.
///
/// `level`: 0 = error, 1 = warn, 2 = info, 3 = debug, 4 = trace; anything else
/// is treated as info. No-op on a NULL or non-UTF-8 `msg`.
///
/// # Safety
/// `msg` must point to a NUL-terminated UTF-8 string or be NULL.
#[no_mangle]
pub unsafe extern "C" fn svpn_core_log(level: c_int, msg: *const c_char) {
    let Some(text) = cstr_to_str(msg) else {
        return;
    };
    match level {
        0 => log::error!(target: "ne", "{text}"),
        1 => log::warn!(target: "ne", "{text}"),
        3 => log::debug!(target: "ne", "{text}"),
        4 => log::trace!(target: "ne", "{text}"),
        _ => log::info!(target: "ne", "{text}"),
    }
}

/// Set the App Group container path where the FFI may stage logs / cache.
/// `dir` may be NULL or empty. Currently advisory: ShadowVPN's data plane keeps
/// no on-disk state of its own (chnroute is passed by absolute path in
/// `config_json`), but the hook mirrors meow's `*_set_home_dir` so the Swift
/// side has a stable place to point future file-backed logging at.
///
/// # Safety
/// `dir` must point to a NUL-terminated UTF-8 string or be NULL.
#[no_mangle]
pub unsafe extern "C" fn svpn_core_set_home_dir(dir: *const c_char) {
    let parsed = cstr_to_str(dir)
        .map(str::to_owned)
        .filter(|s| !s.is_empty());
    // Point the mirrored log file at <home_dir>/logs/svpn-tunnel.log so the
    // app's Log view (which tails that file) actually has content to show.
    if let Some(ref dir) = parsed {
        logging::set_log_file(dir);
    }
    logging::bridge_log(&format!("svpn_core_set_home_dir: {parsed:?}"));
}

/// Return the last error message for the calling thread. The pointer is owned
/// by the crate and valid until the next error is set on the same thread — copy
/// immediately if retention is needed.
#[no_mangle]
pub extern "C" fn svpn_core_last_error() -> *const c_char {
    LAST_ERROR.with(|e| e.borrow().as_ptr())
}

// ---------------------------------------------------------------------------
// Country → CIDR resolution (runtime split-tunnel bypass set, cached)
// ---------------------------------------------------------------------------

/// Resolve the bypass-CIDR file for an ISO country code, extracting it from the
/// bundled MaxMind GeoLite2 Country mmdb the first time and caching it.
///
/// Writes the absolute path of the cache file (`<cache_dir>/chnroute-<COUNTRY>-
/// <mmdb_len>.txt`, plain `a.b.c.d/len`-per-line text) into `out`/`out_cap`,
/// NUL-terminated. Returns the number of bytes the path needs (excluding the
/// NUL); if the return value is `>= out_cap` the path was truncated — allocate
/// `ret + 1` and call again. Returns `-1` on error (inspect
/// `svpn_core_last_error`): a missing/invalid mmdb, an unknown country, or an
/// unwritable cache directory.
///
/// The expensive mmdb walk runs at most once per `(country, mmdb)`; later calls
/// return the cached path immediately. Swift parses the returned file for
/// `NEPacketTunnelNetworkSettings.excludedRoutes` and passes the same path back
/// as `config_json["chnroute_path"]` for the chinadns decision.
///
/// # Safety
/// `mmdb_path`, `country`, and `cache_dir` must each be NUL-terminated UTF-8 C
/// strings. `out` must reference `out_cap` writable bytes if non-NULL.
#[no_mangle]
pub unsafe extern "C" fn svpn_country_cidrs_file(
    mmdb_path: *const c_char,
    country: *const c_char,
    cache_dir: *const c_char,
    out: *mut c_char,
    out_cap: c_int,
) -> c_int {
    let (Some(mmdb), Some(cc), Some(dir)) = (
        cstr_to_str(mmdb_path),
        cstr_to_str(country),
        cstr_to_str(cache_dir),
    ) else {
        set_error("svpn_country_cidrs_file: a NULL / non-utf-8 argument".into());
        return -1;
    };

    let path = match country::ensure_country_file(mmdb, cc, dir) {
        Ok(p) => p,
        Err(e) => {
            logging::bridge_log(&format!("svpn_country_cidrs_file ERROR: {e}"));
            set_error(e);
            return -1;
        }
    };

    let bytes = path.as_bytes();
    let needed = bytes.len();
    if !out.is_null() && out_cap > 0 {
        let cap = out_cap as usize;
        let copy = needed.min(cap - 1); // leave room for the NUL
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out as *mut u8, copy);
        *out.add(copy) = 0;
    }
    needed as c_int
}

// ---------------------------------------------------------------------------
// Data plane (NEPacketTunnelFlow bridge)
// ---------------------------------------------------------------------------

/// C-compatible egress callback. Invoked from the data-plane tokio runtime
/// whenever a decrypted IP packet (or a synthesized chinadns response) is bound
/// for Swift's `NEPacketTunnelFlow`. Swift guarantees `ctx` stays live between
/// `svpn_tun_start` and the join performed by `svpn_tun_stop_blocking`.
pub type SvpnWritePacket = unsafe extern "C" fn(ctx: *mut c_void, data: *const u8, len: usize);

/// Start the ShadowVPN data plane with a Swift-owned egress callback and a JSON
/// config (see [`config::RuntimeConfig`] for the schema). The ingest side is
/// driven by `svpn_tun_ingest`; an internal mpsc queue means there's no file
/// descriptor between Swift and Rust.
///
/// Returns 0 on success, -1 on error (inspect `svpn_core_last_error`).
///
/// # Safety
/// `ctx` is opaque to Rust but must remain valid for any dispatch that occurs
/// between this call and `svpn_tun_stop_blocking`. `cb` must be a non-null C
/// function pointer that stays valid for the lifetime of the tunnel.
/// `config_json` must be a NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn svpn_tun_start(
    ctx: *mut c_void,
    cb: SvpnWritePacket,
    config_json: *const c_char,
) -> c_int {
    let Some(json) = cstr_to_str(config_json) else {
        set_error("config_json is null or not utf-8".into());
        return -1;
    };
    logging::bridge_log("svpn_tun_start");
    match engine::start(ctx, cb, json) {
        Ok(()) => 0,
        Err(e) => {
            logging::bridge_log(&format!("svpn_tun_start ERROR: {e}"));
            set_error(e);
            -1
        }
    }
}

/// Feed a raw IP packet from `NEPacketTunnelFlow.readPackets` into the data
/// plane. Returns 0 if the packet was queued (or dropped under backpressure),
/// -1 if the tunnel isn't running. Non-blocking; callers shouldn't hold
/// `readPackets` completion handlers waiting.
///
/// # Safety
/// `data` must reference `len` bytes of readable memory.
#[no_mangle]
pub unsafe extern "C" fn svpn_tun_ingest(data: *const u8, len: usize) -> c_int {
    if data.is_null() || len == 0 {
        return 0;
    }
    let slice = std::slice::from_raw_parts(data, len);
    engine::ingest(slice)
}

/// Stop the data plane. Idempotent. Fire-and-forget: the session tasks drain on
/// the runtime after this returns. Use only when the egress `ctx` is retained
/// until a later start or an explicit blocking stop.
#[no_mangle]
pub extern "C" fn svpn_tun_stop() {
    logging::bridge_log("svpn_tun_stop");
    engine::stop();
}

/// Stop the data plane and BLOCK until the egress task (the only caller of the
/// `SvpnWritePacket` callback) has fully torn down. Once this returns, the
/// egress callback is guaranteed never to fire again, so the caller may safely
/// release the `ctx` it passed to `svpn_tun_start` — required for a terminal
/// stop, where releasing the writer while the egress task is still draining is a
/// use-after-free. Call from a NON-runtime thread (the Swift tunnel control
/// queue). Idempotent.
#[no_mangle]
pub extern "C" fn svpn_tun_stop_blocking() {
    logging::bridge_log("svpn_tun_stop_blocking");
    engine::stop_blocking();
}

/// Returns 1 if the data plane is running, 0 otherwise.
#[no_mangle]
pub extern "C" fn svpn_is_running() -> c_int {
    if engine::is_running() {
        1
    } else {
        0
    }
}

/// Write cumulative upload/download byte counters (plaintext IP bytes). Safe to
/// call before `svpn_tun_start` — returns zero counters.
///
/// # Safety
/// `up` and `down`, if non-NULL, must reference writable 64-bit integer slots.
#[no_mangle]
pub unsafe extern "C" fn svpn_engine_traffic(up: *mut i64, down: *mut i64) {
    let (u, d) = engine::traffic();
    if !up.is_null() {
        *up = u;
    }
    if !down.is_null() {
        *down = d;
    }
}

/// Resident memory size of the FFI's containing process, in bytes — the same
/// number macOS jetsam compares against the 50 MiB PacketTunnel cap, so Swift
/// can chart the on-device RSS curve. Returns 0 on platforms where the mach
/// call isn't available (non-Apple targets).
#[no_mangle]
pub extern "C" fn svpn_resident_bytes() -> u64 {
    rss::resident_bytes().unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Crate-level tests (host): crypto round-trip + chnroute parse.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod ffi_tests {
    use crate::vendor::crypto::{decrypt_packet, encrypt_packet, evp_bytes_to_key, Cipher};
    use crate::vendor::policy::chnroute::ChnRoute;

    /// End-to-end crypto round-trip through the vendored module — proves the
    /// shadowsocks AEAD UDP scheme is wired correctly for every cipher.
    #[test]
    fn crypto_round_trip_all_ciphers() {
        let plaintext = b"a raw IP packet that traverses the ShadowVPN tunnel";
        for cipher in [
            Cipher::Aes128Gcm,
            Cipher::Aes256Gcm,
            Cipher::ChaCha20Poly1305,
        ] {
            let key = evp_bytes_to_key(b"correct horse battery staple", cipher.key_len());
            let datagram = encrypt_packet(cipher, &key, plaintext).expect("encrypt");
            assert_eq!(
                datagram.len(),
                cipher.salt_len() + plaintext.len() + 16,
                "wire layout for {}",
                cipher.name()
            );
            let recovered = decrypt_packet(cipher, &key, &datagram).expect("decrypt");
            assert_eq!(recovered, plaintext, "round trip for {}", cipher.name());
        }
    }

    /// A single-byte flip anywhere in the datagram must fail authentication.
    #[test]
    fn crypto_rejects_tampered_datagram() {
        let cipher = Cipher::ChaCha20Poly1305;
        let key = evp_bytes_to_key(b"pw", cipher.key_len());
        let mut datagram = encrypt_packet(cipher, &key, b"authenticate me").expect("encrypt");
        let last = datagram.len() - 1;
        datagram[last] ^= 0x01;
        assert!(decrypt_packet(cipher, &key, &datagram).is_err());
    }

    /// chnroute parse + merge + lookup — the load-bearing split-routing table.
    #[test]
    fn chnroute_parses_and_classifies() {
        let r = ChnRoute::from_lines([
            "# China ranges",
            "1.0.1.0/24",
            "1.0.2.0/23", // adjacent -> merges with the line above
            "114.114.114.0/24",
            "",
            "garbage-line",
        ]);
        // 1.0.1.0/24 + 1.0.2.0/23 are contiguous -> 1 merged range, plus the
        // 114-range -> 2 total.
        assert_eq!(r.len(), 2);
        assert!(r.contains("1.0.1.1".parse().unwrap()));
        assert!(r.contains("114.114.114.114".parse().unwrap()));
        // Google DNS is not in China.
        assert!(!r.contains("8.8.8.8".parse().unwrap()));
    }
}
