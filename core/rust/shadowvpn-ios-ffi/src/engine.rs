//! The ShadowVPN data plane: a tokio multi-thread runtime driving one UDP
//! socket `connect()`ed to the server, a 25 s keepalive ticker, and an egress
//! task that decrypts server datagrams and hands the plaintext IP packets back
//! to Swift through the C write callback.
//!
//! # Topology (no OS TUN inside the NetworkExtension)
//!
//! Swift owns `NEPacketTunnelFlow`. There is no file descriptor between Swift
//! and Rust — packets cross the boundary as function calls:
//!
//! ```text
//!  readPackets ──svpn_tun_ingest──▶ ingest_tx ─┐
//!                                               │  (ingress task)
//!                                  encrypt_packet + socket.send
//!                                               │
//!                                        UDP socket ⇆ server
//!                                               │
//!                              socket.recv + decrypt_packet  (egress task)
//!                                               │
//!                            SvpnWritePacket(ctx, plaintext) ──▶ writePackets
//! ```
//!
//! Three tokio tasks per session: **ingress** (drains the ingest mpsc, encrypts,
//! sends), **egress** (recv/decrypt/callback), and **keepalive** (25 s 1-byte
//! `0x00`). The egress task is the only one that touches the Swift writer `ctx`,
//! so the terminal-stop contract (see [`stop_blocking`]) only has to join *it*.
//!
//! # Lifecycle / threading contract (mirrors meow's `meow_tun_*`)
//!
//! * [`start`] is idempotent-ish: a second start without a stop is rejected.
//! * [`stop`] is fire-and-forget — it lowers the running flag and drops the
//!   ingest sender; the session tasks drain on the runtime.
//! * [`stop_blocking`] additionally **joins the egress task** before returning,
//!   so once it returns the `SvpnWritePacket` callback is guaranteed never to
//!   fire again and Swift may release the `ctx`. Releasing `ctx` while the
//!   egress task is still draining is the exact use-after-free meow documents.
//!
//! All packet crypto delegates to the vendored [`crate::vendor::crypto`].

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use parking_lot::Mutex;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::config::{Mode, RuntimeConfig};
use crate::dns_intercept::{self, DnsInterceptor};
use crate::logging;
use crate::vendor::crypto::{decrypt_packet, encrypt_packet};
use crate::vendor::protocol::max_datagram_size;

/// How often to send a keepalive datagram (per upstream `client.rs`).
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(25);
/// Keepalive plaintext: a single zero byte — smaller than any IP header, so the
/// server drops it cheaply and it never reaches a TUN-write path.
const KEEPALIVE_PAYLOAD: &[u8] = &[0u8];

/// Bound on the ingest mpsc. `svpn_tun_ingest` must return promptly (iOS queues
/// `readPackets` itself if we block), so the channel is bounded and the FFI
/// drops under backpressure rather than awaiting capacity. 1024 packets is
/// ~1.4 MB at a 1400-byte MTU — generous head-room for a transient burst.
const INGEST_QUEUE_DEPTH: usize = 1024;

/// Bound on how long [`stop_blocking`] waits for the egress task to join before
/// giving up. iOS's `stopTunnel` grace window is finite; a pathological hang
/// must not freeze it. A late callback is vanishingly rare and far less bad than
/// a frozen shutdown — so on timeout we log and return.
const JOIN_TIMEOUT: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// Process-wide runtime + session state
// ---------------------------------------------------------------------------

/// The data-plane tokio runtime. Multi-thread so recv/send/keepalive overlap;
/// built once and reused across start/stop cycles (cheap, avoids re-spawning
/// worker threads on every reconnect).
fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            // Two workers is ample: the data plane is recv/decrypt + send/encrypt
            // plus a timer. Keep it small for the NE memory budget.
            .worker_threads(2)
            .thread_name("svpn-dataplane")
            // 1 MiB stacks (tokio defaults to 2 MiB). Virtual, demand-paged on
            // Darwin, so RSS tracks the deepest poll, not the cap.
            .thread_stack_size(1024 * 1024)
            .enable_all()
            .build()
            .expect("failed to build svpn-dataplane tokio runtime")
    })
}

/// `true` between a successful [`start`] and a [`stop`]/[`stop_blocking`].
static RUNNING: AtomicBool = AtomicBool::new(false);

/// Cumulative bytes sent upstream (plaintext IP bytes ingested and forwarded).
static UP_BYTES: AtomicI64 = AtomicI64::new(0);
/// Cumulative bytes received downstream (plaintext IP bytes egressed to Swift).
static DOWN_BYTES: AtomicI64 = AtomicI64::new(0);

/// Live session handles. `None` when stopped. Holds the ingest sender (dropping
/// it ends the ingress task) and the join handles for the bounded stop.
struct Session {
    /// Sender feeding the ingress task. `ingest` clones it per packet; `stop`
    /// drops the slot's copy so the ingress task's `recv()` returns `None`.
    ingest_tx: mpsc::Sender<Vec<u8>>,
    /// Egress task handle — the ONLY task that invokes the Swift `ctx`
    /// callback. `stop_blocking` joins this before returning.
    egress: tokio::task::JoinHandle<()>,
    /// Ingress task handle. Joined opportunistically on the next start.
    ingress: tokio::task::JoinHandle<()>,
    /// Keepalive task handle. Aborted on stop.
    keepalive: tokio::task::JoinHandle<()>,
}

fn session_slot() -> &'static Mutex<Option<Session>> {
    static S: OnceLock<Mutex<Option<Session>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(None))
}

// ---------------------------------------------------------------------------
// Swift write-callback context
// ---------------------------------------------------------------------------

/// C-compatible egress callback: `(ctx, data, len)`. Invoked from the egress
/// task whenever a decrypted IP packet (or a synthesized chinadns response) is
/// bound for `NEPacketTunnelFlow`. Swift guarantees `ctx` stays live between
/// [`start`] and the join in [`stop_blocking`].
pub type WritePacketFn = unsafe extern "C" fn(ctx: *mut c_void, data: *const u8, len: usize);

/// Wraps the raw `ctx` pointer so the egress closure can be `Send` onto the
/// tokio runtime. The pointer is opaque to Rust; its validity for the session's
/// lifetime is the caller's contract (upheld by `stop_blocking`'s join).
#[derive(Clone, Copy)]
pub struct WriteCtx {
    ctx: *mut c_void,
    cb: WritePacketFn,
}

// SAFETY: `ctx` is only ever dereferenced by `cb`, a C function Swift promises
// is thread-safe (it forwards to `NEPacketTunnelFlow.writePackets`, itself
// thread-safe). We never read/write the pointee in Rust. The blocking-stop
// join ensures no `emit` outlives the caller's release of `ctx`.
unsafe impl Send for WriteCtx {}
unsafe impl Sync for WriteCtx {}

impl WriteCtx {
    /// Hand `packet` to Swift via the C callback.
    pub fn emit(&self, packet: &[u8]) {
        // SAFETY: see the `unsafe impl Send`. `packet` is a valid slice; the
        // callback copies it synchronously (it does not retain the pointer).
        unsafe { (self.cb)(self.ctx, packet.as_ptr(), packet.len()) }
    }
}

// ---------------------------------------------------------------------------
// Start / stop
// ---------------------------------------------------------------------------

/// Start the data plane.
///
/// Binds an ephemeral UDP socket, `connect()`s it to `cfg.server`, and spawns
/// the ingress / egress / keepalive tasks. Returns a human-readable error
/// string on a config or socket failure. Rejects a double-start (caller must
/// `stop` first).
///
/// # Safety
/// `ctx` must remain valid until a [`stop_blocking`] returns (or the next
/// `start`). `cb` must be a non-null C function pointer valid for the session.
pub fn start(ctx: *mut c_void, cb: WritePacketFn, config_json: &str) -> Result<(), String> {
    if RUNNING.load(Ordering::SeqCst) {
        return Err("svpn data plane already running; stop first".to_string());
    }

    let cfg = RuntimeConfig::from_json(config_json)?;
    logging::bridge_log(&format!(
        "svpn start: server={} cipher={} mode={:?} mtu={}",
        cfg.server,
        cfg.cipher.name(),
        cfg.mode,
        cfg.mtu
    ));

    let writer = WriteCtx { ctx, cb };
    let rt = runtime();

    // Bind + connect synchronously on the runtime so a failure surfaces here
    // (before we flip RUNNING) and the FFI can report it via last_error.
    let socket = rt
        .block_on(async {
            let s = UdpSocket::bind(("0.0.0.0", 0)).await?;
            s.connect(&cfg.server).await?;
            Ok::<_, std::io::Error>(s)
        })
        .map_err(|e| format!("failed to bind/connect UDP socket to {}: {e}", cfg.server))?;
    let local = socket
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "<unknown>".to_string());
    logging::bridge_log(&format!("svpn UDP {local} connected to {}", cfg.server));
    let socket = Arc::new(socket);

    let cfg = Arc::new(cfg);
    let cipher = cfg.cipher;
    let master_key: Arc<[u8]> = Arc::from(cfg.master_key.clone().into_boxed_slice());

    // chinadns interceptor — only built in chinadns mode. In every other mode
    // it is `None` and the ingress path is the plain encrypt-and-forward loop.
    let interceptor: Option<Arc<DnsInterceptor>> = if cfg.mode == Mode::Chinadns {
        match dns_intercept::DnsInterceptor::new(&cfg, socket.clone(), cipher, master_key.clone()) {
            Ok(i) => {
                logging::bridge_log("svpn chinadns interceptor active");
                Some(Arc::new(i))
            }
            Err(e) => {
                // chinadns is best-effort and explicitly secondary to chnroute
                // split routing (DESIGN.md). A failure to build it must NOT take
                // the tunnel down — log and fall back to plain forwarding.
                logging::bridge_log(&format!(
                    "svpn chinadns interceptor unavailable ({e}); falling back to plain forward"
                ));
                None
            }
        }
    } else {
        None
    };

    let (ingest_tx, ingest_rx) = mpsc::channel::<Vec<u8>>(INGEST_QUEUE_DEPTH);

    // --- egress task: recv -> decrypt -> Swift callback --------------------
    let egress = rt.spawn(egress_loop(
        socket.clone(),
        cipher,
        master_key.clone(),
        writer,
        interceptor.clone(),
    ));

    // --- ingress task: ingest mpsc -> encrypt -> send ----------------------
    let ingress = rt.spawn(ingress_loop(
        ingest_rx,
        socket.clone(),
        cipher,
        master_key.clone(),
        writer,
        interceptor,
    ));

    // --- keepalive task: 25 s 1-byte 0x00 ----------------------------------
    let keepalive = rt.spawn(keepalive_loop(socket, cipher, master_key));

    *session_slot().lock() = Some(Session {
        ingest_tx,
        egress,
        ingress,
        keepalive,
    });
    RUNNING.store(true, Ordering::SeqCst);
    Ok(())
}

/// Fire-and-forget stop. Lowers the running flag, aborts keepalive, and drops
/// the ingest sender so the ingress task ends. The egress task is left to drain
/// on the runtime — use [`stop_blocking`] when the caller is about to release
/// `ctx`.
pub fn stop() {
    RUNNING.store(false, Ordering::SeqCst);
    if let Some(session) = session_slot().lock().take() {
        // Dropping `ingest_tx` closes the ingress channel; keepalive is a timer
        // loop with no natural end, so abort it. The egress task ends when the
        // socket recv errors or its handle is aborted/joined.
        session.keepalive.abort();
        session.egress.abort();
        session.ingress.abort();
        drop(session.ingest_tx);
    }
}

/// Blocking stop: signal stop, then **join the egress task** before returning.
///
/// Once this returns the `SvpnWritePacket` callback is guaranteed never to fire
/// again, so the caller may safely release the writer `ctx` it passed to
/// [`start`]. This is the terminal-stop path the NE's `stopTunnel` uses;
/// without the join, Swift releasing `ctx` while the egress task still drains
/// is a use-after-free.
///
/// MUST be called from a NON-runtime thread (the Swift tunnel control queue):
/// it `block_on`s the data-plane runtime. Bounded by [`JOIN_TIMEOUT`].
/// Idempotent.
pub fn stop_blocking() {
    RUNNING.store(false, Ordering::SeqCst);
    let Some(session) = session_slot().lock().take() else {
        return;
    };

    // Abort the non-egress tasks immediately (they never touch `ctx`).
    session.keepalive.abort();
    session.ingress.abort();
    drop(session.ingest_tx);

    // Abort the egress task too, then JOIN it: abort requests cancellation, the
    // join awaits the task actually leaving its poll. After this await the
    // egress closure — the only `emit` caller — has fully unwound, so no late
    // callback can race Swift's `ctx` release.
    let egress = session.egress;
    egress.abort();
    runtime().block_on(async move {
        match tokio::time::timeout(JOIN_TIMEOUT, egress).await {
            // Clean join, or a cancellation (abort) — both mean the task is gone.
            Ok(Ok(())) => {}
            Ok(Err(e)) if e.is_cancelled() => {}
            Ok(Err(e)) => {
                logging::bridge_log(&format!("svpn stop_blocking: egress join error: {e}"));
            }
            Err(_) => {
                log::warn!(
                    "svpn stop_blocking: egress join timed out after {JOIN_TIMEOUT:?}; \
                     releasing ctx anyway"
                );
            }
        }
    });
    logging::bridge_log("svpn stop_blocking: egress joined, ctx safe to release");
}

/// Whether the data plane is currently running.
pub fn is_running() -> bool {
    RUNNING.load(Ordering::SeqCst)
}

/// Queue a raw IP packet from `NEPacketTunnelFlow.readPackets`. Non-blocking;
/// drops under backpressure (returns 0 — a dropped packet is not an error from
/// Swift's perspective). Returns -1 only when the data plane isn't running.
pub fn ingest(packet: &[u8]) -> i32 {
    let Some(tx) = session_slot().lock().as_ref().map(|s| s.ingest_tx.clone()) else {
        return -1;
    };
    match tx.try_send(packet.to_vec()) {
        Ok(()) => 0,
        Err(mpsc::error::TrySendError::Full(_)) => {
            // Bounded queue saturated — drop. `readPackets` must return promptly.
            0
        }
        Err(mpsc::error::TrySendError::Closed(_)) => -1,
    }
}

/// Write the cumulative up/down byte counters (atomic loads). Safe before
/// `start` — returns zeros.
pub fn traffic() -> (i64, i64) {
    (
        UP_BYTES.load(Ordering::Relaxed),
        DOWN_BYTES.load(Ordering::Relaxed),
    )
}

// ---------------------------------------------------------------------------
// Tasks
// ---------------------------------------------------------------------------

/// Ingress: drain the ingest channel, optionally intercept chinadns DNS, else
/// encrypt and send to the server.
async fn ingress_loop(
    mut rx: mpsc::Receiver<Vec<u8>>,
    socket: Arc<UdpSocket>,
    cipher: crate::vendor::crypto::Cipher,
    master_key: Arc<[u8]>,
    writer: WriteCtx,
    interceptor: Option<Arc<DnsInterceptor>>,
) {
    while let Some(pkt) = rx.recv().await {
        // chinadns mode: an A/IN query to dst port 53 is handled out-of-band by
        // the interceptor (direct + tunneled split) and must NOT be forwarded
        // as-is. `try_intercept` returns true if it took ownership of the packet.
        if let Some(ref intc) = interceptor {
            if intc.try_intercept(&pkt, writer).await {
                continue;
            }
        }

        let datagram = match encrypt_packet(cipher, &master_key, &pkt) {
            Ok(d) => d,
            Err(e) => {
                // Crypto failure on egress is non-fatal: skip this packet.
                log::debug!(
                    "svpn: dropping un-encryptable {}-byte packet: {e}",
                    pkt.len()
                );
                continue;
            }
        };
        match socket.send(&datagram).await {
            Ok(_) => {
                UP_BYTES.fetch_add(pkt.len() as i64, Ordering::Relaxed);
            }
            Err(e) => {
                // A send failure on a connected socket is fatal for this session.
                log::warn!("svpn ingress: send to server failed, ending session: {e}");
                return;
            }
        }
    }
    log::debug!("svpn ingress: ingest channel closed, task exiting");
}

/// Egress: recv datagrams from the server, decrypt, drop sub-IP-header
/// payloads, and hand the plaintext IP packet to Swift via the callback.
async fn egress_loop(
    socket: Arc<UdpSocket>,
    cipher: crate::vendor::crypto::Cipher,
    master_key: Arc<[u8]>,
    writer: WriteCtx,
    interceptor: Option<Arc<DnsInterceptor>>,
) {
    let mut buf = vec![0u8; max_datagram_size(cipher)];
    loop {
        let n = match socket.recv(&mut buf).await {
            Ok(n) => n,
            Err(e) => {
                log::warn!("svpn egress: recv from server failed, ending session: {e}");
                return;
            }
        };

        let plaintext = match decrypt_packet(cipher, &master_key, &buf[..n]) {
            Ok(p) => p,
            Err(e) => {
                // Forged/corrupt/keepalive-echo datagrams are normal on an open
                // UDP port — drop, don't end the session.
                log::debug!("svpn egress: dropping undecryptable {n}-byte datagram: {e}");
                continue;
            }
        };

        // Drop anything too small to be an IP packet (an IPv4 header alone is 20
        // bytes): keepalive echoes and sub-IP-header noise must never reach the
        // tun-write path.
        if plaintext.len() < 20 {
            continue;
        }

        // chinadns: a tunneled clean DNS reply (server -> dns_remote -> back)
        // arrives here as a UDP/IPv4 packet from dns_remote. Let the interceptor
        // pair it with the pending direct answer and decide; if it consumes the
        // packet it synthesizes the client-facing response itself.
        if let Some(ref intc) = interceptor {
            if intc.try_handle_tunneled_reply(&plaintext, writer).await {
                continue;
            }
        }

        DOWN_BYTES.fetch_add(plaintext.len() as i64, Ordering::Relaxed);
        writer.emit(&plaintext);
    }
}

/// Keepalive: every 25 s, send a tiny encrypted `0x00` datagram so NAT mappings
/// stay open and the server keeps learning our source address.
async fn keepalive_loop(
    socket: Arc<UdpSocket>,
    cipher: crate::vendor::crypto::Cipher,
    master_key: Arc<[u8]>,
) {
    let mut ticker = tokio::time::interval(KEEPALIVE_INTERVAL);
    // Don't fire a burst if we ever fall behind (e.g. after device sleep).
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        let datagram = match encrypt_packet(cipher, &master_key, KEEPALIVE_PAYLOAD) {
            Ok(d) => d,
            Err(e) => {
                log::warn!("svpn keepalive: encrypt failed, skipping: {e}");
                continue;
            }
        };
        if let Err(e) = socket.send(&datagram).await {
            log::warn!("svpn keepalive: send failed, ending keepalive: {e}");
            return;
        }
    }
}
