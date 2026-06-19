//! chinadns split-DNS interceptor (best-effort, A/IN only).
//!
//! This is the *secondary* feature called out in `DESIGN.md`: the load-bearing
//! split routing is the Swift-side `chnroute.txt` excluded-route set, which
//! works regardless of anything here. The interceptor is kept deliberately
//! modular and isolated so that a failure to build or run it (no clean path, a
//! malformed packet, an unparsable chnroute file) degrades to plain forwarding
//! without ever taking the tunnel down.
//!
//! # What it does
//!
//! For an intercepted A/IN query (an ingested IPv4/UDP packet to dst port 53):
//!
//! 1. Fire the query **direct** to `dns_local` over a plain Rust [`UdpSocket`].
//!    NE sockets bypass the tunnel, so this yields the *domestic* answer.
//! 2. Fire a clean copy **through the tunnel**: craft a fresh UDP/IPv4 packet
//!    addressed to `dns_remote`, encrypt it, and send it down the normal
//!    `socket.send` path. The server routes it; the reply returns through the
//!    tunnel and surfaces in the egress loop (see [`try_handle_tunneled_reply`]).
//! 3. Decide with [`ChnRoute::contains`] on the **local** answer's first A
//!    record: if it is in chnroute the name is domestic → return the local
//!    answer (its IPs are china-routed = direct); otherwise return the
//!    clean/remote answer.
//! 4. Synthesize the response IPv4/UDP packet back to the client via the egress
//!    callback — swap src/dst addr+port and recompute the IPv4 + UDP checksums.
//!
//! Scope bounds (per `DESIGN.md`): **A/IN queries only**. AAAA and everything
//! else is relayed to `dns_local` and its answer returned verbatim (NODATA-ish
//! pass-through). If the clean path is unavailable, fall back to the local
//! answer.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::net::UdpSocket;

use crate::config::RuntimeConfig;
use crate::engine::WriteCtx;
use crate::vendor::crypto::{encrypt_packet, Cipher};
use crate::vendor::dns::{a_records, question};
use crate::vendor::policy::chnroute::ChnRoute;

/// IPv4 protocol number for UDP.
const IPPROTO_UDP: u8 = 17;
/// Minimum IPv4 header length (no options), in bytes.
const IPV4_MIN_HEADER: usize = 20;
/// UDP header length, in bytes.
const UDP_HEADER: usize = 8;
/// The well-known DNS port.
const DNS_PORT: u16 = 53;
/// RR TYPE for `A` and CLASS for `IN` — the only query shape we intercept.
const TYPE_A: u16 = 1;
const CLASS_IN: u16 = 1;

/// How long we wait for the direct `dns_local` answer before giving up and
/// falling back. Domestic resolvers answer in single-digit ms; a second is a
/// generous ceiling that still keeps a dead resolver from stalling the app.
const LOCAL_QUERY_TIMEOUT: Duration = Duration::from_secs(1);

/// A parsed view of an ingested IPv4/UDP DNS query packet — the fields we need
/// to (a) decide whether to intercept and (b) synthesize the response.
struct ParsedQuery {
    /// Client (source) IPv4 address — becomes the response *destination*.
    client_ip: Ipv4Addr,
    /// Client (source) UDP port — becomes the response *destination* port.
    client_port: u16,
    /// The DNS server the client addressed (response *source*).
    server_ip: Ipv4Addr,
    /// The DNS server port the client addressed (response *source* port).
    server_port: u16,
    /// The DNS message payload (UDP body).
    dns: Vec<u8>,
}

/// State for a single in-flight clean (tunneled) query, keyed by DNS txid, so
/// the egress loop can pair an incoming tunneled reply with the original
/// client. We keep the client addressing + the local answer (if it arrived
/// first) so the decision can be made when either side completes.
struct Pending {
    /// Client addressing, for synthesizing the response.
    client_ip: Ipv4Addr,
    client_port: u16,
    server_ip: Ipv4Addr,
    server_port: u16,
}

/// The chinadns interceptor. Cheap to clone-share via `Arc`.
pub struct DnsInterceptor {
    /// China IPv4 ranges, loaded once from `chnroute_path`.
    chnroute: ChnRoute,
    /// Domestic resolver `ip:port`.
    dns_local: SocketAddrV4,
    /// Clean upstream resolver `ip:port`.
    dns_remote: SocketAddrV4,
    /// Plain (untunneled) socket for the direct `dns_local` query.
    direct: Arc<UdpSocket>,
    /// The tunnel's server-connected UDP socket, for the clean tunneled copy.
    tunnel: Arc<UdpSocket>,
    /// Cipher + key for encrypting the tunneled clean query.
    cipher: Cipher,
    master_key: Arc<[u8]>,
    /// In-flight tunneled queries keyed by DNS transaction id.
    pending: Mutex<HashMap<u16, Pending>>,
}

impl DnsInterceptor {
    /// Build the interceptor. Returns an error string (logged, then ignored by
    /// the caller, which falls back to plain forwarding) if the chnroute file
    /// can't be read, the DNS endpoints don't parse, or the direct socket can't
    /// be bound.
    pub fn new(
        cfg: &RuntimeConfig,
        tunnel: Arc<UdpSocket>,
        cipher: Cipher,
        master_key: Arc<[u8]>,
    ) -> Result<Self, String> {
        let path = cfg
            .chnroute_path
            .as_deref()
            .ok_or_else(|| "chinadns: chnroute_path missing".to_string())?;
        let chnroute =
            ChnRoute::load(path).map_err(|e| format!("chinadns: load {path} failed: {e}"))?;

        let dns_local = parse_sockaddr_v4(cfg.dns_local.as_deref().unwrap_or(""))
            .ok_or_else(|| "chinadns: dns_local is not a valid ip:port".to_string())?;
        let dns_remote = parse_sockaddr_v4(cfg.dns_remote.as_deref().unwrap_or(""))
            .ok_or_else(|| "chinadns: dns_remote is not a valid ip:port".to_string())?;

        // Bind a plain socket for the direct domestic query. On iOS this socket
        // is outside the tunnel's included routes, so it reaches dns_local over
        // the physical link (the whole point of the split).
        let direct = std::net::UdpSocket::bind(("0.0.0.0", 0))
            .and_then(|s| {
                s.set_nonblocking(true)?;
                Ok(s)
            })
            .map_err(|e| format!("chinadns: bind direct socket failed: {e}"))?;
        let direct = UdpSocket::from_std(direct)
            .map_err(|e| format!("chinadns: adopt direct socket failed: {e}"))?;

        Ok(DnsInterceptor {
            chnroute,
            dns_local,
            dns_remote,
            direct: Arc::new(direct),
            tunnel,
            cipher,
            master_key,
            pending: Mutex::new(HashMap::new()),
        })
    }

    /// Examine an ingested packet. Returns `true` if the interceptor took
    /// ownership (the caller must NOT forward it as-is); `false` to let the
    /// normal encrypt-and-forward path handle it.
    ///
    /// Only A/IN UDP/53 IPv4 queries are intercepted. AAAA and other qtypes are
    /// relayed to `dns_local` and their answer returned verbatim (still
    /// consumed so they don't double-send), per the bounded scope.
    pub async fn try_intercept(&self, packet: &[u8], writer: WriteCtx) -> bool {
        let Some(q) = parse_udp_dns_query(packet) else {
            return false; // not an IPv4/UDP/53 packet — forward normally
        };

        // Read the question. A malformed DNS body → leave it to the normal path.
        let Some((_name, qtype, qclass)) = question(&q.dns) else {
            return false;
        };

        // Non-A/IN: relay to dns_local and return its answer verbatim. We still
        // "consume" it (return true) because we already handle the resolution
        // out-of-band; forwarding it through the tunnel too would double-answer.
        if qtype != TYPE_A || qclass != CLASS_IN {
            if let Some(answer) = self.query_direct(&q.dns).await {
                self.emit_response(&q, &answer, writer);
            }
            // If the direct relay failed, drop silently — best-effort.
            return true;
        }

        // A/IN: kick off the clean tunneled copy (fire-and-forget; the reply is
        // paired later in the egress loop), then race the direct domestic answer.
        self.send_clean_tunneled(&q);

        let Some(local_answer) = self.query_direct(&q.dns).await else {
            // No domestic answer; the tunneled clean reply (if any) will be
            // delivered by the egress path. Nothing to synthesize here.
            return true;
        };

        // Decide on the local answer's first A record.
        let first_local = a_records(&local_answer).into_iter().next();
        let domestic = match first_local {
            Some(ip) => self.chnroute.contains(ip),
            // No A record (NXDOMAIN / empty) — treat as domestic and return the
            // local answer; there's nothing for chnroute to classify.
            None => true,
        };

        if domestic {
            // Domestic name → china-routed IPs are direct → return local answer.
            // The matching tunneled reply, if it arrives, is dropped by the
            // egress pairing logic (txid no longer pending after we clear it).
            self.clear_pending(&q.dns);
            self.emit_response(&q, &local_answer, writer);
        }
        // else: foreign name → trust the clean/remote answer, which arrives via
        // the tunnel and is synthesized by `try_handle_tunneled_reply`. We leave
        // the pending entry in place so that path can complete.
        true
    }

    /// Examine a decrypted, tunneled IPv4/UDP packet from the egress loop. If it
    /// is a DNS reply from `dns_remote` matching a pending clean query, pair it,
    /// synthesize the client-facing response, and return `true`. Otherwise
    /// `false` (the egress loop forwards it normally).
    pub async fn try_handle_tunneled_reply(&self, plaintext: &[u8], writer: WriteCtx) -> bool {
        let Some(q) = parse_udp_dns_query(plaintext) else {
            return false;
        };
        // A tunneled DNS *reply* travels FROM the remote resolver: src port 53,
        // src ip == dns_remote.
        if q.server_port != DNS_PORT || q.server_ip != *self.dns_remote.ip() {
            return false;
        }
        let Some(txid) = txid(&q.dns) else {
            return false;
        };

        // Only act if we still have this txid pending (i.e. the foreign branch
        // chose to wait for the clean answer). If the domestic branch already
        // answered, the entry was cleared and we drop this reply.
        let Some(pending) = self.pending.lock().remove(&txid) else {
            return false;
        };

        // Synthesize the response back to the original client. The reply's UDP
        // payload (`q.dns`) is the clean answer; address it from the client's
        // intended DNS server (the one it queried) back to the client.
        let resp = build_udp_ipv4(
            pending.server_ip,
            pending.server_port,
            pending.client_ip,
            pending.client_port,
            &q.dns,
        );
        writer.emit(&resp);
        true
    }

    /// Fire the DNS message at `dns_local` over the direct socket and await one
    /// reply (bounded). Returns the reply's DNS payload, or `None` on timeout /
    /// IO error.
    async fn query_direct(&self, dns: &[u8]) -> Option<Vec<u8>> {
        let sock = self.direct.clone();
        if sock.send_to(dns, self.dns_local).await.is_err() {
            return None;
        }
        let mut buf = vec![0u8; 1500];
        match tokio::time::timeout(LOCAL_QUERY_TIMEOUT, sock.recv_from(&mut buf)).await {
            Ok(Ok((n, _from))) => Some(buf[..n].to_vec()),
            _ => None,
        }
    }

    /// Send a clean copy of the query through the tunnel: craft a UDP/IPv4
    /// packet addressed to `dns_remote`, encrypt it, and push it down the
    /// server-connected socket. Records the txid as pending so the egress loop
    /// can pair the reply. Fire-and-forget: any failure just means the clean
    /// branch won't complete (we fall back to the local answer).
    fn send_clean_tunneled(&self, q: &ParsedQuery) {
        let Some(txid) = txid(&q.dns) else {
            return;
        };
        self.pending.lock().insert(
            txid,
            Pending {
                client_ip: q.client_ip,
                client_port: q.client_port,
                server_ip: q.server_ip,
                server_port: q.server_port,
            },
        );

        // Source the tunneled query from the client's addressing so the server's
        // reply returns to the same 5-tuple the client expects. The destination
        // is the clean remote resolver.
        let pkt = build_udp_ipv4(
            q.client_ip,
            q.client_port,
            *self.dns_remote.ip(),
            self.dns_remote.port(),
            &q.dns,
        );
        let datagram = match encrypt_packet(self.cipher, &self.master_key, &pkt) {
            Ok(d) => d,
            Err(_) => {
                self.pending.lock().remove(&txid);
                return;
            }
        };
        // try_send-style: spawn the send so we don't block the ingress task.
        let tunnel = self.tunnel.clone();
        tokio::spawn(async move {
            let _ = tunnel.send(&datagram).await;
        });
    }

    /// Drop any pending entry for this query's txid (used when the domestic
    /// branch wins so a late tunneled reply is ignored).
    fn clear_pending(&self, dns: &[u8]) {
        if let Some(txid) = txid(dns) {
            self.pending.lock().remove(&txid);
        }
    }

    /// Synthesize an IPv4/UDP DNS response back to the client and emit it via
    /// the egress callback. Source = the DNS server the client queried; dest =
    /// the client.
    fn emit_response(&self, q: &ParsedQuery, dns_payload: &[u8], writer: WriteCtx) {
        let resp = build_udp_ipv4(
            q.server_ip,
            q.server_port,
            q.client_ip,
            q.client_port,
            dns_payload,
        );
        writer.emit(&resp);
    }
}

/// Parse `ip:port` into a [`SocketAddrV4`] (IPv4 only; IPv6 endpoints are out of
/// scope for the chnroute decision).
fn parse_sockaddr_v4(s: &str) -> Option<SocketAddrV4> {
    s.parse::<SocketAddrV4>().ok()
}

/// Extract the DNS transaction id (first two bytes) from a DNS message.
fn txid(dns: &[u8]) -> Option<u16> {
    if dns.len() < 2 {
        return None;
    }
    Some(u16::from_be_bytes([dns[0], dns[1]]))
}

/// Parse an IPv4/UDP packet to dst port 53, extracting the addressing + DNS
/// payload. Returns `None` for anything that isn't a well-formed IPv4/UDP/53
/// datagram (IPv6, TCP, fragmented, truncated, wrong port).
fn parse_udp_dns_query(pkt: &[u8]) -> Option<ParsedQuery> {
    if pkt.len() < IPV4_MIN_HEADER {
        return None;
    }
    // Version (high nibble) must be 4.
    if pkt[0] >> 4 != 4 {
        return None;
    }
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    if ihl < IPV4_MIN_HEADER || pkt.len() < ihl + UDP_HEADER {
        return None;
    }
    // Protocol must be UDP.
    if pkt[9] != IPPROTO_UDP {
        return None;
    }
    // Reject fragmented datagrams: MF flag set or non-zero fragment offset. A
    // DNS query fits in one datagram; reassembly is out of scope.
    let flags_frag = u16::from_be_bytes([pkt[6], pkt[7]]);
    let mf = flags_frag & 0x2000 != 0;
    let frag_off = flags_frag & 0x1fff;
    if mf || frag_off != 0 {
        return None;
    }

    let src_ip = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst_ip = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);

    let udp = &pkt[ihl..];
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    if dst_port != DNS_PORT {
        return None;
    }
    let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    // UDP length covers header + payload; clamp to the actual buffer.
    if udp_len < UDP_HEADER || ihl + udp_len > pkt.len() {
        return None;
    }
    let dns = udp[UDP_HEADER..udp_len].to_vec();
    if dns.is_empty() {
        return None;
    }

    Some(ParsedQuery {
        client_ip: src_ip,
        client_port: src_port,
        server_ip: dst_ip,
        server_port: dst_port,
        dns,
    })
}

/// Build a complete IPv4/UDP packet carrying `payload`, with a correct IPv4
/// header checksum and UDP checksum (pseudo-header included).
///
/// Returns `[ IPv4 header (20B) | UDP header (8B) | payload ]`.
fn build_udp_ipv4(
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = UDP_HEADER + payload.len();
    let total_len = IPV4_MIN_HEADER + udp_len;
    let mut pkt = vec![0u8; total_len];

    // --- IPv4 header ---
    pkt[0] = 0x45; // version 4, IHL 5 (20 bytes, no options)
    pkt[1] = 0x00; // DSCP/ECN 0
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[4..6].copy_from_slice(&0u16.to_be_bytes()); // identification 0
    pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // flags: DF set, frag 0
    pkt[8] = 64; // TTL
    pkt[9] = IPPROTO_UDP;
    // checksum (10..12) left zero for now
    pkt[12..16].copy_from_slice(&src_ip.octets());
    pkt[16..20].copy_from_slice(&dst_ip.octets());
    let ip_csum = checksum(&pkt[..IPV4_MIN_HEADER]);
    pkt[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    // --- UDP header ---
    let u = IPV4_MIN_HEADER;
    pkt[u..u + 2].copy_from_slice(&src_port.to_be_bytes());
    pkt[u + 2..u + 4].copy_from_slice(&dst_port.to_be_bytes());
    pkt[u + 4..u + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    // checksum (u+6..u+8) left zero, computed below over the pseudo-header
    pkt[u + 8..].copy_from_slice(payload);

    let udp_csum = udp_checksum(src_ip, dst_ip, &pkt[u..]);
    // A computed UDP checksum of 0 is transmitted as 0xFFFF (RFC 768): a zero
    // field means "no checksum", which would change its meaning.
    let udp_csum = if udp_csum == 0 { 0xffff } else { udp_csum };
    pkt[u + 6..u + 8].copy_from_slice(&udp_csum.to_be_bytes());

    pkt
}

/// One's-complement Internet checksum over `data` (RFC 1071). Used for the IPv4
/// header.
fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// UDP checksum: the one's-complement sum over the IPv4 pseudo-header
/// (src, dst, zero, protocol, UDP length) plus the UDP header + payload.
fn udp_checksum(src: Ipv4Addr, dst: Ipv4Addr, udp: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header.
    let s = src.octets();
    let d = dst.octets();
    sum += u16::from_be_bytes([s[0], s[1]]) as u32;
    sum += u16::from_be_bytes([s[2], s[3]]) as u32;
    sum += u16::from_be_bytes([d[0], d[1]]) as u32;
    sum += u16::from_be_bytes([d[2], d[3]]) as u32;
    sum += IPPROTO_UDP as u32; // zero byte + protocol
    sum += udp.len() as u32; // UDP length (again)

    // UDP header + payload.
    let mut chunks = udp.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal A/IN query body for `name` with txid `id`.
    fn dns_query(id: u16, name: &str) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&id.to_be_bytes());
        m.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        for label in name.split('.') {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&TYPE_A.to_be_bytes());
        m.extend_from_slice(&CLASS_IN.to_be_bytes());
        m
    }

    #[test]
    fn build_and_reparse_round_trips() {
        let payload = dns_query(0xBEEF, "example.com");
        let pkt = build_udp_ipv4(
            Ipv4Addr::new(10, 8, 0, 2),
            5353,
            Ipv4Addr::new(8, 8, 8, 8),
            53,
            &payload,
        );
        // IPv4 header checksum must validate to zero when summed including the
        // stored checksum.
        assert_eq!(checksum(&pkt[..IPV4_MIN_HEADER]), 0);

        let q = parse_udp_dns_query(&pkt).expect("parses as UDP/53 query");
        assert_eq!(q.client_ip, Ipv4Addr::new(10, 8, 0, 2));
        assert_eq!(q.client_port, 5353);
        assert_eq!(q.server_ip, Ipv4Addr::new(8, 8, 8, 8));
        assert_eq!(q.server_port, 53);
        assert_eq!(q.dns, payload);
        assert_eq!(txid(&q.dns), Some(0xBEEF));
    }

    #[test]
    fn udp_checksum_validates_to_zero() {
        let payload = dns_query(0x1234, "a.test");
        let pkt = build_udp_ipv4(
            Ipv4Addr::new(1, 2, 3, 4),
            1000,
            Ipv4Addr::new(5, 6, 7, 8),
            53,
            &payload,
        );
        // Recomputing the UDP checksum over the segment (with the stored
        // checksum present) yields 0 for a valid datagram. 0xFFFF substitution
        // only happens when the raw sum was 0, which it is not here.
        let udp = &pkt[IPV4_MIN_HEADER..];
        let v = udp_checksum(Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(5, 6, 7, 8), udp);
        assert_eq!(v, 0, "valid UDP datagram checksum verifies to zero");
    }

    #[test]
    fn rejects_non_udp_and_non_53() {
        // TCP (proto 6) to port 53.
        let mut pkt = build_udp_ipv4(
            Ipv4Addr::new(1, 1, 1, 1),
            1,
            Ipv4Addr::new(2, 2, 2, 2),
            53,
            b"x",
        );
        pkt[9] = 6; // TCP
        assert!(parse_udp_dns_query(&pkt).is_none());

        // UDP but to port 80, not 53.
        let pkt2 = build_udp_ipv4(
            Ipv4Addr::new(1, 1, 1, 1),
            1,
            Ipv4Addr::new(2, 2, 2, 2),
            80,
            b"x",
        );
        assert!(parse_udp_dns_query(&pkt2).is_none());
    }

    #[test]
    fn rejects_truncated_and_ipv6() {
        assert!(parse_udp_dns_query(&[0x45, 0x00]).is_none()); // too short
        let mut v6 = vec![0u8; 40];
        v6[0] = 0x60; // version 6
        assert!(parse_udp_dns_query(&v6).is_none());
    }
}
