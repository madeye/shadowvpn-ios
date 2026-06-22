# ShadowVPN iOS — implementation blueprint

> **Implemented.** The split-tunnel bypass set is selected **at runtime by
> country** (Settings → Bypass Country), derived from the bundled MaxMind
> GeoLite2 `Country.mmdb` by the FFI `svpn_country_cidrs_file(mmdb, country,
> cache_dir)` and **cached per country** to
> `<AppGroup>/cidr-cache/chnroute-<COUNTRY>-<mmdbLen>.txt` (the mmdb walk runs at
> most once per country). The static build-time `chnroute.txt` and the app-side
> `ChnrouteStager` described below were the first cut and have been removed; the
> `core/rust/chnroute-gen` tool remains as an offline utility. References to
> "chnroute" / `chnroute_path` in the code are now the **selected country's**
> CIDR file, not specifically China.


A native iOS client for **ShadowVPN** (a UDP, pre-shared-key, layer-3 tunnel using
the shadowsocks AEAD UDP wire scheme). It mirrors the project structure, build and
signing setup of the sibling project `../meow-ios`, but the data plane is far
simpler: ShadowVPN is a raw-IP point-to-point tunnel — **no tun2socks, no lwip, no
SOCKS, no Clash engine.**

Upstream protocol/reference (Rust): https://github.com/madeye/shadowvpn. The Rust
FFI **points to that repo** for the reusable, OS-agnostic modules, vendoring a
minimal subset of them (see below).

## What we reuse from meow-ios (read these for patterns)
- `../meow-ios/project.yml` — XcodeGen spec (app + PacketTunnel app-extension + a
  local SPM shared package + a Rust xcframework). We mirror its target layout,
  entitlements, app-group, post-build strip, schemes.
- `../meow-ios/PacketTunnel/Sources/*` — the ObjC NetworkExtension driver:
  `PacketTunnelProvider.m` (NE lifecycle + path monitor + debounced restart),
  `MWTunnelEngine.m` (start/stop/restart, ingress readPackets loop, traffic pump),
  `MWPacketWriter.m` (egress C callback → `writePackets`), `MWTunnelSettings.m`
  (NEPacketTunnelNetworkSettings: addresses, includedRoutes, excludedRoutes, DNS,
  MTU), `MWIPCListener`, `MWSharedStore`, `MWAppGroup`, `MWDarwinBridge`,
  `MWPreferences`. We adapt these, renaming `MW`→`SV`, `meow_*`→`svpn_*`.
- `../meow-ios/MeowShared/*` — the SPM package pattern (models + IPC, App Group,
  SharedStore, DarwinNotifications, Preferences). We build a smaller `SVPNShared`.
- `../meow-ios/App/Sources/*` — SwiftUI app shell: `MeowApp`, `AppModel`,
  `Services/VpnManager.swift` (NETunnelProviderManager), `Views/GlassCard.swift`,
  `HomeView`, `SettingsView`, `LogsView`, `ContentView`. We mirror the *design
  language* (GlassCard, tabbed layout) with ShadowVPN's much smaller settings set.
- `../meow-ios/scripts/{build-rust.sh,generate-xcodeproj.sh}` — adapt verbatim.

## Identity / signing (reuse meow's)
- App bundle id: `com.tangzixiang.shadowvpn`
- Extension bundle id: `com.tangzixiang.shadowvpn.PacketTunnel`
- App group: `group.com.tangzixiang.shadowvpn`
- Keychain access group: `$(AppIdentifierPrefix)com.tangzixiang.shadowvpn`
- Team: `32B45SMMQL` (automatic signing, via `Local.xcconfig` `DEVELOPMENT_TEAM`)
- Deployment target iOS 17.0, Swift 6, `SWIFT_STRICT_CONCURRENCY: complete`.
- Display name: **ShadowVPN**. NO Firebase, NO Yams, NO subscriptions.

## Repository layout (final)
```
project.yml                         # XcodeGen spec
Local.xcconfig                      # DEVELOPMENT_TEAM = 32B45SMMQL (gitignored)
DESIGN.md
core/rust/
  shadowvpn-ios-ffi/                # the iOS C-ABI crate -> ShadowVPNCore.xcframework
  chnroute-gen/                     # DONE: one-shot mmdb -> chnroute.txt tool
ShadowVPNCore/
  include/shadowvpn_core.h          # cbindgen output (committed)
  Frameworks/ShadowVPNCore.xcframework  # built by scripts/build-rust.sh (gitignored)
Shared/Resources/
  chnroute.txt                      # DONE: 5486 CN CIDRs, generated once from Country.mmdb
  gfwlist.txt                       # chinadns force-tunnel override domains (scripts/gen-gfwlist.sh)
  Country.mmdb                      # kept for regeneration only; NOT bundled at runtime
SVPNShared/                         # SPM package (SVPNModels + SVPNIPC)
PacketTunnel/Sources/               # ObjC NE extension (SV* classes)
App/Sources/                        # SwiftUI app
App/Resources/                      # assets, localization
scripts/                            # build-rust.sh, generate-xcodeproj.sh
```

## Rust FFI crate — `core/rust/shadowvpn-ios-ffi`
crate-type `["staticlib"]`. Builds `libshadowvpn_ios_ffi.a` for `aarch64-apple-ios`
and `aarch64-apple-ios-sim`, packed into `ShadowVPNCore.xcframework`. cbindgen emits
`include/shadowvpn_core.h`. `[profile.release]` opt-level "z", lto, panic=abort,
strip — small for the 50 MB NE budget (this crate is tiny vs meow).

### Dependency on upstream shadowvpn ("point to this repo")
Add `shadowvpn = { git = "https://github.com/madeye/shadowvpn" }` and reuse:
`shadowvpn::crypto` (Cipher, evp_bytes_to_key, encrypt_packet, decrypt_packet),
`shadowvpn::protocol` (sizing), `shadowvpn::policy::chnroute::ChnRoute`,
`shadowvpn::policy::dns` (question/a_records/min_ttl wire parsing).
**Build risk:** the whole `shadowvpn` lib also compiles `tun_device` (tun-rs) and
`policy::{route,dnsconf}` which are OS-native and may not cross-compile to
`aarch64-apple-ios`. **First** try the git dep and `cargo build --target
aarch64-apple-ios`. **If it fails to compile for iOS**, fall back to vendoring ONLY
the iOS-safe modules into this crate by copying `crypto.rs`, `protocol.rs`,
`policy/chnroute.rs`, `policy/dns.rs` from upstream `src/` (keep
the upstream MIT header + a `// vendored from madeye/shadowvpn` note). Do NOT bring
tun-rs / maxminddb / route / dnsconf into the iOS build. chnroute on iOS is a plain
text file (no mmdb at runtime). Document whichever path you took at the top of
`lib.rs`.

### Data plane (replaces tun-rs with the NE packet flow, mirroring meow's FFI)
There is NO OS TUN inside the NE. Swift owns `NEPacketTunnelFlow`. The crate runs a
tokio multi-thread runtime with: one UDP socket `connect()`ed to the server, a
keepalive ticker (25 s, 1-byte `0x00` plaintext per upstream), and an egress task.

### C ABI (prefix `svpn_`, generate header with cbindgen; keep doc-comments)
```
void  svpn_core_init(void);                       // idempotent logging init (oslog)
void  svpn_core_log(int level, const char *msg);  // 0=err..4=trace, NE lifecycle logs
void  svpn_core_set_home_dir(const char *dir);    // App Group container path (logs/cache)
const char *svpn_core_last_error(void);           // thread-local last error

typedef void (*SvpnWritePacket)(void *ctx, const uint8_t *data, uintptr_t len);

// config_json (UTF-8): {"server":"host:port","password":"...","cipher":"chacha20-poly1305",
//   "mode":"full|chnroute|chinadns","mtu":1400,
//   "dns_local":"114.114.114.114:53","dns_remote":"8.8.8.8:53",
//   "chnroute_path":"/abs/chnroute.txt","gfwlist_path":"/abs/gfwlist.txt"}
// gfwlist_path is OPTIONAL and consulted only in chinadns mode: a force-tunnel
// override (upstream PR #17) — names on it always take the clean tunneled path.
int   svpn_tun_start(void *ctx, SvpnWritePacket cb, const char *config_json); // 0 ok / -1 err
int   svpn_tun_ingest(const uint8_t *data, uintptr_t len);  // Swift readPackets -> here
void  svpn_tun_stop(void);                          // fire-and-forget
void  svpn_tun_stop_blocking(void);                 // join egress before ctx release (NE stop)
int   svpn_is_running(void);
void  svpn_engine_traffic(int64_t *up, int64_t *down);   // cumulative bytes (atomics)
uint64_t svpn_resident_bytes(void);                 // phys footprint via mach (0 off-Apple)
```
Lifecycle/threading contract is identical to meow's `meow_tun_*` (see
`MWTunnelEngine.m`): `svpn_tun_stop_blocking()` must guarantee the egress callback
never fires again before Swift releases the writer `ctx` (avoid the use-after-free
meow documents). Ingest is non-blocking; drop under backpressure.

### Datagram path (per upstream `src/bin/client.rs`)
- ingest(pkt): if `mode==chinadns` and pkt is IPv4/UDP/dstport 53 → hand to the
  chinadns interceptor (below) and DO NOT forward as-is. Otherwise
  `encrypt_packet(cipher, key, pkt)` → `socket.send`.
- recv loop: `socket.recv` → `decrypt_packet`; drop if len < 20 (keepalive/sub-IP);
  else egress callback. Count bytes both directions for `svpn_engine_traffic`.

### chinadns mode (in-FFI split DNS — secondary feature; keep modular & isolated)
Module `dns_intercept.rs`. For an intercepted A query: send the query to `dns_local`
via a **direct** Rust UDP socket (NE sockets bypass the tunnel → domestic answer),
and send a parallel clean query to `dns_remote` **through the tunnel** by crafting a
UDP/IPv4 packet to `dns_remote` and pushing it through the normal encrypt→server
path (the server routes it; the reply returns through the tunnel). Decide with
`ChnRoute::contains`: if the **local** answer's first A record is in chnroute → the
name is domestic → return the local answer (its IPs are china-routed = direct);
otherwise return the clean/remote answer. Synthesize the response IP/UDP packet back
to the client via the egress callback (swap src/dst, recompute IPv4 + UDP checksums).
**gfwlist force-tunnel override (upstream PR #17):** when a `gfwlist_path` is
supplied, any queried name matching the bundled gfwlist (`GfwList::matches`,
domain-suffix) skips the local-vs-clean race entirely and always resolves via the
clean tunneled upstream — covering domains the GFW poisons to an in-China-looking
address that the race would otherwise misclassify as domestic. The override is
optional: a missing/unreadable gfwlist just disables it (plain chinadns race).
Reuse `shadowvpn::policy::dns::{question,a_records,min_ttl}`. **Bound the scope:**
A/IN queries only; anything else (AAAA, etc.) — for AAAA return NODATA or just relay
to dns_local. If a clean path is unavailable, fall back to the local answer. This
mode is best-effort; the chnroute split-routing below is the load-bearing feature
and must work even if chinadns is simplified.

## Routing on iOS — handled in Swift (`SVTunnelSettings`), NOT in Rust
`NEPacketTunnelNetworkSettings` (mirror `MWTunnelSettings.m`):
- tunnel addresses `10.8.0.2/30` (peer-style), MTU from config (default 1400, MSS
  clamp benefit as meow documents).
- `mode==full`: includedRoutes = `[defaultRoute]`; excludedRoutes = LAN set
  (copy meow's `ipv4LanExcludedRoutes`, keeping 127/8 omitted, tunnel subnet split).
- `mode==chnroute` / `mode==chinadns`: includedRoutes = `[defaultRoute]`;
  excludedRoutes = LAN set **+ every CIDR parsed from the bundled `chnroute.txt`**.
  China IPs therefore bypass the tunnel (direct); everything else is tunneled. Parse
  `chnroute.txt` (skip `#`/blank lines; `a.b.c.d/len` → `NEIPv4Route` with computed
  mask). ~5.5k routes is acceptable. (iOS caps are generous; if a problem surfaces,
  log a truncation count — never silently drop.)
- DNS: `mode==chinadns` → `NEDNSSettings(servers:[dns_local_ip, dns_remote_ip])`
  with `matchDomains:[""]`; else inherit system DNS (no NEDNSSettings) so split
  routing alone applies. Keep IPv4-only (no IPv6Settings), like meow.

`chnroute.txt` must be readable by the **extension**: bundle it in the PacketTunnel
target resources (NE reads its own bundle) AND in the app (for display/staging).
The app also stages it into the App Group on launch (mirror meow's GeoAssetStager)
so the NE can read a stable path; pass that path as `chnroute_path` in config_json,
or read from the extension bundle directly — pick one and be consistent.

## SVPNShared (SPM, swift-tools 6.x; products: SVPNModels, SVPNIPC)
- `Profile`: server (host), port, password, cipher (enum: aes-128-gcm/aes-256-gcm/
  chacha20-poly1305), mode (enum: full/chnroute/chinadns), dnsLocal, dnsRemote, mtu.
  Codable; persisted in the App Group (SharedStore) and to the NE via
  `NETunnelProviderProtocol.providerConfiguration`.
- `VpnState` (stage enum: disconnected/connecting/connected/error + message + bytes).
- `AppGroup` (container URL, UserDefaults(suiteName:)), `SharedStore` (state + traffic
  JSON in the container), `DarwinNotifications` (cross-process notify), `Preferences`.
  Mirror MeowShared’s files closely but trimmed.

## App (SwiftUI, mirror meow’s design)
- `ShadowVPNApp` (@main), `AppModel` (@Observable), `VpnManager`
  (NETunnelProviderManager: load/save manager, start/stop, observe status &
  connectedDate, write Profile into providerConfiguration + protocol serverAddress).
- `ContentView`: TabView → Home / Settings / Logs.
- `HomeView`: big connect toggle, status pill, live up/down rate + totals (from
  SharedStore traffic via Darwin notifications), current mode/server summary —
  use `GlassCard` styling copied/adapted from meow.
- `SettingsView`: server, port, password (SecureField), cipher Picker, mode Picker
  (Full / ChinaRoute split / ChinaDNS), dns_local & dns_remote (shown for chinadns).
  Persist to Profile.
- `LogsView`: tail the App Group log file (the NE writes via svpn_core_log → file).
- Resources: AppIcon/Assets, en + zh-Hans Localizable.strings, chnroute.txt copy.

## project.yml essentials (adapt meow’s)
- options.bundleIdPrefix `com.tangzixiang.shadowvpn`; deploymentTarget iOS 17.
- targets: `shadowvpn-ios` (application), `PacketTunnel` (app-extension),
  package `SVPNShared`. Link `ShadowVPNCore/Frameworks/ShadowVPNCore.xcframework`
  (embed:false, optional:true) into BOTH app and PacketTunnel; `OTHER_LDFLAGS:[-ObjC]`;
  HEADER_SEARCH_PATHS `$(SRCROOT)/ShadowVPNCore/include`. PacketTunnel needs a
  bridging header to import `shadowvpn_core.h`. App embeds PacketTunnel
  (embed:true, codeSign:true). Entitlements: app-groups, packet-tunnel-provider,
  keychain-access-groups. Post-build `strip -Sx` on Release. Scheme builds app +
  extension. No Firebase/Yams packages.
- Info.plist: PacketTunnel `NSExtension` point
  `com.apple.networkextension.packet-tunnel`, principal class `PacketTunnelProvider`.

## Build / verify (the orchestrator runs these after the workflow)
1. `bash scripts/build-rust.sh` → `cargo build --target aarch64-apple-ios{,-sim}` →
   `ShadowVPNCore.xcframework` + refreshed `shadowvpn_core.h`.
2. `bash scripts/generate-xcodeproj.sh` (xcodegen).
3. `xcodebuild -project shadowvpn-ios.xcodeproj -scheme shadowvpn-ios \
   -destination 'generic/platform=iOS Simulator' build` — fix until it compiles.
4. `cargo test` in the FFI crate for crypto round-trip + chnroute parse.

## Conventions
- ObjC NE files: prefix `SV` (e.g. `SVTunnelEngine`, `SVPacketWriter`,
  `SVTunnelSettings`, `SVPacketTunnelProvider`), os_log subsystem
  `com.tangzixiang.shadowvpn.PacketTunnel`.
- Swift 6 strict concurrency; keep `@MainActor` where meow does.
- Match the surrounding code’s comment density and idiom. swiftlint/swiftformat
  configs copied from meow.

---

## QUIC / HTTP3 carrier obfuscation (`obfs`)

Optional traffic shaping that makes each UDP datagram look like a QUIC 1-RTT
(HTTP/3) short-header packet, to evade naive UDP/protocol classification. It is
**cosmetic framing only** — no added security — and is applied *outside* the
shadowsocks AEAD envelope. Selected per profile via `config_json["obfs"]`
(`"none"` default, or `"quic"`). **Both ends must agree**; the server applies the
exact inverse (`shadowvpn-server` reads `"obfs": "quic"` in `server.json`).

Implemented in `core/rust/shadowvpn-ios-ffi/src/obfs.rs` (client) and upstream
`src/obfs.rs` (server, madeye/shadowvpn) — keep the two byte-compatible.

### Wire format

Every datagram (the `salt ++ AEAD(ciphertext ++ tag)` envelope, including
keepalives and the chinadns clean query) is prefixed with:

```text
[ first byte (1) ] [ DCID (8) ] [ packet number (PN_LEN) ] [ payload … ]
  0b01RR_SPKK         opaque        big-endian counter         salt ++ AEAD
```

* **first byte** — header-form bit `0x80` CLEAR and fixed bit `0x40` SET (QUIC
  short header). The low two bits hold `PN_LEN - 1` (QUIC packet-number-length
  field); the remaining bits are randomized (header-protected ⇒ random in real
  QUIC). This implementation emits `PN_LEN = 2`.
* **DCID** — `DEFAULT_DCID_LEN = 8` opaque bytes, generated once per session and
  reused (a real QUIC connection keeps a constant DCID). Both directions wrap
  with their own DCID; the value is never read on decode.
* **packet number** — a `PN_LEN`-byte big-endian counter (cosmetic).

### Decode (self-describing given the fixed 8-byte DCID)

```text
first  = pkt[0]
require: (first & 0x80) == 0  &&  (first & 0x40) != 0     # else drop (not obfs)
pn_len = (first & 0x03) + 1
payload = pkt[1 + 8 + pn_len ..]                          # then AEAD-decrypt
```

A packet whose first byte isn't a short header is dropped before the AEAD, so a
mismatched (non-obfs) peer simply gets no traffic — `obfs` must match on both
ends. Pairs naturally with **UDP/443**, where real HTTP/3 lives.
