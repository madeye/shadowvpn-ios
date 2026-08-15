#import "SVTunnelSettings.h"
#import "SVEngineLog.h"
#import <os/log.h>
#import <arpa/inet.h>

static os_log_t gLog;

// The point-to-point tunnel interface address. ShadowVPN hands the TUN a tiny
// /30 (10.8.0.0/30: usable .1/.2) in the RFC1918 10/8 block — the client takes
// .2 and treats the rest as the peer side. This must be carved back out of the
// 10/8 LAN exclusion below, otherwise the tunnel's own address range would be
// declared "direct" and the interface routing would be inconsistent.
// Fallback tunnel inner address if the profile's peer_ip is missing/invalid.
// Matches the reference server's peer_ip so return routing works by default.
static NSString *const kDefaultTunnelAddress = @"10.9.0.2";
static NSString *const kTunnelSubnetMask     = @"255.255.255.252";  // /30

@implementation SVTunnelSettings

+ (void)initialize {
    if (self == [SVTunnelSettings class]) {
        gLog = os_log_create("com.tangzixiang.shadowvpn.PacketTunnel", "settings");
    }
}

+ (NEPacketTunnelNetworkSettings *)makeWithServerAddress:(NSString *)serverAddress
                                                tunnelIP:(NSString *)tunnelIP
                                                    mode:(NSString *)mode
                                                dnsLocal:(nullable NSString *)dnsLocal
                                               dnsRemote:(nullable NSString *)dnsRemote
                                                     mtu:(NSInteger)mtu
                                             chnrouteURL:(nullable NSURL *)chnrouteURL
                                        serverExclusions:(nullable NSArray<NSString *> *)serverExclusions {
    NEPacketTunnelNetworkSettings *settings =
        [[NEPacketTunnelNetworkSettings alloc] initWithTunnelRemoteAddress:serverAddress];

    // Validate the configured tunnel IP; fall back to the default if it isn't a
    // dotted IPv4 (so a typo can't wedge the tunnel at a bad address).
    struct in_addr probe;
    if (tunnelIP.length == 0 || inet_pton(AF_INET, tunnelIP.UTF8String, &probe) != 1) {
        os_log_error(gLog, "invalid tunnel IP %{public}@, using %{public}@", tunnelIP, kDefaultTunnelAddress);
        tunnelIP = kDefaultTunnelAddress;
    }

    // IPv4 — claim the /30 tunnel address and route the default route into the
    // tunnel. The split is implemented as excludedRoutes: anything in the LAN
    // set (and, for chnroute/chinadns, anything in chnroute.txt) bypasses the
    // tunnel and goes out the physical interface directly.
    NEIPv4Settings *ipv4 = [[NEIPv4Settings alloc]
        initWithAddresses:@[tunnelIP]
              subnetMasks:@[kTunnelSubnetMask]];
    ipv4.includedRoutes = @[[NEIPv4Route defaultRoute]];

    NSMutableArray<NEIPv4Route *> *excluded =
        [[self ipv4LanExcludedRoutesForTunnelIP:tunnelIP] mutableCopy];

    BOOL isSplit = [mode isEqualToString:@"chnroute"] || [mode isEqualToString:@"chinadns"];
    if (isSplit && chnrouteURL) {
        NSUInteger appended = [self appendChnrouteExclusions:excluded fromURL:chnrouteURL];
        os_log_info(gLog, "settings: appended %lu chnroute exclusions (mode=%{public}@)",
                    (unsigned long)appended, mode);
        SVEngineLogf(SVLogInfo, @"NE: tunnel settings — %lu chnroute exclusions (mode=%@)",
                     (unsigned long)appended, mode);
    }

    // Always send the server's own IP(s) direct. The Rust core opens a UDP socket
    // to the server from inside this extension; with a default route claimed by
    // the tunnel, those packets would otherwise route back into the tunnel and
    // loop. Excluding the server /32 keeps the encrypted carrier on the physical
    // interface. Matters in every mode when the server isn't already in the
    // bypass set (e.g. an overseas server in chnroute mode).
    for (NSString *ip in serverExclusions) {
        struct in_addr a;
        if (ip.length == 0 || inet_pton(AF_INET, ip.UTF8String, &a) != 1) continue;
        [excluded addObject:[[NEIPv4Route alloc] initWithDestinationAddress:ip
                                                                subnetMask:@"255.255.255.255"]];
        os_log_info(gLog, "settings: excluded server route %{public}@/32", ip);
        SVEngineLogf(SVLogInfo, @"NE: tunnel settings — server bypass %@/32", ip);
    }

    ipv4.excludedRoutes = excluded;
    settings.IPv4Settings = ipv4;

    // IPv6 — the tunnel itself is IPv4-only, but leaving IPv6Settings nil lets
    // dual-stack apps send traffic straight out the physical interface over
    // native v6 while the app reports "connected" (#17). Claim the v6 default
    // route as a blackhole instead: v6 packets route into the TUN, the core's
    // ingest drops every non-IPv4 packet, and applications fall back to IPv4
    // via Happy Eyeballs rather than leaking. The address is a ULA that never
    // appears on the wire. Link-local and multicast stay direct so NDP and
    // local discovery keep working; they never leave the local segment.
    NEIPv6Settings *ipv6 = [[NEIPv6Settings alloc]
        initWithAddresses:@[@"fd7a:7376:706e::2"]
     networkPrefixLengths:@[@64]];
    ipv6.includedRoutes = @[[NEIPv6Route defaultRoute]];
    ipv6.excludedRoutes = @[
        [[NEIPv6Route alloc] initWithDestinationAddress:@"fe80::" networkPrefixLength:@10],
        [[NEIPv6Route alloc] initWithDestinationAddress:@"ff00::" networkPrefixLength:@8],
    ];
    settings.IPv6Settings = ipv6;
    os_log_info(gLog, "settings: IPv6 default route blackholed (IPv4-only tunnel)");

    // DNS. We always install NEDNSSettings and claim every domain ([@""]) so the
    // OS routes ALL lookups to resolvers we control, through the tunnel —
    // otherwise iOS keeps using the inherited LAN/ISP resolver, whose queries
    // never enter the tunnel and get poisoned/leaked (the classic "tunnel is up
    // but pages won't resolve" failure, confirmed by zero port-53 traffic on the
    // server's tun).
    //
    //  * ChinaDNS: domestic + clean upstreams; the in-FFI split-DNS interceptor
    //    decides per query (via chnroute) which answer to return.
    //  * Full (everything else): just the clean upstream, reached through the
    //    tunnel, so every lookup gets an un-poisoned answer.
    if ([mode isEqualToString:@"chinadns"]) {
        NSMutableArray<NSString *> *servers = [NSMutableArray array];
        NSString *localIP  = [self hostFromHostPort:dnsLocal];
        NSString *remoteIP = [self hostFromHostPort:dnsRemote];
        if (localIP)  [servers addObject:localIP];
        if (remoteIP) [servers addObject:remoteIP];
        if (servers.count > 0) {
            NEDNSSettings *dns = [[NEDNSSettings alloc] initWithServers:servers];
            dns.matchDomains = @[@""];  // claim every domain
            settings.DNSSettings = dns;
        }
    } else {
        NSString *remoteIP = [self hostFromHostPort:dnsRemote] ?: @"8.8.8.8";
        NEDNSSettings *dns = [[NEDNSSettings alloc] initWithServers:@[remoteIP]];
        dns.matchDomains = @[@""];  // route every lookup through the tunnel
        settings.DNSSettings = dns;
        os_log_info(gLog, "settings: full-mode DNS via %{public}@ (through tunnel)", remoteIP);
        SVEngineLogf(SVLogInfo, @"NE: full-mode DNS via %@ (through tunnel)", remoteIP);
    }

    // MTU from the profile (default 1400). The app's TCP stack derives MSS from
    // this (MTU - 40), keeping payloads small enough to survive PMTU black-holes
    // on CN routes where ICMP Fragmentation-Needed is filtered, without relying
    // on PMTUD. 1400 also leaves headroom for the AEAD salt + tag and the UDP/IP
    // outer headers the core wraps each datagram in.
    settings.MTU = @(mtu > 0 ? mtu : 1400);
    return settings;
}

// MARK: - LAN exclusions

// The private/link-local/multicast ranges that should always go direct, never
// through the tunnel. The 10/8 block is special-cased: the ShadowVPN TUN sits
// inside 10/8 itself, so we exclude all of 10/8 EXCEPT the tunnel's own /30
// (computed from `tunnelIP`) — that /30 must stay routed into the tunnel.
// 127/8 is intentionally omitted: iOS rejects a loopback excluded route and
// drops the entire excludedRoutes payload if one is present.
+ (NSArray<NEIPv4Route *> *)ipv4LanExcludedRoutesForTunnelIP:(NSString *)tunnelIP {
    NSMutableArray<NEIPv4Route *> *routes = [NSMutableArray array];

    // 10.0.0.0/8 minus the tunnel's /30 (so the tun's own subnet stays in-tunnel).
    [self appendTen8ExcludingTunnel:tunnelIP into:routes];

    // 172.16/12 and 192.168/16 private ranges.
    [routes addObject:[[NEIPv4Route alloc] initWithDestinationAddress:@"172.16.0.0"  subnetMask:@"255.240.0.0"]];
    [routes addObject:[[NEIPv4Route alloc] initWithDestinationAddress:@"192.168.0.0" subnetMask:@"255.255.0.0"]];
    // Link-local, multicast, limited broadcast.
    [routes addObject:[[NEIPv4Route alloc] initWithDestinationAddress:@"169.254.0.0" subnetMask:@"255.255.0.0"]];
    [routes addObject:[[NEIPv4Route alloc] initWithDestinationAddress:@"224.0.0.0"   subnetMask:@"240.0.0.0"]];
    [routes addObject:[[NEIPv4Route alloc] initWithDestinationAddress:@"255.255.255.255" subnetMask:@"255.255.255.255"]];
    return routes;
}

// Append the minimal set of CIDR blocks that tile 10.0.0.0/8 while leaving the
// tunnel's /30 (the /30 containing `tunnelIP`) unclaimed — i.e. the complement
// of that /30 within 10/8. This is the standard "exclude one subnet from a
// supernet" walk: at each prefix length from /9../30 we keep the sibling half
// that does NOT contain the tunnel and descend into the half that does. That is
// exactly 22 routes.
+ (void)appendTen8ExcludingTunnel:(NSString *)tunnelIP
                             into:(NSMutableArray<NEIPv4Route *> *)routes {
    struct in_addr a;
    if (inet_pton(AF_INET, tunnelIP.UTF8String, &a) != 1) {
        return;
    }
    uint32_t ip = ntohl(a.s_addr);
    uint32_t base30 = ip & 0xFFFFFFFCu;        // /30 network containing the tunnel
    for (uint32_t len = 9; len <= 30; len++) {
        uint32_t bit = 1u << (32 - len);
        uint32_t maskNext = 0xFFFFFFFFu << (32 - len);
        uint32_t halfWithTunnel = base30 & maskNext;
        uint32_t keepNet = halfWithTunnel ^ bit;  // the sibling half (no tunnel)
        [routes addObject:[[NEIPv4Route alloc]
            initWithDestinationAddress:[self dottedAddrForUInt:keepNet]
                            subnetMask:[self dottedMaskForPrefix:len]]];
    }
}

// Format a host-order IPv4 as dotted-decimal.
+ (NSString *)dottedAddrForUInt:(uint32_t)addr {
    return [NSString stringWithFormat:@"%u.%u.%u.%u",
            (addr >> 24) & 0xFF, (addr >> 16) & 0xFF,
            (addr >> 8) & 0xFF, addr & 0xFF];
}

// MARK: - chnroute parsing

// Parse chnroute.txt ("a.b.c.d/len" lines, '#' comments and blank lines skipped)
// and append each CIDR as an excluded NEIPv4Route with a dotted mask computed
// from the prefix length. Returns the count appended. ~5.5k routes is within
// iOS's (generous) limits; we never silently drop — a malformed line is logged
// and skipped, the rest are kept.
+ (NSUInteger)appendChnrouteExclusions:(NSMutableArray<NEIPv4Route *> *)excluded
                               fromURL:(NSURL *)url {
    NSError *err = nil;
    NSString *text = [NSString stringWithContentsOfURL:url
                                              encoding:NSUTF8StringEncoding
                                                 error:&err];
    if (!text) {
        os_log_error(gLog, "settings: chnroute read failed at %{public}@: %{public}@",
                     url.path, err.localizedDescription);
        SVEngineLogf(SVLogError, @"NE: chnroute read failed at %@: %@",
                     url.path, err.localizedDescription);
        return 0;
    }

    NSUInteger appended = 0;
    NSUInteger skipped  = 0;
    NSArray<NSString *> *lines = [text componentsSeparatedByCharactersInSet:
                                  [NSCharacterSet newlineCharacterSet]];
    for (NSString *raw in lines) {
        NSString *line = [raw stringByTrimmingCharactersInSet:
                          [NSCharacterSet whitespaceCharacterSet]];
        if (line.length == 0 || [line hasPrefix:@"#"]) continue;

        NSRange slash = [line rangeOfString:@"/"];
        if (slash.location == NSNotFound) { skipped++; continue; }

        NSString *addr     = [line substringToIndex:slash.location];
        NSString *prefixStr = [line substringFromIndex:slash.location + 1];
        NSInteger prefix   = prefixStr.integerValue;
        if (prefix < 0 || prefix > 32) { skipped++; continue; }

        // Validate the dotted address; reject anything inet_pton won't accept so
        // we don't hand NEIPv4Route a garbage destination.
        struct in_addr a;
        if (inet_pton(AF_INET, addr.UTF8String, &a) != 1) { skipped++; continue; }

        NSString *mask = [self dottedMaskForPrefix:(uint32_t)prefix];
        [excluded addObject:[[NEIPv4Route alloc] initWithDestinationAddress:addr
                                                                subnetMask:mask]];
        appended++;
    }

    if (skipped > 0) {
        os_log_info(gLog, "settings: chnroute parsed %lu routes, skipped %lu malformed lines",
                    (unsigned long)appended, (unsigned long)skipped);
    }
    return appended;
}

// Convert a CIDR prefix length (0…32) to a dotted-decimal subnet mask string,
// e.g. 24 -> "255.255.255.0", 23 -> "255.255.254.0", 0 -> "0.0.0.0".
+ (NSString *)dottedMaskForPrefix:(uint32_t)prefix {
    uint32_t mask = (prefix == 0) ? 0u : (0xFFFFFFFFu << (32 - prefix));
    return [NSString stringWithFormat:@"%u.%u.%u.%u",
            (mask >> 24) & 0xFF, (mask >> 16) & 0xFF,
            (mask >> 8) & 0xFF,  mask & 0xFF];
}

// MARK: - Helpers

// Extract the host portion of a "host:port" upstream string. NEDNSSettings wants
// bare server IPs, not host:port. Returns nil for nil/empty input.
+ (nullable NSString *)hostFromHostPort:(nullable NSString *)hostPort {
    if (hostPort.length == 0) return nil;
    NSRange colon = [hostPort rangeOfString:@":" options:NSBackwardsSearch];
    if (colon.location == NSNotFound) return hostPort;
    return [hostPort substringToIndex:colon.location];
}

@end
