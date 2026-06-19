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
static NSString *const kTunnelAddress    = @"10.8.0.2";
static NSString *const kTunnelSubnetMask = @"255.255.255.252";  // /30

@implementation SVTunnelSettings

+ (void)initialize {
    if (self == [SVTunnelSettings class]) {
        gLog = os_log_create("com.tangzixiang.shadowvpn.PacketTunnel", "settings");
    }
}

+ (NEPacketTunnelNetworkSettings *)makeWithServerAddress:(NSString *)serverAddress
                                                    mode:(NSString *)mode
                                                dnsLocal:(nullable NSString *)dnsLocal
                                               dnsRemote:(nullable NSString *)dnsRemote
                                                     mtu:(NSInteger)mtu
                                             chnrouteURL:(nullable NSURL *)chnrouteURL {
    NEPacketTunnelNetworkSettings *settings =
        [[NEPacketTunnelNetworkSettings alloc] initWithTunnelRemoteAddress:serverAddress];

    // IPv4 — claim the /30 tunnel address and route the default route into the
    // tunnel. The split is implemented as excludedRoutes: anything in the LAN
    // set (and, for chnroute/chinadns, anything in chnroute.txt) bypasses the
    // tunnel and goes out the physical interface directly.
    NEIPv4Settings *ipv4 = [[NEIPv4Settings alloc]
        initWithAddresses:@[kTunnelAddress]
              subnetMasks:@[kTunnelSubnetMask]];
    ipv4.includedRoutes = @[[NEIPv4Route defaultRoute]];

    NSMutableArray<NEIPv4Route *> *excluded =
        [[self ipv4LanExcludedRoutes] mutableCopy];

    BOOL isSplit = [mode isEqualToString:@"chnroute"] || [mode isEqualToString:@"chinadns"];
    if (isSplit && chnrouteURL) {
        NSUInteger appended = [self appendChnrouteExclusions:excluded fromURL:chnrouteURL];
        os_log_info(gLog, "settings: appended %lu chnroute exclusions (mode=%{public}@)",
                    (unsigned long)appended, mode);
        SVEngineLogf(SVLogInfo, @"NE: tunnel settings — %lu chnroute exclusions (mode=%@)",
                     (unsigned long)appended, mode);
    }
    ipv4.excludedRoutes = excluded;
    settings.IPv4Settings = ipv4;

    // IPv6 — intentionally left nil (IPv4-only tunnel), matching meow. With no
    // ::/0 route claimed, native IPv6 traffic could bypass the tunnel; ShadowVPN
    // accepts that residual surface (the upstream client is IPv4-only too) and
    // relies on the path monitor's address-family restart to track v4↔v6 shifts.

    // DNS — only in ChinaDNS mode. We point the system resolver at both the
    // domestic and the clean upstream IPs and claim every domain ([@""]) so all
    // lookups funnel through the in-FFI split-DNS interceptor, which decides per
    // query (via chnroute) whether to serve the domestic or the clean answer.
    // For full / chnroute we install no NEDNSSettings, so the system DNS is
    // inherited and split routing alone governs reachability.
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
// through the tunnel. Mirrors meow's set, but the 10/8 block is split into three
// routes so the tunnel's own /30 (10.8.0.0/30) is NOT excluded — meow could
// exclude all of 10/8 because its TUN sat in 172.19/16, but ShadowVPN's TUN is
// inside 10/8 itself. 127/8 is intentionally omitted: iOS rejects a loopback
// excluded route and drops the entire excludedRoutes payload if one is present.
+ (NSArray<NEIPv4Route *> *)ipv4LanExcludedRoutes {
    return @[
        // 10.0.0.0/8 minus the tunnel /30 at 10.8.0.0/30:
        //   10.0.0.0/13     covers 10.0.0.0 – 10.7.255.255
        //   10.8.0.4/30     the three host addresses in 10.8.0.x above the /30
        //   10.8.0.8/29 .. 10.8.0.0/8 remainder via aggregated supernets
        // We express the remainder as the minimal set of CIDR blocks that tile
        // 10.0.0.0/8 while leaving 10.8.0.0/30 unclaimed.
        [[NEIPv4Route alloc] initWithDestinationAddress:@"10.0.0.0"   subnetMask:@"255.248.0.0"], // 10.0.0.0/13
        [[NEIPv4Route alloc] initWithDestinationAddress:@"10.8.0.4"   subnetMask:@"255.255.255.252"], // 10.8.0.4/30
        [[NEIPv4Route alloc] initWithDestinationAddress:@"10.8.0.8"   subnetMask:@"255.255.255.248"], // 10.8.0.8/29
        [[NEIPv4Route alloc] initWithDestinationAddress:@"10.8.0.16"  subnetMask:@"255.255.255.240"], // 10.8.0.16/28
        [[NEIPv4Route alloc] initWithDestinationAddress:@"10.8.0.32"  subnetMask:@"255.255.255.224"], // 10.8.0.32/27
        [[NEIPv4Route alloc] initWithDestinationAddress:@"10.8.0.64"  subnetMask:@"255.255.255.192"], // 10.8.0.64/26
        [[NEIPv4Route alloc] initWithDestinationAddress:@"10.8.0.128" subnetMask:@"255.255.255.128"], // 10.8.0.128/25
        [[NEIPv4Route alloc] initWithDestinationAddress:@"10.8.1.0"   subnetMask:@"255.255.255.0"],   // 10.8.1.0/24
        [[NEIPv4Route alloc] initWithDestinationAddress:@"10.8.2.0"   subnetMask:@"255.255.254.0"],   // 10.8.2.0/23
        [[NEIPv4Route alloc] initWithDestinationAddress:@"10.8.4.0"   subnetMask:@"255.255.252.0"],   // 10.8.4.0/22
        [[NEIPv4Route alloc] initWithDestinationAddress:@"10.8.8.0"   subnetMask:@"255.255.248.0"],   // 10.8.8.0/21
        [[NEIPv4Route alloc] initWithDestinationAddress:@"10.8.16.0"  subnetMask:@"255.255.240.0"],   // 10.8.16.0/20
        [[NEIPv4Route alloc] initWithDestinationAddress:@"10.8.32.0"  subnetMask:@"255.255.224.0"],   // 10.8.32.0/19
        [[NEIPv4Route alloc] initWithDestinationAddress:@"10.8.64.0"  subnetMask:@"255.255.192.0"],   // 10.8.64.0/18
        [[NEIPv4Route alloc] initWithDestinationAddress:@"10.8.128.0" subnetMask:@"255.255.128.0"],   // 10.8.128.0/17
        [[NEIPv4Route alloc] initWithDestinationAddress:@"10.9.0.0"   subnetMask:@"255.255.0.0"],     // 10.9.0.0/16
        [[NEIPv4Route alloc] initWithDestinationAddress:@"10.10.0.0"  subnetMask:@"255.254.0.0"],     // 10.10.0.0/15
        [[NEIPv4Route alloc] initWithDestinationAddress:@"10.12.0.0"  subnetMask:@"255.252.0.0"],     // 10.12.0.0/14
        [[NEIPv4Route alloc] initWithDestinationAddress:@"10.16.0.0"  subnetMask:@"255.240.0.0"],     // 10.16.0.0/12
        [[NEIPv4Route alloc] initWithDestinationAddress:@"10.32.0.0"  subnetMask:@"255.224.0.0"],     // 10.32.0.0/11
        [[NEIPv4Route alloc] initWithDestinationAddress:@"10.64.0.0"  subnetMask:@"255.192.0.0"],     // 10.64.0.0/10
        [[NEIPv4Route alloc] initWithDestinationAddress:@"10.128.0.0" subnetMask:@"255.128.0.0"],     // 10.128.0.0/9
        // 172.16/12 and 192.168/16 private ranges
        [[NEIPv4Route alloc] initWithDestinationAddress:@"172.16.0.0"    subnetMask:@"255.240.0.0"],
        [[NEIPv4Route alloc] initWithDestinationAddress:@"192.168.0.0"   subnetMask:@"255.255.0.0"],
        // Link-local, multicast, limited broadcast
        [[NEIPv4Route alloc] initWithDestinationAddress:@"169.254.0.0"   subnetMask:@"255.255.0.0"],
        // 127/8 intentionally omitted — iOS rejects loopback and drops the whole excludedRoutes payload
        [[NEIPv4Route alloc] initWithDestinationAddress:@"224.0.0.0"     subnetMask:@"240.0.0.0"],
        [[NEIPv4Route alloc] initWithDestinationAddress:@"255.255.255.255" subnetMask:@"255.255.255.255"],
    ];
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
