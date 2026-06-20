#import "PacketTunnelProvider.h"
#import "SVTunnelEngine.h"
#import "SVTunnelSettings.h"
#import "SVIPCListener.h"
#import "SVSharedStore.h"
#import "SVDarwinBridge.h"
#import "SVAppGroup.h"
#import "SVEngineLog.h"
#import "shadowvpn_core.h"
#import <os/log.h>
#import <stdatomic.h>
#import <netdb.h>
#import <arpa/inet.h>
@import Network;

static os_log_t gLog;

// Quiet window after the last path event before a triggered engine restart
// actually fires. Long enough to ride out rapid path churn (a Wi-Fi↔cellular
// handoff emits several updates) without stacking restarts, short enough that a
// genuine path change recovers the tunnel quickly.
static const NSTimeInterval kEngineRestartDebounceS = 3.0;

@implementation PacketTunnelProvider {
    SVTunnelEngine     *_engine;
    SVIPCListener      *_ipcListener;

    nw_path_monitor_t   _pathMonitor;
    dispatch_queue_t    _pathQueue;
    BOOL                _havePath;
    BOOL                _lastSatisfied;
    nw_interface_type_t _lastInterfaceType;
    BOOL                _lastHasIPv4;
    BOOL                _lastHasIPv6;

    // Serializes blocking engine start/stop/restart. NE lifecycle callbacks can
    // arrive on different system queues; SVTunnelEngine owns non-atomic state and
    // must not be driven concurrently.
    dispatch_queue_t    _engineControlQueue;
    // Monotonic counter bumped by every restart source/invalidator. A debounced
    // restart block captures the value at schedule time and only runs if it's
    // still current when the window elapses, so a burst of path changes collapses
    // to a single restart after things settle.
    _Atomic uint64_t    _restartGeneration;
    // Bumped whenever the path monitor starts or stops. Path callbacks capture it
    // so a canceled monitor can't schedule a delayed restart for a later tunnel
    // generation.
    _Atomic uint64_t    _pathGeneration;

    // The Profile-derived config_json handed to SVTunnelEngine. Captured at
    // startTunnel time so an in-place restart reuses the same configuration.
    NSString           *_configJSON;
    NSString           *_profileID;
    NSString           *_profileName;
}

+ (void)initialize {
    if (self == [PacketTunnelProvider class]) {
        gLog = os_log_create("com.tangzixiang.shadowvpn.PacketTunnel", "provider");
    }
}

- (instancetype)init {
    self = [super init];
    if (self) {
        dispatch_queue_attr_t attr =
            dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL,
                                                    QOS_CLASS_USER_INITIATED,
                                                    0);
        _engineControlQueue = dispatch_queue_create(
            "com.tangzixiang.shadowvpn.PacketTunnel.engine-control", attr);
        atomic_init(&_restartGeneration, 0);
        atomic_init(&_pathGeneration, 0);
    }
    return self;
}

// MARK: - Lifecycle

- (void)startTunnelWithOptions:(NSDictionary<NSString *, NSObject *> *)options
             completionHandler:(void (^)(NSError *))completionHandler {
    os_log_info(gLog, "startTunnel");
    // svpn_core_init is idempotent and required before any svpn_core_log; calling
    // it here makes the NE-lifecycle log lines below land in the shared log file
    // even before the engine's own startRuntime runs it again.
    svpn_core_init();
    svpn_core_set_home_dir([SVAppGroup containerURL].path.UTF8String);
    SVEngineLog(SVLogInfo, @"NE: startTunnel");

    // The app pushes the active Profile into the NETunnelProviderProtocol's
    // providerConfiguration (see VpnManager). Read the profile fields out of it,
    // assemble the config_json for the core and the routing parameters for the
    // tunnel settings. A nil providerConfiguration means a misconfigured manager.
    NETunnelProviderProtocol *proto =
        (NETunnelProviderProtocol *)self.protocolConfiguration;
    NSDictionary *cfg = proto.providerConfiguration ?: @{};

    NSString *server = proto.serverAddress ?: cfg[@"server"] ?: @"127.0.0.1:8388";
    NSString *mode   = [self stringFromConfig:cfg key:@"mode" fallback:@"full"];
    NSString *dnsLocal  = [self stringFromConfig:cfg key:@"dns_local"  fallback:nil];
    NSString *dnsRemote = [self stringFromConfig:cfg key:@"dns_remote" fallback:nil];
    NSInteger mtu = [self integerFromConfig:cfg key:@"mtu" fallback:1400];
    NSString *country = [self stringFromConfig:cfg key:@"country" fallback:@"CN"];
    // Tunnel inner client IP (TUN address). Must match the server's peer_ip so
    // return traffic routes back down the tunnel. Defaults to the reference
    // server's peer_ip.
    NSString *peerIP = [self stringFromConfig:cfg key:@"peer_ip" fallback:@"10.9.0.2"];
    _profileID   = [self stringFromConfig:cfg key:@"profileID"   fallback:nil];
    _profileName = [self stringFromConfig:cfg key:@"profileName" fallback:nil];

    // Derive (and cache) the bypass-CIDR file for the selected country from the
    // bundled mmdb. The same file path feeds both the excluded routes and the
    // chinadns decision (chnroute_path). nil ⇒ the country set is unavailable
    // (mmdb missing or no networks for the code); split modes degrade to a full
    // tunnel for the session and chinadns start will fail validation cleanly.
    NSURL *chnrouteURL = [self resolveCountryCIDRURLForCountry:country];
    _configJSON = [self buildConfigJSONFromConfig:cfg
                                            mode:mode
                                     chnrouteURL:chnrouteURL];

    // Resolve the server host to dotted IPv4 literal(s). iOS rejects a bare
    // hostname as the tunnel remote address, and the resolved IPs double as the
    // /32 server-bypass routes so the core's carrier socket doesn't loop. Fall
    // back to the raw host if resolution fails (the engine start will then
    // surface the real reachability error).
    NSString *serverHost = [self hostFromHostPort:server];
    NSArray<NSString *> *serverIPs = [self resolveIPv4ForHost:serverHost];
    NSString *remoteAddress = serverIPs.firstObject ?: serverHost;
    if (serverIPs.count == 0) {
        SVEngineLogf(SVLogError, @"NE: could not resolve server host %@ to an IPv4 address", serverHost);
    }

    NEPacketTunnelNetworkSettings *settings =
        [SVTunnelSettings makeWithServerAddress:remoteAddress
                                       tunnelIP:peerIP
                                          mode:mode
                                      dnsLocal:dnsLocal
                                     dnsRemote:dnsRemote
                                           mtu:mtu
                                   chnrouteURL:chnrouteURL
                              serverExclusions:serverIPs];

    [self writeState:@"connecting" errorMessage:nil];

    __weak __typeof__(self) weak = self;
    [self setTunnelNetworkSettings:settings completionHandler:^(NSError *settingsErr) {
        __strong __typeof__(weak) strong0 = weak;
        if (!strong0) { completionHandler(settingsErr); return; }
        if (settingsErr) {
            os_log_error(gLog, "setTunnelNetworkSettings failed: %{public}@",
                         settingsErr.localizedDescription);
            SVEngineLogf(SVLogError, @"NE: setTunnelNetworkSettings failed: %@",
                         settingsErr.localizedDescription);
            [strong0 writeState:@"error" errorMessage:settingsErr.localizedDescription];
            completionHandler(settingsErr);
            return;
        }
        dispatch_async(strong0->_engineControlQueue, ^{
            __strong __typeof__(weak) self = weak;
            if (!self) { completionHandler(nil); return; }

            SVTunnelEngine *engine =
                [[SVTunnelEngine alloc] initWithPacketFlow:self.packetFlow
                                               configJSON:self->_configJSON];
            NSError *startErr = nil;
            if (![engine startWithError:&startErr]) {
                os_log_error(gLog, "engine start failed: %{public}@",
                             startErr.localizedDescription);
                SVEngineLogf(SVLogError, @"NE: engine start failed: %@",
                             startErr.localizedDescription);
                [self writeState:@"error" errorMessage:startErr.localizedDescription];
                completionHandler(startErr);
                return;
            }
            self->_engine = engine;

            // The app's only in-process command is "stop"; wire it through the
            // command Darwin notification to a clean tunnel cancel.
            SVIPCListener *listener = [[SVIPCListener alloc] initWithHandler:^{
                __strong __typeof__(weak) self = weak;
                if (self) [self cancelTunnelWithError:nil];
            }];
            [listener start];
            self->_ipcListener = listener;

            [self startPathMonitor];

            [self writeState:@"connected" errorMessage:nil];
            completionHandler(nil);
        });
    }];
}

- (void)stopTunnelWithReason:(NEProviderStopReason)reason
           completionHandler:(void (^)(void))completionHandler {
    os_log_info(gLog, "stopTunnel reason=%ld", (long)reason);
    SVEngineLogf(SVLogInfo, @"NE: stopTunnel reason=%ld", (long)reason);
    // Invalidate any pending debounced restart before tearing down.
    atomic_fetch_add_explicit(&_restartGeneration, 1, memory_order_relaxed);
    dispatch_async(_engineControlQueue, ^{
        [self stopPathMonitor];
        SVTunnelEngine *engine = self->_engine;
        self->_engine = nil;
        [engine stop];
        SVIPCListener *listener = self->_ipcListener;
        self->_ipcListener = nil;
        [listener stop];
        [self writeState:@"disconnected" errorMessage:nil];
        completionHandler();
    });
}

- (void)sleepWithCompletionHandler:(void (^)(void))completionHandler {
    os_log_info(gLog, "sleep: keeping tun active before device sleep");
    SVEngineLog(SVLogInfo, @"NE: sleep — keeping tun active before device sleep");
    // Invalidate any pending engine restart: we're heading to sleep, so a restart
    // now would just be torn down. Bumping the generation makes the scheduled
    // block bail when it fires.
    atomic_fetch_add_explicit(&_restartGeneration, 1, memory_order_relaxed);
    completionHandler();
}

- (void)wake {
    os_log_info(gLog, "wake: rebinding carrier socket after device sleep");
    SVEngineLog(SVLogInfo, @"NE: wake — rebinding carrier socket after device sleep");
    // A sleep/wake cycle can strand the core's connect()ed UDP carrier socket on
    // a source address/route the kernel invalidated while the device slept: sends
    // then silently blackhole and recv never returns, so no engine task errors
    // and the tunnel sits connected-but-frozen. The nw_path_monitor only rebinds
    // on a satisfied / interface-type / address-family transition, and none of
    // those fire when we wake on the same network — which is exactly why manually
    // switching networks "unfreezes" traffic. Schedule the same debounced in-place
    // engine restart so the carrier socket is rebound against the post-wake
    // network; the debounce coalesces with any path updates the wake itself emits.
    [self scheduleEngineRestartForReason:@"wake"];
}

// MARK: - Debounced restart

- (void)scheduleEngineRestartForReason:(NSString *)reason {
    uint64_t gen =
        atomic_fetch_add_explicit(&_restartGeneration, 1, memory_order_relaxed) + 1;
    __weak __typeof__(self) weak = self;
    dispatch_after(
        dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kEngineRestartDebounceS * NSEC_PER_SEC)),
        dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            __strong __typeof__(weak) self = weak;
            if (!self) return;
            if (atomic_load_explicit(&self->_restartGeneration, memory_order_relaxed) != gen) {
                os_log_info(gLog, "%{public}@ restart: superseded by newer event, skipping",
                            reason);
                return;
            }
            [self restartEngineForGeneration:gen reason:reason];
        });
}

// Restart the running engine in place. No-op if no engine is running (e.g. a
// restart raced a stop). Runs on _engineControlQueue so it can't interleave with
// a user/app stop.
- (void)restartEngineForGeneration:(uint64_t)gen reason:(NSString *)reason {
    dispatch_async(_engineControlQueue, ^{
        if (atomic_load_explicit(&self->_restartGeneration, memory_order_relaxed) != gen) {
            os_log_info(gLog, "%{public}@ restart: superseded before engine restart, skipping",
                        reason);
            return;
        }
        SVTunnelEngine *engine = self->_engine;
        if (!engine) {
            os_log_info(gLog, "%{public}@ restart: no engine running, skipping", reason);
            return;
        }

        NSError *startErr = nil;
        if (![engine restartWithError:&startErr]) {
            os_log_error(gLog, "%{public}@ restart: engine start failed: %{public}@",
                         reason, startErr.localizedDescription);
            SVEngineLogf(SVLogError, @"NE: %@ restart — engine start failed: %@",
                         reason, startErr.localizedDescription);
            self->_engine = nil;
            [self writeState:@"error" errorMessage:startErr.localizedDescription];
            // A failed restart leaves no working data path. Tear the tunnel down
            // so NE on-demand / the app can re-establish cleanly rather than
            // sitting connected-but-dead.
            [self cancelTunnelWithError:startErr];
            return;
        }
        os_log_info(gLog, "%{public}@ restart: engine restarted", reason);
        SVEngineLogf(SVLogInfo, @"NE: %@ restart — engine restarted", reason);
    });
}

// MARK: - State

- (void)writeState:(NSString *)stage errorMessage:(nullable NSString *)errorMessage {
    NSMutableDictionary *state = [([SVSharedStore readState] ?: @{}) mutableCopy];
    state[@"stage"] = stage;
    if (_profileID)   state[@"profileID"]   = _profileID;   else [state removeObjectForKey:@"profileID"];
    if (_profileName) state[@"profileName"] = _profileName; else [state removeObjectForKey:@"profileName"];
    if (errorMessage) state[@"message"] = errorMessage;
    else              [state removeObjectForKey:@"message"];
    if ([stage isEqualToString:@"connected"]) {
        // VpnState.startedAt is a Date decoded with `.secondsSince1970`; write a
        // numeric epoch-seconds value to match the Swift decoder.
        state[@"startedAt"] = @([[NSDate date] timeIntervalSince1970]);
    } else {
        [state removeObjectForKey:@"startedAt"];
    }
    NSError *err = nil;
    if (![SVSharedStore writeState:state error:&err]) {
        os_log_error(gLog, "state write failed: %{public}@", err);
        return;
    }
    [SVDarwinBridge post:SVNotificationState];
}

// MARK: - Network path monitoring

- (void)startPathMonitor {
    uint64_t pathGen =
        atomic_fetch_add_explicit(&_pathGeneration, 1, memory_order_relaxed) + 1;
    _pathQueue = dispatch_queue_create("com.tangzixiang.shadowvpn.PacketTunnel.path",
                                       DISPATCH_QUEUE_SERIAL);
    _havePath = NO;
    _lastSatisfied = NO;
    _lastInterfaceType = nw_interface_type_other;
    _lastHasIPv4 = NO;
    _lastHasIPv6 = NO;

    nw_path_monitor_t monitor = nw_path_monitor_create();
    nw_path_monitor_set_queue(monitor, _pathQueue);

    __weak __typeof__(self) weak = self;
    nw_path_monitor_set_update_handler(monitor, ^(nw_path_t _Nonnull path) {
        __strong __typeof__(weak) self = weak;
        if (!self) return;
        [self handlePathUpdate:path generation:pathGen];
    });
    nw_path_monitor_start(monitor);
    _pathMonitor = monitor;
}

- (void)stopPathMonitor {
    atomic_fetch_add_explicit(&_pathGeneration, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&_restartGeneration, 1, memory_order_relaxed);
    if (_pathMonitor) {
        nw_path_monitor_cancel(_pathMonitor);
        _pathMonitor = nil;
    }
    _pathQueue = nil;
}

// Caller queue: _pathQueue (serial). All ivar access here is single-threaded.
- (void)handlePathUpdate:(nw_path_t)path generation:(uint64_t)pathGen {
    if (atomic_load_explicit(&_pathGeneration, memory_order_relaxed) != pathGen) {
        os_log_info(gLog, "path: stale monitor update ignored");
        return;
    }

    nw_path_status_t status = nw_path_get_status(path);
    BOOL satisfied = (status == nw_path_status_satisfied);

    nw_interface_type_t iface = nw_interface_type_other;
    BOOL hasIPv4 = NO;
    BOOL hasIPv6 = NO;
    if (satisfied) {
        if (nw_path_uses_interface_type(path, nw_interface_type_wifi)) {
            iface = nw_interface_type_wifi;
        } else if (nw_path_uses_interface_type(path, nw_interface_type_cellular)) {
            iface = nw_interface_type_cellular;
        } else if (nw_path_uses_interface_type(path, nw_interface_type_wired)) {
            iface = nw_interface_type_wired;
        }
        hasIPv4 = nw_path_has_ipv4(path);
        hasIPv6 = nw_path_has_ipv6(path);
    }

    if (!_havePath) {
        _havePath = YES;
        _lastSatisfied = satisfied;
        _lastInterfaceType = iface;
        _lastHasIPv4 = hasIPv4;
        _lastHasIPv6 = hasIPv6;
        os_log_info(gLog, "path: initial satisfied=%d iface=%d v4=%d v6=%d",
                    satisfied, iface, hasIPv4, hasIPv6);
        return;
    }

    BOOL shouldRestart = NO;
    if (satisfied && !_lastSatisfied) {
        os_log_info(gLog, "path: connectivity regained");
        SVEngineLog(SVLogInfo, @"NE: path — connectivity regained");
        shouldRestart = YES;
    } else if (satisfied && iface != _lastInterfaceType) {
        os_log_info(gLog, "path: interface changed %d -> %d", _lastInterfaceType, iface);
        SVEngineLogf(SVLogInfo, @"NE: path — interface changed %d -> %d",
                     _lastInterfaceType, iface);
        shouldRestart = YES;
    } else if (satisfied && (hasIPv4 != _lastHasIPv4 || hasIPv6 != _lastHasIPv6)) {
        // Same interface, same satisfied state, but the address-family set
        // changed — e.g. the Wi-Fi network silently lost (or gained) IPv6 via
        // expired RAs. Re-bind the UDP socket against the new network shape by
        // restarting the engine after a debounce. The ShadowVPN socket is
        // connect()ed, so a stale source address otherwise blackholes traffic.
        os_log_info(gLog, "path: address family changed v4 %d -> %d, v6 %d -> %d",
                    _lastHasIPv4, hasIPv4, _lastHasIPv6, hasIPv6);
        SVEngineLogf(SVLogInfo, @"NE: path — address family changed v4 %d -> %d, v6 %d -> %d",
                     _lastHasIPv4, hasIPv4, _lastHasIPv6, hasIPv6);
        shouldRestart = YES;
    }

    _lastSatisfied = satisfied;
    _lastInterfaceType = iface;
    _lastHasIPv4 = hasIPv4;
    _lastHasIPv6 = hasIPv6;

    if (shouldRestart) {
        os_log_info(gLog, "path: scheduling debounced engine restart");
        SVEngineLog(SVLogInfo, @"NE: path — scheduling debounced engine restart");
        [self scheduleEngineRestartForReason:@"path"];
    }
}

// MARK: - Config helpers

// Resolve the bypass-CIDR file for `country` (ISO alpha-2). The extension
// bundles the MaxMind GeoLite2 Country.mmdb; the core extracts the country's
// IPv4 networks from it and caches the resulting CIDR text to a file in the App
// Group container (svpn_country_cidrs_file) the first time, reusing the cache on
// later starts. Returns the cache file URL, or nil if the mmdb is missing or the
// country has no networks (the caller logs and degrades gracefully).
- (nullable NSURL *)resolveCountryCIDRURLForCountry:(NSString *)country {
    // Fast path: a precomputed chnroute.txt (CN) is bundled, so the default
    // country skips the one-time mmdb -> CIDR extraction entirely. Any other
    // country falls through to the mmdb extraction (cached per country) below.
    if ([country caseInsensitiveCompare:@"CN"] == NSOrderedSame) {
        NSURL *bundled = [[NSBundle mainBundle] URLForResource:@"chnroute" withExtension:@"txt"];
        if (bundled && [[NSFileManager defaultManager] fileExistsAtPath:bundled.path]) {
            os_log_info(gLog, "using bundled chnroute.txt for CN (skipping mmdb extraction)");
            SVEngineLog(SVLogInfo, @"NE: using bundled chnroute.txt for CN (no mmdb extraction)");
            return bundled;
        }
    }

    NSURL *mmdb = [[NSBundle mainBundle] URLForResource:@"Country" withExtension:@"mmdb"];
    if (!mmdb || ![[NSFileManager defaultManager] fileExistsAtPath:mmdb.path]) {
        os_log_error(gLog, "Country.mmdb not found in extension bundle");
        SVEngineLog(SVLogError, @"NE: Country.mmdb not found in extension bundle");
        return nil;
    }

    // Per-country cache lives under the shared container so it survives restarts
    // and is reachable by the core's absolute-path reads.
    NSURL *cacheDir = [[SVAppGroup containerURL] URLByAppendingPathComponent:@"cidr-cache"
                                                                isDirectory:YES];

    const char *mmdbC    = mmdb.path.UTF8String;
    const char *countryC = country.UTF8String;
    const char *cacheC   = cacheDir.path.UTF8String;

    // bytes-needed / retry truncation pattern (mirrors the meow convert calls).
    int needed = svpn_country_cidrs_file(mmdbC, countryC, cacheC, NULL, 0);
    if (needed < 0) {
        NSString *msg = [self lastRustError] ?: @"country CIDR extraction failed";
        os_log_error(gLog, "svpn_country_cidrs_file(%{public}@) failed: %{public}@",
                     country, msg);
        SVEngineLogf(SVLogError, @"NE: country CIDR extraction for %@ failed: %@", country, msg);
        return nil;
    }

    char *buf = (char *)malloc((size_t)needed + 1);
    if (!buf) { return nil; }
    int wrote = svpn_country_cidrs_file(mmdbC, countryC, cacheC, buf, needed + 1);
    NSURL *result = nil;
    if (wrote >= 0) {
        NSString *path = [NSString stringWithUTF8String:buf];
        if (path.length > 0) {
            result = [NSURL fileURLWithPath:path];
            os_log_info(gLog, "country %{public}@ CIDR file: %{public}@", country, path);
            SVEngineLogf(SVLogInfo, @"NE: country %@ bypass CIDRs ready at %@", country, path);
        }
    }
    free(buf);
    return result;
}

// Read the last error the Rust core set on this thread, or nil.
- (nullable NSString *)lastRustError {
    const char *p = svpn_core_last_error();
    return (p && p[0]) ? [NSString stringWithUTF8String:p] : nil;
}

// Assemble the `config_json` string for svpn_tun_start from the providerConfig.
// The shape matches the C-ABI contract in shadowvpn_core.h / Profile.configJSON:
//   {"server","password","cipher","mode","mtu","dns_local","dns_remote",
//    "chnroute_path"?}
// We rebuild it here (rather than trust an app-provided blob) so the NE controls
// exactly what the core sees, and so chnroute_path points at the path the NE
// resolved above. If the app already provided a ready "config_json" string we
// honour it, only injecting the resolved chnroute_path for split modes.
- (NSString *)buildConfigJSONFromConfig:(NSDictionary *)cfg
                                  mode:(NSString *)mode
                           chnrouteURL:(nullable NSURL *)chnrouteURL {
    BOOL isSplit = [mode isEqualToString:@"chnroute"] || [mode isEqualToString:@"chinadns"];

    NSString *provided = [self stringFromConfig:cfg key:@"config_json" fallback:nil];
    NSMutableDictionary *dict = nil;
    if (provided) {
        NSData *data = [provided dataUsingEncoding:NSUTF8StringEncoding];
        id obj = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:nil] : nil;
        if ([obj isKindOfClass:[NSDictionary class]]) {
            dict = [obj mutableCopy];
        }
    }
    if (!dict) {
        dict = [NSMutableDictionary dictionary];
        dict[@"server"]     = [self stringFromConfig:cfg key:@"server"   fallback:@""];
        dict[@"password"]   = [self stringFromConfig:cfg key:@"password" fallback:@""];
        dict[@"cipher"]     = [self stringFromConfig:cfg key:@"cipher"   fallback:@"chacha20-poly1305"];
        dict[@"mode"]       = mode;
        dict[@"mtu"]        = @([self integerFromConfig:cfg key:@"mtu" fallback:1400]);
        dict[@"dns_local"]  = [self stringFromConfig:cfg key:@"dns_local"  fallback:@"114.114.114.114:53"];
        dict[@"dns_remote"] = [self stringFromConfig:cfg key:@"dns_remote" fallback:@"8.8.8.8:53"];
    }
    // Carrier obfuscation ("none" | "quic"). Injected even when the app provided
    // a ready config_json, so the core always sees the profile's choice.
    dict[@"obfs"] = [self stringFromConfig:cfg key:@"obfs" fallback:@"none"];
    if (isSplit && chnrouteURL) {
        dict[@"chnroute_path"] = chnrouteURL.path;
    }

    NSData *json = [NSJSONSerialization dataWithJSONObject:dict
                                                  options:NSJSONWritingSortedKeys
                                                    error:nil];
    NSString *str = json ? [[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding] : nil;
    return str ?: @"{}";
}

- (nullable NSString *)stringFromConfig:(NSDictionary *)cfg
                                   key:(NSString *)key
                              fallback:(nullable NSString *)fallback {
    id v = cfg[key];
    if ([v isKindOfClass:[NSString class]] && [(NSString *)v length] > 0) return v;
    return fallback;
}

- (NSInteger)integerFromConfig:(NSDictionary *)cfg
                           key:(NSString *)key
                      fallback:(NSInteger)fallback {
    id v = cfg[key];
    if ([v isKindOfClass:[NSNumber class]]) return [(NSNumber *)v integerValue];
    if ([v isKindOfClass:[NSString class]]) return [(NSString *)v integerValue];
    return fallback;
}

// Strip a trailing ":port" from a "host:port" string for the tunnel-settings
// remote-address label (NEPacketTunnelNetworkSettings wants a bare host).
- (NSString *)hostFromHostPort:(NSString *)hostPort {
    if (hostPort.length == 0) return hostPort;
    NSRange colon = [hostPort rangeOfString:@":" options:NSBackwardsSearch];
    if (colon.location == NSNotFound) return hostPort;
    return [hostPort substringToIndex:colon.location];
}

// Resolve a host to its dotted-IPv4 address(es). Returns a de-duplicated list in
// resolver order, or an empty array if resolution fails. If `host` is already a
// dotted-IPv4 literal it is returned as-is without a lookup. Synchronous
// getaddrinfo is acceptable here: startTunnel runs off the main thread and a
// brief blocking resolve at connect time mirrors what the core would do anyway.
- (NSArray<NSString *> *)resolveIPv4ForHost:(NSString *)host {
    if (host.length == 0) return @[];

    struct in_addr literal;
    if (inet_pton(AF_INET, host.UTF8String, &literal) == 1) {
        return @[host];
    }

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;        // IPv4-only tunnel
    hints.ai_socktype = SOCK_DGRAM;   // the carrier is UDP

    struct addrinfo *results = NULL;
    int rc = getaddrinfo(host.UTF8String, NULL, &hints, &results);
    if (rc != 0 || results == NULL) {
        if (results) freeaddrinfo(results);
        os_log_error(gLog, "resolve %{public}@ failed: %{public}s", host, gai_strerror(rc));
        return @[];
    }

    NSMutableArray<NSString *> *ips = [NSMutableArray array];
    for (struct addrinfo *ai = results; ai != NULL; ai = ai->ai_next) {
        if (ai->ai_family != AF_INET || ai->ai_addr == NULL) continue;
        struct sockaddr_in *sin = (struct sockaddr_in *)ai->ai_addr;
        char buf[INET_ADDRSTRLEN] = {0};
        if (inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf)) == NULL) continue;
        NSString *ip = [NSString stringWithUTF8String:buf];
        if (ip.length > 0 && ![ips containsObject:ip]) [ips addObject:ip];
    }
    freeaddrinfo(results);
    return ips;
}

@end
