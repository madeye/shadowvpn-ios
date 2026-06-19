#import "SVTunnelEngine.h"
#import "SVAppGroup.h"
#import "SVPacketWriter.h"
#import "SVSharedStore.h"
#import "SVDarwinBridge.h"
#import "SVEngineLog.h"
#import "shadowvpn_core.h"
#import <stdatomic.h>
#import <os/log.h>
#import <mach/mach.h>
#import <malloc/malloc.h>

static os_log_t gLog;

// Phys-footprint soft cap. iOS jetsam terminates a packet-tunnel extension that
// crosses roughly 50 MiB of physical footprint. ShadowVPN's data plane is far
// lighter than meow's (no lwip/tun2socks, no per-flow relay buffers — just a
// single UDP socket and AEAD framing), so it sits well under the cap; the
// watchdog exists only as a safety net. When footprint crosses the threshold we
// nudge the allocator to return free pages rather than restart the tun, which
// would disrupt the live connection for marginal gain.
static const NSInteger kSoftCapFootprintMB   = 35;
static const NSTimeInterval kReliefCooldownS = 60.0;

@implementation SVTunnelEngine {
    NEPacketTunnelFlow *_flow;
    NSString *_configJSON;

    SVPacketWriter *_writer;
    void *_writerCtx;          // CFRetained SVPacketWriter*, passed to svpn_tun_start

    BOOL _started;
    BOOL _tunStarted;
    _Atomic BOOL _ingressRunning;
    // Bumped on terminal stop / restart teardown. A readPackets completion
    // captures the epoch when it arms and drops itself if the epoch advanced, so
    // an in-flight handler from a superseded generation can neither ingest into a
    // restarted tun nor re-arm a second concurrent read chain (NEPacketTunnelFlow
    // permits one outstanding read at a time). An in-place restart deliberately
    // keeps the original chain alive and does NOT bump the epoch.
    _Atomic uint64_t _ingressEpoch;
    _Atomic int64_t _ingressPackets;

    dispatch_source_t _trafficTimer;
    int64_t _lastUp;
    int64_t _lastDown;
    NSTimeInterval _lastTime;
    int _pumpTick;
    NSTimeInterval _lastReliefAttempt;  // CFAbsoluteTime; 0 = never
}

+ (void)initialize {
    if (self == [SVTunnelEngine class]) {
        gLog = os_log_create("com.tangzixiang.shadowvpn.PacketTunnel", "engine");
    }
}

- (instancetype)initWithPacketFlow:(NEPacketTunnelFlow *)flow
                        configJSON:(NSString *)configJSON {
    self = [super init];
    if (self) {
        _flow = flow;
        _configJSON = [configJSON copy];
        atomic_init(&_ingressRunning, NO);
        atomic_init(&_ingressEpoch, 0);
        atomic_init(&_ingressPackets, 0);
    }
    return self;
}

// MARK: - Writer context lifecycle

- (void)releaseWriterContext {
    if (_writerCtx) {
        CFBridgingRelease(_writerCtx);
        _writerCtx = NULL;
    }
    _writer = nil;
}

// MARK: - Runtime (FFI start)

// Brings the Rust core up: idempotent logging init, home dir for the rotating
// log file, then the tun start that spins up the UDP socket + recv/egress tasks
// + keepalive. svpn_core_set_home_dir must run BEFORE svpn_tun_start so the core
// resolves its log path inside the App Group container, not an ephemeral one.
- (BOOL)startRuntimeWithError:(NSError **)error {
    NSString *homeDir = [SVAppGroup containerURL].path;

    svpn_core_init();
    svpn_core_set_home_dir(homeDir.UTF8String);

    int rc = svpn_tun_start(_writerCtx, svpnPacketWriterCB, _configJSON.UTF8String);
    if (rc != 0) {
        NSString *msg = [self lastRustError] ?: @"svpn_tun_start failed";
        if (error) *error = [NSError errorWithDomain:@"SVTunnelEngine"
                                                code:1
                                            userInfo:@{NSLocalizedDescriptionKey: msg}];
        return NO;
    }
    _tunStarted = YES;
    return YES;
}

// MARK: - Start

- (BOOL)startWithError:(NSError **)error {
    if (_started) return YES;
    _started = YES;

    os_log_info(gLog, "engine: startWithError entry");
    SVEngineLog(SVLogInfo, @"NE: engine start");

    SVPacketWriter *writer = [[SVPacketWriter alloc] initWithFlow:_flow];
    _writer    = writer;
    _writerCtx = (void *)CFBridgingRetain(writer);

    if (![self startRuntimeWithError:error]) {
        [self releaseWriterContext];
        _started = NO;
        return NO;
    }

    [self startIngressLoop];
    [self startTrafficPump];
    return YES;
}

// MARK: - Restart (network path change)

- (BOOL)restartWithError:(NSError **)error {
    if (!_started) {
        if (error) *error = [NSError errorWithDomain:@"SVTunnelEngine"
                                                code:3
                                            userInfo:@{NSLocalizedDescriptionKey:
                                                           @"engine not started"}];
        return NO;
    }

    os_log_info(gLog, "engine: restart entry");
    SVEngineLog(SVLogInfo, @"NE: engine restart");

    [self stopTrafficPump];
    if (_tunStarted) {
        // BLOCKING stop so the old egress task can't fire the writer callback
        // while we restart on top of the same CFRetained writer context.
        svpn_tun_stop_blocking();
        _tunStarted = NO;
    }

    if (![self startRuntimeWithError:error]) {
        atomic_store_explicit(&_ingressRunning, NO, memory_order_relaxed);
        atomic_fetch_add_explicit(&_ingressEpoch, 1, memory_order_relaxed);
        [self releaseWriterContext];
        _started = NO;
        return NO;
    }

    // Do NOT call startIngressLoop here. The original readPackets chain stays
    // armed across the in-place restart; arming a second read on the same
    // NEPacketTunnelFlow would violate its one-outstanding-read contract.
    [self startTrafficPump];
    return YES;
}

// MARK: - Stop

- (void)stop {
    if (!_started) return;
    _started = NO;

    SVEngineLog(SVLogInfo, @"NE: engine stop");

    atomic_store_explicit(&_ingressRunning, NO, memory_order_relaxed);
    atomic_fetch_add_explicit(&_ingressEpoch, 1, memory_order_relaxed);

    [self stopTrafficPump];

    // BLOCKING stop: wait for the core's recv/egress tasks — and their egress
    // callback into svpnPacketWriterCB — to fully terminate BEFORE releasing the
    // writer ctx below. svpn_tun_stop() is fire-and-forget, so CFBridgingRelease-
    // ing the CFBridgingRetain'd writer right after a fire-and-forget stop could
    // free the object while a still-draining egress task calls back into it: a
    // use-after-free. svpn_tun_stop_blocking() joins the tasks first.
    if (_tunStarted) {
        svpn_tun_stop_blocking();
        _tunStarted = NO;
    }

    [self releaseWriterContext];
}

// MARK: - Engine state

- (BOOL)isRunning {
    return svpn_is_running() != 0;
}

// MARK: - Ingress loop (readPackets → svpn_tun_ingest)

- (void)startIngressLoop {
    atomic_store_explicit(&_ingressRunning, YES, memory_order_relaxed);
    [self readNextPackets];
}

- (void)readNextPackets {
    if (!atomic_load_explicit(&_ingressRunning, memory_order_relaxed)) return;
    uint64_t epoch = atomic_load_explicit(&_ingressEpoch, memory_order_relaxed);
    __weak __typeof__(self) weak = self;
    [_flow readPacketsWithCompletionHandler:^(NSArray<NSData *> *packets,
                                              NSArray<NSNumber *> *protocols) {
        @autoreleasepool {
            __strong __typeof__(weak) self = weak;
            if (!self) return;
            if (!atomic_load_explicit(&self->_ingressRunning, memory_order_relaxed)) return;
            // Epoch guard: a stop after this read was armed bumps _ingressEpoch.
            // Drop the stale completion so an in-flight handler from a superseded
            // generation neither ingests into a fresh tun instance nor re-arms a
            // second concurrent readPackets chain.
            if (atomic_load_explicit(&self->_ingressEpoch, memory_order_relaxed) != epoch) return;
            for (NSData *pkt in packets) {
                // Non-blocking; the core drops under backpressure (DESIGN.md).
                svpn_tun_ingest((const uint8_t *)pkt.bytes, (uintptr_t)pkt.length);
                atomic_fetch_add_explicit(&self->_ingressPackets, 1, memory_order_relaxed);
            }
            os_log_debug(gLog, "ingress batch: %zu packets", packets.count);
            [self readNextPackets];
        }
    }];
}

// MARK: - Traffic pump (500 ms interval)

- (void)startTrafficPump {
    os_log_debug(gLog, "engine: startTrafficPump entry");
    _lastUp   = 0;
    _lastDown = 0;
    _lastTime = [[NSDate date] timeIntervalSinceReferenceDate];

    dispatch_queue_t q = dispatch_get_global_queue(QOS_CLASS_BACKGROUND, 0);
    _trafficTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, q);
    dispatch_source_set_timer(_trafficTimer,
        dispatch_time(DISPATCH_TIME_NOW, 500 * NSEC_PER_MSEC),
        500 * NSEC_PER_MSEC,
        10  * NSEC_PER_MSEC);

    __weak __typeof__(self) weak = self;
    dispatch_source_set_event_handler(_trafficTimer, ^{
        [weak emitTrafficSnapshot];
    });
    dispatch_resume(_trafficTimer);
}

- (void)stopTrafficPump {
    if (_trafficTimer) {
        dispatch_source_cancel(_trafficTimer);
        _trafficTimer = nil;
    }
}

- (void)emitTrafficSnapshot {
    int64_t up = 0, down = 0;
    svpn_engine_traffic(&up, &down);

    NSTimeInterval now = [[NSDate date] timeIntervalSinceReferenceDate];
    double dt = MAX(0.001, now - _lastTime);
    int64_t upRate   = (int64_t)((double)(up   - _lastUp)   / dt);
    int64_t downRate = (int64_t)((double)(down - _lastDown) / dt);
    _lastUp = up; _lastDown = down; _lastTime = now;

    int64_t ingressPkts = atomic_load_explicit(&_ingressPackets, memory_order_relaxed);
    int64_t egressPkts  = _writer.egressPackets;

    // Footprint: prefer phys_footprint (the metric jetsam compares against the
    // NE limit). svpn_resident_bytes is also available from the core but reports
    // a resident_size-style figure; phys_footprint is the truer headroom gauge,
    // so we use it for both the published snapshot and the soft-cap watchdog.
    struct task_vm_info vmi = {0};
    mach_msg_type_number_t vmic = TASK_VM_INFO_COUNT;
    NSInteger footprintMB = -1;
    if (task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&vmi, &vmic) == KERN_SUCCESS) {
        footprintMB = (NSInteger)(vmi.phys_footprint / (1024 * 1024));
    }

    NSString *memline = [NSString stringWithFormat:
        @"tick=%d footprint=%ldMB up=%lldB/s down=%lldB/s totalUp=%lldB totalDown=%lldB "
         "ingress=%lld egress=%lld\n",
        _pumpTick, (long)footprintMB, upRate, downRate, up, down,
        ingressPkts, egressPkts];
    os_log_debug(gLog, "memstats %{public}@", memline);

    _pumpTick++;
    if (_pumpTick % 10 == 0) {
        malloc_zone_pressure_relief(NULL, 0);
    }

    [self maybeRelieveForFootprint:footprintMB now:now];

    // Publish a TrafficSnapshot the app's SharedStore decodes. The Swift decoder
    // uses `.secondsSince1970` for the `timestamp` Date field, so we write a
    // numeric epoch-seconds value here (NOT a reference-date or ISO string), and
    // the keys mirror SVPNModels.TrafficSnapshot exactly.
    NSTimeInterval epochSeconds = now + NSTimeIntervalSince1970;
    NSDictionary *snapshot = @{
        @"uploadBytes":   @(up),
        @"downloadBytes": @(down),
        @"uploadRate":    @(upRate),
        @"downloadRate":  @(downRate),
        @"timestamp":     @(epochSeconds),
        @"footprintMB":   @(footprintMB < 0 ? 0 : footprintMB),
    };

    NSError *err = nil;
    if (![SVSharedStore writeTraffic:snapshot error:&err]) {
        os_log_error(gLog, "traffic write failed: %{public}@", err);
        return;
    }
    [SVDarwinBridge post:SVNotificationTraffic];
}

// MARK: - Soft-cap watchdog

- (void)maybeRelieveForFootprint:(NSInteger)footprintMB now:(NSTimeInterval)now {
    if (footprintMB < kSoftCapFootprintMB) return;
    if (_lastReliefAttempt > 0 && (now - _lastReliefAttempt) < kReliefCooldownS) {
        return;
    }
    _lastReliefAttempt = now;
    os_log_error(gLog,
                 "soft-cap: footprint=%ldMB >= %ldMB, calling malloc_zone_pressure_relief",
                 (long)footprintMB, (long)kSoftCapFootprintMB);
    malloc_zone_pressure_relief(NULL, 0);
}

// MARK: - Helpers

- (NSString *)lastRustError {
    const char *p = svpn_core_last_error();
    return (p && p[0]) ? [NSString stringWithUTF8String:p] : nil;
}

@end
