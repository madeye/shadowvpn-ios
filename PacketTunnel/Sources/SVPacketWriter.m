#import "SVPacketWriter.h"
#import <stdatomic.h>

// NEPacketTunnelFlow wants the address family of each packet alongside it. We
// select it from the IP version nibble of the packet's first byte. ShadowVPN is
// configured IPv4-only (no NEIPv6Settings), so in practice every egress packet
// is AF_INET — but we still honour an IPv6 inner packet correctly rather than
// mislabel it, matching the meow driver.
static NSArray<NSNumber *> *sIPv4Proto;
static NSArray<NSNumber *> *sIPv6Proto;

@implementation SVPacketWriter {
    NEPacketTunnelFlow *_flow;
    _Atomic int64_t _egressPackets;
}

+ (void)initialize {
    if (self == [SVPacketWriter class]) {
        sIPv4Proto = @[@(AF_INET)];
        sIPv6Proto = @[@(AF_INET6)];
    }
}

- (instancetype)initWithFlow:(NEPacketTunnelFlow *)flow {
    self = [super init];
    if (self) {
        _flow = flow;
        atomic_init(&_egressPackets, 0);
    }
    return self;
}

- (void)writeData:(const uint8_t *)data length:(NSUInteger)length {
    @autoreleasepool {
        NSData *packet = [NSData dataWithBytes:data length:length];
        NSArray<NSNumber *> *proto =
            (length > 0 && (data[0] >> 4) == 6) ? sIPv6Proto : sIPv4Proto;
        [_flow writePackets:@[packet] withProtocols:proto];
        atomic_fetch_add_explicit(&_egressPackets, 1, memory_order_relaxed);
    }
}

- (int64_t)egressPackets {
    return atomic_load_explicit(&_egressPackets, memory_order_relaxed);
}

@end

void svpnPacketWriterCB(void *ctx, const uint8_t *data, uintptr_t len) {
    if (!ctx || !data || len == 0) return;
    SVPacketWriter *writer = (__bridge SVPacketWriter *)ctx;
    [writer writeData:data length:(NSUInteger)len];
}
