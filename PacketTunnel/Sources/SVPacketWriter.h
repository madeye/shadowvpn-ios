#pragma once
#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>
#import "shadowvpn_core.h"

// Egress side of the data plane: the Rust core, after decrypting a datagram it
// received from the server, hands the inner IP packet back to us through the
// `SvpnWritePacket` callback. We push it into the NEPacketTunnelFlow so the
// kernel delivers it to the app that owns the connection.
@interface SVPacketWriter : NSObject
- (instancetype)initWithFlow:(NEPacketTunnelFlow *)flow;
- (void)writeData:(const uint8_t *)data length:(NSUInteger)length;
/// Cumulative packets handed to `writePackets:` — surfaced for footprint logging.
@property (nonatomic, readonly) int64_t egressPackets;
@end

// C callback matching the `SvpnWritePacket` typedef in shadowvpn_core.h. `ctx`
// is the CFRetained SVPacketWriter* passed to `svpn_tun_start`. The engine
// guarantees (via `svpn_tun_stop_blocking`) that this never fires again after a
// blocking stop returns, so the writer can be released without a use-after-free.
void svpnPacketWriterCB(void *ctx, const uint8_t *data, uintptr_t len);
