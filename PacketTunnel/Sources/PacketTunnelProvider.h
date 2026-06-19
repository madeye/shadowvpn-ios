#pragma once
#import <NetworkExtension/NetworkExtension.h>

// The ShadowVPN packet-tunnel provider. Declared as the NSExtensionPrincipalClass
// in PacketTunnel/Info.plist. Owns the NE lifecycle, the network-path monitor
// (with a debounced in-place engine restart) and the SVTunnelEngine data plane.
@interface PacketTunnelProvider : NEPacketTunnelProvider
@end
