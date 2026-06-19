#pragma once
#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>

// Builds the NEPacketTunnelNetworkSettings for the tunnel from the active
// Profile-derived config the provider passes in. ShadowVPN does all of its
// split-routing here in Swift/ObjC via includedRoutes/excludedRoutes — the Rust
// core only sees a raw bidirectional IP pipe; it does not know or care which IPs
// are tunneled. See DESIGN.md "Routing on iOS".
@interface SVTunnelSettings : NSObject

/// @param serverAddress  Tunnel remote address (the server host/IP), used only
///                       as the NEPacketTunnelNetworkSettings remote-address
///                       label — routing is governed by the route sets below.
/// @param mode           "full" | "chnroute" | "chinadns".
/// @param dnsLocal       Domestic DNS upstream "host:port" (chinadns only).
/// @param dnsRemote      Clean DNS upstream "host:port" (chinadns only).
/// @param mtu            Tunnel MTU (Profile.mtu, default 1400).
/// @param chnrouteURL    File URL of chnroute.txt (the NE's own bundle copy or
///                       the App-Group staged copy). Read for chnroute/chinadns
///                       to append every China CIDR as an excluded route. May be
///                       nil for "full".
+ (NEPacketTunnelNetworkSettings *)makeWithServerAddress:(NSString *)serverAddress
                                                    mode:(NSString *)mode
                                                dnsLocal:(nullable NSString *)dnsLocal
                                               dnsRemote:(nullable NSString *)dnsRemote
                                                     mtu:(NSInteger)mtu
                                             chnrouteURL:(nullable NSURL *)chnrouteURL;
@end
