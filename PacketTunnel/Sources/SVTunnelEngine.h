#pragma once
#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>

// Drives the ShadowVPN data plane: owns the NEPacketTunnelFlow, the CFRetained
// egress writer context, the ingress (read → svpn_tun_ingest) loop and the
// ~500 ms traffic pump that publishes counters to the App Group.
//
// Unlike meow there is no separate engine vs tun2socks split: for ShadowVPN the
// Rust core's `svpn_tun_start` IS the whole engine (it spins up the UDP socket,
// the recv/egress tasks and the keepalive ticker). So start/stop/restart map to
// a single pair of FFI calls, with the writer-context lifecycle (CFBridgingRetain
// → svpn_tun_stop_blocking → CFBridgingRelease) ordered exactly as meow's to
// avoid the use-after-free its comments document.
@interface SVTunnelEngine : NSObject

/// @param flow        The provider's NEPacketTunnelFlow (ingress + egress).
/// @param configJSON  The Profile-derived `config_json` string passed verbatim
///                    to `svpn_tun_start` (see Profile.configJSONString in
///                    SVPNShared). Includes server/password/cipher/mode/mtu and,
///                    for split modes, dns_local/dns_remote/chnroute_path.
- (instancetype)initWithPacketFlow:(NEPacketTunnelFlow *)flow
                        configJSON:(NSString *)configJSON;

/// Blocking: runs `svpn_core_init`, `svpn_core_set_home_dir` and `svpn_tun_start`,
/// then arms the ingress loop and the traffic pump. Call on a background queue.
- (BOOL)startWithError:(NSError **)error;

/// Blocking: tears the tun down and re-starts it in place for a network-path
/// change, preserving the already-armed ingress read chain.
- (BOOL)restartWithError:(NSError **)error;

/// Blocking: stops the tun (joining its egress task), then releases the writer
/// context. Stops the ingress loop and traffic pump first.
- (void)stop;

/// Whether the Rust core reports the tunnel running (`svpn_is_running`).
@property (nonatomic, readonly) BOOL isRunning;

@end
