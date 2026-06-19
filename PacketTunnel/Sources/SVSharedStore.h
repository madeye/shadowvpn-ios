#pragma once
#import <Foundation/Foundation.h>

// Reads/writes the JSON the app and extension share in the App Group container.
// The on-disk shapes MUST stay byte-compatible with the Swift Codable models in
// SVPNShared (VpnState, TrafficSnapshot): the app decodes these files with a
// JSONDecoder whose date strategy is `.secondsSince1970`, so any Date-typed
// field (state.startedAt, traffic.timestamp) is written here as a numeric
// epoch-seconds value, never an ISO string.
//
// Unlike meow there is no pending-intent queue in UserDefaults: ShadowVPN's only
// app→extension command is a stop, delivered as a Darwin notification that the
// SVIPCListener turns into `cancelTunnelWithError:` directly.
@interface SVSharedStore : NSObject
+ (BOOL)writeState:(NSDictionary *)state error:(NSError **)error;
+ (nullable NSDictionary *)readState;
+ (BOOL)writeTraffic:(NSDictionary *)traffic error:(NSError **)error;
+ (nullable NSDictionary *)readTraffic;
@end
