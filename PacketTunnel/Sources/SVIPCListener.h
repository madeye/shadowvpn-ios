#pragma once
#import <Foundation/Foundation.h>

// Listens for the app's `command` Darwin notification and invokes a handler.
//
// ShadowVPN's IPC is intentionally minimal versus meow's intent-queue design:
// the only message the app sends the extension is "stop", posted as the
// `com.tangzixiang.shadowvpn.command` Darwin notification. There is no payload
// and no UserDefaults intent record to drain — the handler simply tears the
// tunnel down. (Disconnects normally go through NETunnelProviderManager, which
// calls `stopTunnelWithReason:`; this channel exists for an in-process stop that
// doesn't round-trip through the manager.)
typedef void (^SVCommandHandler)(void);

@interface SVIPCListener : NSObject
- (instancetype)initWithHandler:(SVCommandHandler)handler;
- (void)start;
- (void)stop;
@end
