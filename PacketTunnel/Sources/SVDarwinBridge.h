#pragma once
#import <Foundation/Foundation.h>

// Cross-process notification channel (CFNotificationCenter Darwin center)
// between the app and the packet-tunnel extension. The names match
// SVPNShared/Sources/SVPNIPC/DarwinNotifications.swift exactly so a post from
// either process is observed by the other. The notification carries no payload —
// it's a "go read the App Group container" nudge; the data lives in the shared
// state.json / traffic.json / UserDefaults.
typedef NS_ENUM(NSUInteger, SVNotification) {
    SVNotificationCommand,
    SVNotificationState,
    SVNotificationTraffic,
};

/// A live registration with the Darwin notify center. Retain it for as long as
/// you want callbacks; `-stop` (or dealloc) tears the registration down.
@interface SVDarwinObserver : NSObject
- (void)stop;
@end

@interface SVDarwinBridge : NSObject
+ (void)post:(SVNotification)notification;
+ (SVDarwinObserver *)observe:(SVNotification)notification handler:(dispatch_block_t)handler;
+ (void)remove:(SVDarwinObserver *)observer;
@end
