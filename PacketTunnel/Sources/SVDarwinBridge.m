#import "SVDarwinBridge.h"
#import <CoreFoundation/CoreFoundation.h>

// Must match SVPNNotification.rawValue in DarwinNotifications.swift.
static NSString *nameFor(SVNotification n) {
    switch (n) {
        case SVNotificationCommand: return @"com.tangzixiang.shadowvpn.command";
        case SVNotificationState:   return @"com.tangzixiang.shadowvpn.state";
        case SVNotificationTraffic: return @"com.tangzixiang.shadowvpn.traffic";
    }
}

@interface SVDarwinObserver ()
@property (nonatomic, copy) NSString *name;
@property (nonatomic, copy) dispatch_block_t handler;
@property (nonatomic, assign) BOOL active;
@end

@implementation SVDarwinObserver

- (instancetype)initWithName:(NSString *)name handler:(dispatch_block_t)handler {
    self = [super init];
    if (self) {
        _name    = name;
        _handler = handler;
    }
    return self;
}

- (void)register {
    void *ctx = (__bridge void *)self;
    CFNotificationCenterAddObserver(
        CFNotificationCenterGetDarwinNotifyCenter(),
        ctx,
        darwinCallback,
        (__bridge CFStringRef)_name,
        NULL,
        CFNotificationSuspensionBehaviorDeliverImmediately
    );
    _active = YES;
}

static void darwinCallback(CFNotificationCenterRef c, void *observer,
                            CFNotificationName name, const void *obj,
                            CFDictionaryRef info) {
    SVDarwinObserver *this = (__bridge SVDarwinObserver *)observer;
    if (this.handler) this.handler();
}

- (void)stop {
    if (!_active) return;
    CFNotificationCenterRemoveObserver(
        CFNotificationCenterGetDarwinNotifyCenter(),
        (__bridge void *)self,
        (__bridge CFStringRef)_name,
        NULL
    );
    _active = NO;
}

- (void)dealloc { [self stop]; }

@end

@implementation SVDarwinBridge

+ (void)post:(SVNotification)notification {
    CFNotificationCenterPostNotification(
        CFNotificationCenterGetDarwinNotifyCenter(),
        (__bridge CFNotificationName)nameFor(notification),
        NULL, NULL, true
    );
}

+ (SVDarwinObserver *)observe:(SVNotification)notification handler:(dispatch_block_t)handler {
    SVDarwinObserver *obs = [[SVDarwinObserver alloc] initWithName:nameFor(notification)
                                                          handler:handler];
    [obs register];
    return obs;
}

+ (void)remove:(SVDarwinObserver *)observer {
    [observer stop];
}

@end
