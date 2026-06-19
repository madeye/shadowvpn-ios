#import "SVAppGroup.h"

NSString *const SVAppGroupIdentifier = @"group.com.tangzixiang.shadowvpn";

@implementation SVAppGroup

+ (NSString *)identifier {
    return SVAppGroupIdentifier;
}

+ (NSURL *)containerURL {
    NSURL *url = [[NSFileManager defaultManager]
        containerURLForSecurityApplicationGroupIdentifier:SVAppGroupIdentifier];
    NSAssert(url, @"App Group container unavailable — entitlement missing '%@'",
             SVAppGroupIdentifier);
    return url;
}

+ (NSURL *)stateURL {
    return [[self containerURL] URLByAppendingPathComponent:@"state.json"];
}

+ (NSURL *)trafficURL {
    return [[self containerURL] URLByAppendingPathComponent:@"traffic.json"];
}

+ (NSURL *)logsDirURL {
    return [[self containerURL] URLByAppendingPathComponent:@"logs" isDirectory:YES];
}

+ (NSURL *)chnrouteURL {
    return [[self containerURL] URLByAppendingPathComponent:@"chnroute.txt"];
}

+ (NSUserDefaults *)defaults {
    NSUserDefaults *d = [[NSUserDefaults alloc] initWithSuiteName:SVAppGroupIdentifier];
    NSAssert(d, @"Shared UserDefaults unavailable for suite '%@'", SVAppGroupIdentifier);
    return d;
}

@end
