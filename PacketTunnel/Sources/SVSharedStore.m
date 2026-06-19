#import "SVSharedStore.h"
#import "SVAppGroup.h"

@implementation SVSharedStore

+ (BOOL)writeDict:(NSDictionary *)dict toURL:(NSURL *)url error:(NSError **)error {
    NSURL *dir = [url URLByDeletingLastPathComponent];
    if (![[NSFileManager defaultManager] createDirectoryAtURL:dir
                                 withIntermediateDirectories:YES
                                                  attributes:nil
                                                       error:error]) {
        return NO;
    }
    NSData *data = [NSJSONSerialization dataWithJSONObject:dict options:0 error:error];
    if (!data) return NO;
    return [data writeToURL:url options:NSDataWritingAtomic error:error];
}

+ (nullable NSDictionary *)readDictFromURL:(NSURL *)url {
    NSData *data = [NSData dataWithContentsOfURL:url];
    if (!data) return nil;
    id obj = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    return [obj isKindOfClass:[NSDictionary class]] ? obj : nil;
}

+ (BOOL)writeState:(NSDictionary *)state error:(NSError **)error {
    return [self writeDict:state toURL:[SVAppGroup stateURL] error:error];
}

+ (nullable NSDictionary *)readState {
    return [self readDictFromURL:[SVAppGroup stateURL]];
}

+ (BOOL)writeTraffic:(NSDictionary *)traffic error:(NSError **)error {
    return [self writeDict:traffic toURL:[SVAppGroup trafficURL] error:error];
}

+ (nullable NSDictionary *)readTraffic {
    return [self readDictFromURL:[SVAppGroup trafficURL]];
}

@end
