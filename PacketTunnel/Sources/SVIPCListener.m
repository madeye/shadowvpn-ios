#import "SVIPCListener.h"
#import "SVDarwinBridge.h"

@implementation SVIPCListener {
    SVCommandHandler _handler;
    SVDarwinObserver *_observer;
}

- (instancetype)initWithHandler:(SVCommandHandler)handler {
    self = [super init];
    if (self) { _handler = [handler copy]; }
    return self;
}

- (void)start {
    SVCommandHandler handler = _handler;
    _observer = [SVDarwinBridge observe:SVNotificationCommand handler:^{
        if (handler) handler();
    }];
}

- (void)stop {
    if (_observer) {
        [SVDarwinBridge remove:_observer];
        _observer = nil;
    }
}

@end
