#import "SVEngineLog.h"
#import "shadowvpn_core.h"

void SVEngineLog(SVLogLevel level, NSString *msg) {
    if (msg.length == 0) return;
    svpn_core_log((int)level, msg.UTF8String);
}

void SVEngineLogf(SVLogLevel level, NSString *format, ...) {
    if (format == nil) return;
    va_list args;
    va_start(args, format);
    NSString *msg = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    SVEngineLog(level, msg);
}
