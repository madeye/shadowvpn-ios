#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Severity levels mirroring `svpn_core_log`'s contract (Rust `tracing`):
/// 0 = error, 1 = warn, 2 = info, 3 = debug, 4 = trace.
typedef NS_ENUM(int, SVLogLevel) {
    SVLogError = 0,
    SVLogWarn = 1,
    SVLogInfo = 2,
    SVLogDebug = 3,
    SVLogTrace = 4,
};

/// Tee a NetworkExtension-host log line into the Rust core's logging pipeline so
/// it lands in the App-Group log file (`<container>/logs/svpn-tunnel.log`)
/// interleaved with the engine's own output. The app's `LogsView` tails that
/// file — `OSLogStore` can only see the app's own process, never this extension,
/// so the shared file is the only way the NE lifecycle narrative reaches the UI.
///
/// This complements (does not replace) the `os_log` calls in the driver: those
/// keep full live-debugging detail in the unified log, while these lines give
/// the exportable file the start/stop, sleep/wake and path-change story.
///
/// Safe to call before `svpn_core_init` — the line is simply dropped until the
/// core's subscriber is installed.
void SVEngineLog(SVLogLevel level, NSString *msg);

/// `NSLog`-style variadic convenience over ``SVEngineLog``.
void SVEngineLogf(SVLogLevel level, NSString *format, ...) NS_FORMAT_FUNCTION(2, 3);

NS_ASSUME_NONNULL_END
