#pragma once
#import <Foundation/Foundation.h>

// App Group container layout, mirrored from SVPNShared/Sources/SVPNModels/
// AppGroup.swift so the ObjC NE driver and the Swift app agree byte-for-byte on
// where the shared state/traffic JSON and the tunnel log file live. ShadowVPN's
// container is far smaller than meow's: no Clash YAML, no effective config, no
// REST credentials — just state, traffic, the staged chnroute copy and the log.
extern NSString *const SVAppGroupIdentifier;

@interface SVAppGroup : NSObject
@property (class, nonatomic, readonly) NSString *identifier;
/// Shared container both processes read/write. Asserts when the App Group
/// entitlement is missing — that is a provisioning bug that should fail loudly.
@property (class, nonatomic, readonly) NSURL *containerURL;
/// `state.json` — the latest VpnState the extension publishes (SVPNModels.VpnState).
@property (class, nonatomic, readonly) NSURL *stateURL;
/// `traffic.json` — the latest TrafficSnapshot from the traffic pump.
@property (class, nonatomic, readonly) NSURL *trafficURL;
/// `logs/` directory the Rust core writes its rotating log into.
@property (class, nonatomic, readonly) NSURL *logsDirURL;
/// `chnroute.txt` staged by the app into the container (a stable path the NE can
/// pass as `chnroute_path` in config_json). The NE also bundles its own copy.
@property (class, nonatomic, readonly) NSURL *chnrouteURL;
/// Shared UserDefaults suite (selected Profile JSON, log level, on-demand flag).
@property (class, nonatomic, readonly) NSUserDefaults *defaults;
@end
