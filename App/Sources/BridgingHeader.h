// Imported by the app target via SWIFT_OBJC_BRIDGING_HEADER so the ShadowVPN
// Rust core's C surface is visible to Swift. The app links the same
// ShadowVPNCore.xcframework as the extension but never drives the tunnel
// lifecycle — it only touches the pure-function subset (e.g. svpn_core_log for
// diagnostics). The packet-tunnel lifecycle (svpn_tun_*) lives entirely in the
// NE extension.
#pragma once

#import "shadowvpn_core.h"
