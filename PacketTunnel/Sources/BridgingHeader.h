// Imported by the PacketTunnel target via SWIFT_OBJC_BRIDGING_HEADER so the
// ShadowVPN Rust core's C surface (svpn_tun_* lifecycle, svpn_core_* logging,
// traffic counters) is visible to any Swift compiled into the extension. The
// NE driver itself is ObjC (SV* classes) and imports shadowvpn_core.h directly,
// but the bridging header keeps the door open for Swift glue without a project
// regeneration.
#pragma once

#import "shadowvpn_core.h"
