#!/usr/bin/env bash
# Build shadowvpn-ios-ffi for iOS device + simulator and pack into an XCFramework.
#
# Outputs:
#   ShadowVPNCore/Frameworks/ShadowVPNCore.xcframework  (device + sim staticlibs)
#   ShadowVPNCore/include/shadowvpn_core.h              (cbindgen header, committed)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CRATE_DIR="$ROOT/core/rust/shadowvpn-ios-ffi"
OUT_DIR="$ROOT/ShadowVPNCore/Frameworks"
HEADER_SRC="$CRATE_DIR/include/shadowvpn_core.h"
HEADER_DST="$ROOT/ShadowVPNCore/include/shadowvpn_core.h"

TARGETS_REQUIRED=(aarch64-apple-ios aarch64-apple-ios-sim)
PROFILE="release"

# Match the iOS deployment target declared in project.yml so the Rust static
# libs and the Xcode targets agree on LC_BUILD_VERSION minos.
export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-17.0}"

for target in "${TARGETS_REQUIRED[@]}"; do
    if ! rustup target list --installed | grep -qx "$target"; then
        echo "==> Adding rust target $target"
        rustup target add "$target"
    fi
done

cd "$CRATE_DIR"

echo "==> cargo build --target aarch64-apple-ios (device)"
cargo build --release --target aarch64-apple-ios

echo "==> cargo build --target aarch64-apple-ios-sim (simulator)"
cargo build --release --target aarch64-apple-ios-sim

DEVICE_LIB="$CRATE_DIR/target/aarch64-apple-ios/$PROFILE/libshadowvpn_ios_ffi.a"
SIM_LIB="$CRATE_DIR/target/aarch64-apple-ios-sim/$PROFILE/libshadowvpn_ios_ffi.a"

if [[ ! -f "$DEVICE_LIB" || ! -f "$SIM_LIB" ]]; then
    echo "error: expected static libs missing" >&2
    exit 1
fi

mkdir -p "$OUT_DIR" "$(dirname "$HEADER_DST")"
rm -rf "$OUT_DIR/ShadowVPNCore.xcframework"

# Ensure the header we ship to Swift matches what cbindgen emitted.
if [[ -f "$HEADER_SRC" ]]; then
    cp "$HEADER_SRC" "$HEADER_DST"
fi

HEADERS_STAGE="$(mktemp -d)"
cp "$HEADER_DST" "$HEADERS_STAGE/shadowvpn_core.h"

echo "==> xcodebuild -create-xcframework"
xcodebuild -create-xcframework \
    -library "$DEVICE_LIB" -headers "$HEADERS_STAGE" \
    -library "$SIM_LIB" -headers "$HEADERS_STAGE" \
    -output "$OUT_DIR/ShadowVPNCore.xcframework"

rm -rf "$HEADERS_STAGE"
echo "==> wrote $OUT_DIR/ShadowVPNCore.xcframework"
