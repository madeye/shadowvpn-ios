# shadowvpn-ios

Native iOS client for **ShadowVPN** — a UDP, pre-shared-key, layer-3 tunnel
using the shadowsocks AEAD UDP wire scheme. A SwiftUI app drives an
`NEPacketTunnelProvider` extension; the data plane (crypto + datagram pump +
optional ChinaDNS split) lives in a small Rust core wrapped as
`ShadowVPNCore.xcframework`.

See [`DESIGN.md`](DESIGN.md) for the full blueprint.

## Layout

```
App/              SwiftUI app target (Sources + Resources, incl. chnroute.txt)
PacketTunnel/     NEPacketTunnelProvider extension (ObjC SV* driver)
SVPNShared/       Local SPM package shared by app + extension (SVPNModels, SVPNIPC)
ShadowVPNCore/    C header + XCFramework for the Rust core
Shared/Resources/ chnroute.txt (CN CIDR set) bundled into the extension
core/rust/        shadowvpn-ios-ffi (the C-ABI crate) + chnroute-gen
scripts/          build-rust.sh, generate-xcodeproj.sh
```

## Building

The native library is built first and wrapped as an XCFramework that both the
app and the extension link against:

```sh
./scripts/build-rust.sh        # → ShadowVPNCore/Frameworks/ShadowVPNCore.xcframework
```

The Xcode project is generated from `project.yml` via
[`xcodegen`](https://github.com/yonaskolb/XcodeGen):

```sh
brew install xcodegen
./scripts/generate-xcodeproj.sh   # → shadowvpn-ios.xcodeproj
```

Then build the app (and embedded extension):

```sh
xcodebuild -project shadowvpn-ios.xcodeproj -scheme shadowvpn-ios \
  -destination 'generic/platform=iOS Simulator' build
```

### Signing

Signing is automatic. Create a gitignored `Local.xcconfig` (a template is in the
repo) with your team id before generating the project:

```
DEVELOPMENT_TEAM = 32B45SMMQL
```

- App bundle id: `com.tangzixiang.shadowvpn`
- Extension bundle id: `com.tangzixiang.shadowvpn.PacketTunnel`
- App group: `group.com.tangzixiang.shadowvpn`
- Deployment target: iOS 17.0

## License

[MIT](LICENSE) © 2026 Max Lv
