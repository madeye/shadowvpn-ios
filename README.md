# shadowvpn-ios

Native iOS client for **ShadowVPN** — a UDP, pre-shared-key, layer-3 tunnel
using the shadowsocks AEAD UDP wire scheme. A SwiftUI app drives an
`NEPacketTunnelProvider` extension; the data plane (crypto + datagram pump +
optional ChinaDNS split) lives in a small Rust core wrapped as
`ShadowVPNCore.xcframework`.

See [`DESIGN.md`](DESIGN.md) for the full blueprint.

## Public beta

ShadowVPN is in open **TestFlight** beta — install it on your iPhone or iPad:

[![Join the TestFlight beta](https://img.shields.io/badge/TestFlight-Join%20the%20beta-35dcc8?logo=apple&logoColor=white)](https://testflight.apple.com/join/anD9vU5M)

- **Beta:** <https://testflight.apple.com/join/anD9vU5M>
- **Landing page:** <https://madeye.github.io/shadowvpn-ios/> (served from [`docs/`](docs/))

It's bring-your-own-server: run the open-source
[ShadowVPN server](https://github.com/madeye/shadowvpn), then point the app at it
(enter the details or scan a `shadowvpn://` QR code). No account required.

## Layout

```
App/              SwiftUI app target (Sources + Resources, incl. chnroute.txt)
PacketTunnel/     NEPacketTunnelProvider extension (ObjC SV* driver)
SVPNShared/       Local SPM package shared by app + extension (SVPNModels, SVPNIPC)
ShadowVPNCore/    C header + XCFramework for the Rust core
Shared/Resources/ chnroute.txt (CN CIDR set) + gfwlist.txt, bundled into the extension
core/rust/        shadowvpn-ios-ffi (the C-ABI crate) + chnroute-gen
scripts/          build-rust.sh, generate-xcodeproj.sh, gen-gfwlist.sh
docs/             GitHub Pages landing page (index.html + assets)
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

## Privacy

ShadowVPN is a self-hosted VPN client: you connect to **your own** server, and
no traffic is ever proxied through any service operated by us.

- **No data collection.** The app has no analytics, no tracking, no ads, and no
  third-party SDKs. We do not operate any server that receives your data.
- **No account.** There is no sign-up, login, or identity of any kind.
- **On-device only.** Your server addresses, pre-shared keys, and settings are
  stored locally on your device (in the app group container) and never leave it
  except to establish the tunnel you configured.
- **Tunnel traffic.** Your network traffic flows directly between your device
  and the server you specify, encrypted with the shadowsocks AEAD scheme. We
  cannot see it.
- **GeoIP database.** Country-based split tunneling is resolved entirely
  on-device from a bundled MaxMind GeoLite2 database. No lookups are sent
  anywhere.

Because the app collects nothing, there is nothing for us to share, sell, or
disclose. Questions: open an issue at
<https://github.com/madeye/shadowvpn-ios>.

## License

[MIT](LICENSE) © 2026 Max Lv
