// swift-tools-version: 6.0
import PackageDescription

// SVPNShared is the local SPM package shared between the SwiftUI app and the
// packet-tunnel extension. It is deliberately tiny compared to meow-ios'
// MeowShared: ShadowVPN has no Clash YAML, no subscriptions and no GeoIP
// download, so there are no external dependencies (no Yams) — just the model
// types both processes serialize and the App-Group / Darwin-notification IPC
// plumbing.
//
//  * `SVPNModels` — pure value types (`Profile`, `VpnState`, …), the App-Group
//    identifiers and shared `UserDefaults` keys. No platform UI imports, so it
//    compiles for `swift test` on macOS as well as for iOS.
//  * `SVPNIPC` — the cross-process glue: a JSON-backed `SharedStore` in the App
//    Group container and the `CFNotificationCenter` Darwin-notification bridge.
let package = Package(
    name: "SVPNShared",
    platforms: [
        .iOS(.v17),
        // macOS 15 lets `swift test` drive SVPNSharedTests from the command
        // line. Production builds always target iOS via `project.yml`; this
        // declaration only exists so CI / local dev can run the pure-logic
        // tests without spinning up a simulator.
        .macOS(.v15),
    ],
    products: [
        .library(name: "SVPNModels", targets: ["SVPNModels"]),
        .library(name: "SVPNIPC", targets: ["SVPNIPC"]),
    ],
    targets: [
        .target(
            name: "SVPNModels",
            path: "Sources/SVPNModels",
        ),
        .target(
            name: "SVPNIPC",
            dependencies: ["SVPNModels"],
            path: "Sources/SVPNIPC",
        ),
        .testTarget(
            name: "SVPNSharedTests",
            dependencies: ["SVPNModels", "SVPNIPC"],
            path: "Tests/SVPNSharedTests",
        ),
    ],
)
