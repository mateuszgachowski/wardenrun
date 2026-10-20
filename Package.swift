// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "wardenrun",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "WardenrunCore", targets: ["WardenrunCore"]),
    ],
    targets: [
        .target(name: "WardenrunCore"),
        // The macOS layer: Security, LocalAuthentication, hardening. Every file is wrapped in
        // `#if canImport(Darwin)`, so on Linux (CI) the module is empty.
        .target(name: "WardenrunMac", dependencies: ["WardenrunCore"]),
        .testTarget(name: "WardenrunCoreTests", dependencies: ["WardenrunCore"]),
        .testTarget(name: "WardenrunMacTests", dependencies: ["WardenrunMac", "WardenrunCore"]),
    ]
)
