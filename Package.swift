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
        .testTarget(name: "WardenrunCoreTests", dependencies: ["WardenrunCore"]),
    ]
)
