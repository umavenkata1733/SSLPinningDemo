// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "SecureNetworkingKit",
    platforms: [
        .iOS(.v16),
        .macOS(.v13)
    ],
    products: [
        .library(
            name: "SecureNetworkingKit",
            targets: ["SecureNetworkingKit"]
        )
    ],
    targets: [
        .target(
            name: "SecureNetworkingKit",
            resources: [
                .process("Resources")
            ]
        ),
        .testTarget(
            name: "SecureNetworkingKitTests",
            dependencies: ["SecureNetworkingKit"]
        )
    ]
)
