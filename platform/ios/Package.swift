// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "LocalNetwork",
    platforms: [
        .iOS(.v15),
    ],
    products: [
        .library(
            name: "LocalNetwork",
            targets: ["LocalNetwork"]
        ),
    ],
    targets: [
        .target(name: "LocalNetwork"),
    ]
)
