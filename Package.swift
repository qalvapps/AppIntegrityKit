// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "AppIntegrityKit",
    platforms: [
        .iOS(.v15),
        .watchOS(.v9),
        .macOS(.v13)
    ],
    products: [
        .library(
            name: "AppIntegrityKit",
            targets: ["AppIntegrityKit"]
        )
    ],
    targets: [
        .target(
            name: "AppIntegrityKit",
            path: "AppIntegrityKit",
            exclude: ["AppIntegrityKit.docc"],
            linkerSettings: [
                .linkedFramework("DeviceCheck"),
                .linkedFramework("Security")
            ]
        ),
        .testTarget(
            name: "AppIntegrityKitTests",
            dependencies: ["AppIntegrityKit"],
            path: "AppIntegrityKitTests"
        )
    ]
)
