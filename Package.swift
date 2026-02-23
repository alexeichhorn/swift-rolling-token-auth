// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "RollingTokenAuth",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15),
        .tvOS(.v13),
        .watchOS(.v6),
    ],
    products: [
        .library(
            name: "RollingTokenAuth",
            targets: ["RollingTokenAuth"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "4.2.0"),
    ],
    targets: [
        .target(
            name: "RollingTokenAuth",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),
        .testTarget(
            name: "RollingTokenAuthTests",
            dependencies: ["RollingTokenAuth"]
        ),
    ]
)
