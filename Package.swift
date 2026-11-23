// swift-tools-version: 6.4

import PackageDescription

let package = Package(
    name: "swift-rfc-4226",
    platforms: [
        .macOS(.v27),
        .iOS(.v27),
        .tvOS(.v27),
        .watchOS(.v27),
        .visionOS(.v27),
    ],
    products: [
        .library(name: "RFC 4226", targets: ["RFC 4226"])
    ],
    dependencies: [
        .package(url: "https://github.com/swift-ietf/swift-rfc.git", branch: "main"),
        .package(
            url: "https://github.com/swift-ietf/swift-rfc-2104.git",
            branch: "main"
        ),
    ],
    targets: [
        .target(
            name: "RFC 4226",
            dependencies: [
                .product(name: "IETF RFC", package: "swift-rfc"),
                .product(name: "RFC 2104", package: "swift-rfc-2104"),
            ]
        ),
        .testTarget(
            name: "RFC 4226 Tests",
            dependencies: [
                .target(name: "RFC 4226")
            ]
        ),
    ],
    swiftLanguageModes: [.v6]
)

for target in package.targets where ![.system, .binary, .plugin, .macro].contains(target.type) {
    target.swiftSettings =
        (target.swiftSettings ?? []) + [
            .strictMemorySafety(),
            .enableUpcomingFeature("ExistentialAny"),
            .enableUpcomingFeature("InternalImportsByDefault"),
            .enableUpcomingFeature("MemberImportVisibility"),
            .enableUpcomingFeature("NonisolatedNonsendingByDefault"),
            .enableUpcomingFeature("InferIsolatedConformances"),
            .enableExperimentalFeature("Lifetimes"),
            .treatAllWarnings(as: .error),
        ]
}
