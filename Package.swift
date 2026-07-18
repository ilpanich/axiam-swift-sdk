// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "AxiamSDK",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
    ],
    products: [
        .library(name: "AxiamSDK", targets: ["AxiamSDK"]),
    ],
    dependencies: [
        // HTTP client with cross-platform TLS + client-cert mTLS via NIOSSL.
        // (URLSession client certs need Apple's Security.framework and don't work on Linux.)
        .package(url: "https://github.com/swift-server/async-http-client.git", from: "1.21.0"),
        // TLSConfiguration: certificate chain / private key from PEM, custom CA trust roots.
        .package(url: "https://github.com/apple/swift-nio-ssl.git", from: "2.25.0"),
        // EdDSA / Ed25519 JWKS signature verification.
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.2.0"),
        // Core NIO — used directly by the SDK for ByteBuffer and by the test HTTP server.
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.62.0"),
        // DocC static-site generation for the GitHub Pages docs workflow.
        // Build-tool plugin only — not linked into the AxiamSDK product.
        .package(url: "https://github.com/apple/swift-docc-plugin.git", from: "1.3.0"),
    ],
    targets: [
        .target(
            name: "AxiamSDK",
            dependencies: [
                .product(name: "AsyncHTTPClient", package: "async-http-client"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
            ]
        ),
        .testTarget(
            name: "AxiamSDKTests",
            dependencies: [
                "AxiamSDK",
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),
    ]
)
