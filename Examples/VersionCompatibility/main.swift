// VersionCompatibility — reports the compiling toolchain against the range this SDK is
// built and tested against, and says whether Swift 6 language mode is in effect.
//
// The floor takes care of itself: SwiftPM reads `swift-tools-version` before resolving
// anything, so a toolchain older than 6.2 refuses the package outright with a clear
// message. Nothing takes care of the upper end — a package resolves and builds on a newer
// toolchain whether or not anybody ever compiled it there, and the differences that
// matter (strict concurrency, `Sendable` inference, isolation checking) surface as errors
// only once someone tries.
//
// The line worth reading here is the language mode. `Package.swift` sets
// `.swiftLanguageMode(.v6)` on every target, so the SDK's sources are compiled under full
// strict-concurrency checking. That is invisible from the outside, and it is the
// difference between "the concurrency guarantees were checked" and "they were intended".
//
// This example is illustrative and self-contained: no server, no network, no configuration.
//
// Build:  swift build --target VersionCompatibilityExample
// Run:    swift run VersionCompatibilityExample

import Foundation
import AxiamSDK

/// The Swift version compiling *this file*, which is the consumer's toolchain rather than
/// whatever built the SDK.
let compilingSwift: String = {
    #if swift(>=6.4)
    return "6.4 or newer"
    #elseif swift(>=6.3)
    return "6.3"
    #elseif swift(>=6.2)
    return "6.2"
    #else
    return "older than 6.2"
    #endif
}()

print("compiling Swift:      \(compilingSwift)")
print("SDK tools-version:    \(SupportedVersions.minimumSwiftToolsVersion) (floor)")
print("newest tested Swift:  \(SupportedVersions.newestTestedSwift)")
print("Swift 6 language mode: \(SupportedVersions.isSwiftSixLanguageMode ? "on" : "off")")

if SupportedVersions.isSwiftSixLanguageMode {
    print("""
        SUPPORTED: this SDK's sources were compiled in Swift 6 language mode, under full \
        strict-concurrency checking — data-race safety is enforced, not assumed.
        """)
} else {
    // Should be unreachable for the package as published: every target in Package.swift
    // carries `.swiftLanguageMode(.v6)`. Reaching it means the sources were built some
    // other way (vendored into a Swift 5 mode target, say), which is worth knowing.
    print("""
        UNEXPECTED: Swift 6 language mode is off for the SDK. Build it through its own \
        Package.swift, which sets `.swiftLanguageMode(.v6)` on every target.
        """)
}
