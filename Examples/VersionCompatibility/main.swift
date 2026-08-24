// VersionCompatibility — reports the compiling toolchain against the range this SDK is
// built and tested against, and says whether Swift 6 language mode is in effect.
//
// The floor takes care of itself: SwiftPM reads `swift-tools-version` before resolving
// anything, so a toolchain older than 5.9 refuses the package outright with a clear
// message. Nothing takes care of the upper end — a package declaring tools-version 5.9
// resolves and builds on a Swift 6 toolchain whether or not anybody ever compiled it
// there, and the differences that matter (strict concurrency, `Sendable` inference,
// isolation checking) surface as errors only once someone tries.
//
// The line worth reading here is the language mode. This package ships two manifests —
// `Package.swift` at tools-version 5.9 and `Package@swift-6.0.swift` at 6.0 — and SwiftPM
// picks by toolchain. On Swift 6 the second one wins and compiles the SDK's targets under
// full strict-concurrency checking. That is invisible from the outside, and it is the
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
    #if swift(>=6.3)
    return "6.3 or newer"
    #elseif swift(>=6.2)
    return "6.2"
    #elseif swift(>=6.1)
    return "6.1"
    #elseif swift(>=6.0)
    return "6.0"
    #elseif swift(>=5.10)
    return "5.10"
    #elseif swift(>=5.9)
    return "5.9"
    #else
    return "older than 5.9"
    #endif
}()

print("compiling Swift:      \(compilingSwift)")
print("SDK tools-version:    \(SupportedVersions.minimumSwiftToolsVersion) (floor)")
print("newest tested Swift:  \(SupportedVersions.newestTestedSwift)")
print("Swift 6 language mode: \(SupportedVersions.isSwiftSixLanguageMode ? "on" : "off")")

if SupportedVersions.isSwiftSixLanguageMode {
    print("""
        SUPPORTED: built via Package@swift-6.0.swift, so this SDK's sources were compiled \
        under full strict-concurrency checking — data-race safety is enforced, not assumed.
        """)
} else {
    #if swift(>=6.0)
    // Should be unreachable: a 6.x toolchain selects the 6.0 manifest. Reaching it means
    // the version-specific manifest was not picked up, which is worth knowing.
    print("""
        UNEXPECTED: a Swift 6 toolchain is compiling this, but Swift 6 language mode is \
        off — Package@swift-6.0.swift was not selected. Check that it is present and \
        declares swift-tools-version 6.0.
        """)
    #else
    print("""
        SUPPORTED: Swift 5 language mode, via Package.swift. Concurrency diagnostics are \
        warnings here rather than errors; build with a Swift 6 toolchain to have them \
        enforced.
        """)
    #endif
}
