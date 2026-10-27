/// The range of Swift versions this SDK is built and tested against.
///
/// The floor enforces itself: SwiftPM reads `swift-tools-version` before it resolves
/// anything, and an older toolchain refuses the package outright with a clear message.
/// Nothing enforces the upper end — a package resolves and builds on a newer toolchain
/// whether or not anybody ever compiled it there, and the differences that matter
/// (strict concurrency, `Sendable` inference, isolation checking) are exactly the ones
/// that surface as errors only once someone tries.
///
/// These values name both ends, so a build script or a compatibility note can report the
/// range without hardcoding numbers that go stale.
///
/// ## One manifest, Swift 6 language mode
///
/// The package ships a single `Package.swift` at tools-version 6.2, and every target in
/// it is compiled in **Swift 6 language mode** — full strict-concurrency checking as
/// errors. Through 1.1.x the floor was 5.9 and a second, version-specific manifest
/// (`Package@swift-6.0.swift`) carried the language mode for 6.x toolchains; with the
/// floor at 6.2 every toolchain that can resolve the package reads the setting directly,
/// so that file is gone.
///
/// `VersionPolicyTests` asserts these values against the manifest and the CI matrix, so
/// none of them can drift.
public enum SupportedVersions {

    /// The minimum Swift tools version required to resolve this package.
    ///
    /// Mirrors the `swift-tools-version` in `Package.swift`. SwiftPM refuses to resolve
    /// the package on an older toolchain. 6.2 is the Swift in Xcode 26, the oldest Xcode
    /// App Store Connect accepts, and the oldest Swift the current swift-crypto and
    /// async-http-client releases support.
    public static let minimumSwiftToolsVersion = "6.2"

    /// The newest Swift version this SDK has a green build against.
    ///
    /// Mirrors the upper leg of the CI matrix, which runs the official Swift Linux
    /// container image for that release.
    public static let newestTestedSwift = "6.4"

    /// Whether **this library** was compiled in Swift 6 language mode.
    ///
    /// Always `true` for a build of this package as published: the floor is a 6.x
    /// toolchain and `Package.swift` sets `.swiftLanguageMode(.v6)` on every target.
    /// Reported rather than assumed, because the difference is invisible from the outside
    /// and decides whether the concurrency guarantees were checked or merely intended —
    /// a consumer who vendors the sources into a Swift 5 mode target would see `false`.
    ///
    /// This reads the *language mode*, not the toolchain: `#if swift(>=6.0)` tests the
    /// former and `#if compiler(>=6.0)` the latter.
    public static var isSwiftSixLanguageMode: Bool {
        #if swift(>=6.0)
        return true
        #else
        return false
        #endif
    }
}
