/// The range of Swift versions this SDK is built and tested against.
///
/// The floor enforces itself: SwiftPM reads `swift-tools-version` before it resolves
/// anything, and an older toolchain refuses the package outright with a clear message.
/// Nothing enforces the upper end — a package declaring tools-version 5.9 resolves and
/// builds on a Swift 6 toolchain whether or not anybody ever compiled it there, and the
/// differences that matter (strict concurrency, `Sendable` inference, isolation checking)
/// are exactly the ones that surface as errors only once someone tries.
///
/// These values name both ends, so a build script or a compatibility note can report the
/// range without hardcoding numbers that go stale.
///
/// ## Two manifests
///
/// The package ships `Package.swift` (tools-version 5.9) *and*
/// `Package@swift-6.0.swift` (tools-version 6.0). SwiftPM selects by toolchain, which is
/// what lets the SDK keep a 5.9 floor while compiling its own targets in **Swift 6
/// language mode** wherever a 6.x toolchain is present — full strict-concurrency checking
/// as errors, without dropping consumers still on 5.9.
///
/// `VersionPolicyTests` asserts these values against both manifests and the CI matrix, so
/// none of them can drift.
public enum SupportedVersions {

    /// The minimum Swift tools version required to resolve this package.
    ///
    /// Mirrors the `swift-tools-version` in `Package.swift`. SwiftPM refuses to resolve
    /// the package on an older toolchain.
    public static let minimumSwiftToolsVersion = "5.9"

    /// The newest Swift version this SDK has a green build against.
    ///
    /// Mirrors the upper leg of the CI matrix. Constrained to versions with an official
    /// Swift Linux container image, which is what CI runs — Swift 6.4 exists for Apple
    /// platforms but has no Linux image yet.
    public static let newestTestedSwift = "6.3"

    /// Whether **this library** was compiled in Swift 6 language mode.
    ///
    /// `true` when built by a 6.0+ toolchain, which selects `Package@swift-6.0.swift` and
    /// its per-target language-mode setting. Reported rather than assumed, because the
    /// difference is invisible from the outside and decides whether the concurrency
    /// guarantees were checked or merely intended.
    ///
    /// This reads the *language mode*, not the toolchain: `#if swift(>=6.0)` tests the
    /// former and `#if compiler(>=6.0)` the latter, and they genuinely differ in this
    /// package. On a 6.x toolchain the library and the examples are built in Swift 6
    /// mode while the test target is deliberately still built in Swift 5 mode — the
    /// library and examples compile clean under full strict-concurrency checking and the
    /// test harness does not, so scoping the mode to the targets that actually ship is
    /// what makes the guarantee about the artifact you get rather than about a rewrite of
    /// the test suite.
    public static var isSwiftSixLanguageMode: Bool {
        #if swift(>=6.0)
        return true
        #else
        return false
        #endif
    }
}
