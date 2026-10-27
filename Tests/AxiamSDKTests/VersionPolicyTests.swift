import XCTest
import Foundation
@testable import AxiamSDK

/// Language-version support policy.
///
/// This SDK declares which Swift versions it supports in three places that nothing
/// compares:
///
/// - `swift-tools-version` in `Package.swift` — the floor. A toolchain older than this
///   refuses to resolve the package at all.
/// - the `swift` matrix in `.github/workflows/sdk-ci-swift.yml` — the only declaration
///   that is ever compiled.
/// - ``SupportedVersions`` — the only one a consumer can read.
///
/// Through 1.1.x there was a fourth, `Package@swift-6.0.swift`, a version-specific manifest
/// that carried Swift 6 language mode while the floor sat at 5.9, and these tests held
/// the two manifests in parity. The floor is now 6.2, so a single manifest carries the
/// mode itself — and a version-specific manifest reappearing would silently shadow it on
/// every toolchain it names, which is asserted against below.
final class VersionPolicyTests: XCTestCase {

    // MARK: - Locating the repository

    /// Walks up from this source file to the package root.
    ///
    /// `#filePath` rather than `Bundle` because the manifests and the workflow are not
    /// resources and are not copied into the test bundle.
    private func repoRoot() throws -> URL {
        var dir = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()   // AxiamSDKTests
            .deletingLastPathComponent()   // Tests
            .deletingLastPathComponent()   // <root>

        // Tolerate an unexpected layout rather than asserting a fixed depth.
        var hops = 0
        while !FileManager.default.fileExists(atPath: dir.appendingPathComponent("Package.swift").path) {
            let parent = dir.deletingLastPathComponent()
            hops += 1
            guard parent != dir, hops < 8 else {
                throw XCTSkip("could not locate the package root from \(#filePath)")
            }
            dir = parent
        }
        return dir
    }

    private func read(_ relative: String) throws -> String {
        let url = try repoRoot().appendingPathComponent(relative)
        return try String(contentsOf: url, encoding: .utf8)
    }

    // MARK: - Parsing

    /// The `// swift-tools-version:X.Y` line at the top of a manifest.
    private func toolsVersion(of manifest: String) throws -> String {
        let pattern = #"^//\s*swift-tools-version:\s*([0-9]+\.[0-9]+)"#
        let regex = try NSRegularExpression(pattern: pattern, options: [.anchorsMatchLines])
        let range = NSRange(manifest.startIndex..., in: manifest)
        guard let match = regex.firstMatch(in: manifest, range: range),
              let captured = Range(match.range(at: 1), in: manifest) else {
            XCTFail("manifest declares no swift-tools-version")
            return ""
        }
        return String(manifest[captured])
    }

    /// The `swift: ['6.2', '6.4']` list from the CI build matrix.
    private func ciMatrix(_ workflow: String) throws -> [String] {
        let pattern = #"^\s*swift:\s*\[([^\]]*)\]\s*$"#
        let regex = try NSRegularExpression(pattern: pattern, options: [.anchorsMatchLines])
        let range = NSRange(workflow.startIndex..., in: workflow)
        let matches = regex.matches(in: workflow, range: range)

        XCTAssertEqual(
            matches.count, 1,
            "expected exactly one `swift:` matrix in sdk-ci-swift.yml; a second would mean "
                + "this test only checks one of them"
        )
        guard let first = matches.first, let captured = Range(first.range(at: 1), in: workflow) else {
            return []
        }
        return workflow[captured]
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: CharacterSet(charactersIn: " '\"")) }
            .filter { !$0.isEmpty }
    }

    /// The `container: swift:X.Y-…` image a single-job workflow runs in.
    private func containerSwift(_ workflow: String) throws -> String? {
        let pattern = #"^\s*container:\s*swift:([0-9]+\.[0-9]+)-"#
        let regex = try NSRegularExpression(pattern: pattern, options: [.anchorsMatchLines])
        let range = NSRange(workflow.startIndex..., in: workflow)
        guard let match = regex.firstMatch(in: workflow, range: range),
              let captured = Range(match.range(at: 1), in: workflow) else { return nil }
        return String(workflow[captured])
    }

    /// `"6.2"` → `[6, 2]`, so versions compare numerically rather than as strings.
    private func numeric(_ version: String) -> [Int] {
        version.split(separator: ".").map { Int($0) ?? 0 }
    }

    // MARK: - The policy

    /// `SupportedVersions.minimumSwiftToolsVersion` matches what `Package.swift` declares.
    ///
    /// It is the only part of the floor a consumer can read, so a stale value would report
    /// a minimum SwiftPM does not enforce.
    func testMinimumToolsVersionConstantMatchesTheManifest() throws {
        let declared = try toolsVersion(of: try read("Package.swift"))
        XCTAssertEqual(
            SupportedVersions.minimumSwiftToolsVersion, declared,
            "SupportedVersions.minimumSwiftToolsVersion has drifted from Package.swift"
        )
    }

    /// No version-specific manifest (`Package@swift-X.Y.swift`) exists.
    ///
    /// SwiftPM selects such a file purely by filename on every toolchain at or above the
    /// version it names, and then ignores `Package.swift` entirely. With the floor at 6.2,
    /// a leftover `Package@swift-6.0.swift` would be the manifest *every* supported
    /// toolchain reads, and edits to `Package.swift` would silently stop mattering.
    func testNoVersionSpecificManifestShadowsPackageSwift() throws {
        let entries = try FileManager.default.contentsOfDirectory(atPath: try repoRoot().path)
        let shadows = entries.filter { $0.hasPrefix("Package@swift-") && $0.hasSuffix(".swift") }
        XCTAssertEqual(
            shadows, [],
            "version-specific manifests \(shadows) would shadow Package.swift — the package "
                + "has a single manifest since the floor moved to 6.2"
        )
    }

    /// The floor is a Swift 6 toolchain, so `.swiftLanguageMode` is available to the
    /// one manifest and no version-specific manifest is needed to carry it.
    func testFloorIsASwiftSixToolsVersion() throws {
        let declared = try toolsVersion(of: try read("Package.swift"))
        XCTAssertGreaterThanOrEqual(
            numeric(declared).first ?? 0, 6,
            "Package.swift declares tools-version \(declared); `.swiftLanguageMode` needs 6.0"
        )
    }

    /// EVERY target in the manifest turns on Swift 6 language mode — no exceptions.
    ///
    /// Pinning the count matters in both directions. Too few settings and some target has
    /// silently dropped to Swift 5 mode — green, and testing nothing it was added to test.
    /// Too many is not possible with an equality check, which is the point of writing it
    /// as one.
    func testEveryTargetUsesSwiftSixLanguageMode() throws {
        let manifest = try read("Package.swift")

        let targetCount = manifest.components(separatedBy: ".target(").count - 1
            + manifest.components(separatedBy: ".testTarget(").count - 1
            + manifest.components(separatedBy: ".executableTarget(").count - 1
        let settingsCount = manifest.components(separatedBy: ".swiftLanguageMode(.v6)").count - 1

        XCTAssertGreaterThan(targetCount, 1, "the manifest declares no targets")
        XCTAssertEqual(
            settingsCount, targetCount,
            "\(targetCount) targets and \(settingsCount) language-mode settings — every "
                + "target must carry `.swiftLanguageMode(.v6)`"
        )
        XCTAssertFalse(
            manifest.contains(".swiftLanguageMode(.v5)"),
            "a target has been pinned back to Swift 5 language mode. If the suite stopped "
                + "compiling under Swift 6, fix the site rather than the mode — the whole "
                + "package is migrated and dropping one target hides the regression"
        )
    }

    /// The two targets it would be easiest to get wrong — the library and the test
    /// target — each carry the mode by name.
    ///
    /// The count above is satisfied by any arrangement that totals correctly, so it
    /// would not notice the mode moving off the library and onto a second copy
    /// somewhere else.
    func testTheLibraryAndTestTargetsBothCarrySwiftSixMode() throws {
        let manifest = try read("Package.swift")

        guard let testStart = manifest.range(of: ".testTarget("),
              let nextTarget = manifest.range(
                  of: ".executableTarget(", range: testStart.upperBound..<manifest.endIndex)
        else {
            return XCTFail("could not locate the test target stanza in Package.swift")
        }

        let testStanza = manifest[testStart.lowerBound..<nextTarget.lowerBound]
        XCTAssertTrue(
            testStanza.contains(".swiftLanguageMode(.v6)"),
            "the test target has lost the Swift 6 language mode. Note that DELETING the "
                + "setting is not what reverting looks like: under tools-version 6.x, Swift 6 "
                + "is the DEFAULT, so an absent setting still means `.v6`. Only an explicit "
                + "`.v5` opts out, and this suite does not need one"
        )

        // The library target is the first `.target(` in the file, and it must have it.
        guard let libStart = manifest.range(of: ".target(\n            name: \"AxiamSDK\"") else {
            return XCTFail("could not locate the AxiamSDK library target")
        }
        let libStanza = manifest[libStart.lowerBound..<testStart.lowerBound]
        XCTAssertTrue(
            libStanza.contains(".swiftLanguageMode(.v6)"),
            "the AxiamSDK library target has lost the Swift 6 language mode — the one target "
                + "that most needs it, since it is what consumers actually get"
        )
    }

    /// The coverage and docs workflows run a toolchain inside the supported range.
    ///
    /// They are not part of the gating matrix, but a container below the floor cannot
    /// resolve the package at all, and one above the newest leg measures a build nobody
    /// has gated.
    func testAuxiliaryWorkflowsRunASupportedToolchain() throws {
        let floor = numeric(SupportedVersions.minimumSwiftToolsVersion)
        let newest = numeric(SupportedVersions.newestTestedSwift)
        for file in ["coverage.yml", "docs.yml"] {
            let workflow = try read(".github/workflows/\(file)")
            guard let image = try containerSwift(workflow) else {
                XCTFail("\(file) declares no `container: swift:X.Y-…` image")
                continue
            }
            let v = numeric(image)
            XCTAssertTrue(
                v.lexicographicallyPrecedes(floor) == false && newest.lexicographicallyPrecedes(v) == false,
                "\(file) runs Swift \(image), outside the supported "
                    + "\(SupportedVersions.minimumSwiftToolsVersion)–\(SupportedVersions.newestTestedSwift) range"
            )
        }
    }

    /// The gating matrix is the floor and the newest, and the floor is the declared one.
    func testCiMatrixIsFloorAndNewest() throws {
        let matrix = try ciMatrix(try read(".github/workflows/sdk-ci-swift.yml"))
        XCTAssertEqual(matrix.count, 2, "expected exactly 2 CI legs, got \(matrix)")
        XCTAssertEqual(
            matrix.first, SupportedVersions.minimumSwiftToolsVersion,
            "the lower CI leg is not the declared tools-version floor"
        )
        XCTAssertEqual(
            matrix.last, SupportedVersions.newestTestedSwift,
            "the upper CI leg does not match SupportedVersions.newestTestedSwift"
        )
    }

    /// The newest leg is a Swift 6 toolchain.
    ///
    /// Implied by the floor today, but asserted on its own so a matrix edit that drops
    /// the newest leg below 6 cannot pass on the strength of the floor check alone.
    func testTheNewestLegIsASwiftSixToolchain() throws {
        let newest = SupportedVersions.newestTestedSwift
        let major = Int(newest.split(separator: ".").first.map(String.init) ?? "0") ?? 0
        XCTAssertGreaterThanOrEqual(
            major, 6,
            "the newest CI leg is Swift \(newest); Swift 6 language mode needs a 6.x toolchain"
        )
    }

    /// The LIBRARY really was compiled in Swift 6 language mode.
    ///
    /// ``SupportedVersions/isSwiftSixLanguageMode`` is evaluated in the *library*, so
    /// reading it from here crosses the boundary and reports what the shipping target
    /// actually got — something no amount of reading the manifest can establish, since
    /// the manifest could be right and the setting still not applied. The floor is a 6.x
    /// toolchain, so there is no Swift 5 branch left to accept.
    func testLibraryIsCompiledInSwiftSixMode() throws {
        XCTAssertTrue(
            SupportedVersions.isSwiftSixLanguageMode,
            "the library reports Swift 5 language mode — its `.swiftLanguageMode(.v6)` "
                + "setting in Package.swift did not reach the library target"
        )
    }

    /// THIS TARGET really was compiled in Swift 6 language mode.
    ///
    /// The manifest assertions above read a file; this one reads the compiler. Reverting
    /// the test target to `.v5` leaves the string checks to catch it, but only this can
    /// tell whether the setting was applied. `#if swift(>=6.0)` tests the language mode,
    /// not the toolchain (`#if compiler(>=6.0)` does that).
    func testTheSuiteItselfIsCompiledInSwiftSixMode() throws {
        var languageModeIsSix = false
        #if swift(>=6.0)
        languageModeIsSix = true
        #endif
        XCTAssertTrue(
            languageModeIsSix,
            "this test target was compiled in Swift 5 language mode — it has been pinned "
                + "back to .v5"
        )
    }
}
