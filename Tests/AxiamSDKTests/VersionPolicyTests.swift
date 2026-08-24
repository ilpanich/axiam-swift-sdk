import XCTest
import Foundation
@testable import AxiamSDK

/// Language-version support policy, and the parity of the two package manifests.
///
/// This SDK declares which Swift versions it supports in four places that nothing
/// compares:
///
/// - `swift-tools-version` in `Package.swift` — the floor. A toolchain older than this
///   refuses to resolve the package at all.
/// - `swift-tools-version` in `Package@swift-6.0.swift` — the version-specific manifest,
///   which SwiftPM selects automatically on any 6.0+ toolchain and which is what turns on
///   Swift 6 language mode for this package's own targets.
/// - the `swift` matrix in `.github/workflows/sdk-ci-swift.yml` — the only declaration
///   that is ever compiled.
/// - ``SupportedVersions`` — the only one a consumer can read.
///
/// The two manifests are the fragile part. They describe the same package and must stay
/// identical apart from the `swiftSettings` that carry the language mode — but SwiftPM has
/// no include mechanism, so the duplication is structural and nothing but a test can hold
/// them together. A target added to one and not the other produces a package that builds
/// on one toolchain and fails on the other, which is precisely the class of bug the
/// version-specific manifest exists to avoid.
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

    /// The `swift: ['5.9', '6.3']` list from the CI build matrix.
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

    /// Every target name a manifest declares, in order.
    private func targetNames(_ manifest: String) throws -> [String] {
        let pattern = #"name:\s*"([A-Za-z0-9_]+)""#
        let regex = try NSRegularExpression(pattern: pattern, options: [])
        let range = NSRange(manifest.startIndex..., in: manifest)
        return regex.matches(in: manifest, range: range).compactMap {
            Range($0.range(at: 1), in: manifest).map { r in String(manifest[r]) }
        }
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

    /// The version-specific manifest declares the tools version its filename promises.
    ///
    /// `Package@swift-6.0.swift` is selected by SwiftPM purely on the filename. If the
    /// tools-version inside it were lower, the file would be selected and then quietly
    /// build without the language mode it exists to enable.
    func testVersionSpecificManifestDeclaresToolsVersionSix() throws {
        let declared = try toolsVersion(of: try read("Package@swift-6.0.swift"))
        XCTAssertEqual(
            declared, "6.0",
            "Package@swift-6.0.swift must declare swift-tools-version 6.0 — the filename "
                + "selects it, but only the declared version unlocks .swiftLanguageMode"
        )
    }

    /// Every SHIPPING target in the 6.0 manifest turns on Swift 6 language mode.
    ///
    /// Exactly one target is excluded, and only one: the test target. The library and
    /// all the examples compile clean under Swift 6; the test harness does not, in 48
    /// places that are all `NSLock` in async test doubles, `[String: Any]` fixtures
    /// captured in `@Sendable` handler closures, and fixtures held as statics.
    ///
    /// Pinning the count both ways matters. Too few settings and a shipping target has
    /// silently dropped to Swift 5 mode on a Swift 6 toolchain — green, and testing
    /// nothing it was added to test. Too many and someone has put the mode back on the
    /// test target without doing the migration, which turns the whole leg red for
    /// reasons unrelated to the SDK.
    func testEveryShippingTargetUsesSwiftSixLanguageMode() throws {
        let manifest = try read("Package@swift-6.0.swift")

        let targetCount = manifest.components(separatedBy: ".target(").count - 1
            + manifest.components(separatedBy: ".testTarget(").count - 1
            + manifest.components(separatedBy: ".executableTarget(").count - 1
        let settingsCount = manifest.components(separatedBy: ".swiftLanguageMode(.v6)").count - 1

        XCTAssertGreaterThan(targetCount, 1, "the 6.0 manifest declares no targets")
        XCTAssertEqual(
            settingsCount, targetCount - 1,
            "\(targetCount) targets and \(settingsCount) language-mode settings — expected "
                + "every target except the test one to carry it"
        )
    }

    /// The excluded target is the test target, and nothing else.
    ///
    /// The count above would be equally satisfied by putting the mode on the test
    /// target and dropping it from the library, which is the exact inversion of what
    /// this package wants.
    func testTheTargetWithoutSwiftSixModeIsTheTestTarget() throws {
        let manifest = try read("Package@swift-6.0.swift")

        guard let testStart = manifest.range(of: ".testTarget("),
              let nextTarget = manifest.range(
                  of: ".executableTarget(", range: testStart.upperBound..<manifest.endIndex)
        else {
            return XCTFail("could not locate the test target stanza in the 6.0 manifest")
        }

        let testStanza = manifest[testStart.lowerBound..<nextTarget.lowerBound]
        XCTAssertFalse(
            testStanza.contains(".swiftLanguageMode(.v6)"),
            "the test target carries the Swift 6 language mode, but the suite has not been "
                + "migrated for it — expect ~48 strict-concurrency errors"
        )

        // Absence is NOT an opt-out, and this is the assertion that says so.
        //
        // Under swift-tools-version 6.0, Swift 6 is the DEFAULT language mode for every
        // target. Simply omitting the setting leaves the target at that default, which
        // is the opposite of what deleting it looks like it does. This cost a CI round
        // to learn: the test target was still compiled in Swift 6 mode, and still
        // failing, after its `.v6` setting had been removed.
        XCTAssertTrue(
            testStanza.contains(".swiftLanguageMode(.v5)"),
            "the test target does not explicitly declare Swift 5 language mode. Under "
                + "tools-version 6.0 that means it gets Swift 6 by default, and the suite "
                + "has not been migrated for it — opting out has to be explicit"
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

    /// The two manifests describe the same package.
    ///
    /// SwiftPM has no include mechanism, so the duplication is unavoidable; this is what
    /// keeps it honest. A target present in one and not the other builds on one toolchain
    /// and fails on the other.
    func testBothManifestsDeclareTheSameTargets() throws {
        let five = try targetNames(try read("Package.swift"))
        let six = try targetNames(try read("Package@swift-6.0.swift"))
        XCTAssertEqual(
            five, six,
            "Package.swift and Package@swift-6.0.swift declare different targets — they "
                + "must stay identical apart from swiftSettings"
        )
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

    /// The newest leg is a Swift 6 toolchain, so the 6.0 manifest is exercised at all.
    ///
    /// Without this, both legs could sit on 5.x and `Package@swift-6.0.swift` would never
    /// be selected by anything — an entire file, and the language mode it carries, dead.
    func testTheNewestLegSelectsTheVersionSpecificManifest() throws {
        let newest = SupportedVersions.newestTestedSwift
        let major = Int(newest.split(separator: ".").first.map(String.init) ?? "0") ?? 0
        XCTAssertGreaterThanOrEqual(
            major, 6,
            "the newest CI leg is Swift \(newest), so Package@swift-6.0.swift is never "
                + "selected and Swift 6 language mode is never compiled"
        )
    }

    /// On a Swift 6 toolchain, the LIBRARY really was compiled in Swift 6 language mode.
    ///
    /// This is the assertion that catches a silent fallback, and it works because the two
    /// directives mean different things: `#if compiler(>=6.0)` tests the **toolchain**,
    /// `#if swift(>=6.0)` tests the **language mode**. They deliberately disagree inside
    /// this file — on the 6.3 leg the toolchain is 6.x while this test target is still
    /// compiled in Swift 5 mode, so only the compiler check is true here.
    ///
    /// ``SupportedVersions/isSwiftSixLanguageMode`` is evaluated in the *library*, which
    /// does get the mode. So reading it from here crosses the boundary and reports what
    /// the shipping target actually got — something no amount of reading the manifest can
    /// establish, since the manifest could be right and the setting still not applied.
    func testLibraryIsCompiledInSwiftSixModeOnASixToolchain() throws {
        #if compiler(>=6.0)
        XCTAssertTrue(
            SupportedVersions.isSwiftSixLanguageMode,
            "a Swift 6 toolchain is in use, but the library reports Swift 5 language mode — "
                + "Package@swift-6.0.swift was not selected, or its swiftSettings did not "
                + "reach the library target"
        )
        #else
        XCTAssertFalse(
            SupportedVersions.isSwiftSixLanguageMode,
            "the library reports Swift 6 language mode on a Swift 5 toolchain, which should "
                + "not be reachable"
        )
        // A 5.x toolchain must be at or above the declared floor, or resolution would have
        // failed before reaching a test.
        XCTAssertEqual(
            SupportedVersions.minimumSwiftToolsVersion.split(separator: ".").first.map(String.init),
            "5",
            "running a Swift 5 toolchain but the declared floor is not 5.x"
        )
        #endif
    }
}
