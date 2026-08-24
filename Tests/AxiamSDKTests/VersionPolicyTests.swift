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

    /// The 6.0 manifest actually turns on Swift 6 language mode, on every target.
    ///
    /// A target that lost its `swiftSettings` would compile in Swift 5 mode on a Swift 6
    /// toolchain — silently, and reporting green.
    func testEveryTargetInTheSixManifestUsesSwiftSixLanguageMode() throws {
        let manifest = try read("Package@swift-6.0.swift")
        let targetCount = manifest.components(separatedBy: ".target(").count - 1
            + manifest.components(separatedBy: ".testTarget(").count - 1
            + manifest.components(separatedBy: ".executableTarget(").count - 1
        let settingsCount = manifest.components(separatedBy: ".swiftLanguageMode(.v6)").count - 1

        XCTAssertGreaterThan(targetCount, 0, "the 6.0 manifest declares no targets")
        XCTAssertEqual(
            settingsCount, targetCount,
            "\(targetCount) targets but \(settingsCount) .swiftLanguageMode(.v6) settings — "
                + "a target without it compiles in Swift 5 mode on a Swift 6 toolchain"
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

    /// The compiler running this suite agrees with the manifest that was selected.
    ///
    /// Closes the loop from the inside: `#if swift(>=6.0)` reflects the toolchain actually
    /// in use, not a file anyone can edit.
    func testRunningCompilerMatchesTheSelectedManifest() throws {
        #if swift(>=6.0)
        // On a 6.x toolchain SwiftPM must have chosen the version-specific manifest, so
        // this code was compiled in Swift 6 language mode.
        XCTAssertGreaterThanOrEqual(
            Int(SupportedVersions.newestTestedSwift.split(separator: ".").first.map(String.init) ?? "0") ?? 0,
            6,
            "running a Swift 6 toolchain that SupportedVersions does not acknowledge"
        )
        #else
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
