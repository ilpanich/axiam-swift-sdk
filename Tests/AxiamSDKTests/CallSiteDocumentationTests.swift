import XCTest

/// Call-site documentation the contract makes an SDK repeat where a caller reads it (R-29,
/// SW-14, SW-15). The generated sources are read as text: what is asserted is the doc comment
/// a developer sees at the declaration, which no behavioural test can observe.
///
/// The comments come from `Scripts/gen_management.py`; CI's drift check keeps the committed
/// files equal to its output, so a note dropped from the generator fails here too.
final class CallSiteDocumentationTests: XCTestCase {

    private func generated(_ file: String) throws -> String {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()  // AxiamSDKTests
            .deletingLastPathComponent()  // Tests
            .deletingLastPathComponent()  // repository root
        return try String(
            contentsOf: root.appendingPathComponent("Sources/AxiamSDK/Management/Generated/\(file)"),
            encoding: .utf8)
    }

    /// The `///` block directly above the first line of `source` (after `after`) that starts
    /// with `declaration`, joined into one string.
    private func docComment(
        _ source: String, before declaration: String, after anchor: String? = nil
    ) throws -> String {
        var lines = source.components(separatedBy: "\n")
        if let anchor {
            let start = try XCTUnwrap(
                lines.firstIndex { $0.contains(anchor) }, "anchor \(anchor) not found")
            lines = Array(lines[start...])
        }
        let index = try XCTUnwrap(
            lines.firstIndex { $0.trimmingCharacters(in: .whitespaces).hasPrefix(declaration) },
            "\(declaration) not found")
        var doc: [String] = []
        var cursor = index - 1
        while cursor >= 0 {
            let line = lines[cursor].trimmingCharacters(in: .whitespaces)
            guard line.hasPrefix("///") else { break }
            doc.insert(String(line.dropFirst(3)).trimmingCharacters(in: .whitespaces), at: 0)
            cursor -= 1
        }
        return doc.joined(separator: " ")
    }

    /// §31.3 rule 2: "An SDK MUST document the rule at **both** call sites" — `create` as well
    /// as `update`.
    func testScimTargetsCreateStatesThatTheCredentialIsBoundToItsURL() throws {
        let source = try generated("ManagementNamespaces.swift")
        for (method, label) in [
            ("public func create(body: ScimTargetInput)", "create"),
            ("public func update(", "update"),
        ] {
            let doc = try docComment(
                source, before: method, after: "public struct ScimTargetsApi")
            XCTAssertTrue(doc.contains("bound to its URL"), "\(label): the rule is not stated")
            XCTAssertTrue(doc.contains("§31.3 rule 2"), "\(label): the rule is not cited")
            for moved in ["baseURL", "auth.token_url", "auth.type"] {
                XCTAssertTrue(doc.contains(moved), "\(label): \(moved) is not named")
            }
        }
    }

    /// §29.3 rule 2: the ECDSA / HTTP-Redirect caveat "where it documents the field" — on
    /// `spSigningCertPEM` of the input and of the read, not only on the methods.
    func testTheSpSigningCertificateFieldCarriesTheEcdsaNote() throws {
        let source = try generated("ManagementModels.swift")
        for (type, declaration) in [
            ("public struct SamlServiceProviderInput", "public var spSigningCertPEM"),
            ("public struct SamlServiceProvider:", "public let spSigningCertPEM"),
        ] {
            let doc = try docComment(source, before: declaration, after: type)
            XCTAssertTrue(doc.contains("HTTP-POST"), "\(type): the ECDSA note is missing")
            XCTAssertTrue(doc.contains("RSA-only"), "\(type): the HTTP-Redirect note is missing")
            XCTAssertTrue(doc.contains("§29.3 rule 2"), "\(type): the rule is not cited")
        }
    }
}
