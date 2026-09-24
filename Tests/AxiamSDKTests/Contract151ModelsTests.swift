import XCTest
@testable import AxiamSDK

/// CONTRACT.md §27.13 — the two generator defects C-1 EXECUTED item 2 names ("every
/// generator ported so far got both wrong"), pinned directly against the generated
/// types, plus the third open-decoding rule S-7 rule 2 restates for `cert_type`.
///
/// Mirrors `axiam-rust-sdk`'s `tests/contract_151_models_test.rs`.
final class Contract151ModelsTests: XCTestCase {

    // MARK: - SubjectAltName (§27.13 S-7 rule 1)

    /// The wire shape is externally tagged: `{"dns": "..."}` or `{"ip": "..."}`, never
    /// `{}`. The pre-fix generator emitted an EMPTY struct for `oneOf` schemas it did not
    /// otherwise recognise, which decodes anything and encodes as `{}` on every case —
    /// indistinguishable from every other case and from no name at all.
    func testSubjectAltNameDecodesDnsAndIp() throws {
        let dns = try JSONDecoder().decode(SubjectAltName.self, from: Data(#"{"dns":"api.example.internal"}"#.utf8))
        XCTAssertEqual(dns, .dns("api.example.internal"))

        let ip = try JSONDecoder().decode(SubjectAltName.self, from: Data(#"{"ip":"10.0.0.5"}"#.utf8))
        XCTAssertEqual(ip, .ip("10.0.0.5"))
    }

    /// **The fix, pinned exactly.** Encoding produces exactly ONE key — `dns` or `ip` —
    /// never `{}` and never both. Asserted on the actual serialized JSON object's key
    /// set, not merely that decode-then-encode round-trips (an empty struct round-trips
    /// `{}` to `{}` perfectly well and would still pass a looser assertion).
    func testSubjectAltNameEncodesExactlyOneKeyNeverAnEmptyObject() throws {
        let dnsData = try JSONEncoder().encode(SubjectAltName.dns("api.lakeside.internal"))
        let dnsObject = try XCTUnwrap(JSONSerialization.jsonObject(with: dnsData) as? [String: Any])
        XCTAssertEqual(Set(dnsObject.keys), ["dns"])
        XCTAssertEqual(dnsObject["dns"] as? String, "api.lakeside.internal")

        let ipData = try JSONEncoder().encode(SubjectAltName.ip("10.0.0.5"))
        let ipObject = try XCTUnwrap(JSONSerialization.jsonObject(with: ipData) as? [String: Any])
        XCTAssertEqual(Set(ipObject.keys), ["ip"])
    }

    /// An array of mixed variants — the actual shape `CreateCertificateRequest.subjectAltNames`
    /// carries — round-trips key-for-key.
    func testSubjectAltNameArrayRoundTrips() throws {
        let names: [SubjectAltName] = [.dns("api.lakeside.internal"), .ip("10.0.0.5")]
        let data = try JSONEncoder().encode(names)
        let decoded = try JSONDecoder().decode([SubjectAltName].self, from: data)
        XCTAssertEqual(decoded, names)
    }

    /// A `CreateCertificateRequest` carrying `subjectAltNames` sends them on the wire in
    /// the externally-tagged shape, and the field is omitted (never `null`/`[]`) when unset.
    func testCreateCertificateRequestSubjectAltNamesOnTheWire() throws {
        let withNames = CreateCertificateRequest(
            certType: .server, issuerCAID: "ca-1", keyAlgorithm: .ed25519,
            subject: "CN=api", subjectAltNames: [.dns("api.example.internal")], validityDays: 365)
        let data = try JSONEncoder().encode(withNames)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        let sans = try XCTUnwrap(object["subject_alt_names"] as? [[String: Any]])
        XCTAssertEqual(sans.count, 1)
        XCTAssertEqual(sans[0]["dns"] as? String, "api.example.internal")

        let withoutNames = CreateCertificateRequest(
            certType: .device, issuerCAID: "ca-1", keyAlgorithm: .ed25519,
            subject: "CN=device-1", validityDays: 365)
        let data2 = try JSONEncoder().encode(withoutNames)
        let object2 = try XCTUnwrap(JSONSerialization.jsonObject(with: data2) as? [String: Any])
        XCTAssertNil(object2["subject_alt_names"], "an unset subjectAltNames must be OMITTED, never null or []")
    }

    // MARK: - `inherit` on the role-side listings (§27.13 S-10 rule 3)

    /// **The fix, pinned exactly.** A role-side listing (`RoleGroupAssignment`) whose
    /// `inherit` key is ABSENT — what a pre-1.51 server sends, and what the schema's own
    /// "required" marking would otherwise make a naive `Bool` decode THROW on — decodes
    /// successfully and reads as `true` through `inherits`, never `false` and never a
    /// decode failure.
    func testRoleGroupAssignmentWithNoInheritKeyDecodesAndInheritsIsTrue() throws {
        let json = Data(#"{"group":{"id":"g-1","name":"editors","description":"","metadata":{},"tenant_id":"t-1","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}}"#.utf8)
        let decoded = try JSONDecoder().decode(RoleGroupAssignment.self, from: json)
        XCTAssertNil(decoded.inherit, "the raw field is nil when absent — never silently false")
        XCTAssertTrue(decoded.inherits, "absent MUST read as true (§27.13 S-10 rule 3)")
    }

    /// The I4 twin: an EXPLICIT `false` is read as `false`, not overridden by the
    /// absent-means-true rule.
    func testRoleGroupAssignmentWithExplicitFalseInheritReadsFalse() throws {
        let json = Data(#"{"group":{"id":"g-1","name":"editors","description":"","metadata":{},"tenant_id":"t-1","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"},"inherit":false}"#.utf8)
        let decoded = try JSONDecoder().decode(RoleGroupAssignment.self, from: json)
        XCTAssertEqual(decoded.inherit, false)
        XCTAssertFalse(decoded.inherits)
    }

    /// The subject-side listing (`RoleAssignment`, returned by `groups.listRoles` etc.)
    /// carries the SAME optional shape and the same `inherits` convenience.
    func testRoleAssignmentWithNoInheritKeyInheritsIsTrue() throws {
        let json = Data(#"{"role":{"id":"r-1","name":"editor","description":"","is_global":false,"tenant_id":"t-1","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}}"#.utf8)
        let decoded = try JSONDecoder().decode(RoleAssignment.self, from: json)
        XCTAssertNil(decoded.inherit)
        XCTAssertTrue(decoded.inherits)
    }

    // MARK: - `cert_type: "Server"` decodes openly (§27.13 S-7 rule 2)

    /// `CertificateType` is an OPEN enum (§27.11 rule 1's discipline, restated for S-7):
    /// `"Server"` — new in contract 1.51 — decodes to its own case now that the spec is
    /// re-vendored, and a value this SDK's copy of the spec does NOT list still decodes
    /// to `.unknown` rather than failing the whole response.
    func testCertificateTypeServerDecodesToItsOwnCase() throws {
        let decoded = try JSONDecoder().decode(CertificateType.self, from: Data(#""Server""#.utf8))
        XCTAssertEqual(decoded, .server)
    }

    /// **Open decoding, pinned.** A value not in this SDK's copy of the spec decodes to
    /// `.unknown` rather than throwing — so one unrecognised `cert_type` in a
    /// `certificates.list` page does not fail the whole page, including every OTHER
    /// record the caller did ask for.
    func testAnUnknownCertTypeDecodesOpenlyInsteadOfFailing() throws {
        let decoded = try JSONDecoder().decode(CertificateType.self, from: Data(#""FutureType""#.utf8))
        XCTAssertEqual(decoded, .unknown)

        // The whole-page case: one unrecognised cert_type among two known ones.
        let page = Data(#"[{"cert_type":"User"},{"cert_type":"FutureType"},{"cert_type":"Server"}]"#.utf8)
        struct Row: Decodable { let cert_type: CertificateType }
        let rows = try JSONDecoder().decode([Row].self, from: page)
        XCTAssertEqual(rows.map(\.cert_type), [.user, .unknown, .server])
    }
}
