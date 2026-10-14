import XCTest
@testable import AxiamSDK

/// Contract 1.61's `Certificate.user_id` (§34.5, §27.11 rule 5): an optional, nullable member of
/// every `Certificate` read, and an optional request member of `certificates.generate` and
/// `certificates.sign_csr`. The SSF half of 1.61 (`SsfStreamInput.expected_updated_at`, §32.8
/// test 1) is in `SsfManagementTests`. `CibaPendingList` (§33.3 rule 16) is not modelled: no
/// registry operation returns it and this SDK drives no console route.
final class Contract161ManagementTests: XCTestCase {

    private static let userID = "66666666-6666-4666-8666-666666666666"

    private static func json(_ object: [String: Any]) -> String {
        String(decoding: try! JSONSerialization.data(withJSONObject: object), as: UTF8.self)
    }

    private static func certificateObject(_ extra: [String: Any] = [:]) -> [String: Any] {
        var body: [String: Any] = [
            "cert_type": "User",
            "created_at": "2026-10-10T00:00:00Z",
            "fingerprint": "aa:bb",
            "id": UUID().uuidString.lowercased(),
            "issuer_ca_id": UUID().uuidString.lowercased(),
            "key_algorithm": "Ed25519",
            "metadata": [String: Any](),
            "not_after": "2027-10-10T00:00:00Z",
            "not_before": "2026-10-10T00:00:00Z",
            "public_cert_pem": "pem",
            "status": "Active",
            "subject": "CN=ada",
            "tenant_id": ManagementFixture.tenantID,
        ]
        for (key, value) in extra { body[key] = value }
        return body
    }

    private static func generateRequest(userID: String?) -> CreateCertificateRequest {
        CreateCertificateRequest(
            certType: .user,
            issuerCAID: UUID().uuidString.lowercased(),
            keyAlgorithm: .ed25519,
            subject: "CN=ada",
            userID: userID,
            validityDays: 30)
    }

    private static func signRequest(userID: String?) -> SignCertificateCsrRequest {
        SignCertificateCsrRequest(
            certType: .user,
            csrPEM: "-----BEGIN CERTIFICATE REQUEST-----",
            issuerCAID: UUID().uuidString.lowercased(),
            userID: userID,
            validityDays: 30)
    }

    func testGenerateSendsUserIDExactlyAsGivenAndOmitsTheKeyWithoutOne() async throws {
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 200, body: Self.json(Self.certificateObject(
                ["private_key_pem": "k", "user_id": Self.userID]))),
            (status: 200, body: Self.json(Self.certificateObject(["private_key_pem": "k"]))),
            (status: 200, body: Self.json(Self.certificateObject(["private_key_pem": "k"]))),
        ])

        let named = try await client.certificates.generate(body: Self.generateRequest(userID: Self.userID))
        XCTAssertEqual(transport.last?.method, "POST")
        XCTAssertEqual(transport.last?.jsonBody?["user_id"] as? String, Self.userID)
        XCTAssertEqual(named.userID, Self.userID)

        // Not judged client-side: the server answers 400 for what it refuses.
        _ = try await client.certificates.generate(body: Self.generateRequest(userID: "not-a-uuid"))
        XCTAssertEqual(transport.last?.jsonBody?["user_id"] as? String, "not-a-uuid")

        // Unset: no `user_id` key at all, and in particular not `null`.
        let unnamed = try await client.certificates.generate(body: Self.generateRequest(userID: nil))
        let sent = try XCTUnwrap(transport.last?.jsonBody)
        XCTAssertNil(sent["user_id"])
        XCTAssertFalse(sent.keys.contains("user_id"), "the key is omitted, not null")
        XCTAssertNil(unnamed.userID)
    }

    func testSignCSRSendsUserIDExactlyAsGivenAndOmitsTheKeyWithoutOne() async throws {
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 200, body: Self.json(Self.certificateObject(["user_id": Self.userID]))),
            (status: 200, body: Self.json(Self.certificateObject(["user_id": NSNull()]))),
        ])

        let named = try await client.certificates.signCSR(body: Self.signRequest(userID: Self.userID))
        XCTAssertEqual(transport.last?.path, "/api/v1/certificates/sign-csr")
        XCTAssertEqual(transport.last?.jsonBody?["user_id"] as? String, Self.userID)
        XCTAssertEqual(named.userID, Self.userID)

        let unnamed = try await client.certificates.signCSR(body: Self.signRequest(userID: nil))
        let sent = try XCTUnwrap(transport.last?.jsonBody)
        XCTAssertFalse(sent.keys.contains("user_id"), "the key is omitted, not null")
        XCTAssertNil(unnamed.userID)
    }

    /// A `Certificate` body carrying a UUID, one carrying `null` and one lacking the member each
    /// decode, and the last two give "no account named" — never a nil UUID, and never a value
    /// taken from `metadata` or the subject.
    func testACertificateDecodesAUUIDANullAndAnAbsentUserID() async throws {
        let decoder = JSONDecoder()
        func decode(_ object: [String: Any]) throws -> Certificate {
            try decoder.decode(Certificate.self, from: Data(Self.json(object).utf8))
        }
        XCTAssertEqual(try decode(Self.certificateObject(["user_id": Self.userID])).userID, Self.userID)
        XCTAssertNil(try decode(Self.certificateObject(
            ["user_id": NSNull(), "metadata": ["user_id": Self.userID]])).userID)
        XCTAssertNil(try decode(Self.certificateObject()).userID)

        // The same through the wire on `get`, and on a list page whose items differ.
        let (client, _) = try await ManagementFixture.signedIn([
            (status: 200, body: Self.json(Self.certificateObject(["user_id": NSNull()]))),
            (status: 200, body: Self.json([
                "items": [Self.certificateObject(["user_id": Self.userID]), Self.certificateObject()],
                "total": 2, "offset": 0, "limit": 50,
            ])),
        ])
        let one = try await client.certificates.get(id: UUID().uuidString.lowercased())
        XCTAssertNil(one.userID)
        let page = try await client.certificates.list()
        XCTAssertEqual(page.items.count, 2)
        XCTAssertEqual(page.items[0].userID, Self.userID)
        XCTAssertNil(page.items[1].userID)
    }
}
