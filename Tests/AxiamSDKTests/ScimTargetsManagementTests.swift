import XCTest
@testable import AxiamSDK

/// The `scim_targets` management namespace — CONTRACT.md §31.8's six required tests, plus the
/// read-modify-write helper.
///
/// The credential is generated at run time: a literal would be a credential in the repository
/// and would let a redaction test pass by coincidence.
final class ScimTargetsManagementTests: XCTestCase {

    private static let targetsPath = "/api/v1/scim-targets"

    private static func json(_ object: [String: Any]) -> String {
        String(decoding: try! JSONSerialization.data(withJSONObject: object), as: UTF8.self)
    }

    private static func credential() -> String { "scim-\(SecretKit.random())" }

    private static func targetObject(_ extra: [String: Any] = [:]) -> [String: Any] {
        var body: [String: Any] = [
            "id": UUID().uuidString.lowercased(),
            "tenant_id": ManagementFixture.tenantID,
            "name": "Downstream",
            "base_url": "https://idp.example/scim/v2",
            "enabled": true,
            "auth": ["type": "bearer"],
            "scope": ["type": "all_users"],
            "push_groups": false,
            "user_name_from": "username",
            "deprovision": "deactivate",
            "created_at": "2026-10-05T00:00:00Z",
            "updated_at": "2026-10-05T00:00:00Z",
            "state": [
                "last_success_at": NSNull(), "last_failure_at": NSNull(),
                "last_failure_reason": NSNull(), "consecutive_failures": 0,
                "dead_lettered_total": 0, "last_reconciled_at": NSNull(),
            ] as [String: Any],
        ]
        for (key, value) in extra { body[key] = value }
        return body
    }

    private static func input(credential: String?) -> ScimTargetInput {
        ScimTargetInput(
            auth: .bearer(),
            baseURL: "https://idp.example/scim/v2",
            credential: credential.map { Sensitive($0) },
            name: "Downstream",
            scope: .allUsers())
    }

    private static func encodedObject<T: Encodable>(_ value: T) throws -> [String: Any] {
        try XCTUnwrap(
            JSONSerialization.jsonObject(with: try JSONEncoder().encode(value)) as? [String: Any])
    }

    // MARK: - 1. Redaction

    func testTheCredentialIsOnTheWireAndInNoRendering() async throws {
        let credential = Self.credential()
        let body = Self.input(credential: credential)
        for rendering in SecretKit.renderings(body) {
            XCTAssertFalse(SecretKit.leaks(rendering, credential), "the credential leaked")
        }

        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 400, body: #"{"error": "validation_error", "message": "base_url: refused"}"#),
        ])
        do {
            _ = try await client.scimTargets.create(body: body)
            XCTFail("a 400 must surface")
        } catch {
            let rendering = SecretKit.renderings(error).joined(separator: "\n")
            XCTAssertFalse(SecretKit.leaks(rendering, credential), "the credential leaked into an error")
        }
        let sent = try XCTUnwrap(transport.last?.jsonBody)
        XCTAssertEqual(sent["credential"] as? String, credential, "but it is on the wire")
    }

    // MARK: - 2. No credential on the response

    func testACredentialInAResponseIsDropped() async throws {
        let leaked = Self.credential()
        let id = UUID().uuidString.lowercased()
        let (client, _) = try await ManagementFixture.signedIn([
            (status: 200, body: Self.json(Self.targetObject([
                "credential": leaked, "credential_set": true,
            ]))),
        ])

        let target = try await client.scimTargets.get(id: id)
        XCTAssertEqual(target.name, "Downstream")
        let reencoded = String(decoding: try JSONEncoder().encode(target), as: UTF8.self)
        for rendering in SecretKit.renderings(target) + [reencoded] {
            XCTAssertFalse(SecretKit.leaks(rendering, leaked), "a response credential was surfaced")
        }
        // `ScimTargetResponse` declares no credential member: naming one here would not
        // compile.
    }

    // MARK: - 3. Replacement and the omitted credential

    func testUpdateWithoutACredentialSendsNoKeyAndTheVariantsKeepTheirShape() async throws {
        let id = UUID().uuidString.lowercased()
        let credential = Self.credential()
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 200, body: Self.json(Self.targetObject())),
            (status: 200, body: Self.json(Self.targetObject())),
        ])

        _ = try await client.scimTargets.update(id: id, body: Self.input(credential: nil))
        _ = try await client.scimTargets.update(id: id, body: Self.input(credential: credential))

        let sent = transport.requests
        XCTAssertEqual(sent.map(\.method), ["PUT", "PUT"])
        XCTAssertEqual(sent.first?.path, "\(Self.targetsPath)/\(id)")
        let kept = try XCTUnwrap(sent[0].jsonBody)
        let replaced = try XCTUnwrap(sent[1].jsonBody)
        XCTAssertNil(kept["credential"], "no credential key")
        XCTAssertEqual(replaced["credential"] as? String, credential)
        // `name`, `baseURL`, `auth` and `scope` are non-optional initializer parameters: an
        // input without them does not compile.

        let bearer = try Self.encodedObject(ScimTargetAuth.bearer())
        XCTAssertEqual(Set(bearer.keys), ["type"])
        XCTAssertEqual(bearer["type"] as? String, "bearer")

        let clientCredentials = try Self.encodedObject(ScimTargetAuth.oauth2ClientCredentials(
            tokenURL: "https://idp.example/token", clientID: "axiam", scope: "scim"))
        XCTAssertEqual(Set(clientCredentials.keys), ["type", "client_id", "scope", "token_url"])
        XCTAssertEqual(clientCredentials["type"] as? String, "oauth2_client_credentials")
        XCTAssertEqual(clientCredentials["client_id"] as? String, "axiam")
        XCTAssertEqual(clientCredentials["scope"] as? String, "scim")
        XCTAssertEqual(clientCredentials["token_url"] as? String, "https://idp.example/token")

        let allUsers = try Self.encodedObject(ScimTargetScope.allUsers())
        XCTAssertEqual(Set(allUsers.keys), ["type"])
        XCTAssertEqual(allUsers["type"] as? String, "all_users")

        let group = UUID().uuidString.lowercased()
        let groups = try Self.encodedObject(ScimTargetScope.groups([group]))
        XCTAssertEqual(Set(groups.keys), ["type", "group_ids"])
        XCTAssertEqual(groups["type"] as? String, "groups")
        XCTAssertEqual(groups["group_ids"] as? [String], [group])
    }

    // MARK: - 4. Open decoding and pagination

    func testUnknownValuesDecodeAndTheWalkCarriesSearch() async throws {
        let odd = Self.targetObject([
            "auth": ["type": "mtls", "certificate_id": UUID().uuidString.lowercased()],
            "deprovision": "archive",
            "user_name_from": "employee_number",
            "state": NSNull(),
        ])
        let failing = Self.targetObject([
            "state": [
                "last_success_at": NSNull(), "last_failure_at": "2026-10-05T01:00:00Z",
                "last_failure_reason": "a reason this SDK has never seen",
                "consecutive_failures": 3, "dead_lettered_total": 1,
                "last_reconciled_at": NSNull(),
            ] as [String: Any],
        ])
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 200, body: Self.json(["items": [odd], "total": 2, "offset": 0, "limit": 1])),
            (status: 200, body: Self.json(["items": [failing], "total": 2, "offset": 1, "limit": 1])),
            (status: 200, body: Self.json(["items": [Any](), "total": 2, "offset": 2, "limit": 1])),
        ])

        var request = PageRequest(offset: 0, limit: 1, search: "downstream")
        var all: [ScimTargetResponse] = []
        while true {
            let page = try await client.scimTargets.list(page: request)
            XCTAssertEqual(page.total, 2)
            if page.isEmpty { break }
            all.append(contentsOf: page.items)
            request = page.nextRequest
        }
        XCTAssertEqual(all.count, 2)
        XCTAssertEqual(all[0].auth.type, "mtls", "an unknown auth.type decodes")
        XCTAssertFalse(all[0].auth.isKnown)
        XCTAssertEqual(all[0].deprovision, .unknown)
        XCTAssertEqual(all[0].userNameFrom, .unknown)
        XCTAssertNil(all[0].state)
        XCTAssertEqual(all[1].state?.lastFailureReason, "a reason this SDK has never seen")
        XCTAssertEqual(all[1].state?.consecutiveFailures, 3)
        XCTAssertEqual(transport.count, 3)
        for sent in transport.requests {
            XCTAssertTrue(sent.query.contains("search=downstream"), "every page carries the search")
        }

        // An unknown variant decodes but is never sent: the write is refused locally, before
        // any request, as a ValidationError.
        let echo = ScimTargetInput(copying: all[0])
        do {
            _ = try await client.scimTargets.update(id: all[0].id, body: echo)
            XCTFail("an unknown auth.type must not be sent")
        } catch AxiamError.network(let error) {
            XCTAssertTrue(error.isValidation)
        }
        XCTAssertEqual(transport.count, 3, "nothing was sent")
        XCTAssertThrowsError(try JSONEncoder().encode(all[0].auth))
    }

    // MARK: - 5. No retry

    func testNoWriteIsRetriedOn503() async throws {
        let id = UUID().uuidString.lowercased()
        let (client, transport) = try await ManagementFixture.signedIn(
            Array(repeating: (status: 503, body: ""), count: 4), retryEnabled: true)
        let targets = client.scimTargets

        var failures: [Error] = []
        var counts: [Int] = []
        do {
            _ = try await targets.create(body: Self.input(credential: Self.credential()))
        } catch { failures.append(error) }
        counts.append(transport.count)
        do {
            _ = try await targets.update(id: id, body: Self.input(credential: nil))
        } catch { failures.append(error) }
        counts.append(transport.count)
        do { try await targets.delete(id: id) } catch { failures.append(error) }
        counts.append(transport.count)
        do { _ = try await targets.reconcile(id: id) } catch { failures.append(error) }
        counts.append(transport.count)

        XCTAssertEqual(counts, [1, 2, 3, 4], "exactly one request per write")
        XCTAssertEqual(failures.count, 4)
        for failure in failures {
            guard case AxiamError.network(let network) = failure else {
                return XCTFail("a 503 is a NetworkError")
            }
            XCTAssertEqual(network.statusCode, 503)
        }
    }

    // MARK: - 6. Errors and reconcile

    func testStatusesMapAndReconcileIsABodyless202() async throws {
        let id = UUID().uuidString.lowercased()
        let other = UUID().uuidString.lowercased()
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 400, body: #"{"error": "validation_error", "message": "credential: required on create"}"#),
            (status: 409, body: #"{"error": "conflict", "message": "the SCIM target changed since it was read"}"#),
            (status: 409, body: #"{"error": "conflict", "message": "a run holds the claim"}"#),
            (status: 404, body: #"{"error": "not_found", "message": "no"}"#),
            (status: 202, body: Self.json(["target_id": id, "status": "started"])),
            // The 401, then the §9 refresh it triggers, which fails too.
            (status: 401, body: #"{"error": "unauthorized", "message": "human only"}"#),
            (status: 401, body: #"{"error": "unauthorized"}"#),
        ])
        let targets = client.scimTargets

        do {
            _ = try await targets.create(body: Self.input(credential: nil))
            XCTFail("expected a 400")
        } catch AxiamError.network(let error) {
            XCTAssertTrue(error.isValidation)
            XCTAssertTrue(error.message.contains("credential"))
        }
        do {
            _ = try await targets.update(id: id, body: Self.input(credential: nil))
            XCTFail("expected a 409")
        } catch AxiamError.authz(let error) {
            XCTAssertEqual(error.managementFailure, .conflict)
        }
        do {
            _ = try await targets.reconcile(id: other)
            XCTFail("expected a 409")
        } catch AxiamError.authz(let error) {
            XCTAssertEqual(error.managementFailure, .conflict)
        }
        do {
            _ = try await targets.get(id: id)
            XCTFail("expected a 404")
        } catch AxiamError.authz(let error) {
            XCTAssertEqual(error.managementFailure, .notFound)
        }

        let accepted = try await targets.reconcile(id: id)
        XCTAssertEqual(accepted.targetID, id)
        XCTAssertEqual(accepted.status, "started")
        let reconcile = try XCTUnwrap(transport.last)
        XCTAssertEqual(reconcile.method, "POST")
        XCTAssertEqual(reconcile.path, "\(Self.targetsPath)/\(id)/reconcile")
        XCTAssertNil(reconcile.body, "reconcile sends no body")

        do {
            try await targets.delete(id: id)
            XCTFail("expected a 401")
        } catch AxiamError.auth(_) {
            // expected: the §9 refresh failed too, so the 401 surfaces as AuthError
        }
    }

    func testAReadConvertsIntoTheReplacementBodyWithoutACredential() throws {
        let target = try JSONDecoder().decode(
            ScimTargetResponse.self, from: Data(Self.json(Self.targetObject()).utf8))
        var body = ScimTargetInput(copying: target)
        XCTAssertNil(body.credential, "absent keeps the stored credential")
        XCTAssertEqual(body.baseURL, target.baseURL)
        XCTAssertEqual(body.enabled, true)
        body.name = "Downstream (renamed)"
        let sent = try Self.encodedObject(body)
        XCTAssertNil(sent["credential"])
        XCTAssertEqual(sent["name"] as? String, "Downstream (renamed)")
        XCTAssertEqual((sent["auth"] as? [String: Any])?["type"] as? String, "bearer")
    }
}
