import XCTest
@testable import AxiamSDK

/// The `directory` management namespace — CONTRACT.md §30.8's six required tests, plus the
/// read-modify-write helper and the open `last_result`.
///
/// The bind secret is generated at run time: a literal would be a credential in the
/// repository and would let a redaction test pass by coincidence.
final class DirectoryManagementTests: XCTestCase {

    private static let directoryPath = "/api/v1/tenants/\(ManagementFixture.tenantID)/directory"

    private static func secret() -> String { "bind-\(SecretKit.random())" }

    static func json(_ object: [String: Any]) -> String {
        String(decoding: try! JSONSerialization.data(withJSONObject: object), as: UTF8.self)
    }

    private static func configObject() -> [String: Any] {
        [
            "id": UUID().uuidString.lowercased(),
            "tenant_id": ManagementFixture.tenantID,
            "enabled": true,
            "kind": "active_directory",
            "url": "ldaps://dc.corp.example",
            "start_tls": false,
            "bind_dn": "cn=svc,dc=corp",
            "base_dn": "dc=corp",
            "user_filter": "(sAMAccountName={username})",
            "user_attribute_map": [
                "username": "sAMAccountName", "email": "mail",
                "display_name": "displayName", "external_id": "objectGUID",
            ],
            "group_base_dn": NSNull(),
            "group_filter": NSNull(),
            "group_member_attribute": "member",
            "group_nesting_depth": 5,
            "group_mappings": [Any](),
            "sync_interval_secs": 3600,
            "jit_provisioning": false,
            "trust_anchors_pem": [Any](),
            "created_at": "2026-10-04T00:00:00Z",
            "updated_at": "2026-10-04T00:00:00Z",
        ]
    }

    private static var configBody: String { json(configObject()) }

    /// A replacement body with only the seven required members (and, optionally, the secret).
    private static func setBody(bindSecret: String?) -> SetDirectoryConfig {
        SetDirectoryConfig(
            baseDn: "dc=corp",
            bindDn: "cn=svc,dc=corp",
            bindSecret: bindSecret.map { Sensitive($0) },
            enabled: true,
            kind: .activeDirectory,
            startTLS: false,
            url: "ldaps://dc.corp.example",
            userFilter: "(sAMAccountName={username})")
    }

    // MARK: - 1. Redaction

    func testTheBindSecretReachesTheWireAndNoRendering() async throws {
        let secret = Self.secret()
        let set = Self.setBody(bindSecret: secret)
        let update = UpdateDirectoryConfig(bindSecret: Sensitive(secret))
        for rendering in [
            String(describing: set), String(reflecting: set), "\(set)",
            String(describing: update), String(reflecting: update), "\(update)",
        ] {
            XCTAssertFalse(SecretKit.leaks(rendering, secret), "the bind secret leaked")
        }

        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 400, body: #"{"error": "validation_error", "message": "url: plaintext LDAP is refused"}"#),
        ])
        do {
            _ = try await client.directory.set(body: set)
            XCTFail("a 400 must surface")
        } catch {
            let rendering = "\(error) \(String(reflecting: error))"
            XCTAssertFalse(SecretKit.leaks(rendering, secret), "the bind secret leaked into an error")
        }
        let sent = try XCTUnwrap(transport.last?.jsonBody)
        XCTAssertEqual(sent["bind_secret"] as? String, secret, "but it is on the wire")
    }

    // MARK: - 2. No secret on the response

    func testABindSecretInAResponseIsDropped() async throws {
        let leaked = Self.secret()
        var object = Self.configObject()
        object["bind_secret"] = leaked
        let (client, _) = try await ManagementFixture.signedIn([
            (status: 200, body: Self.json(object)),
        ])

        let config = try await client.directory.get()
        XCTAssertEqual(config.url, "ldaps://dc.corp.example")
        let reencoded = String(decoding: try JSONEncoder().encode(config), as: UTF8.self)
        for rendering in [String(describing: config), String(reflecting: config), reencoded] {
            XCTAssertFalse(SecretKit.leaks(rendering, leaked), "a response secret was surfaced")
        }
        // ... and there is no accessor: `DirectoryConfig` declares no `bindSecret`, which
        // this file would fail to compile against if it did.
    }

    // MARK: - 3. Sparse update

    func testUpdateSendsExactlyTheMembersItWasGiven() async throws {
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 200, body: Self.configBody),
            (status: 200, body: Self.configBody),
            (status: 200, body: Self.configBody),
        ])
        let secret = Self.secret()

        _ = try await client.directory.update(body: UpdateDirectoryConfig(enabled: false))
        _ = try await client.directory.update(body: UpdateDirectoryConfig(
            bindSecret: Sensitive(secret), url: "ldaps://dc2.corp.example"))
        _ = try await client.directory.update(body: UpdateDirectoryConfig(groupFilter: .some(nil)))

        let sent = transport.requests
        XCTAssertEqual(sent.map(\.method), ["PATCH", "PATCH", "PATCH"])
        XCTAssertEqual(sent.first?.path, Self.directoryPath)

        let first = try XCTUnwrap(sent[0].jsonBody)
        XCTAssertEqual(Set(first.keys), ["enabled"])
        XCTAssertEqual(first["enabled"] as? Bool, false)

        let second = try XCTUnwrap(sent[1].jsonBody)
        XCTAssertEqual(Set(second.keys), ["bind_secret", "url"])
        XCTAssertEqual(second["bind_secret"] as? String, secret)

        let third = try XCTUnwrap(sent[2].jsonBody)
        XCTAssertEqual(Set(third.keys), ["group_filter"])
        XCTAssertTrue(third["group_filter"] is NSNull, "an explicit null clears the filter")
    }

    func testAnAbsentAndANullGroupFilterDecodeApart() throws {
        let absent = try JSONDecoder().decode(UpdateDirectoryConfig.self, from: Data("{}".utf8))
        let cleared = try JSONDecoder().decode(
            UpdateDirectoryConfig.self, from: Data(#"{"group_filter": null}"#.utf8))
        let set = try JSONDecoder().decode(
            UpdateDirectoryConfig.self, from: Data(#"{"group_filter": "(objectClass=group)"}"#.utf8))
        XCTAssertNil(absent.groupFilter)
        XCTAssertEqual(cleared.groupFilter, .some(nil))
        XCTAssertEqual(set.groupFilter, .some("(objectClass=group)"))
    }

    // MARK: - 4. Replacement

    func testSetSendsEveryRequiredMemberAndDecodes201And200() async throws {
        // `SetDirectoryConfig` cannot be built without its seven required members: they are
        // non-optional initializer parameters, so a call that omits one does not compile.
        // What is left to check is the wire.
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 201, body: Self.configBody),
            (status: 200, body: Self.configBody),
        ])
        for _ in 0..<2 {
            let config = try await client.directory.set(body: Self.setBody(bindSecret: nil))
            XCTAssertTrue(config.enabled)
            let sent = try XCTUnwrap(transport.last?.jsonBody)
            XCTAssertEqual(transport.last?.method, "PUT")
            for required in [
                "enabled", "kind", "url", "start_tls", "bind_dn", "base_dn", "user_filter",
            ] {
                XCTAssertNotNil(sent[required], "\(required) missing")
            }
            XCTAssertNil(sent["bind_secret"], "absent keeps the stored secret")
        }
        XCTAssertEqual(transport.count, 2)
    }

    // MARK: - 5. No retry

    func testNoWriteIsRetriedOn503() async throws {
        let (client, transport) = try await ManagementFixture.signedIn(
            [
                (status: 503, body: ""),
                (status: 503, body: ""),
                (status: 503, body: ""),
                (status: 503, body: ""),
            ],
            retryEnabled: true)

        var failures: [Error] = []
        do {
            _ = try await client.directory.set(body: Self.setBody(bindSecret: Self.secret()))
        } catch { failures.append(error) }
        XCTAssertEqual(transport.count, 1, "set: exactly one request")
        do {
            _ = try await client.directory.update(body: UpdateDirectoryConfig())
        } catch { failures.append(error) }
        XCTAssertEqual(transport.count, 2, "update: exactly one request")
        do {
            try await client.directory.delete()
        } catch { failures.append(error) }
        XCTAssertEqual(transport.count, 3, "delete: exactly one request")
        do {
            _ = try await client.directory.linkAccount(
                body: LinkDirectoryAccount(userID: UUID().uuidString.lowercased()))
        } catch { failures.append(error) }
        XCTAssertEqual(transport.count, 4, "link_account: exactly one request")

        XCTAssertEqual(failures.count, 4)
        for failure in failures {
            guard case AxiamError.network(let network) = failure else {
                return XCTFail("a 503 is a NetworkError")
            }
            XCTAssertEqual(network.statusCode, 503)
        }
        XCTAssertEqual(transport.requests.map(\.method), ["PUT", "PATCH", "DELETE", "POST"])
    }

    // MARK: - 6. Errors and link_account

    func testErrorsMapPerSection2AndLinkAccountSendsOnlyTheUserID() async throws {
        let user = UUID().uuidString.lowercased()
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 400, body: #"{"error": "validation_error", "message": "url: changing the connection requires entering the bind secret again"}"#),
            (status: 409, body: #"{"error": "conflict", "message": "opaque_mode"}"#),
            (status: 404, body: #"{"error": "not_found", "message": "none"}"#),
            (status: 200, body: Self.json([
                "user_id": user, "directory_external_id": "3f2a-objectguid",
                "webauthn_credentials_deleted": 2, "certificates_revoked": 1,
                "was_already_linked": false,
            ])),
        ])

        do {
            _ = try await client.directory.set(body: Self.setBody(bindSecret: nil))
            XCTFail("expected a 400")
        } catch AxiamError.network(let error) {
            XCTAssertTrue(error.isValidation)
            XCTAssertTrue(error.message.contains("bind secret again"))
        }
        do {
            _ = try await client.directory.update(body: UpdateDirectoryConfig(enabled: true))
            XCTFail("expected a 409")
        } catch AxiamError.authz(let error) {
            XCTAssertEqual(error.managementFailure, .conflict)
        }
        do {
            _ = try await client.directory.get()
            XCTFail("expected a 404")
        } catch AxiamError.authz(let error) {
            XCTAssertEqual(error.managementFailure, .notFound)
        }

        let result = try await client.directory.linkAccount(body: LinkDirectoryAccount(userID: user))
        let sent = try XCTUnwrap(transport.last?.jsonBody)
        XCTAssertEqual(Set(sent.keys), ["user_id"])
        XCTAssertEqual(sent["user_id"] as? String, user)
        XCTAssertEqual(transport.last?.path, "\(Self.directoryPath)/links")
        XCTAssertEqual(result.userID, user)
        XCTAssertEqual(result.directoryExternalID, "3f2a-objectguid")
        XCTAssertEqual(result.webauthnCredentialsDeleted, 2)
        XCTAssertEqual(result.certificatesRevoked, 1)
        XCTAssertFalse(result.wasAlreadyLinked)
    }

    func testSyncStatusDecodesAnUnknownResultAndTheFirstRunNulls() async throws {
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 200, body: #"{"last_result": "something_new", "last_attempt_at": null, "last_full_run_at": null, "full_required": true, "has_watermark": false}"#),
        ])
        let status = try await client.directory.getSyncStatus()
        XCTAssertEqual(status.lastResult, "something_new")
        XCTAssertNil(status.lastAttemptAt)
        XCTAssertTrue(status.fullRequired)
        XCTAssertFalse(status.hasWatermark)
        XCTAssertEqual(transport.last?.path, "\(Self.directoryPath)/sync-status")
    }

    func testAReadConvertsIntoTheReplacementBodyWithoutASecret() throws {
        let config = try JSONDecoder().decode(DirectoryConfig.self, from: Data(Self.configBody.utf8))
        let body = SetDirectoryConfig(copying: config)
        XCTAssertNil(body.bindSecret, "absent keeps the stored secret")
        XCTAssertEqual(body.url, config.url)
        XCTAssertEqual(body.groupNestingDepth, 5)
        XCTAssertEqual(body.syncIntervalSecs, 3600)
        XCTAssertEqual(body.userAttributeMap?.email, "mail")
    }
}
