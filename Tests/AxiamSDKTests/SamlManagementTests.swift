import XCTest
@testable import AxiamSDK

/// The `saml` management namespace — CONTRACT.md §29.8's eight required tests.
final class SamlManagementTests: XCTestCase {

    private static let samlPath = "/api/v1/tenants/\(ManagementFixture.tenantID)/saml"

    private static func json(_ object: Any) -> String {
        String(decoding: try! JSONSerialization.data(withJSONObject: object), as: UTF8.self)
    }

    private static func spObject(_ extra: [String: Any] = [:]) -> [String: Any] {
        var body: [String: Any] = [
            "id": UUID().uuidString.lowercased(),
            "tenant_id": ManagementFixture.tenantID,
            "enabled": true,
            "display_name": "Payroll",
            "entity_id": "https://payroll.example/sp",
            "acs_urls": [[
                "url": "https://payroll.example/acs", "binding": "http_post",
                "index": 0, "is_default": true,
            ] as [String: Any]],
            "slo_url": NSNull(),
            "slo_binding": NSNull(),
            "name_id_format": "persistent",
            "sign_responses": true,
            "encrypt_assertions": false,
            "sp_signing_cert_pem": NSNull(),
            "sp_encryption_cert_pem": NSNull(),
            "want_authn_requests_signed": false,
            "allow_idp_initiated": false,
            "attribute_mappings": [Any](),
            "allowed_groups": [Any](),
            "created_at": "2026-10-04T00:00:00Z",
            "updated_at": "2026-10-04T00:00:00Z",
        ]
        for (key, value) in extra { body[key] = value }
        return body
    }

    private static func credentialObject(_ status: String, _ extra: [String: Any] = [:]) -> [String: Any] {
        var body: [String: Any] = [
            "id": UUID().uuidString.lowercased(),
            "tenant_id": ManagementFixture.tenantID,
            "issuer_ca_id": UUID().uuidString.lowercased(),
            "certificate_pem": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
            "serial": "0a1b",
            "fingerprint": String(repeating: "ab", count: 32),
            "not_before": "2026-10-04T00:00:00Z",
            "not_after": "2027-10-04T00:00:00Z",
            "status": status,
            "created_at": "2026-10-04T00:00:00Z",
            "retired_at": NSNull(),
        ]
        for (key, value) in extra { body[key] = value }
        return body
    }

    private static func input() -> SamlServiceProviderInput {
        SamlServiceProviderInput(
            acsUrls: [AcsEndpoint(
                binding: .httpPost, index: 0, isDefault: true,
                url: "https://payroll.example/acs")],
            displayName: "Payroll",
            entityID: "https://payroll.example/sp")
    }

    private static func isValidation(_ error: Error) -> Bool {
        if case AxiamError.network(let network) = error { return network.isValidation }
        return false
    }

    // MARK: - 1. Replacement

    func testUpdateServiceProviderPutsTheWholeRegistration() async throws {
        let id = UUID().uuidString.lowercased()
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 200, body: Self.json(Self.spObject())),
        ])

        // The read-modify-write form: every member of a read carried over.
        let current = try JSONDecoder().decode(
            SamlServiceProvider.self, from: Data(Self.json(Self.spObject()).utf8))
        var body = SamlServiceProviderInput(copying: current)
        body.displayName = "Payroll (EU)"
        let sp = try await client.saml.updateServiceProvider(spID: id, body: body)
        XCTAssertEqual(sp.entityID, "https://payroll.example/sp")

        XCTAssertEqual(transport.last?.method, "PUT")
        XCTAssertEqual(transport.last?.path, "\(Self.samlPath)/service-providers/\(id)")
        let sent = try XCTUnwrap(transport.last?.jsonBody)
        for member in [
            "acs_urls", "allow_idp_initiated", "allowed_groups", "attribute_mappings",
            "display_name", "enabled", "encrypt_assertions", "entity_id", "name_id_format",
            "sign_responses", "want_authn_requests_signed",
        ] {
            XCTAssertNotNil(sent[member], "\(member) not sent")
        }
        XCTAssertEqual(sent["display_name"] as? String, "Payroll (EU)")
        // `displayName`, `entityID` and `acsUrls` are non-optional initializer parameters:
        // an input without them does not compile.
    }

    // MARK: - 2. No signing switch, open decoding

    func testSignAssertionsDoesNotExistAndUnknownValuesDecode() async throws {
        let id = UUID().uuidString.lowercased()
        var object = Self.spObject(["sign_assertions": false, "some_future_member": 1])
        object["acs_urls"] = [[
            "url": "https://payroll.example/acs", "binding": "http_artifact",
            "index": 0, "is_default": true,
        ] as [String: Any]]
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 200, body: Self.json(object)),
            (status: 200, body: Self.json(Self.spObject())),
        ])

        let sp = try await client.saml.getServiceProvider(spID: id)
        XCTAssertEqual(sp.acsUrls.first?.binding, .unknown, "an unknown binding decodes")

        // An unknown enum value is decoded, but MUST NOT be sent: replace the ACS entry that
        // carries it before writing back.
        var input = SamlServiceProviderInput(copying: sp)
        input.acsUrls = [AcsEndpoint(
            binding: .httpPost, index: 0, isDefault: true, url: "https://payroll.example/acs")]
        _ = try await client.saml.updateServiceProvider(spID: id, body: input)

        let sent = try XCTUnwrap(transport.last?.jsonBody)
        XCTAssertNil(sent["sign_assertions"])
        XCTAssertNil(sent["some_future_member"])
    }

    // MARK: - 3. Draft round trip

    func testParseSpMetadataSendsExactlyOneMemberAndTheDraftCreates() async throws {
        let serviceProvider: [String: Any] = [
            "display_name": "Imported",
            "entity_id": "https://imported.example/sp",
            "acs_urls": [[
                "url": "https://imported.example/acs", "binding": "http_post",
                "index": 1, "is_default": false,
            ] as [String: Any]],
            "want_authn_requests_signed": true,
            "sp_signing_cert_pem": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
        ]
        let draft: [String: Any] = [
            "service_provider": serviceProvider,
            "signing_certificate_fingerprint": String(repeating: "cd", count: 32),
            "encryption_certificate_fingerprint": NSNull(),
            "warnings": ["the metadata's signature was not evaluated"],
        ]
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 200, body: Self.json(draft)),
            (status: 200, body: Self.json(draft)),
            (status: 201, body: Self.json(Self.spObject())),
        ])

        let fromURL = try await client.saml.parseSpMetadata(
            body: .fromURL("https://imported.example/metadata"))
        _ = try await client.saml.parseSpMetadata(body: .fromXML("<EntityDescriptor/>"))

        for bothOrNeither in [
            ParseSamlSpMetadata(metadataURL: "https://a", metadataXml: "<x/>"),
            ParseSamlSpMetadata(),
        ] {
            do {
                _ = try await client.saml.parseSpMetadata(body: bothOrNeither)
                XCTFail("both or neither must be refused locally")
            } catch {
                XCTAssertTrue(Self.isValidation(error), "expected the local ValidationError")
            }
        }
        XCTAssertEqual(transport.count, 2, "the refused calls sent nothing")
        let first = try XCTUnwrap(transport.requests[0].jsonBody)
        XCTAssertEqual(Set(first.keys), ["metadata_url"])
        XCTAssertEqual(first["metadata_url"] as? String, "https://imported.example/metadata")
        let second = try XCTUnwrap(transport.requests[1].jsonBody)
        XCTAssertEqual(Set(second.keys), ["metadata_xml"])
        XCTAssertEqual(second["metadata_xml"] as? String, "<EntityDescriptor/>")
        XCTAssertEqual(fromURL.warnings.count, 1)

        _ = try await client.saml.createServiceProvider(body: fromURL.serviceProvider)
        let created = try XCTUnwrap(transport.last?.jsonBody)
        let expected = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(Self.json(serviceProvider).utf8))
                as? [String: Any])
        XCTAssertEqual(
            NSDictionary(dictionary: created), NSDictionary(dictionary: expected),
            "the draft's service_provider is sent unchanged")
    }

    // MARK: - 4. Credentials carry no key

    func testACredentialHasNoKeyMemberAndPromotionMayRetireNothing() async throws {
        let leaked = "leaked-key-\(SecretKit.random())"
        let id = UUID().uuidString.lowercased()
        let (client, _) = try await ManagementFixture.signedIn([
            (status: 200, body: Self.json(Self.credentialObject("retired", ["private_key_pem": leaked]))),
            (status: 200, body: Self.json([
                "active": Self.credentialObject("active"), "retired": NSNull(),
            ] as [String: Any])),
        ])

        let credential = try await client.saml.retireIdpCredential(credentialID: id)
        let reencoded = String(decoding: try JSONEncoder().encode(credential), as: UTF8.self)
        for rendering in SecretKit.renderings(credential) + [reencoded] {
            XCTAssertFalse(SecretKit.leaks(rendering, leaked), "the leaked key value was surfaced")
            XCTAssertFalse(rendering.contains("private_key_pem"))
        }
        // No accessor: `SamlIdpCredential` declares no key member, which this file would fail
        // to compile against if it did.

        let promotion = try await client.saml.promoteIdpCredential(credentialID: id)
        XCTAssertNil(promotion.retired)
        XCTAssertEqual(promotion.active.status, .active)
    }

    // MARK: - 5. Pagination

    func testServiceProvidersPageWithSearchAndCredentialsAreAPlainList() async throws {
        let page1 = Self.json([
            "items": [Self.spObject()], "total": 2, "offset": 0, "limit": 1,
        ] as [String: Any])
        let page2 = Self.json([
            "items": [Self.spObject()], "total": 2, "offset": 1, "limit": 1,
        ] as [String: Any])
        let empty = Self.json(["items": [Any](), "total": 2, "offset": 2, "limit": 1] as [String: Any])
        let credentials = Self.json([Self.credentialObject("next"), Self.credentialObject("active")])
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 200, body: page1),
            (status: 200, body: page2),
            (status: 200, body: empty),
            (status: 200, body: credentials),
        ])

        var request = PageRequest(offset: 0, limit: 1, search: "payroll")
        var collected: [SamlServiceProvider] = []
        while true {
            let page = try await client.saml.listServiceProviders(page: request)
            XCTAssertEqual(page.total, 2)
            if page.isEmpty { break }
            collected.append(contentsOf: page.items)
            request = page.nextRequest
        }
        XCTAssertEqual(collected.count, 2)
        let walk = transport.requests.prefix(3)
        XCTAssertEqual(walk.count, 3)
        for sent in walk {
            XCTAssertTrue(sent.query.contains("search=payroll"), "every page carries the search")
        }

        let list: [SamlIdpCredential] = try await client.saml.listIdpCredentials()
        XCTAssertEqual(list.count, 2)
        XCTAssertEqual(list.first?.status, .next)
    }

    // MARK: - 6. No retry

    func testNoneOfTheSevenWritesIsRetriedOn503() async throws {
        let id = UUID().uuidString.lowercased()
        let (client, transport) = try await ManagementFixture.signedIn(
            Array(repeating: (status: 503, body: ""), count: 7), retryEnabled: true)
        let saml = client.saml

        var failures: [Error] = []
        var counts: [Int] = []
        do { _ = try await saml.createServiceProvider(body: Self.input()) } catch { failures.append(error) }
        counts.append(transport.count)
        do { _ = try await saml.updateServiceProvider(spID: id, body: Self.input()) } catch { failures.append(error) }
        counts.append(transport.count)
        do { try await saml.deleteServiceProvider(spID: id) } catch { failures.append(error) }
        counts.append(transport.count)
        do { _ = try await saml.parseSpMetadata(body: .fromURL("https://m")) } catch { failures.append(error) }
        counts.append(transport.count)
        do {
            _ = try await saml.issueIdpCredential(body: IssueSamlIdpCredential(
                issuerCAID: UUID().uuidString.lowercased(), slot: .next))
        } catch { failures.append(error) }
        counts.append(transport.count)
        do { _ = try await saml.promoteIdpCredential(credentialID: id) } catch { failures.append(error) }
        counts.append(transport.count)
        do { _ = try await saml.retireIdpCredential(credentialID: id) } catch { failures.append(error) }
        counts.append(transport.count)

        XCTAssertEqual(counts, [1, 2, 3, 4, 5, 6, 7], "exactly one request per write")
        XCTAssertEqual(failures.count, 7)
        for failure in failures {
            guard case AxiamError.network(let network) = failure else {
                return XCTFail("a 503 is a NetworkError")
            }
            XCTAssertEqual(network.statusCode, 503)
        }
    }

    // MARK: - 7. Errors

    func testStatusesMapPerSection2() async throws {
        let id = UUID().uuidString.lowercased()
        let (client, _) = try await ManagementFixture.signedIn([
            (status: 409, body: #"{"error": "conflict", "message": "entity_id"}"#),
            (status: 400, body: #"{"error": "validation_error", "message": "entity_id is immutable: register a new service provider"}"#),
            (status: 404, body: #"{"error": "not_found", "message": "no"}"#),
            (status: 409, body: #"{"error": "conflict", "message": "not next"}"#),
            (status: 503, body: #"{"error": "service_unavailable", "message": "saml"}"#),
        ])
        let saml = client.saml

        do {
            _ = try await saml.createServiceProvider(body: Self.input())
            XCTFail("expected a 409")
        } catch AxiamError.authz(let error) {
            XCTAssertEqual(error.managementFailure, .conflict)
        }
        do {
            _ = try await saml.updateServiceProvider(spID: id, body: Self.input())
            XCTFail("expected a 400")
        } catch AxiamError.network(let error) {
            XCTAssertTrue(error.isValidation)
            XCTAssertTrue(error.message.contains("immutable"))
        }
        do {
            _ = try await saml.getServiceProvider(spID: id)
            XCTFail("expected a 404")
        } catch AxiamError.authz(let error) {
            XCTAssertEqual(error.managementFailure, .notFound)
        }
        do {
            _ = try await saml.promoteIdpCredential(credentialID: id)
            XCTFail("expected a 409")
        } catch AxiamError.authz(let error) {
            XCTAssertEqual(error.managementFailure, .conflict)
        }
        do {
            _ = try await saml.parseSpMetadata(body: .fromURL("https://m"))
            XCTFail("expected a 503")
        } catch AxiamError.network(let error) {
            XCTAssertFalse(error.isValidation)
            XCTAssertEqual(error.statusCode, 503)
        }
    }

    // MARK: - 8. Readiness is read, not cached

    func testGetIdpIsNeverCachedAndKeepsNullApartFromAbsent() async throws {
        let active = UUID().uuidString.lowercased()
        let body = Self.json([
            "tenant_id": ManagementFixture.tenantID, "saml_available": true,
            "saml_idp_enabled": false, "metadata_served": true,
            "entity_id": "https://iam.example/saml/v2/t",
            "metadata_url": "https://iam.example/saml/v2/t/metadata",
            "sso_url": "https://iam.example/saml/v2/t/sso",
            "slo_url": "https://iam.example/saml/v2/t/slo",
            "active_credential_id": active, "next_credential_id": NSNull(),
        ] as [String: Any])
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 200, body: body), (status: 200, body: body),
        ])

        // The configured tenant goes in the path: `getIdp` takes no tenant argument.
        let info = try await client.saml.getIdp()
        _ = try await client.saml.getIdp()
        XCTAssertEqual(transport.count, 2, "two calls, two requests")
        for sent in transport.requests {
            XCTAssertEqual(sent.path, "\(Self.samlPath)/idp")
        }
        XCTAssertEqual(info.activeCredentialID, .some(active))
        XCTAssertEqual(info.nextCredentialID, .some(nil), "null, not absent")
        XCTAssertTrue(info.samlAvailable && info.metadataServed && !info.samlIdpEnabled)

        let without = try JSONDecoder().decode(SamlIdpInfo.self, from: Data(Self.json([
            "tenant_id": ManagementFixture.tenantID, "saml_available": true,
            "saml_idp_enabled": false, "metadata_served": false, "entity_id": "e",
            "metadata_url": "m", "sso_url": "s", "slo_url": "l",
        ] as [String: Any]).utf8))
        XCTAssertNil(without.nextCredentialID, "absent stays absent")

        // Re-encoding keeps the distinction too.
        let reencoded = try XCTUnwrap(JSONSerialization.jsonObject(
            with: try JSONEncoder().encode(info)) as? [String: Any])
        XCTAssertTrue(reencoded["next_credential_id"] is NSNull)
        let reencodedWithout = try XCTUnwrap(JSONSerialization.jsonObject(
            with: try JSONEncoder().encode(without)) as? [String: Any])
        XCTAssertNil(reencodedWithout["next_credential_id"])
    }
}
