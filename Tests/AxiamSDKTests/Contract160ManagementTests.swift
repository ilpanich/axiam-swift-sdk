import XCTest
@testable import AxiamSDK

/// Contract 1.60's §27.15 members (§34.4): `window_minutes` on the notification rules (note 1),
/// and the federation configuration's `allow_sha1_signatures` (note 6),
/// `idp_metadata_signing_cert_pem` (note 7) and explicit-`null` clearing on `update_config`
/// (note 8, with §27.4 rule 5's exact key-set test).
final class Contract160ManagementTests: XCTestCase {

    private static let ruleID = "44444444-4444-4444-8444-444444444444"
    private static let configID = "55555555-5555-4555-8555-555555555555"

    /// The ten members of `UpdateFederationConfigRequest` an explicit `null` clears (§27.15
    /// note 8).
    private static let clearable = [
        "metadata_url", "idp_signing_cert_pem", "idp_metadata_signing_cert_pem", "provider_slug",
        "authorization_endpoint", "token_endpoint", "userinfo_endpoint", "apple_team_id",
        "apple_key_id", "button_icon",
    ]

    private static func json(_ object: [String: Any]) -> String {
        String(decoding: try! JSONSerialization.data(withJSONObject: object), as: UTF8.self)
    }

    private static func object(_ data: Data) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    /// A PEM-shaped certificate made at run time; the SDK passes it through and never parses it.
    private static func certificatePEM() -> String {
        "-----BEGIN CERTIFICATE-----\n\(SecretKit.random())\n-----END CERTIFICATE-----\n"
    }

    // MARK: - §27.15 note 1: window_minutes

    private static func rule(windowMinutes: Int?) -> CreateNotificationRuleRequest {
        CreateNotificationRuleRequest(
            description: "Mail on lockout",
            events: [.accountLocked],
            name: "Lockouts",
            recipientEmails: ["secops@acme.test"],
            windowMinutes: windowMinutes)
    }

    private static func ruleObject(windowMinutes: Int) -> [String: Any] {
        [
            "id": ruleID,
            "tenant_id": ManagementFixture.tenantID,
            "name": "Lockouts",
            "description": "Mail on lockout",
            "events": ["account_locked"],
            "recipient_emails": ["secops@acme.test"],
            "enabled": true,
            "window_minutes": windowMinutes,
            "created_at": "2026-10-05T00:00:00Z",
            "updated_at": "2026-10-05T00:00:00Z",
        ]
    }

    /// §27.15 note 1's required test: `create` with `window_minutes` sends it as given — never
    /// clamped, even outside 1 to 1440, which is the server's to refuse — `create` without it
    /// sends no such key, and a response carrying it decodes it.
    func testWindowMinutesIsSentAsGivenOmittedWhenUnsetAndDecoded() async throws {
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 200, body: Self.json(Self.ruleObject(windowMinutes: 60))),
            (status: 200, body: Self.json(Self.ruleObject(windowMinutes: 15))),
            (status: 400, body: #"{"error": "validation_error", "message": "window_minutes: 1 to 1440"}"#),
            (status: 200, body: Self.json(Self.ruleObject(windowMinutes: 30))),
        ])
        let rules = client.notificationRules

        let created = try await rules.create(body: Self.rule(windowMinutes: 60))
        let given = try XCTUnwrap(transport.last?.jsonBody)
        XCTAssertEqual(given["window_minutes"] as? Int, 60, "sent as given")
        XCTAssertEqual(created.windowMinutes, 60, "the response member decodes")

        let defaulted = try await rules.create(body: Self.rule(windowMinutes: nil))
        let unset = try XCTUnwrap(transport.last?.jsonBody)
        XCTAssertEqual(
            Set(unset.keys), ["description", "events", "name", "recipient_emails"],
            "no window_minutes key when the caller did not set it")
        XCTAssertEqual(defaulted.windowMinutes, 15, "the server's default, as it answered")

        do {
            _ = try await rules.create(body: Self.rule(windowMinutes: 5000))
            XCTFail("expected the server's 400")
        } catch AxiamError.network(let error) {
            XCTAssertTrue(error.isValidation)
        }
        let outOfRange = try XCTUnwrap(transport.last?.jsonBody)
        XCTAssertEqual(outOfRange["window_minutes"] as? Int, 5000, "never clamped")

        // `update` is sparse: the member alone.
        let updated = try await rules.update(
            id: Self.ruleID, body: UpdateNotificationRuleRequest(windowMinutes: 30))
        let sparse = try XCTUnwrap(transport.last?.jsonBody)
        XCTAssertEqual(Set(sparse.keys), ["window_minutes"])
        XCTAssertEqual(sparse["window_minutes"] as? Int, 30)
        XCTAssertEqual(updated.windowMinutes, 30)
    }

    // MARK: - §27.15 notes 6 and 7: the federation configuration's SAML members

    private static func configObject() -> [String: Any] {
        [
            "id": configID,
            "tenant_id": ManagementFixture.tenantID,
            "provider": "Acme IdP",
            "protocol": "Saml",
            "provider_kind": "saml",
            "client_id": "axiam-sp",
            "attribute_map": [String: Any](),
            "enabled": true,
            "token_exchange": [
                "enabled": false,
                "accepted_audiences": [String](),
                "subject_mapping": "by_email",
                "scope_map": [String: Any](),
                "max_token_age_secs": 300,
            ] as [String: Any],
            "allow_tenant_inheritance": false,
            "scopes": [String](),
            "effective_scopes": [String](),
            "allowed_issuer_tenants": [String](),
            "allowed_algorithms": ["RS256"],
            "mints_client_secret": false,
            "pkce_required": false,
            "has_bundled_mark": false,
            "allow_sha1_signatures": false,
            "idp_metadata_signing_cert_pem": NSNull(),
            "created_at": "2026-10-05T00:00:00Z",
            "updated_at": "2026-10-05T00:00:00Z",
        ]
    }

    /// §27.15 notes 6 and 7: both members are sent only when the caller sets them, and then as
    /// given.
    func testTheSamlMembersAreSentOnlyWhenSet() async throws {
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 200, body: Self.json(Self.configObject())),
            (status: 200, body: Self.json(Self.configObject())),
        ])
        let pem = Self.certificatePEM()

        _ = try await client.federation.createConfig(body: CreateFederationConfigRequest(
            clientID: "axiam-sp",
            clientSecret: Sensitive("cs-\(SecretKit.random())"),
            `protocol`: "Saml",
            provider: "Acme IdP"))
        let plain = try XCTUnwrap(transport.last?.jsonBody)
        XCTAssertEqual(Set(plain.keys), ["client_id", "client_secret", "protocol", "provider"])

        _ = try await client.federation.createConfig(body: CreateFederationConfigRequest(
            allowSha1Signatures: true,
            clientID: "axiam-sp",
            clientSecret: Sensitive("cs-\(SecretKit.random())"),
            idpMetadataSigningCertPEM: pem,
            `protocol`: "Saml",
            provider: "Acme IdP"))
        let set = try XCTUnwrap(transport.last?.jsonBody)
        XCTAssertEqual(set["allow_sha1_signatures"] as? Bool, true)
        XCTAssertEqual(set["idp_metadata_signing_cert_pem"] as? String, pem)
    }

    /// §27.15 note 6: a response without `allow_sha1_signatures` — from a server before 1.0.0
    /// — decodes as `false` rather than failing; one carrying it decodes it. Note 7: the
    /// metadata signing certificate is `nil` when `null` or absent.
    func testAnAbsentAllowSha1SignaturesReadsFalse() throws {
        var legacy = Self.configObject()
        legacy.removeValue(forKey: "allow_sha1_signatures")
        legacy.removeValue(forKey: "idp_metadata_signing_cert_pem")
        let old = try JSONDecoder().decode(
            FederationConfigResponse.self, from: Data(Self.json(legacy).utf8))
        XCTAssertFalse(old.allowSha1Signatures)
        XCTAssertNil(old.idpMetadataSigningCertPEM)

        let unset = try JSONDecoder().decode(
            FederationConfigResponse.self, from: Data(Self.json(Self.configObject()).utf8))
        XCTAssertFalse(unset.allowSha1Signatures)
        XCTAssertNil(unset.idpMetadataSigningCertPEM, "null when unset")

        let pem = Self.certificatePEM()
        var current = Self.configObject()
        current["allow_sha1_signatures"] = true
        current["idp_metadata_signing_cert_pem"] = pem
        let decoded = try JSONDecoder().decode(
            FederationConfigResponse.self, from: Data(Self.json(current).utf8))
        XCTAssertTrue(decoded.allowSha1Signatures)
        XCTAssertEqual(decoded.idpMetadataSigningCertPEM, pem)
    }

    // MARK: - §27.15 note 8: an explicit null clears

    /// §27.15 note 8 with §27.4 rule 5's exact key-set test: an update that clears one member
    /// sends exactly that key, as `null`; a member left `nil` is not sent; a member set to a
    /// value is sent as it.
    func testAnUpdateClearingOneMemberSendsExactlyThatKeyAsNull() async throws {
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 200, body: Self.json(Self.configObject())),
            (status: 200, body: Self.json(Self.configObject())),
            (status: 200, body: Self.json(Self.configObject())),
        ])
        let federation = client.federation

        _ = try await federation.updateConfig(
            id: Self.configID,
            body: UpdateFederationConfigRequest(idpMetadataSigningCertPEM: .some(nil)))
        let cleared = try XCTUnwrap(transport.last?.jsonBody)
        XCTAssertEqual(Set(cleared.keys), ["idp_metadata_signing_cert_pem"])
        XCTAssertTrue(cleared["idp_metadata_signing_cert_pem"] is NSNull, "an explicit null clears it")

        _ = try await federation.updateConfig(
            id: Self.configID, body: UpdateFederationConfigRequest(enabled: false))
        let untouched = try XCTUnwrap(transport.last?.jsonBody)
        XCTAssertEqual(Set(untouched.keys), ["enabled"], "an omitted member is not sent")

        _ = try await federation.updateConfig(
            id: Self.configID,
            body: UpdateFederationConfigRequest(metadataURL: "https://idp.example/metadata"))
        let replaced = try XCTUnwrap(transport.last?.jsonBody)
        XCTAssertEqual(Set(replaced.keys), ["metadata_url"])
        XCTAssertEqual(replaced["metadata_url"] as? String, "https://idp.example/metadata")
    }

    /// Every one of the ten keeps "set to null" distinct from "unset" through a decode and an
    /// encode; a member that cannot be cleared reads an explicit `null` as absent, as the
    /// server does, and does not send it.
    func testAllTenNullableMembersKeepNullDistinctFromAbsent() throws {
        for key in Self.clearable {
            let decoded = try JSONDecoder().decode(
                UpdateFederationConfigRequest.self, from: Data("{\"\(key)\": null}".utf8))
            let sent = try Self.object(try JSONEncoder().encode(decoded))
            XCTAssertEqual(Set(sent.keys), [key], "\(key): the null survives")
            XCTAssertTrue(sent[key] is NSNull, "\(key): sent as null")

            let absent = try JSONDecoder().decode(
                UpdateFederationConfigRequest.self, from: Data("{}".utf8))
            XCTAssertTrue(try Self.object(try JSONEncoder().encode(absent)).isEmpty)
        }

        let notClearable = try JSONDecoder().decode(
            UpdateFederationConfigRequest.self, from: Data(#"{"enabled": null}"#.utf8))
        XCTAssertNil(notClearable.enabled)
        XCTAssertTrue(try Self.object(try JSONEncoder().encode(notClearable)).isEmpty)
    }
}
