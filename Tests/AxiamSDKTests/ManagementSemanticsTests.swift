import XCTest
@testable import AxiamSDK

/// CONTRACT.md §27.4 — the rules that are easy to get wrong and silent when wrong.
///
/// The generated suite proves each route is reached and each response decodes. These are the
/// assertions it structurally cannot make: what a request body actually contains, whether a
/// re-scoped handle is a new object, how many times a failed call went out, and which error
/// type came back.
final class ManagementSemanticsTests: XCTestCase {

    private static let uuid = ManagementFixture.tenantID

    private static let rolePage = """
        {"items": [{"created_at": "2026-08-26T00:00:00Z", "description": "Edits documents", \
        "id": "\(ManagementFixture.tenantID)", "is_global": false, "name": "editor", "tenant_id": "\(ManagementFixture.tenantID)", \
        "updated_at": "2026-08-26T00:00:00Z"}], "total": 412}
        """

    private static let roleObject = """
        {"created_at": "2026-08-26T00:00:00Z", "description": "Edits documents", \
        "id": "\(ManagementFixture.tenantID)", "is_global": false, "name": "editor", "tenant_id": "\(ManagementFixture.tenantID)", \
        "updated_at": "2026-08-26T00:00:00Z"}
        """

    private static let emptyPage = #"{"items": [], "total": 412}"#

    // MARK: - §27.2 the handles

    func testAcquiringAHandlePerformsNoIO() async throws {
        let (client, transport) = try await ManagementFixture.signedIn()

        // §27.2 rule 1. Twenty-four handles, plus the aggregate and the manifest.
        _ = client.roles
        _ = client.users
        _ = client.serviceAccounts
        _ = client.management.certificates
        _ = client.manifest

        XCTAssertEqual(transport.count, 0)
    }

    func testTheTwoAccessorFormsAreEquivalent() async throws {
        // §27.2 rule 4: "where an SDK offers both, the two MUST return equivalent handles".
        // Equivalent means the same request, not merely the same type.
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 200, body: Self.rolePage),
            (status: 200, body: Self.rolePage),
        ])

        _ = try await client.roles.list()
        let direct = try XCTUnwrap(transport.last)
        _ = try await client.management.roles.list()
        let viaAggregate = try XCTUnwrap(transport.last)

        XCTAssertEqual(direct.method, viaAggregate.method)
        XCTAssertEqual(direct.path, viaAggregate.path)
        XCTAssertEqual(direct.query, viaAggregate.query)
    }

    // MARK: - §27.4 rule 1: no session, no wire call

    func testAnUnauthenticatedManagementCallSendsNothing() async throws {
        let (client, transport) = try await ManagementFixture.anonymous()

        await XCTAssertThrowsErrorAsync(try await client.roles.list())

        XCTAssertEqual(transport.count, 0)
    }

    // MARK: - §27.4 rule 3: implicit and overridden identifiers

    func testTheClientsOwnOrgIdIsSubstituted() async throws {
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 200, body: #"{"items": [], "total": 0}"#),
        ])

        _ = try await client.caCertificates.list()

        // Asserted on the PATH, not on the arguments — an SDK that accepted the id and then
        // failed to interpolate it passes an argument-level assertion.
        XCTAssertEqual(
            transport.last?.path,
            "/api/v1/organizations/\(ManagementFixture.orgID)/ca-certificates")
    }

    func testAnExplicitScopeOverridesTheClientsOwn() async throws {
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 200, body: #"{"items": [], "total": 0}"#),
            (status: 200, body: #"{"items": [], "total": 0}"#),
        ])

        let handle = client.caCertificates
        _ = try await handle.inOrg(ManagementFixture.otherOrg).list()
        XCTAssertEqual(
            transport.last?.path,
            "/api/v1/organizations/\(ManagementFixture.otherOrg)/ca-certificates")

        // And the handle it was derived from still points where it did. A handle that
        // repointed itself would mean an unrelated code path could send this one's next
        // WRITE to somebody else's organization.
        _ = try await handle.list()
        XCTAssertEqual(
            transport.last?.path,
            "/api/v1/organizations/\(ManagementFixture.orgID)/ca-certificates")
    }

    func testASlugOnlyClientRefusesARouteNeedingAUuid() async throws {
        let (client, transport) = try await ManagementFixture.unscoped()

        await XCTAssertThrowsErrorAsync(try await client.caCertificates.list())

        // Client-side, with zero wire calls beyond the login this fixture performed.
        XCTAssertEqual(transport.count, 0)
    }

    func testTheTenantHeaderIsStillPresentOnManagementRequests() async throws {
        // §5 rule 2 does not lapse on this surface.
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 200, body: Self.rolePage),
        ])

        _ = try await client.roles.list()

        XCTAssertEqual(transport.last?.header("X-Tenant-ID"), ManagementFixture.tenantID)
    }

    func testAPathSegmentIsPercentEscaped() async throws {
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 200, body: Self.roleObject),
        ])

        _ = try? await client.roles.get(roleID: "a/../b")

        // A `/` inside an identifier would otherwise silently re-route the request onto a
        // different endpoint.
        XCTAssertEqual(transport.last?.path, "/api/v1/roles/a%2F..%2Fb")
    }

    // MARK: - §27.4 rule 4: paging

    func testPageTotalIsTheServersCountNotThePageLength() async throws {
        let (client, _) = try await ManagementFixture.signedIn([
            (status: 200, body: Self.rolePage),
        ])

        let page = try await client.roles.list()

        // The fixture carries ONE item and a total of 412. A `Page` that reported
        // `total = items.count` passes every test written against a single-page fixture.
        XCTAssertEqual(page.count, 1)
        XCTAssertEqual(page.total, 412)
    }

    func testAutoPagingStopsOnAnEmptyPageNotAShortOne() async throws {
        let (client, transport) = try await ManagementFixture.signedIn([
            // A SHORT page: one item where 50 were asked for. Auto-paging must not stop.
            (status: 200, body: Self.rolePage),
            (status: 200, body: Self.rolePage),
            (status: 200, body: Self.emptyPage),
        ])

        var request = PageRequest()
        var seen = 0
        var offsets: [String] = []
        while true {
            let page = try await client.roles.list(page: request)
            offsets.append(transport.last?.query ?? "")
            if page.isEmpty { break }
            seen += page.count
            request = page.nextRequest
        }

        XCTAssertEqual(seen, 2)
        XCTAssertEqual(transport.count, 3)
        // Advanced by the REQUESTED limit, never by the short count — advancing by 1 would
        // re-request rows the caller has already seen.
        XCTAssertEqual(offsets, ["offset=0&limit=50", "offset=50&limit=50",
                                 "offset=100&limit=50"])
    }

    func testABareArrayOperationIsNotModelledAsAPage() async throws {
        let (client, _) = try await ManagementFixture.signedIn([
            (status: 200, body: "[]"),
        ])

        // `scopes.list` answers a bare JSON array. Typed as a page it would fail to decode;
        // the assertion is that this compiles and returns an Array.
        let scopes: [Scope] = try await client.scopes.list(resourceID: Self.uuid)

        XCTAssertTrue(scopes.isEmpty)
    }

    // MARK: - §27.4 rule 5: sparse vs replacement bodies

    func testASparseUpdateSerializesExactlyTheFieldsItWasGiven() async throws {
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 200, body: Self.roleObject),
        ])

        _ = try await client.roles.update(
            roleID: Self.uuid, body: UpdateRole(description: "only this"))

        let body = try XCTUnwrap(transport.last?.jsonBody)
        // The full key set, not "description is present". Asserting presence passes even
        // when `name` and `is_global` went along as explicit nulls — which is a REPLACEMENT,
        // and would blank both.
        XCTAssertEqual(Set(body.keys), ["description"])
    }

    func testAReplacementBodyCarriesEveryField() async throws {
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 200, body: Self.roleObject),
        ])

        // `CreateRoleRequest` has no defaults: every field is required, so a caller cannot
        // omit one. That is the type-level half of rule 5, and it is checked by this file
        // compiling at all.
        _ = try await client.roles.create(
            body: CreateRoleRequest(description: "Edits", isGlobal: false, name: "editor"))

        let body = try XCTUnwrap(transport.last?.jsonBody)
        XCTAssertEqual(Set(body.keys), ["description", "is_global", "name"])
    }

    func testAnUnsetQueryFilterIsOmittedRatherThanSentEmpty() async throws {
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 200, body: #"{"items": [], "total": 0}"#),
        ])

        _ = try await client.audit.list(action: "login")

        // `?outcome=` is a filter matching nothing, which is a different request from not
        // filtering at all.
        let query = try XCTUnwrap(transport.last?.query)
        XCTAssertTrue(query.contains("action=login"), query)
        XCTAssertFalse(query.contains("outcome="), query)
    }

    // MARK: - §27.4 rule 7: the error classification

    func testNotFoundIsCatchableAsAuthzError() async throws {
        let (client, _) = try await ManagementFixture.signedIn([
            (status: 404, body: #"{"message": "no such role"}"#),
        ])

        do {
            _ = try await client.roles.get(roleID: Self.uuid)
            XCTFail("expected a 404 to throw")
        } catch AxiamError.authz(let error) {
            // Under `.authz`, which is the surprising part and the deliberate part: AXIAM
            // answers 404 for an object in another tenant precisely so a probing caller
            // cannot tell "does not exist" from "exists, not yours".
            XCTAssertEqual(error.managementFailure, .notFound)
        }
    }

    func testConflictIsCatchableAsAuthzErrorAndIsNotRetried() async throws {
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 409, body: #"{"message": "already exists"}"#),
        ])

        do {
            _ = try await client.roles.create(
                body: CreateRoleRequest(description: "d", isGlobal: false, name: "editor"))
            XCTFail("expected a 409 to throw")
        } catch AxiamError.authz(let error) {
            XCTAssertEqual(error.managementFailure, .conflict)
        }
        XCTAssertEqual(transport.count, 1)
    }

    func testValidationIsCatchableAsNetworkErrorAndIsNotRetried() async throws {
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 422, body: #"{"message": "name is required"}"#),
            (status: 422, body: #"{"message": "name is required"}"#),
            (status: 422, body: #"{"message": "name is required"}"#),
        ])

        do {
            // A GET, so §16 would retry a NetworkError — and `ValidationError` IS one, by
            // rule 7's placement. Rule 8 plus the explicit exclusion is what stops a body
            // the server has already rejected from being sent three times.
            _ = try await client.roles.get(roleID: Self.uuid)
            XCTFail("expected a 422 to throw")
        } catch AxiamError.network(let error) {
            XCTAssertTrue(error.isValidation)
            XCTAssertEqual(error.statusCode, 422)
        }
        XCTAssertEqual(transport.count, 1)
    }

    func testAnOrdinary403StillMapsToPlainAuthzError() async throws {
        let (client, _) = try await ManagementFixture.signedIn([
            (status: 403, body: #"{"message": "forbidden"}"#),
        ])

        do {
            _ = try await client.roles.get(roleID: Self.uuid)
            XCTFail("expected a 403 to throw")
        } catch AxiamError.authz(let error) {
            // §2's mapping is untouched: no sub-type discriminator on an ordinary refusal.
            XCTAssertNil(error.managementFailure)
        }
    }

    // MARK: - §27.4 rule 6: deletes are not idempotent

    func testASecondDeleteSurfacesNotFoundAndIsNotSwallowed() async throws {
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 204, body: ""),
            (status: 404, body: #"{"message": "no such role"}"#),
        ])

        try await client.roles.delete(roleID: Self.uuid)

        do {
            try await client.roles.delete(roleID: Self.uuid)
            XCTFail("a second delete must not succeed")
        } catch AxiamError.authz(let error) {
            // "It was already gone" and "I deleted it" are different facts, and a
            // provisioning tool that cannot tell them apart cannot audit itself.
            XCTAssertEqual(error.managementFailure, .notFound)
        }
        XCTAssertEqual(transport.count, 2)
    }

    // MARK: - §27.4 rule 8: retry, and §9 refresh

    func testAFailedGetIsRetriedPerSection16() async throws {
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 503, body: ""),
            (status: 503, body: ""),
            (status: 200, body: Self.roleObject),
        ])

        _ = try await client.roles.get(roleID: Self.uuid)

        XCTAssertEqual(transport.count, 3)
    }

    func testAFailedWriteIsNotRetried() async throws {
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 503, body: ""),
            (status: 200, body: Self.roleObject),
        ])

        await XCTAssertThrowsErrorAsync(try await client.roles.create(
            body: CreateRoleRequest(description: "d", isGlobal: false, name: "editor")))

        // Exactly one. A retried POST the server did receive creates the object twice.
        XCTAssertEqual(transport.count, 1)
    }

    func testA401EntersTheRefreshGuardAndRetriesOnce() async throws {
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 401, body: #"{"message": "expired"}"#),
            // The refresh call goes through the same transport and consumes a script slot.
            (status: 200, body: #"{"expires_in": 900}"#),
            (status: 200, body: Self.roleObject),
        ])

        _ = try await client.roles.get(roleID: Self.uuid)

        XCTAssertEqual(transport.count, 3)
        XCTAssertEqual(transport.requests[1].path, "/api/v1/auth/refresh")
        XCTAssertEqual(transport.requests[2].path, "/api/v1/roles/\(Self.uuid)")
    }

    // MARK: - §27.4 rule 11: telemetry labels

    func testTelemetryLabelsCarryThePathTemplateNotTheInterpolatedPath() async throws {
        let recorder = EventRecorder()
        let (client, _) = try await ManagementFixture.signedIn(
            [(status: 200, body: Self.roleObject)], hook: recorder.hook)

        _ = try await client.roles.get(roleID: Self.uuid)

        let templates: [String] = recorder.events.compactMap {
            if case let .requestStart(_, _, pathTemplate, _) = $0 { return pathTemplate }
            return nil
        }
        // A label carrying the id makes every request its own metric series, which is how a
        // dashboard ends up with a hundred thousand series and no aggregate for the route.
        XCTAssertTrue(templates.contains("/api/v1/roles/{role_id}"), "\(templates)")
        XCTAssertFalse(templates.contains { $0.contains(Self.uuid) }, "\(templates)")
    }

    // MARK: - §27.5 one-time secrets

    func testAOneTimeSecretIsRedactedInEveryStringification() async throws {
        let secret = "sk_live_do_not_log_me"
        let body = """
            {"client_id": "svc-1", "client_secret": "\(secret)", \
            "created_at": "2026-08-26T00:00:00Z", "id": "\(Self.uuid)", "name": "device-1", \
            "status": "Active", "tenant_id": "\(Self.uuid)", \
            "updated_at": "2026-08-26T00:00:00Z"}
            """
        let (client, _) = try await ManagementFixture.signedIn([(status: 201, body: body)])

        let account = try await client.serviceAccounts.create(
            body: CreateServiceAccountRequest(name: "device-1"))

        // Scan the rendering for the fixture VALUE rather than asserting the type — a
        // `Sensitive` that printed its contents would satisfy a type assertion.
        XCTAssertFalse(String(describing: account).contains(secret))
        XCTAssertFalse("\(account.clientSecret)".contains(secret))
        XCTAssertEqual("\(account.clientSecret)", "[SENSITIVE]")

        // And it still reaches the caller who asks for it at the point of use.
        XCTAssertEqual(account.clientSecret.expose(), secret)
    }

    func testARequestSideSecretStillReachesTheWire() async throws {
        let secret = "whsec_abcdef"
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 201, body: """
                {"created_at": "2026-08-26T00:00:00Z", "enabled": true, \
                "events": ["user_created"], "id": "\(Self.uuid)", \
                "retry_policy": {"backoff_multiplier": 1.5, "initial_delay_secs": 1, \
                "max_retries": 3}, "tenant_id": "\(Self.uuid)", \
                "updated_at": "2026-08-26T00:00:00Z", "url": "https://example.test/hook"}
                """),
        ])

        _ = try await client.webhooks.create(body: CreateWebhookRequest(
            events: ["user_created"],
            secret: Sensitive(secret),
            url: "https://example.test/hook"))

        // §27.5 rule 1 wraps it so it cannot be logged by accident; the contract still
        // requires it on the wire, and `Sensitive` is deliberately not `Codable`, so the
        // generated `encode(to:)` unwraps it explicitly at exactly this one point.
        let sent = try XCTUnwrap(transport.last?.jsonBody)
        XCTAssertEqual(sent["secret"] as? String, secret)
    }

    func testTheGetProjectionHasNoSecretFieldAtAll() async throws {
        // §27.5 rule 3: a caller who discards a one-time secret because they can "fetch it
        // later" has destroyed the credential. The absence is structural — `Mirror` over the
        // read model finds no `clientSecret` to fetch.
        let read = ServiceAccountResponse(
            clientID: "svc-1", createdAt: "2026-08-26T00:00:00Z", id: Self.uuid,
            name: "device-1", status: .active, tenantID: Self.uuid,
            updatedAt: "2026-08-26T00:00:00Z")

        let properties = Mirror(reflecting: read).children.compactMap { $0.label }
        XCTAssertFalse(properties.contains("clientSecret"), "\(properties)")
    }
}
