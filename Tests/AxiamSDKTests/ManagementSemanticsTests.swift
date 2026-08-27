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

    // MARK: - §27.4 rule 4: search

    func testASearchTermReachesTheQueryString() async throws {
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 200, body: Self.rolePage),
        ])

        _ = try await client.roles.list(page: PageRequest(search: "ada"))

        // Asserted on the request URI, not on the argument: a term the SDK accepts and
        // never sends is exactly the failure this test exists for — every caller-side
        // assertion still passes while the server returns the unfiltered set.
        XCTAssertEqual(transport.last?.query, "offset=0&limit=50&search=ada")
    }

    func testNoSearchTermSendsNoSearchKey() async throws {
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 200, body: Self.rolePage),
        ])

        _ = try await client.roles.list(page: PageRequest(offset: 0, limit: 25))

        // The exact query string, not "does not contain search=". `?search=` is a filter
        // matching nothing, which is a different request from not filtering.
        XCTAssertEqual(transport.last?.query, "offset=0&limit=25")
    }

    func testABlankSearchTermIsTheSameRequestAsNone() async throws {
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 200, body: Self.rolePage),
            (status: 200, body: Self.rolePage),
            (status: 200, body: Self.rolePage),
        ])

        // A search box that fires on every keystroke sends one the moment it is cleared,
        // and "rows containing the empty string" is a different question from "all rows".
        for blank in ["", "   ", "\t\n"] {
            _ = try await client.roles.list(page: PageRequest(offset: 0, limit: 25,
                                                              search: blank))
            XCTAssertEqual(transport.last?.query, "offset=0&limit=25",
                           "a blank term must send no search key")
        }
    }

    func testASearchTermIsTrimmedButNotShortened() async throws {
        let long = String(repeating: "a", count: 300)
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 200, body: Self.rolePage),
        ])

        _ = try await client.roles.list(page: PageRequest(search: "  \(long)  "))

        // The server caps the term's length; re-implementing that cap here would make a
        // client-side truncation the server would not have made into a silently different
        // query the caller cannot see.
        XCTAssertEqual(transport.last?.query, "offset=0&limit=50&search=\(long)")
    }

    func testAWalkCarriesTheSearchTermOnEveryRequest() async throws {
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 200, body: Self.rolePage),
            (status: 200, body: Self.rolePage),
            (status: 200, body: Self.emptyPage),
        ])

        var request = PageRequest(offset: 0, limit: 50, search: "ada")
        while true {
            let page = try await client.roles.list(page: request)
            if page.isEmpty { break }
            request = page.nextRequest
        }

        // Asserted on EVERY recorded request, not on the count: a walk that filtered only
        // its first request returns the matches followed by the unfiltered tail, which
        // reads as a server bug from the caller's side.
        XCTAssertEqual(transport.requests.map(\.query), [
            "offset=0&limit=50&search=ada",
            "offset=50&limit=50&search=ada",
            "offset=100&limit=50&search=ada",
        ])
    }

    func testTheTermRidesOnThePageRequestAndCopiesRatherThanMutates() async throws {
        let original = PageRequest(offset: 10, limit: 25, search: "ada")

        let other = original.matching("grace")

        XCTAssertEqual(original.search, "ada")
        XCTAssertEqual(other.search, "grace")
        XCTAssertEqual(other.offset, 10)
        XCTAssertEqual(other.limit, 25)
        // `next()` keeps the raw term verbatim; normalisation happens on the wire.
        XCTAssertEqual(original.next().search, "ada")
        XCTAssertEqual(original.next().offset, 35)
    }

    // MARK: - §27.11: model additions

    func testAnUnknownEnumValueDecodesInsteadOfFailingThePage() async throws {
        // Two tenants, and only the second has a `kind` this SDK has never seen. A closed
        // enum would throw while decoding it and take the first one — which the caller did
        // ask for — down with it. That blast radius is what §27.11 rule 1 is about.
        let ordinary = Self.tenantRow(slug: "ordinary", kind: "standard")
        let future = Self.tenantRow(slug: "future", kind: "sandbox")
        let page = "{\"items\": [\(ordinary), \(future)], \"total\": 2}"
        let (client, _) = try await ManagementFixture.signedIn([(status: 200, body: page)])

        let tenants = try await client.tenants.list()

        XCTAssertEqual(tenants.count, 2)
        XCTAssertEqual(tenants.items[0].kind, TenantKind.standard)
        XCTAssertEqual(tenants.items[1].kind, TenantKind.unknown)
    }

    func testAnAbsentTenantKindDecodesAsNil() async throws {
        let page = "{\"items\": [\(Self.tenantRow(slug: "legacy", kind: nil))], \"total\": 1}"
        let (client, _) = try await ManagementFixture.signedIn([(status: 200, body: page)])

        let tenants = try await client.tenants.list()

        XCTAssertNil(tenants.items[0].kind)
    }

    func testTenantKindIsReadOnly() throws {
        // §27.11 rule 2: an organization's scope tenant is reserved at organization
        // creation and enforced by a unique index. A client able to set the field could
        // ask for a second one, and the request would be refused at the database rather
        // than at the type. Asserted on the ENCODED body, which is what reaches the server.
        let created = try JSONEncoder().encode(
            CreateTenantRequest(name: "acme", slug: "acme"))
        let updated = try JSONEncoder().encode(UpdateTenant(name: "renamed"))

        XCTAssertFalse(String(decoding: created, as: UTF8.self).contains("kind"))
        XCTAssertFalse(String(decoding: updated, as: UTF8.self).contains("kind"))
    }

    func testTrustedAnchorsKeepsNilDistinctFromZero() throws {
        // §27.11 rule 3: "the listener trusts no CAs" and "there was no listener to ask"
        // are different operational states, and only one of them is a problem. Coalescing
        // the first to 0 reports a healthy plaintext deployment as a broken TLS one.
        let notReloaded = try JSONDecoder().decode(MtlsTrustAnchorResponse.self, from: Data("""
            {"ca_certificate_id": "\(Self.uuid)", "message": "stored; applies at next start", \
            "mtls_trust_anchor": true, "restart_required": true}
            """.utf8))
        let reloadedEmpty = try JSONDecoder().decode(MtlsTrustAnchorResponse.self, from: Data("""
            {"ca_certificate_id": "\(Self.uuid)", "message": "reloaded", \
            "mtls_trust_anchor": false, "restart_required": false, "trusted_anchors": 0}
            """.utf8))

        XCTAssertNil(notReloaded.trustedAnchors)
        XCTAssertEqual(reloadedEmpty.trustedAnchors, 0)
    }

    func testTheCertificateProjectionIsListOnlyAndCostsNoSecondRequest() async throws {
        let bound = ManagementFixture.otherOrg
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 200,
             body: "{\"items\": [\(Self.certificateRow(boundServiceAccountID: bound))], "
                 + "\"total\": 1}"),
            (status: 200, body: Self.certificateRow(boundServiceAccountID: nil)),
        ])

        let listed = try await client.certificates.list()
        let fetched = try await client.certificates.get(id: Self.uuid)

        XCTAssertEqual(listed.items[0].boundServiceAccountID, bound)
        // §27.11 rule 4: null on `get` means "this read does not carry it", not "there is
        // nothing bound" — and the SDK does not go and fetch it. A `get` that silently
        // costs two round trips is what §27.4 rule 3 forbids for slug resolution.
        XCTAssertNil(fetched.boundServiceAccountID)
        XCTAssertEqual(transport.count, 2)
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

    /// A minimal `Tenant` row as the server would send it. `kind` is the bare wire value,
    /// or `nil` to leave the property out entirely.
    private static func tenantRow(slug: String, kind: String?) -> String {
        let kindPair = kind.map { ", \"kind\": \"\($0)\"" } ?? ""
        return """
            {"created_at": "2026-08-26T00:00:00Z", "id": "\(uuid)", "metadata": {}, \
            "name": "\(slug)", "organization_id": "\(ManagementFixture.orgID)", \
            "slug": "\(slug)", "status": "Active", "updated_at": "2026-08-26T00:00:00Z"\(kindPair)}
            """
    }

    /// A minimal `Certificate` row, with or without the list-only projection.
    private static func certificateRow(boundServiceAccountID: String?) -> String {
        let bound = boundServiceAccountID
            .map { ", \"bound_service_account_id\": \"\($0)\"" } ?? ""
        return """
            {"cert_type": "Device", "created_at": "2026-08-26T00:00:00Z", \
            "fingerprint": "aa:bb", "id": "\(uuid)", "issuer_ca_id": "\(uuid)", \
            "key_algorithm": "Ed25519", "metadata": {}, "not_after": "2027-08-26T00:00:00Z", \
            "not_before": "2026-08-26T00:00:00Z", "public_cert_pem": "-----BEGIN CERTIFICATE-----", \
            "status": "Active", "subject": "CN=device-001", "tenant_id": "\(uuid)"\(bound)}
            """
    }
}
