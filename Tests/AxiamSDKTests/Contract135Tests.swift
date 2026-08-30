import Foundation
import XCTest
@testable import AxiamSDK

/// Contract 1.34 §5.2.2 and contract 1.35 §5.2.3 — the acting tenant vs the principal
/// tenant, and tenant-scoped role assignments.
///
/// Two of these rules are the kind an SDK breaks silently rather than loudly, which is why
/// they are pinned here rather than left to the generated conformance suite:
///
/// - **§5.2.2 rule 2.** A registration record for the caller's *own* password is sealed
///   against the tenant the account lives in, not the one the client is pointed at. Get it
///   wrong and the server answers "the OPAQUE session was issued for a different tenant" —
///   but only for an organization-level principal that has switched tenant, so it passes
///   every test written against an ordinary account.
/// - **§5.2.3 rule 1.** `tenant_scope: []` is refused with `400`. `encodeIfPresent` alone
///   does not prevent it: it covers `nil` and nothing else, and an empty array is exactly
///   what building the field from a filtered collection produces for "no tenants named".
final class Contract135Tests: XCTestCase {

    private static let actingTenant = "33333333-3333-4333-8333-333333333333"
    private static let principalTenant = "55555555-5555-4555-8555-555555555555"
    private static let orgID = "11111111-1111-4111-8111-111111111111"
    private static let reachableTenant = "66666666-6666-4666-8666-666666666666"
    private static let scopedTenant = "88888888-8888-4888-8888-888888888888"
    private static let someID = "99999999-9999-4999-8999-999999999999"

    /// The hex `RegistrationResponse` the fake server answers with.
    private static let wireRegistrationResponse = "726573703a"

    private var lib: FakeOpaqueNative!

    /// Minted per run rather than written down. Nothing here depends on the value — the login
    /// stub answers 200 regardless, so what is under test is which tenant the body names,
    /// never whether a credential matched — and a literal that reads like a credential is a
    /// finding for every secret scanner that looks at this repository.
    private var password = ""

    override func setUp() {
        super.setUp()
        lib = FakeOpaqueNative()
        OpaqueLibrary.setForTests(lib)
        password = "fixture-"
            + (0..<8).map { _ in String(format: "%02x", UInt8.random(in: 0...255)) }.joined()
    }

    override func tearDown() {
        OpaqueLibrary.resetForTests()
        lib = nil
        super.tearDown()
    }

    // MARK: - The transport

    /// Answers `/auth/login` with a scripted `user` object and `/auth/opaque/register/start`
    /// with a record the fake library can finish.
    final class ScopedTransport: HTTPTransport, @unchecked Sendable {
        private let lock = NSLock()
        private let user: Data

        private(set) var registerStartBodies: [Data] = []
        private(set) var requestCount = 0

        init(user: [String: Any]) {
            self.user = (try? JSONSerialization.data(withJSONObject: user)) ?? Data()
        }

        func execute(_ spec: HTTPRequestSpec, timeout: TimeInterval) async throws
            -> HTTPResponseData
        {
            lock.locked { respond(to: spec) }
        }

        private func json(_ status: Int, _ body: Data) -> HTTPResponseData {
            HTTPResponseData(
                status: status, headers: [("Content-Type", "application/json")], body: body)
        }

        private func respond(to spec: HTTPRequestSpec) -> HTTPResponseData {
            requestCount += 1
            let path = spec.url.path

            if path.hasSuffix("/auth/opaque/register/start") {
                registerStartBodies.append(spec.body ?? Data())
                let body: [String: Any] = [
                    "opaque_session": "reg-handle",
                    "registration_response": Contract135Tests.wireRegistrationResponse,
                    "ksf": "argon2id",
                    "memory_kib": 19456,
                    "iterations": 2,
                    "parallelism": 1,
                ]
                return json(200, (try? JSONSerialization.data(withJSONObject: body)) ?? Data())
            }

            if path.hasSuffix("/auth/login") {
                // Assembled from the pre-serialized user so nothing non-Sendable crosses
                // into this nonisolated context, the same reason ManagementStubTransport
                // serializes its login answer once.
                var body = Data(#"{"session_id":"sess-1","expires_in":900,"user":"#.utf8)
                body.append(user)
                body.append(Data("}".utf8))
                return json(200, body)
            }

            return json(404, Data(#"{"message":"not found"}"#.utf8))
        }

        func shutdown() async throws {}
    }

    /// A client pointed at the acting tenant **by slug**.
    ///
    /// A slug rather than the UUID on purpose: the register/start body carries `tenant_slug`
    /// for one and `tenant_id` for the other, and §5.2.2 rule 2's override has to *replace*
    /// the slug it finds. Against a UUID tenant there is no slug to displace, so "no
    /// `tenant_slug` in the body" would pass against an implementation that never displaced
    /// anything.
    private func client(_ transport: ScopedTransport) throws -> AxiamClient {
        let config = try AxiamConfig(
            baseURL: URL(string: "https://iam.example.com")!,
            tenantSlug: "acme",
            orgID: Self.orgID,
            retryEnabled: false
        )
        return AxiamClient(config: config, transport: transport)
    }

    private func signIn(_ transport: ScopedTransport) async throws -> (AxiamClient, AxiamUser) {
        let c = try client(transport)
        guard case let .authenticated(user) = try await c.login(
            email: "alice@example.com", password: password)
        else {
            XCTFail("expected an authenticated login")
            throw AxiamError.network(NetworkError("login did not authenticate"))
        }
        return (c, user)
    }

    private func decoded(_ body: Data) throws -> [String: Any] {
        (try JSONSerialization.jsonObject(with: body)) as? [String: Any] ?? [:]
    }

    // MARK: - §5.2.2 — acting tenant vs principal tenant

    func testAnAbsentPrincipalTenantReadsAsTheActingTenant() async throws {
        // A server older than contract 1.34 omits `principal_tenant_id` and cannot switch
        // the acting tenant either, so reading `tenant_id` there is not a guess — it is the
        // only value the field could have had.
        let transport = ScopedTransport(user: [
            "id": "u-1", "username": "alice", "email": "alice@example.test",
            "tenant_id": Self.actingTenant,
        ])
        let (_, user) = try await signIn(transport)

        XCTAssertEqual(user.tenantID, Self.actingTenant)
        XCTAssertEqual(user.principalTenantID, Self.actingTenant)
        XCTAssertNil(user.principalTenantSlug)
    }

    func testADivergentPrincipalTenantIsReportedSeparately() async throws {
        let transport = ScopedTransport(user: [
            "id": "u-1", "username": "alice", "email": "alice@example.test",
            "tenant_id": Self.actingTenant,
            "principal_tenant_id": Self.principalTenant,
            "principal_tenant_slug": "organization",
            "org_id": Self.orgID,
            "organization_level": true,
        ])
        let (_, user) = try await signIn(transport)

        XCTAssertTrue(user.organizationLevel)
        XCTAssertEqual(user.tenantID, Self.actingTenant)
        XCTAssertEqual(user.principalTenantID, Self.principalTenant)
        XCTAssertEqual(user.principalTenantSlug, "organization")
        // Rule 3: read the organization from the session rather than resolving a slug
        // through the `super-admin`-only `GET /api/v1/organizations`.
        XCTAssertEqual(user.orgID, Self.orgID)
    }

    func testReachableTenantIDsNarrowsAnOrganizationLevelPrincipal() async throws {
        let transport = ScopedTransport(user: [
            "id": "u-1", "username": "alice", "email": "alice@example.test",
            "tenant_id": Self.actingTenant,
            "organization_level": true,
            "reachable_tenant_ids": [Self.reachableTenant],
        ])
        let (_, user) = try await signIn(transport)

        // Still true — which is exactly why gating a tenant switcher on this flag alone
        // offers tenants the server refuses at the header.
        XCTAssertTrue(user.organizationLevel)
        XCTAssertEqual(user.reachableTenantIDs, [Self.reachableTenant])
    }

    func testAbsentReachIsUnrestrictedAndSoIsAnEmptyOne() async throws {
        // `nil` means UNRESTRICTED. An empty list would read as "reaches nothing", the
        // opposite of what an omitted field means here — so an empty list on the wire
        // arrives as `nil` too.
        let absent = ScopedTransport(user: [
            "id": "u-1", "username": "alice", "email": "alice@example.test",
            "tenant_id": Self.actingTenant,
        ])
        let (_, absentUser) = try await signIn(absent)
        XCTAssertNil(absentUser.reachableTenantIDs)

        let empty = ScopedTransport(user: [
            "id": "u-1", "username": "alice", "email": "alice@example.test",
            "tenant_id": Self.actingTenant,
            "reachable_tenant_ids": [String](),
        ])
        let (_, emptyUser) = try await signIn(empty)
        XCTAssertNil(emptyUser.reachableTenantIDs)
    }

    // MARK: - §5.2.2 rule 2 — which tenant a registration record is sealed against

    func testEnrolmentForSelfSealsAgainstThePrincipalTenant() async throws {
        let transport = ScopedTransport(user: [
            "id": "u-1", "username": "alice", "email": "alice@example.test",
            "tenant_id": Self.actingTenant,
            "principal_tenant_id": Self.principalTenant,
            "organization_level": true,
        ])
        let (c, _) = try await signIn(transport)

        let enrollment = try await c.opaqueEnrollmentForSelf(password: password)

        let body = try decoded(transport.registerStartBodies[0])
        XCTAssertEqual(body["tenant_id"] as? String, Self.principalTenant)
        // A slug naming the acting tenant would out-vote the principal tenant id
        // server-side, which is the exact confusion this method exists to avoid.
        XCTAssertNil(body["tenant_slug"])
        // The organization half of the workspace still travels: it identifies the
        // organization, not the tenant.
        XCTAssertEqual(body["org_id"] as? String, Self.orgID)
        XCTAssertEqual(enrollment.opaque_session, "reg-handle")
    }

    func testPlainEnrolmentStillSealsAgainstTheActingTenant() async throws {
        // The other call site, unchanged: a record for *another* account is sealed against
        // the tenant being acted on, which is what the client is already pointed at.
        let transport = ScopedTransport(user: [
            "id": "u-1", "username": "alice", "email": "alice@example.test",
            "tenant_id": Self.actingTenant,
            "principal_tenant_id": Self.principalTenant,
            "organization_level": true,
        ])
        let (c, _) = try await signIn(transport)

        _ = try await c.opaqueEnrollment(password: password)

        let body = try decoded(transport.registerStartBodies[0])
        XCTAssertEqual(body["tenant_slug"] as? String, "acme")
        XCTAssertNil(body["tenant_id"])
    }

    func testEnrolmentForSelfRefusesBeforeALogin() async throws {
        // There is no principal tenant to seal against yet, and falling back to the acting
        // one is exactly the bug this method exists to prevent.
        let transport = ScopedTransport(user: [:])
        let c = try client(transport)

        do {
            _ = try await c.opaqueEnrollmentForSelf(password: password)
            XCTFail("expected a network error")
        } catch let AxiamError.network(error) {
            XCTAssertTrue(error.message.contains("principal tenant"), error.message)
        }
        // The request that must NOT happen.
        XCTAssertEqual(transport.requestCount, 0)
    }

    // MARK: - §5.2.3 rules 1 and 2 — tenant_scope on an assignment

    func testAnEmptyTenantScopeNeverReachesTheWire() async throws {
        // `[]` is refused with 400, and an empty array is what building the field from a
        // filtered collection produces for "no tenants named", so both spellings of absent
        // must travel the same way: by not appearing.
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 204, body: ""),
        ])

        try await client.roles.assignToUser(
            roleID: Self.someID,
            body: AssignRoleToUserRequest(tenantScope: [], userID: Self.someID))

        let body = try XCTUnwrap(transport.last?.jsonBody)
        XCTAssertNil(body["tenant_scope"])
        // ...and the rest of the body survives the removal.
        XCTAssertEqual(body["user_id"] as? String, Self.someID)
    }

    func testANamedTenantScopeIsSentOnAllThreeBodies() async throws {
        // Dropping a scope the caller *did* name would turn a refusal they need to see into
        // a success that silently applied no restriction.
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 204, body: ""),
            (status: 204, body: ""),
            (status: 204, body: ""),
        ])
        let scope = [Self.scopedTenant]

        try await client.roles.assignToUser(
            roleID: Self.someID,
            body: AssignRoleToUserRequest(tenantScope: scope, userID: Self.someID))
        XCTAssertEqual(transport.last?.jsonBody?["tenant_scope"] as? [String], scope)

        try await client.roles.assignToGroup(
            roleID: Self.someID,
            body: AssignRoleToGroupRequest(groupID: Self.someID, tenantScope: scope))
        XCTAssertEqual(transport.last?.jsonBody?["tenant_scope"] as? [String], scope)

        try await client.roles.assignToServiceAccount(
            roleID: Self.someID,
            body: AssignRoleToServiceAccountRequest(
                serviceAccountID: Self.someID, tenantScope: scope))
        XCTAssertEqual(transport.last?.jsonBody?["tenant_scope"] as? [String], scope)
    }

    func testOtherEmptyListsAreStillSent() async throws {
        // The allowlist is one field wide on purpose: elsewhere `[]` is meaningful — a
        // replacement body clearing a list — and dropping it would make "remove every entry"
        // inexpressible.
        let webhook = """
            {"created_at": "2026-08-30T00:00:00Z", "enabled": true, "events": [], \
            "id": "\(Self.someID)", "retry_policy": {"backoff_multiplier": 1.5, \
            "initial_delay_secs": 1, "max_retries": 1}, "tenant_id": "\(Self.orgID)", \
            "updated_at": "2026-08-30T00:00:00Z", "url": "https://hook.example"}
            """
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 200, body: webhook),
        ])

        _ = try await client.management.webhooks.update(
            id: Self.someID, body: UpdateWebhookRequest(events: []))

        let body = try XCTUnwrap(transport.last?.jsonBody)
        XCTAssertEqual(body["events"] as? [String], [])
    }
}
