import Foundation
import XCTest
@testable import AxiamSDK

/// CONTRACT.md §5.2 rule 1 — the acting tenant, `X-Axiam-Tenant` (contract 1.51).
///
/// §8 rule 7: "the acting-tenant header is sent when set and absent when not (the I4
/// twin)". This file also covers the gating (organization-level, `reachableTenantIDs`),
/// the C-12 candidate amendment adding the acting tenant to the §17 memo key, and that
/// `X-Axiam-Tenant` never rewrites a `{tenant_id}` path segment (§27.4 rule 3 is
/// unchanged by §5.2 rule 1).
final class ActingTenantTests: XCTestCase {

    private static let actingTenant = UUID(uuidString: "33333333-3333-4333-8333-333333333333")!
    private static let otherTenant = UUID(uuidString: "66666666-6666-4666-8666-666666666666")!
    private static let orgID = "11111111-1111-4111-8111-111111111111"
    /// A tenant id with hex LETTERS, so `.uuidString.lowercased()` actually differs from
    /// `.uuidString` — `actingTenant`/`otherTenant` above are all-digit and can't exercise
    /// N-5.6's case fix at all.
    private static let caseSensitiveTenant = UUID(uuidString: "AABBCCDD-EEFF-4AAB-8CCD-EEFFAABBCCDD")!

    /// Every request this client sends, recorded with its headers — answers `/auth/login`
    /// with a scripted `user` object, `/auth/refresh` and `/auth/logout` with a bare 200,
    /// `/authz/check` with an `allowed` decision, and anything under `/api/v1/resources`
    /// with an empty page (so a management call, e.g. `resources.list`, has something to
    /// decode).
    final class RecordingTransport: HTTPTransport, @unchecked Sendable {
        private let lock = NSLock()
        private let userJSON: Data
        private(set) var requests: [(method: String, path: String, headers: [(String, String)])] = []

        init(user: [String: Any]) {
            self.userJSON = (try? JSONSerialization.data(withJSONObject: user)) ?? Data()
        }

        func execute(_ spec: HTTPRequestSpec, timeout: TimeInterval) async throws -> HTTPResponseData {
            lock.locked {
                requests.append((spec.method.rawValue, spec.url.path, spec.headers))
                let path = spec.url.path
                if path.hasSuffix("/auth/login") {
                    var body = Data(#"{"session_id":"sess-1","expires_in":900,"user":"#.utf8)
                    body.append(userJSON)
                    body.append(Data("}".utf8))
                    return HTTPResponseData(
                        status: 200, headers: [("Content-Type", "application/json")], body: body)
                }
                if path.hasSuffix("/auth/refresh") || path.hasSuffix("/auth/logout") {
                    return HTTPResponseData(status: 200, headers: [], body: Data("{}".utf8))
                }
                if path.hasSuffix("/authz/check") {
                    return HTTPResponseData(
                        status: 200, headers: [("Content-Type", "application/json")],
                        body: Data(#"{"allowed":true}"#.utf8))
                }
                return HTTPResponseData(
                    status: 200, headers: [("Content-Type", "application/json")],
                    body: Data(#"{"items":[],"total":0}"#.utf8))
            }
        }

        func header(_ name: String, of index: Int) -> String? {
            requests[index].headers.first { $0.0.caseInsensitiveCompare(name) == .orderedSame }?.1
        }

        func shutdown() async throws {}
    }

    private func config(actingTenant: UUID? = nil, decisionMemoTtl: TimeInterval? = nil) throws -> AxiamConfig {
        try AxiamConfig(
            baseURL: URL(string: "https://iam.example.com")!,
            tenantID: "tenant-uuid-1",
            orgID: Self.orgID,
            actingTenant: actingTenant,
            retryEnabled: false,
            decisionMemoTtl: decisionMemoTtl)
    }

    private func loggedIn(
        user: [String: Any] = ["id": "u-1", "username": "alice", "email": "a@example.test",
                                "tenant_id": "tenant-uuid-1"],
        actingTenant: UUID? = nil
    ) async throws -> (AxiamClient, RecordingTransport) {
        let transport = RecordingTransport(user: user)
        let client = AxiamClient(config: try config(actingTenant: actingTenant), transport: transport)
        _ = try await client.login(email: "a@example.test", password: "pw")
        return (client, transport)
    }

    // MARK: - §8 rule 7: sent when set, absent when not (the I4 twin)

    func testHeaderSentWhenSetAtConstruction() async throws {
        let (client, transport) = try await loggedIn(actingTenant: Self.actingTenant)
        _ = try await client.checkAccess("read", resource: "doc-1")
        let last = transport.requests.count - 1
        XCTAssertEqual(transport.header("X-Axiam-Tenant", of: last), Self.actingTenant.uuidString)
    }

    /// The I4 twin: a client that never set an acting tenant sends no header at all — byte
    /// for byte what every client sent before contract 1.51.
    func testHeaderAbsentWhenNotSet() async throws {
        let (client, transport) = try await loggedIn()
        _ = try await client.checkAccess("read", resource: "doc-1")
        let last = transport.requests.count - 1
        XCTAssertNil(transport.header("X-Axiam-Tenant", of: last))
    }

    /// The Java lesson (C-4, sent back): present on refresh, logout, and a management
    /// call — not only on `checkAccess`.
    func testHeaderPresentOnRefreshLogoutAndManagementCalls() async throws {
        let (client, transport) = try await loggedIn(actingTenant: Self.actingTenant)

        try await client.refresh()
        let refreshIndex = transport.requests.count - 1
        XCTAssertTrue(transport.requests[refreshIndex].path.hasSuffix("/auth/refresh"))
        XCTAssertEqual(transport.header("X-Axiam-Tenant", of: refreshIndex), Self.actingTenant.uuidString)

        _ = try await client.resources.list()
        let mgmtIndex = transport.requests.count - 1
        XCTAssertEqual(transport.header("X-Axiam-Tenant", of: mgmtIndex), Self.actingTenant.uuidString)

        try await client.logout()
        let logoutIndex = transport.requests.count - 1
        XCTAssertTrue(transport.requests[logoutIndex].path.hasSuffix("/auth/logout"))
        XCTAssertEqual(transport.header("X-Axiam-Tenant", of: logoutIndex), Self.actingTenant.uuidString)
    }

    /// §5.2.2 rule 4: a self-service endpoint — one scoped to the CALLER'S OWN user id —
    /// still gets the header. "Self-service ignores X-Axiam-Tenant" is a rule about what
    /// the SERVER does with it (it scopes the request to `principal_tenant_id` regardless
    /// of what the header names); an SDK MUST NOT help that along by clearing or rewriting
    /// the header for those calls — "send the header as normal; the server decides." The
    /// Java port (C-4) was sent back for exactly this omission.
    ///
    /// `resendOwnVerification()` (`POST /users/me/resend-verification`) is one of the
    /// endpoints §5.2.2 rule 4 names explicitly.
    func testHeaderPresentOnASelfServicePOST() async throws {
        let (client, transport) = try await loggedIn(actingTenant: Self.actingTenant)
        try await client.resendOwnVerification()
        let last = transport.requests.count - 1
        XCTAssertTrue(transport.requests[last].path.hasSuffix("/users/me/resend-verification"))
        XCTAssertEqual(transport.header("X-Axiam-Tenant", of: last), Self.actingTenant.uuidString)
    }

    /// The I4 twin: absent when not set, on the SAME self-service call.
    func testHeaderAbsentOnASelfServicePOSTWhenNotSet() async throws {
        let (client, transport) = try await loggedIn()
        try await client.resendOwnVerification()
        let last = transport.requests.count - 1
        XCTAssertTrue(transport.requests[last].path.hasSuffix("/users/me/resend-verification"))
        XCTAssertNil(transport.header("X-Axiam-Tenant", of: last))
    }

    /// §27.4 rule 3 is unchanged: the acting tenant never rewrites a `{tenant_id}` path
    /// segment. `tenants.get(tenantID:)` — where `{tenant_id}` names the OBJECT being
    /// read, not the context — still names THAT tenant in the path, independent of what
    /// `X-Axiam-Tenant` carries; the header and the path are read by different mechanisms.
    func testActingTenantDoesNotRewriteATenantIDPathSegment() async throws {
        let (client, transport) = try await loggedIn(actingTenant: Self.actingTenant)
        _ = try? await client.tenants.get(tenantID: Self.otherTenant.uuidString)
        let last = transport.requests.count - 1
        XCTAssertTrue(transport.requests[last].path.contains(Self.otherTenant.uuidString))
        XCTAssertEqual(transport.header("X-Axiam-Tenant", of: last), Self.actingTenant.uuidString)
    }

    // MARK: - Gating (§5.2 rule 1): "gate it on what the SDK knows"

    /// A client holding a login result that is NOT organization-level is refused
    /// client-side, with ZERO wire calls (only the login request is on record).
    ///
    /// CONTRACT 1.52 N-5 (C-12): the gate refusal is `AuthzError` — the 403 the server
    /// would answer for the same header change — never `AuthError`.
    func testOnClientRebindRefusesANonOrganizationLevelPrincipalWithZeroWireCalls() async throws {
        let (client, transport) = try await loggedIn() // organization_level defaults false
        let before = transport.requests.count
        do {
            try await client.actingTenant(Self.actingTenant)
            XCTFail("expected a client-side refusal")
        } catch AxiamError.authz {
            // ok
        }
        XCTAssertEqual(transport.requests.count, before, "no request should have been sent")
    }

    /// §5.2.3 rule 4: a tenant outside `reachableTenantIDs` is refused the same way.
    ///
    /// CONTRACT 1.52 N-5 (C-12): also `AuthzError`, not `AuthError`.
    func testOnClientRebindRefusesATenantOutsideReachableTenantIDsWithZeroWireCalls() async throws {
        let (client, transport) = try await loggedIn(user: [
            "id": "u-1", "username": "alice", "email": "a@example.test",
            "tenant_id": "tenant-uuid-1", "organization_level": true,
            "reachable_tenant_ids": [Self.otherTenant.uuidString],
        ])
        let before = transport.requests.count
        do {
            try await client.actingTenant(Self.actingTenant) // not in reachableTenantIDs
            XCTFail("expected a client-side refusal")
        } catch AxiamError.authz {
            // ok
        }
        XCTAssertEqual(transport.requests.count, before)
    }

    /// The positive case: an organization-level principal switching to a tenant inside
    /// its `reachableTenantIDs` succeeds, and the header reaches the wire.
    func testOnClientRebindSucceedsForAnOrganizationLevelPrincipalWithinReach() async throws {
        let (client, transport) = try await loggedIn(user: [
            "id": "u-1", "username": "alice", "email": "a@example.test",
            "tenant_id": "tenant-uuid-1", "organization_level": true,
            "reachable_tenant_ids": [Self.actingTenant.uuidString],
        ])
        try await client.actingTenant(Self.actingTenant)
        _ = try await client.checkAccess("read", resource: "doc-1")
        let last = transport.requests.count - 1
        XCTAssertEqual(transport.header("X-Axiam-Tenant", of: last), Self.actingTenant.uuidString)
    }

    /// CONTRACT 1.52 N-5.6 (C-12): tenant ids compare as UUIDs, never as strings — case
    /// and formatting MUST NOT decide reach. `UUID.uuidString` is always upper-case, but a
    /// real server sends `reachable_tenant_ids` lower-case (`format_uuid_lowercase` on the
    /// wire). A case-sensitive `[String].contains` wrongly refuses this legitimate switch.
    func testOnClientRebindSucceedsWhenServerReachableTenantIDsAreLowercase() async throws {
        let lowercaseFixture = Self.caseSensitiveTenant.uuidString.lowercased()
        XCTAssertNotEqual(
            lowercaseFixture, Self.caseSensitiveTenant.uuidString,
            "the fixture must actually differ in case for this test to mean anything")
        let (client, transport) = try await loggedIn(user: [
            "id": "u-1", "username": "alice", "email": "a@example.test",
            "tenant_id": "tenant-uuid-1", "organization_level": true,
            "reachable_tenant_ids": [lowercaseFixture],
        ])
        try await client.actingTenant(Self.caseSensitiveTenant)
        _ = try await client.checkAccess("read", resource: "doc-1")
        let last = transport.requests.count - 1
        XCTAssertEqual(transport.header("X-Axiam-Tenant", of: last), Self.caseSensitiveTenant.uuidString)
    }

    /// The I4 twin of the case-insensitivity fix: a tenant that is genuinely outside
    /// `reachableTenantIDs` (not merely a case mismatch) is still refused once ids compare
    /// as UUIDs — the fix must not over-reach into accepting anything.
    func testOnClientRebindStillRefusesAGenuinelyUnreachableTenantWithLowercaseFixtures() async throws {
        let (client, transport) = try await loggedIn(user: [
            "id": "u-1", "username": "alice", "email": "a@example.test",
            "tenant_id": "tenant-uuid-1", "organization_level": true,
            "reachable_tenant_ids": [Self.otherTenant.uuidString.lowercased()],
        ])
        let before = transport.requests.count
        do {
            try await client.actingTenant(Self.actingTenant) // not in reachableTenantIDs, any case
            XCTFail("expected a client-side refusal")
        } catch AxiamError.authz {
            // ok
        }
        XCTAssertEqual(transport.requests.count, before)
    }

    /// "A client holding no login result has nothing to gate on. It sends the header as
    /// asked and lets the server's 403 answer" — an organization-level SERVICE ACCOUNT is
    /// a supported design this client cannot distinguish from here, so `checkAccess`
    /// (which needs no prior login) still carries the header when set at construction.
    func testHeaderSentForAClientHoldingNoLoginResult() async throws {
        let transport = RecordingTransport(user: [:])
        let client = AxiamClient(config: try config(actingTenant: Self.actingTenant), transport: transport)
        _ = try await client.checkAccess("read", resource: "doc-1")
        let last = transport.requests.count - 1
        XCTAssertEqual(transport.header("X-Axiam-Tenant", of: last), Self.actingTenant.uuidString)
    }

    // MARK: - Clearing

    func testClearingRemovesTheHeader() async throws {
        let (client, transport) = try await loggedIn(actingTenant: Self.actingTenant)
        try await client.actingTenant(nil)
        _ = try await client.checkAccess("read", resource: "doc-1")
        let last = transport.requests.count - 1
        XCTAssertNil(transport.header("X-Axiam-Tenant", of: last))
    }

    func testClearActingTenantHelperRemovesTheHeader() async throws {
        let (client, transport) = try await loggedIn(actingTenant: Self.actingTenant)
        await client.clearActingTenant()
        _ = try await client.checkAccess("read", resource: "doc-1")
        let last = transport.requests.count - 1
        XCTAssertNil(transport.header("X-Axiam-Tenant", of: last))
    }

    // MARK: - §17 memo key (C-12 candidate amendment)

    /// Without the acting tenant in the key, a memoized answer for tenant A would be
    /// returned for tenant B within the TTL. Two identical checks under two different
    /// acting tenants must both reach the wire.
    func testTheDecisionMemoKeyIncludesTheActingTenantSoCrossTenantAnswersDoNotCollide() async throws {
        let transport = RecordingTransport(user: [
            "id": "u-1", "username": "alice", "email": "a@example.test",
            "tenant_id": "tenant-uuid-1", "organization_level": true,
            "reachable_tenant_ids": [Self.actingTenant.uuidString, Self.otherTenant.uuidString],
        ])
        let client = AxiamClient(
            config: try config(decisionMemoTtl: 5), transport: transport)
        _ = try await client.login(email: "a@example.test", password: "pw")

        try await client.actingTenant(Self.actingTenant)
        _ = try await client.checkAccess("read", resource: "doc-1")
        let afterFirst = transport.requests.count

        try await client.actingTenant(Self.otherTenant)
        _ = try await client.checkAccess("read", resource: "doc-1")
        let afterSecond = transport.requests.count

        XCTAssertEqual(afterSecond, afterFirst + 1, "the second tenant's check must reach the wire")

        // And the SAME tenant, asked again within the TTL, DOES hit the memo.
        try await client.actingTenant(Self.actingTenant)
        _ = try await client.checkAccess("read", resource: "doc-1")
        XCTAssertEqual(transport.requests.count, afterSecond, "a repeat for the SAME acting tenant must hit the memo")
    }
}
