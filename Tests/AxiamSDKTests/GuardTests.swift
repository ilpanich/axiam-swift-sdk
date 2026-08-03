import XCTest
import Foundation
@testable import AxiamSDK

final class GuardTests: XCTestCase {
    let signer = TestSigner()

    /// The tenant UUID the test tokens are issued for. Since SEC-072 the guard binds every
    /// verified session to the *configured* tenant, so the client must be configured with the
    /// same UUID the `tenant_id` claim carries (a slug cannot match a UUID claim).
    static let tenantUUID = "tenant-uuid-1"

    /// `withClient`, with the client configured for ``tenantUUID``.
    private func withGuardClient(
        tenantID: String = GuardTests.tenantUUID,
        router: @escaping TestRouter,
        body: (AxiamClient, TestHTTPServer) async throws -> Void
    ) async throws {
        try await withClient(
            makeConfig: { try TestKit.makeConfig(port: $0, tenantSlug: nil, tenantID: tenantID) },
            router: router,
            body: body
        )
    }

    /// A router that serves JWKS and authz, counting each by key.
    private func makeRouter(authzAllowed: Bool = true) -> TestRouter {
        let signer = self.signer
        return { request, state in
            if request.uri.hasSuffix("/oauth2/jwks") {
                state.increment("jwks")
                return .json(200, signer.jwksJSON())
            }
            if request.uri.contains("/authz/check") {
                state.increment("authz")
                return .json(200, ["allowed": authzAllowed, "reason": authzAllowed ? NSNull() : "denied"])
            }
            return .json(404, [:])
        }
    }

    private func futureClaims(roles: [String] = ["admin"]) -> [String: Any] {
        [
            "sub": "user-42",
            "tenant_id": "tenant-uuid-1",
            "roles": roles,
            "preferred_username": "bob",
            "email": "bob@example.com",
            "exp": Date().addingTimeInterval(3600).timeIntervalSince1970,
        ]
    }

    // MARK: - authentication (§10)

    func testAuthenticateValidBearerToken() async throws {
        let jwt = signer.makeJWT(claims: futureClaims())
        try await withGuardClient(router: makeRouter()) { client, _ in
            let auth = client.makeAuthenticator()
            let ctx = AxiamRequestContext(headers: ["Authorization": "Bearer \(jwt)"])
            let user = try await auth.authenticate(ctx)
            XCTAssertEqual(user.userID, "user-42")
            XCTAssertEqual(user.roles, ["admin"])
            XCTAssertEqual(user.email, "bob@example.com")
        }
    }

    func testAuthenticateFromCookie() async throws {
        let jwt = signer.makeJWT(claims: futureClaims())
        try await withGuardClient(router: makeRouter()) { client, _ in
            let auth = client.makeAuthenticator()
            let user = try await auth.authenticate(AxiamRequestContext(cookies: ["axiam_access": jwt]))
            XCTAssertEqual(user.userID, "user-42")
        }
    }

    func testNoCredentialThrowsAuthError() async throws {
        try await withGuardClient(router: makeRouter()) { client, _ in
            let auth = client.makeAuthenticator()
            do {
                _ = try await auth.authenticate(AxiamRequestContext())
                XCTFail("expected error")
            } catch is AuthError { /* ok */ }
        }
    }

    func testExpiredTokenRejected() async throws {
        var claims = futureClaims()
        // Well outside the §10.1 rule 7 leeway (`AxiamRequestAuthenticator.clockSkewTolerance`).
        claims["exp"] = Date().addingTimeInterval(-3600).timeIntervalSince1970
        let jwt = signer.makeJWT(claims: claims)
        try await withGuardClient(router: makeRouter()) { client, _ in
            let auth = client.makeAuthenticator()
            do {
                _ = try await auth.authenticate(AxiamRequestContext(cookies: ["axiam_access": jwt]))
                XCTFail("expected expired error")
            } catch let error as AuthError {
                XCTAssertTrue(error.message.contains("expired"))
            }
        }
    }

    /// SEC-080: a token with no `exp` claim at all must fail closed rather than being treated as
    /// never-expiring. Previously `if let exp = claims.exp, exp < now` never fired for a `nil`
    /// `exp`, so the token was accepted.
    func testMissingExpClaimRejected() async throws {
        var claims = futureClaims()
        claims.removeValue(forKey: "exp")
        let jwt = signer.makeJWT(claims: claims)
        try await withGuardClient(router: makeRouter()) { client, _ in
            let auth = client.makeAuthenticator()
            do {
                _ = try await auth.authenticate(AxiamRequestContext(cookies: ["axiam_access": jwt]))
                XCTFail("expected rejection of a token with no exp claim")
            } catch let error as AuthError {
                XCTAssertTrue(error.message.contains("exp"))
            }
        }
    }

    /// A malformed (non-numeric) `exp` already fails closed via the JSON decode error; pin this
    /// so a future refactor cannot loosen it back to "absent/invalid exp is accepted".
    func testMalformedExpClaimRejected() async throws {
        var claims = futureClaims()
        claims["exp"] = "not-a-number"
        let jwt = signer.makeJWT(claims: claims)
        try await withGuardClient(router: makeRouter()) { client, _ in
            let auth = client.makeAuthenticator()
            do {
                _ = try await auth.authenticate(AxiamRequestContext(cookies: ["axiam_access": jwt]))
                XCTFail("expected rejection of a token with a malformed exp claim")
            } catch is AuthError { /* ok */ }
        }
    }

    func testNonEdDSAAlgorithmRejected() async throws {
        // alg=HS256 must be rejected before key lookup (alg-confusion defence).
        let jwt = signer.makeJWT(claims: futureClaims(), alg: "HS256")
        try await withGuardClient(router: makeRouter()) { client, _ in
            let auth = client.makeAuthenticator()
            do {
                _ = try await auth.authenticate(AxiamRequestContext(cookies: ["axiam_access": jwt]))
                XCTFail("expected alg rejection")
            } catch let error as AuthError {
                XCTAssertTrue(error.message.contains("EdDSA"))
            }
        }
    }

    func testTamperedSignatureRejected() async throws {
        var jwt = signer.makeJWT(claims: futureClaims())
        jwt.removeLast(3)
        jwt.append("AAA")
        try await withGuardClient(router: makeRouter()) { client, _ in
            let auth = client.makeAuthenticator()
            do {
                _ = try await auth.authenticate(AxiamRequestContext(cookies: ["axiam_access": jwt]))
                XCTFail("expected signature failure")
            } catch is AuthError { /* ok */ }
        }
    }

    func testTenantMismatchRejected() async throws {
        let jwt = signer.makeJWT(claims: futureClaims())
        try await withGuardClient(router: makeRouter()) { client, _ in
            let auth = client.makeAuthenticator()
            let ctx = AxiamRequestContext(
                headers: ["Authorization": "Bearer \(jwt)", "X-Tenant-ID": "some-other-tenant"]
            )
            do {
                _ = try await auth.authenticate(ctx)
                XCTFail("expected tenant mismatch")
            } catch is AuthError { /* ok */ }
        }
    }

    // MARK: - SEC-072 cross-tenant binding

    /// A validly-signed token issued for a **different** tenant of the same organization must be
    /// rejected even when the request carries no `X-Tenant-ID` header at all. The JWKS is
    /// org-wide, so the signature alone proves nothing about tenancy.
    func testCrossTenantTokenRejectedWithoutTenantHeader() async throws {
        var claims = futureClaims()
        claims["tenant_id"] = "tenant-uuid-OTHER"
        let jwt = signer.makeJWT(claims: claims)
        try await withGuardClient(router: makeRouter()) { client, _ in
            let auth = client.makeAuthenticator()
            // No X-Tenant-ID header: the pre-SEC-072 guard accepted this.
            let ctx = AxiamRequestContext(headers: ["Authorization": "Bearer \(jwt)"])
            do {
                _ = try await auth.authenticate(ctx)
                XCTFail("expected cross-tenant rejection")
            } catch let error as AuthError {
                XCTAssertTrue(error.message.contains("tenant"))
            }
        }
    }

    /// The same token also stays rejected when the request self-consistently claims the foreign
    /// tenant (matching `X-Tenant-ID` + `tenant_id` pair) — the old check passed that too.
    func testCrossTenantTokenRejectedWithMatchingTenantHeader() async throws {
        var claims = futureClaims()
        claims["tenant_id"] = "tenant-uuid-OTHER"
        let jwt = signer.makeJWT(claims: claims)
        try await withGuardClient(router: makeRouter()) { client, _ in
            let auth = client.makeAuthenticator()
            let ctx = AxiamRequestContext(
                headers: ["Authorization": "Bearer \(jwt)", "X-Tenant-ID": "tenant-uuid-OTHER"]
            )
            do {
                _ = try await auth.authenticate(ctx)
                XCTFail("expected cross-tenant rejection")
            } catch is AuthError { /* ok */ }
        }
    }

    /// A token with no `tenant_id` claim fails closed rather than inheriting the configured value.
    func testTokenWithoutTenantClaimRejected() async throws {
        var claims = futureClaims()
        claims.removeValue(forKey: "tenant_id")
        let jwt = signer.makeJWT(claims: claims)
        try await withGuardClient(router: makeRouter()) { client, _ in
            let auth = client.makeAuthenticator()
            do {
                _ = try await auth.authenticate(AxiamRequestContext(cookies: ["axiam_access": jwt]))
                XCTFail("expected rejection of a token with no tenant_id claim")
            } catch let error as AuthError {
                XCTAssertTrue(error.message.contains("tenant_id"))
            }
        }
    }

    /// Unit-level coverage of the assertion itself, independent of the HTTP/JWKS plumbing.
    func testAssertTenantSemantics() throws {
        XCTAssertNoThrow(try AxiamRequestAuthenticator.assertTenant(tokenTenant: "t-1", configured: ["t-1"]))
        // Either configured identifier (UUID or slug) may match.
        XCTAssertNoThrow(try AxiamRequestAuthenticator.assertTenant(tokenTenant: "acme", configured: ["t-1", "acme"]))
        XCTAssertThrowsError(try AxiamRequestAuthenticator.assertTenant(tokenTenant: "t-2", configured: ["t-1"]))
        XCTAssertThrowsError(try AxiamRequestAuthenticator.assertTenant(tokenTenant: nil, configured: ["t-1"]))
        XCTAssertThrowsError(try AxiamRequestAuthenticator.assertTenant(tokenTenant: "", configured: ["t-1"]))
        XCTAssertThrowsError(try AxiamRequestAuthenticator.assertTenant(tokenTenant: "t-1", configured: []))
    }

    // MARK: - JWKS single-flight fetch

    func testConcurrentVerificationsFetchJWKSOnce() async throws {
        let jwt = signer.makeJWT(claims: futureClaims())
        try await withGuardClient(router: makeRouter()) { client, server in
            let auth = client.makeAuthenticator()
            try await withThrowingTaskGroup(of: Void.self) { group in
                for _ in 0..<6 {
                    group.addTask {
                        _ = try await auth.authenticate(AxiamRequestContext(cookies: ["axiam_access": jwt]))
                    }
                }
                try await group.waitForAll()
            }
            XCTAssertEqual(server.state.count("jwks"), 1, "JWKS fetch should be single-flighted")
        }
    }

    // MARK: - §11 helpers

    func testRequireAuthGuard() async throws {
        let jwt = signer.makeJWT(claims: futureClaims())
        try await withGuardClient(router: makeRouter()) { client, _ in
            let guardFn = client.makeGuards().requireAuth()
            let user = try await guardFn(AxiamRequestContext(cookies: ["axiam_access": jwt]))
            XCTAssertEqual(user.userID, "user-42")
        }
    }

    func testRequireAccessAllowedForwardsSubject() async throws {
        let jwt = signer.makeJWT(claims: futureClaims())
        try await withGuardClient(router: makeRouter(authzAllowed: true)) { client, server in
            let guardFn = client.makeGuards().requireAccess("edit", resource: "doc-1")
            let user = try await guardFn(AxiamRequestContext(cookies: ["axiam_access": jwt]))
            XCTAssertEqual(user.userID, "user-42")

            let authzReq = server.state.requests(pathContaining: "/authz/check").last
            let body = (try? JSONSerialization.jsonObject(with: authzReq?.body ?? Data())) as? [String: Any]
            XCTAssertEqual(body?["subject_id"] as? String, "user-42", "§11.2: subject is the end user")
            XCTAssertEqual(body?["action"] as? String, "edit")
            XCTAssertEqual(body?["resource_id"] as? String, "doc-1")
        }
    }

    func testRequireAccessDeniedThrowsAuthzError() async throws {
        let jwt = signer.makeJWT(claims: futureClaims())
        try await withGuardClient(router: makeRouter(authzAllowed: false)) { client, _ in
            let guardFn = client.makeGuards().requireAccess("edit", resource: "doc-1")
            do {
                _ = try await guardFn(AxiamRequestContext(cookies: ["axiam_access": jwt]))
                XCTFail("expected denial")
            } catch let error as AuthzError {
                XCTAssertEqual(error.action, "edit")
            }
        }
    }

    func testRequireRoleLocalCheck() async throws {
        let jwt = signer.makeJWT(claims: futureClaims(roles: ["editor"]))
        try await withGuardClient(router: makeRouter()) { client, server in
            let guards = client.makeGuards()

            let ok = try await guards.requireRole("editor", "admin")(AxiamRequestContext(cookies: ["axiam_access": jwt]))
            XCTAssertEqual(ok.userID, "user-42")

            do {
                _ = try await guards.requireRole("superadmin")(AxiamRequestContext(cookies: ["axiam_access": jwt]))
                XCTFail("expected role denial")
            } catch is AuthzError { /* ok */ }

            // require_role is local — no authz round-trip.
            XCTAssertEqual(server.state.count("authz"), 0)
        }
    }
}
