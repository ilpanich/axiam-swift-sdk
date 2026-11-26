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

    // MARK: - access-token path only (§10.1 rules 10-12, contract 1.68; N14)

    /// Asserts `jwt` is refused by the guard with a signature-valid, tenant-correct,
    /// audience-less token and a guard configured with no expected audience.
    ///
    /// `reason` is a fragment the refusal's message must contain, so each negative proves the rule
    /// it is named for refused the token and not some unrelated check.
    private func assertRefused(_ jwt: String, _ label: String, reason: String) async throws {
        try await withGuardClient(router: makeRouter()) { client, _ in
            let auth = client.makeAuthenticator()
            let ctx = AxiamRequestContext(headers: ["Authorization": "Bearer \(jwt)"])
            do {
                _ = try await auth.authenticate(ctx)
                XCTFail("\(label): expected the guard to refuse this token")
            } catch let error as AuthError {
                XCTAssertTrue(
                    error.message.contains(reason),
                    "\(label): refused for the wrong reason: \(error.message)")
            }
        }
    }

    func testN14RefusesPurposeClaimEvenWithAccessTokenTyp() async throws {
        var claims = futureClaims()
        claims["purpose"] = "mfa_challenge"
        try await assertRefused(signer.makeJWT(claims: claims, typ: "at+jwt"), "purpose + at+jwt", reason: "rule 11")
    }

    /// SWI-R1-1: `"purpose": null` is a `purpose` member. A synthesized `Decodable` reads it as
    /// absent, so presence is taken from the verified payload itself (§10.1 rule 11).
    func testN14RefusesNullPurpose() async throws {
        var claims = futureClaims()
        claims["purpose"] = NSNull()
        try await assertRefused(signer.makeJWT(claims: claims, typ: "at+jwt"), "purpose null", reason: "rule 11")
        try await assertRefused(signer.makeJWT(claims: claims, typ: nil), "purpose null, no typ", reason: "rule 11")
    }

    func testN14RefusesWebauthnStateShape() async throws {
        var claims = futureClaims()
        claims["sub"] = "00000000-0000-0000-0000-000000000000"
        claims["purpose"] = "webauthn_authenticate_discoverable"
        try await assertRefused(signer.makeJWT(claims: claims, typ: "at+jwt"), "webauthn shape", reason: "rule 11")
    }

    func testN14RefusesWebauthnStateTyp() async throws {
        try await assertRefused(
            signer.makeJWT(claims: futureClaims(), typ: "axiam-webauthn-state+jwt"), "webauthn typ", reason: "rule 10")
    }

    func testN14RefusesOtherTokenTypes() async throws {
        for typ in ["JWT", "axiam-mfa-challenge+jwt", "axiam-mfa-setup+jwt", "logout+jwt"] {
            try await assertRefused(signer.makeJWT(claims: futureClaims(), typ: typ), "typ \(typ)", reason: "rule 10")
        }
    }

    func testN14RefusesKidlessTokenAgainstOneKeyJwks() async throws {
        try await assertRefused(
            signer.makeJWT(claims: futureClaims(), includeKid: false), "kid-less", reason: "'kid'")
    }

    func testN14AcceptsAccessTokenTypSpellings() async throws {
        for typ in ["at+jwt", "AT+JWT", "application/at+jwt"] {
            let jwt = signer.makeJWT(claims: futureClaims(), typ: typ)
            try await withGuardClient(router: makeRouter()) { client, _ in
                let user = try await client.makeAuthenticator().authenticate(
                    AxiamRequestContext(headers: ["Authorization": "Bearer \(jwt)"]))
                XCTAssertEqual(user.userID, "user-42", "typ \(typ)")
            }
        }
    }

    func testN14AcceptsTokenWithNoTyp() async throws {
        let jwt = signer.makeJWT(claims: futureClaims(), typ: nil)
        try await withGuardClient(router: makeRouter()) { client, _ in
            let user = try await client.makeAuthenticator().authenticate(
                AxiamRequestContext(headers: ["Authorization": "Bearer \(jwt)"]))
            XCTAssertEqual(user.userID, "user-42")
        }
    }
    // MARK: - §11.2 rule 11: `roles` and `scope` (contract 1.68; D-3)

    private func guardContext(_ jwt: String) -> AxiamRequestContext {
        AxiamRequestContext(headers: ["Authorization": "Bearer \(jwt)"])
    }

    /// Rule 11(b): an absent `roles` claim stays distinguishable from `[]` on the identity, and
    /// both fail every `requireRole` with 403 (not 401: the caller IS authenticated).
    func testAbsentRolesIsDistinguishableFromEmptyAndBothFailRequireRoleWith403() async throws {
        var absent = futureClaims()
        absent.removeValue(forKey: "roles")
        let absentJWT = signer.makeJWT(claims: absent)
        let emptyJWT = signer.makeJWT(claims: futureClaims(roles: []))

        try await withGuardClient(router: makeRouter()) { client, _ in
            let auth = client.makeAuthenticator()
            let absentUser = try await auth.authenticate(self.guardContext(absentJWT))
            let emptyUser = try await auth.authenticate(self.guardContext(emptyJWT))
            XCTAssertEqual(absentUser.roles, [])
            XCTAssertEqual(emptyUser.roles, [])
            XCTAssertFalse(absentUser.rolesClaimPresent, "no roles claim")
            XCTAssertTrue(emptyUser.rolesClaimPresent, "a roles claim that says 'none'")

            let requireAdmin = client.makeGuards().requireRole("admin")
            for jwt in [absentJWT, emptyJWT] {
                do {
                    _ = try await requireAdmin(self.guardContext(jwt))
                    XCTFail("expected 403")
                } catch is AuthzError { /* ok */ }
            }
        }
    }

    /// Rule 11(b): a `roles` that is not a JSON array of strings fails `requireRole` with 403,
    /// never 401 and never a match on the strings that happen to be there.
    func testMalformedRolesClaimFailsRequireRoleWith403() async throws {
        let malformed: [(String, Any)] = [
            ("a string", "admin"),
            ("null", NSNull()),
            ("a number inside", ["admin", 7] as [Any]),
            ("a null inside", ["admin", NSNull()] as [Any]),
            ("an object", ["admin": true]),
        ]
        try await withGuardClient(router: makeRouter()) { client, _ in
            let requireAdmin = client.makeGuards().requireRole("admin")
            for (label, value) in malformed {
                var claims = self.futureClaims()
                claims["roles"] = value
                do {
                    _ = try await requireAdmin(self.guardContext(self.signer.makeJWT(claims: claims)))
                    XCTFail("\(label): expected 403")
                } catch is AuthzError { /* ok */
                } catch {
                    XCTFail("\(label): expected AuthzError (403), got \(error)")
                }
            }
        }
    }

    /// Rule 11(a): `requireRole` never reads `scope`.
    func testRequireRoleDoesNotFallBackToScope() async throws {
        var claims = futureClaims()
        claims.removeValue(forKey: "roles")
        claims["scope"] = "admin openid"
        let jwt = signer.makeJWT(claims: claims)
        try await withGuardClient(router: makeRouter()) { client, _ in
            do {
                _ = try await client.makeGuards().requireRole("admin")(self.guardContext(jwt))
                XCTFail("a scope named like a role must not satisfy requireRole")
            } catch is AuthzError { /* ok */ }
            let user = try await client.makeAuthenticator().authenticate(self.guardContext(jwt))
            XCTAssertEqual(user.roles, [], "scopes are never merged into roles")
            XCTAssertEqual(user.scopes, ["admin", "openid"], "the granted scopes are a separate member")
        }
    }

    /// Rule 11(d): `requireScope` splits on single spaces and compares exactly.
    func testRequireScopeMatchesExactEntriesOfTheScopeClaim() async throws {
        var claims = futureClaims()
        claims["scope"] = "openid administrator profile"
        let jwt = signer.makeJWT(claims: claims)
        try await withGuardClient(router: makeRouter()) { client, server in
            let guards = client.makeGuards()
            let ok = try await guards.requireScope("profile", "email")(self.guardContext(jwt))
            XCTAssertEqual(ok.userID, "user-42")

            // `administrator` is not `admin`, and matching is case-sensitive.
            for wanted in ["admin", "Profile", "open"] {
                do {
                    _ = try await guards.requireScope(wanted)(self.guardContext(jwt))
                    XCTFail("'\(wanted)' must not match")
                } catch is AuthzError { /* ok */ }
            }
            XCTAssertEqual(server.state.count("authz"), 0, "require_scope is local")
        }
    }

    /// Rule 11(d): no `scope` claim, or one that is not a string, fails with 403; a route that
    /// needs several scopes stacks the helper and every one must pass.
    func testRequireScopeAbsentOrNonStringIs403AndStackingRequiresEveryOne() async throws {
        var absent = futureClaims()
        absent.removeValue(forKey: "scope")
        var nonString = futureClaims()
        nonString["scope"] = ["openid"]
        var both = futureClaims()
        both["scope"] = "read write"
        var onlyRead = futureClaims()
        onlyRead["scope"] = "read"

        try await withGuardClient(router: makeRouter()) { client, _ in
            let guards = client.makeGuards()
            for claims in [absent, nonString] {
                do {
                    _ = try await guards.requireScope("openid")(self.guardContext(self.signer.makeJWT(claims: claims)))
                    XCTFail("expected 403")
                } catch is AuthzError { /* ok */ }
            }

            let stacked = [guards.requireScope("read"), guards.requireScope("write")]
            func runAll(_ claims: [String: Any]) async throws {
                let context = self.guardContext(self.signer.makeJWT(claims: claims))
                for handler in stacked { _ = try await handler(context) }
            }
            try await runAll(both)
            do {
                try await runAll(onlyRead)
                XCTFail("the stacked helper for 'write' must refuse")
            } catch is AuthzError { /* ok */ }
        }
    }
}
