import XCTest
import Foundation
@testable import AxiamSDK

final class GuardTests: XCTestCase {
    let signer = TestSigner()

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
        try await withClient(router: makeRouter()) { client, _ in
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
        try await withClient(router: makeRouter()) { client, _ in
            let auth = client.makeAuthenticator()
            let user = try await auth.authenticate(AxiamRequestContext(cookies: ["axiam_access": jwt]))
            XCTAssertEqual(user.userID, "user-42")
        }
    }

    func testNoCredentialThrowsAuthError() async throws {
        try await withClient(router: makeRouter()) { client, _ in
            let auth = client.makeAuthenticator()
            do {
                _ = try await auth.authenticate(AxiamRequestContext())
                XCTFail("expected error")
            } catch is AuthError { /* ok */ }
        }
    }

    func testExpiredTokenRejected() async throws {
        var claims = futureClaims()
        claims["exp"] = Date().addingTimeInterval(-60).timeIntervalSince1970
        let jwt = signer.makeJWT(claims: claims)
        try await withClient(router: makeRouter()) { client, _ in
            let auth = client.makeAuthenticator()
            do {
                _ = try await auth.authenticate(AxiamRequestContext(cookies: ["axiam_access": jwt]))
                XCTFail("expected expired error")
            } catch let error as AuthError {
                XCTAssertTrue(error.message.contains("expired"))
            }
        }
    }

    func testNonEdDSAAlgorithmRejected() async throws {
        // alg=HS256 must be rejected before key lookup (alg-confusion defence).
        let jwt = signer.makeJWT(claims: futureClaims(), alg: "HS256")
        try await withClient(router: makeRouter()) { client, _ in
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
        try await withClient(router: makeRouter()) { client, _ in
            let auth = client.makeAuthenticator()
            do {
                _ = try await auth.authenticate(AxiamRequestContext(cookies: ["axiam_access": jwt]))
                XCTFail("expected signature failure")
            } catch is AuthError { /* ok */ }
        }
    }

    func testTenantMismatchRejected() async throws {
        let jwt = signer.makeJWT(claims: futureClaims())
        try await withClient(router: makeRouter()) { client, _ in
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

    // MARK: - JWKS single-flight fetch

    func testConcurrentVerificationsFetchJWKSOnce() async throws {
        let jwt = signer.makeJWT(claims: futureClaims())
        try await withClient(router: makeRouter()) { client, server in
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
        try await withClient(router: makeRouter()) { client, _ in
            let guardFn = client.makeGuards().requireAuth()
            let user = try await guardFn(AxiamRequestContext(cookies: ["axiam_access": jwt]))
            XCTAssertEqual(user.userID, "user-42")
        }
    }

    func testRequireAccessAllowedForwardsSubject() async throws {
        let jwt = signer.makeJWT(claims: futureClaims())
        try await withClient(router: makeRouter(authzAllowed: true)) { client, server in
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
        try await withClient(router: makeRouter(authzAllowed: false)) { client, _ in
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
        try await withClient(router: makeRouter()) { client, server in
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
