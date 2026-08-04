import XCTest
import Foundation
@testable import AxiamSDK

/// CONTRACT.md §10.1 rule 8 — "subject of the decision" (SEC-085, §15.3.1).
///
/// Rules 1-7 ask whether the token is good. Rule 8 asks whether it is the token the decision is
/// even ABOUT. SEC-085 satisfied all seven and was still an authentication bypass: the PHP guard
/// routed a failed verification into a second, successful one against the *application's own*
/// session, so the caller was admitted as the app's service account — in an IAM integration
/// typically far more privileged than the user whose request it replaced.
///
/// This SDK is structurally safe from that shape: ``AxiamRequestAuthenticator`` holds a
/// ``JwksVerifier``, the configured tenants and the optional issuer/audience expectations — never
/// a logged-in client — so there is no second credential in scope to substitute. These tests pin
/// that property rather than assume it, which is the guardrail §15.3.1 asks for.
final class Rule8CallerCredentialTests: XCTestCase {
    let signer = TestSigner()

    static let tenantUUID = "tenant-uuid-1"

    /// The identity an SEC-085-shaped fallback would silently admit callers as.
    static let appPrincipal = "app-service-account"

    private func withGuardClient(
        body: @escaping (AxiamClient, TestHTTPServer) async throws -> Void
    ) async throws {
        let signer = self.signer
        try await withClient(
            makeConfig: {
                try TestKit.makeConfig(
                    port: $0,
                    tenantSlug: nil,
                    tenantID: Self.tenantUUID,
                    expectedIssuer: nil,
                    expectedAudience: nil
                )
            },
            router: { request, state in
                if request.uri.hasSuffix("/oauth2/jwks") {
                    state.increment("jwks")
                    return .json(200, signer.jwksJSON())
                }
                return .json(404, [:])
            },
            body: body
        )
    }

    /// A claim set satisfying every rule; individual tests mutate one thing at a time.
    private func validClaims(sub: String = "caller-1") -> [String: Any] {
        [
            "sub": sub,
            "tenant_id": Self.tenantUUID,
            "roles": ["viewer"],
            "exp": Date().addingTimeInterval(3600).timeIntervalSince1970,
        ]
    }

    /// The application's own credential — same key, same tenant, MORE privileged.
    private func appOwnClaims() -> [String: Any] {
        [
            "sub": Self.appPrincipal,
            "tenant_id": Self.tenantUUID,
            "roles": ["admin"],
            "exp": Date().addingTimeInterval(3600).timeIntervalSince1970,
        ]
    }

    /// A failed caller credential is refused even though a perfectly valid one — for a more
    /// privileged principal, on the same key and tenant — exists and would have verified.
    ///
    /// The precondition is asserted, not assumed: the substitute is first shown to pass this very
    /// guard. Without that, the test could pass merely because nothing was available to
    /// substitute, which would prove nothing — the trap the PHP reference test documents.
    func testFailedCallerTokenIsNotSwappedForAValidOne() async throws {
        var expiredClaims = validClaims()
        expiredClaims["exp"] = Date().addingTimeInterval(-3600).timeIntervalSince1970
        let expired = signer.makeJWT(claims: expiredClaims)
        let appToken = signer.makeJWT(claims: appOwnClaims())

        try await withGuardClient { client, _ in
            let auth = client.makeAuthenticator()

            // Precondition: the substitute really would have been accepted.
            let appUser = try await auth.authenticate(
                AxiamRequestContext(cookies: ["axiam_access": appToken])
            )
            XCTAssertEqual(appUser.userID, Self.appPrincipal)

            // The caller's own credential fails on `exp` alone, so the only way to admit
            // it is to decide on a credential it never presented.
            do {
                let user = try await auth.authenticate(
                    AxiamRequestContext(cookies: ["axiam_access": expired])
                )
                XCTFail(
                    "SECURITY: a caller whose token failed verification was admitted as "
                        + "\(user.userID) — rule 8 violated"
                )
            } catch let error as AuthError {
                XCTAssertFalse(
                    error.message.contains(Self.appPrincipal),
                    "the rejection must not surface the application's own principal"
                )
            }
        }
    }

    /// The positive half: with a valid caller token, the identity returned is the caller's.
    /// A guard that preferred some ambient credential would pass the negative test above while
    /// still being wrong.
    func testTheAuthenticatedIdentityIsTheCallersOwn() async throws {
        let callerToken = signer.makeJWT(claims: validClaims())

        try await withGuardClient { client, _ in
            let auth = client.makeAuthenticator()
            let user = try await auth.authenticate(
                AxiamRequestContext(cookies: ["axiam_access": callerToken])
            )
            XCTAssertEqual(user.userID, "caller-1")
            XCTAssertNotEqual(user.userID, Self.appPrincipal)
        }
    }

    /// Every rejection shape behaves the same way: no identity, and never the app's. `expired` is
    /// the headline case from the finding; the rest cover the failure modes the PHP fallback
    /// equally papered over — all of which previously returned the application's own claims.
    func testNoRejectionShapeYieldsAnIdentity() async throws {
        var expiredClaims = validClaims()
        expiredClaims["exp"] = Date().addingTimeInterval(-3600).timeIntervalSince1970

        var foreignTenant = validClaims()
        foreignTenant["tenant_id"] = "some-other-tenant"

        let cases: [(String, String)] = [
            ("expired", signer.makeJWT(claims: expiredClaims)),
            ("garbage", "not-a-real-jwt"),
            ("unsigned alg:none", signer.makeAlgNoneJWT(claims: validClaims())),
            ("foreign tenant", signer.makeJWT(claims: foreignTenant)),
        ]

        for (label, jwt) in cases {
            try await withGuardClient { client, _ in
                let auth = client.makeAuthenticator()
                do {
                    let user = try await auth.authenticate(
                        AxiamRequestContext(cookies: ["axiam_access": jwt])
                    )
                    XCTFail("[\(label)] SECURITY: admitted as \(user.userID) — rule 8 violated")
                } catch let error as AuthError {
                    XCTAssertFalse(
                        error.message.contains(Self.appPrincipal),
                        "[\(label)] the rejection must not surface the application's own principal"
                    )
                }
            }
        }
    }
}
