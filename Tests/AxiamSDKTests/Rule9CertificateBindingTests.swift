import XCTest
import Foundation
@testable import AxiamSDK

/// CONTRACT.md §10.1 rule 9 — sender-constrained (certificate-bound) access tokens
/// (contract 1.15, RFC 8705 §3 / RFC 7800).
///
/// A token carrying `cnf` is not a bearer token and must not be accepted as one. Three
/// negatives and one positive — and the POSITIVE is the one that matters most: rule 9 must
/// not become "every caller must present a certificate", which would break every
/// deployment that does not use mTLS at all.
final class Rule9CertificateBindingTests: XCTestCase {
    /// A real 43-character base64url x5t#S256, and a different one.
    static let thumbprint = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    static let otherThumbprint = "bWluZS1ub3QteW91cnMtdGhpcy1pcy00My1jaGFyc18"

    /// Decode claims from JSON rather than constructing `JwtClaims` directly, so the
    /// `x5t#S256` CodingKey mapping is exercised too — that key is not a legal Swift
    /// identifier, so it can only be right by way of the explicit mapping, and that is
    /// exactly the kind of thing a refactor drops.
    private func claims(_ json: String) throws -> JwtClaims {
        try JSONDecoder().decode(JwtClaims.self, from: Data(json.utf8))
    }

    private func unbound() throws -> JwtClaims {
        try claims(#"{"sub":"u","tenant_id":"t","exp":9999999999}"#)
    }

    private func bound(_ thumbprint: String) throws -> JwtClaims {
        try claims(#"{"sub":"u","tenant_id":"t","exp":9999999999,"cnf":{"x5t#S256":"\#(thumbprint)"}}"#)
    }

    /// The regression test that keeps rule 9 from becoming a certificate mandate.
    func testUnboundTokenIsAcceptedWithOrWithoutACertificate() throws {
        let token = try unbound()
        XCTAssertNoThrow(
            try AxiamRequestAuthenticator.verifyCertificateBinding(token, presentedThumbprint: nil))
        XCTAssertNoThrow(
            try AxiamRequestAuthenticator.verifyCertificateBinding(
                token, presentedThumbprint: Self.thumbprint))
    }

    func testBoundTokenIsAcceptedWithItsOwnCertificate() throws {
        let token = try bound(Self.thumbprint)
        XCTAssertEqual(token.cnf?.certificateThumbprint, Self.thumbprint)
        XCTAssertNoThrow(
            try AxiamRequestAuthenticator.verifyCertificateBinding(
                token, presentedThumbprint: Self.thumbprint))
    }

    func testBoundTokenIsRejectedWithNoCertificate() throws {
        let token = try bound(Self.thumbprint)
        XCTAssertThrowsError(
            try AxiamRequestAuthenticator.verifyCertificateBinding(token, presentedThumbprint: nil))
        XCTAssertThrowsError(
            try AxiamRequestAuthenticator.verifyCertificateBinding(token, presentedThumbprint: ""))
    }

    func testBoundTokenIsRejectedWithADifferentCertificate() throws {
        let token = try bound(Self.thumbprint)
        XCTAssertThrowsError(
            try AxiamRequestAuthenticator.verifyCertificateBinding(
                token, presentedThumbprint: Self.otherThumbprint))
    }

    /// The subtle one. A `cnf` naming a confirmation method this SDK cannot check is an
    /// unverifiable constraint, never *no* constraint — read the other way, a
    /// sender-constrained token silently degrades to a bearer token the day a newer AXIAM
    /// issues a confirmation this SDK predates.
    func testUnverifiableConfirmationIsRejectedNotIgnored() throws {
        let dpopish = try claims(
            #"{"sub":"u","tenant_id":"t","exp":9999999999,"cnf":{"jkt":"0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"}}"#)

        // It must DECODE — a token naming another method still round-trips...
        XCTAssertNotNil(dpopish.cnf)
        XCTAssertNil(dpopish.cnf?.certificateThumbprint)
        // ...and it must not VALIDATE.
        XCTAssertThrowsError(
            try AxiamRequestAuthenticator.verifyCertificateBinding(dpopish, presentedThumbprint: nil))
        XCTAssertThrowsError(
            try AxiamRequestAuthenticator.verifyCertificateBinding(
                dpopish, presentedThumbprint: Self.thumbprint))
    }

    /// RFC 7515 §2 base64url: unpadded, `-`/`_` rather than `+`/`/`. A padded or
    /// standard-base64 value will not compare equal to what AXIAM put in the token.
    func testThumbprintHelperProducesUnpaddedBase64Url() {
        let der = Data(repeating: 0x42, count: 512)
        let tp = AxiamRequestAuthenticator.certificateThumbprintS256(der: der)

        XCTAssertEqual(tp.count, 43)
        XCTAssertFalse(tp.contains("="))
        XCTAssertFalse(tp.contains("+"))
        XCTAssertFalse(tp.contains("/"))
        XCTAssertEqual(tp, AxiamRequestAuthenticator.certificateThumbprintS256(der: der))

        // A different certificate must produce a different thumbprint.
        var otherDer = der
        otherDer[0] = 0x43
        XCTAssertNotEqual(tp, AxiamRequestAuthenticator.certificateThumbprintS256(der: otherDer))
    }
    // MARK: - end to end, through the guard entry point
    //
    // The cases above exercise the rule in isolation. These drive
    // `authenticateSenderConstrained` against a real signed token and a real
    // JWKS, which is what a resource server actually calls — an isolated rule
    // that no entry point reaches is a rule nobody applies.

    private let signer = TestSigner()

    private func withGuardClient(
        body: @escaping (AxiamClient, TestHTTPServer) async throws -> Void
    ) async throws {
        let signer = self.signer
        try await withClient(
            makeConfig: {
                try TestKit.makeConfig(
                    port: $0,
                    tenantSlug: nil,
                    tenantID: Self.tenantUUID
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

    static let tenantUUID = "tenant-uuid-1"

    private func claims(cnf: [String: Any]? = nil) -> [String: Any] {
        var c: [String: Any] = [
            "sub": "user-42",
            "tenant_id": Self.tenantUUID,
            "roles": ["admin"],
            "exp": Date().addingTimeInterval(3600).timeIntervalSince1970,
        ]
        if let cnf { c["cnf"] = cnf }
        return c
    }

    /// The regression test that keeps rule 9 from becoming a certificate
    /// mandate, asserted where it matters: at the guard.
    func testGuardAcceptsAnUnboundTokenWithOrWithoutACertificate() async throws {
        let jwt = signer.makeJWT(claims: claims())
        try await withGuardClient { client, _ in
            let auth = client.makeAuthenticator()
            let ctx = AxiamRequestContext(cookies: ["axiam_access": jwt])

            let a = try await auth.authenticateSenderConstrained(ctx, presentedThumbprint: nil)
            XCTAssertEqual(a.userID, "user-42")

            let b = try await auth.authenticateSenderConstrained(
                ctx, presentedThumbprint: Self.thumbprint)
            XCTAssertEqual(b.userID, "user-42")
        }
    }

    func testGuardAcceptsABoundTokenWithItsOwnCertificate() async throws {
        let jwt = signer.makeJWT(claims: claims(cnf: ["x5t#S256": Self.thumbprint]))
        try await withGuardClient { client, _ in
            let auth = client.makeAuthenticator()
            let user = try await auth.authenticateSenderConstrained(
                AxiamRequestContext(cookies: ["axiam_access": jwt]),
                presentedThumbprint: Self.thumbprint
            )
            XCTAssertEqual(user.userID, "user-42")
        }
    }

    func testGuardRejectsABoundTokenWithNoOrWrongCertificate() async throws {
        let jwt = signer.makeJWT(claims: claims(cnf: ["x5t#S256": Self.thumbprint]))
        try await withGuardClient { client, _ in
            let auth = client.makeAuthenticator()
            let ctx = AxiamRequestContext(cookies: ["axiam_access": jwt])

            // Explicitly typed: `[nil, x]` would otherwise need inference to
            // land on `[String?]`, and this file is the one place in the suite
            // where "no certificate" and "wrong certificate" must stay distinct.
            let cases: [String?] = [nil, Self.otherThumbprint]
            for presented in cases {
                do {
                    _ = try await auth.authenticateSenderConstrained(
                        ctx, presentedThumbprint: presented)
                    XCTFail("expected the guard to reject (presented: \(presented ?? "nil"))")
                } catch is AuthError { /* ok */ }
            }
        }
    }

    // MARK: - Rule 9 at the DEFAULT entry point (contract 1.51 fix)
    //
    // The defect this section pins: `authenticate(_:)` — the §10 guard entry point that
    // `AxiamGuards`, the §11 helpers and the §28 MCP guard all reach — applied §10.1
    // rules 1-8 and never rule 9. A device login's token (§6.1 rules 6/9,
    // `cnf.x5t#S256`) was therefore accepted here as an ordinary bearer token, with no
    // check that the caller held the named key. A token lifted off a device and replayed
    // as a bearer credential opened every guarded route.
    //
    // The fix: `authenticate(_:presentedProofs:)` gained a `presentedProofs` parameter
    // defaulting to `.none`, and now calls `verifyTokenBinding` after the §10.1 claim
    // checks. An unbound token is unaffected (rule 9's first row); a bound token is
    // refused UNLESS the caller threads through what it proved on this connection.

    /// **This is the test that pins the fix.** Reverting the `verifyTokenBinding` call in
    /// `authenticateVerifiedToken` turns this red: a device token, presented through the
    /// DEFAULT `authenticate(_:)` call with no evidence, must not be accepted as an
    /// ordinary bearer token.
    func testDefaultAuthenticateRefusesABoundTokenWithNoEvidence() async throws {
        let jwt = signer.makeJWT(claims: claims(cnf: ["x5t#S256": Self.thumbprint]))
        try await withGuardClient { client, _ in
            let auth = client.makeAuthenticator()
            let ctx = AxiamRequestContext(cookies: ["axiam_access": jwt])
            do {
                _ = try await auth.authenticate(ctx)
                XCTFail("expected the default authenticate(_:) to refuse a bound token")
            } catch is AuthError { /* ok */ }
        }
    }

    /// The I4 twin: an ordinary unbound token — every token before §6.1 existed, and every
    /// one a non-mTLS deployment will ever mint — verifies exactly as it always did through
    /// the default entry point.
    func testDefaultAuthenticateAcceptsAnUnboundToken() async throws {
        let jwt = signer.makeJWT(claims: claims())
        try await withGuardClient { client, _ in
            let auth = client.makeAuthenticator()
            let user = try await auth.authenticate(AxiamRequestContext(cookies: ["axiam_access": jwt]))
            XCTAssertEqual(user.userID, "user-42")
        }
    }

    /// A caller that DOES have evidence threads it through `presentedProofs` explicitly,
    /// and the same token that was refused above is accepted.
    func testDefaultAuthenticateAcceptsABoundTokenWhenProofsAreSupplied() async throws {
        let jwt = signer.makeJWT(claims: claims(cnf: ["x5t#S256": Self.thumbprint]))
        try await withGuardClient { client, _ in
            let auth = client.makeAuthenticator()
            let user = try await auth.authenticate(
                AxiamRequestContext(cookies: ["axiam_access": jwt]),
                presentedProofs: .certificate(Self.thumbprint)
            )
            XCTAssertEqual(user.userID, "user-42")
        }
    }

    /// The wrong certificate is still a refusal through the default entry point, not
    /// merely "no certificate".
    func testDefaultAuthenticateRefusesABoundTokenWithWrongProofs() async throws {
        let jwt = signer.makeJWT(claims: claims(cnf: ["x5t#S256": Self.thumbprint]))
        try await withGuardClient { client, _ in
            let auth = client.makeAuthenticator()
            do {
                _ = try await auth.authenticate(
                    AxiamRequestContext(cookies: ["axiam_access": jwt]),
                    presentedProofs: .certificate(Self.otherThumbprint)
                )
                XCTFail("expected the default authenticate(_:) to refuse the wrong certificate")
            } catch is AuthError { /* ok */ }
        }
    }
}
