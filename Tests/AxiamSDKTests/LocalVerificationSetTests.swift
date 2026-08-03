import XCTest
import Foundation
@testable import AxiamSDK

/// CONTRACT.md §10.1 "Minimum local-verification set (normative)".
///
/// One test per rule plus the full mandated negative set: expired; no `exp`; non-numeric `exp`;
/// future `nbf`; different tenant; no `tenant_id`; `alg: none`; an HS-signed token bearing an
/// EdDSA key id — and, because this SDK ships the optional issuer/audience configuration, a
/// mismatch case for each of those too.
///
/// Everything here runs through ``AxiamRequestAuthenticator/authenticate(_:)``, the documented
/// guard entry point. ``JwksVerifier/verifySignatureOnlyUnchecked(token:)`` is exercised only to
/// pin that it really is blind to every claim — which is why it may not be used as a guard and
/// why its name says so.
final class LocalVerificationSetTests: XCTestCase {
    let signer = TestSigner()

    static let tenantUUID = "tenant-uuid-1"
    static let issuer = "https://issuer.axiam.test"
    static let audience = "axiam:user"

    private func withGuardClient(
        expectedIssuer: String? = nil,
        expectedAudience: String? = nil,
        body: @escaping (AxiamClient, TestHTTPServer) async throws -> Void
    ) async throws {
        let signer = self.signer
        try await withClient(
            makeConfig: {
                try TestKit.makeConfig(
                    port: $0,
                    tenantSlug: nil,
                    tenantID: Self.tenantUUID,
                    expectedIssuer: expectedIssuer,
                    expectedAudience: expectedAudience
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

    /// A claim set that satisfies every rule; individual tests mutate one thing at a time.
    private func validClaims() -> [String: Any] {
        [
            "sub": "user-42",
            "tenant_id": LocalVerificationSetTests.tenantUUID,
            "roles": ["admin"],
            "exp": Date().addingTimeInterval(3600).timeIntervalSince1970,
        ]
    }

    private func expectRejection(
        _ jwt: String,
        expectedIssuer: String? = nil,
        expectedAudience: String? = nil,
        messageContains: String? = nil,
        jwksFetches: Int? = nil,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async throws {
        try await withGuardClient(expectedIssuer: expectedIssuer, expectedAudience: expectedAudience) { client, server in
            let auth = client.makeAuthenticator()
            do {
                _ = try await auth.authenticate(AxiamRequestContext(cookies: ["axiam_access": jwt]))
                XCTFail("expected rejection", file: file, line: line)
            } catch let error as AuthError {
                if let messageContains {
                    XCTAssertTrue(
                        error.message.contains(messageContains),
                        "message was: \(error.message)",
                        file: file,
                        line: line
                    )
                }
            }
            if let jwksFetches {
                XCTAssertEqual(server.state.count("jwks"), jwksFetches, file: file, line: line)
            }
        }
    }

    private func expectAcceptance(
        _ jwt: String,
        expectedIssuer: String? = nil,
        expectedAudience: String? = nil,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async throws {
        try await withGuardClient(expectedIssuer: expectedIssuer, expectedAudience: expectedAudience) { client, _ in
            let auth = client.makeAuthenticator()
            let user = try await auth.authenticate(AxiamRequestContext(cookies: ["axiam_access": jwt]))
            XCTAssertEqual(user.userID, "user-42", file: file, line: line)
        }
    }

    // MARK: - rule 1: signature, `alg` pinned to EdDSA before key lookup

    func testAlgNoneRejectedWithoutConsultingAKey() async throws {
        try await expectRejection(
            signer.makeAlgNoneJWT(claims: validClaims()),
            messageContains: "EdDSA",
            jwksFetches: 0
        )
    }

    func testHSSignedTokenBearingAnEdDSAKidRejectedWithoutConsultingAKey() async throws {
        try await expectRejection(
            signer.makeHS256JWTWithEdDSAKid(claims: validClaims()),
            messageContains: "EdDSA",
            jwksFetches: 0
        )
    }

    // MARK: - rule 2: `exp` is REQUIRED

    func testExpiredTokenRejectedBeyondTheLeeway() async throws {
        var claims = validClaims()
        claims["exp"] = Date().addingTimeInterval(-3600).timeIntervalSince1970
        try await expectRejection(signer.makeJWT(claims: claims), messageContains: "expired")
    }

    func testTokenWithNoExpRejected() async throws {
        var claims = validClaims()
        claims.removeValue(forKey: "exp")
        try await expectRejection(signer.makeJWT(claims: claims), messageContains: "exp")
    }

    func testTokenWithNonNumericExpRejected() async throws {
        var claims = validClaims()
        claims["exp"] = "tomorrow"
        try await expectRejection(signer.makeJWT(claims: claims))
    }

    // MARK: - rule 3: `nbf` honoured when present

    func testTokenWithFutureNbfRejected() async throws {
        var claims = validClaims()
        claims["nbf"] = Date().addingTimeInterval(3600).timeIntervalSince1970
        try await expectRejection(signer.makeJWT(claims: claims), messageContains: "nbf")
    }

    func testTokenWithPastNbfAccepted() async throws {
        var claims = validClaims()
        claims["nbf"] = Date().addingTimeInterval(-3600).timeIntervalSince1970
        try await expectAcceptance(signer.makeJWT(claims: claims))
    }

    func testTokenWithNonNumericNbfRejected() async throws {
        var claims = validClaims()
        claims["nbf"] = "later"
        try await expectRejection(signer.makeJWT(claims: claims))
    }

    // MARK: - rule 4: `tenant_id` REQUIRED and asserted

    func testTokenForADifferentTenantRejected() async throws {
        var claims = validClaims()
        claims["tenant_id"] = "tenant-uuid-OTHER"
        try await expectRejection(signer.makeJWT(claims: claims), messageContains: "tenant")
    }

    func testTokenWithNoTenantIDRejected() async throws {
        var claims = validClaims()
        claims.removeValue(forKey: "tenant_id")
        try await expectRejection(signer.makeJWT(claims: claims), messageContains: "tenant_id")
    }

    // MARK: - rule 5: `iss` checked only when configured

    func testIssuerNotCheckedWhenUnconfigured() async throws {
        var claims = validClaims()
        claims["iss"] = "https://somebody-else.example"
        try await expectAcceptance(signer.makeJWT(claims: claims))
    }

    func testMismatchedIssuerRejectedWhenConfigured() async throws {
        var claims = validClaims()
        claims["iss"] = "https://somebody-else.example"
        try await expectRejection(
            signer.makeJWT(claims: claims),
            expectedIssuer: Self.issuer,
            messageContains: "iss"
        )
    }

    func testMissingIssuerRejectedWhenConfigured() async throws {
        try await expectRejection(
            signer.makeJWT(claims: validClaims()),
            expectedIssuer: Self.issuer,
            messageContains: "iss"
        )
    }

    func testMatchingIssuerAccepted() async throws {
        var claims = validClaims()
        claims["iss"] = Self.issuer
        try await expectAcceptance(signer.makeJWT(claims: claims), expectedIssuer: Self.issuer)
    }

    // MARK: - rule 6: `aud` checked only when configured

    func testAudienceNotCheckedWhenUnconfigured() async throws {
        var claims = validClaims()
        claims["aud"] = "some-other-api"
        try await expectAcceptance(signer.makeJWT(claims: claims))
    }

    func testMismatchedAudienceRejectedWhenConfigured() async throws {
        var claims = validClaims()
        claims["aud"] = "some-other-api"
        try await expectRejection(
            signer.makeJWT(claims: claims),
            expectedAudience: Self.audience,
            messageContains: "aud"
        )
    }

    func testMissingAudienceRejectedWhenConfigured() async throws {
        try await expectRejection(
            signer.makeJWT(claims: validClaims()),
            expectedAudience: Self.audience,
            messageContains: "aud"
        )
    }

    /// RFC 7519 allows `aud` to be a single string or an array; both forms are honoured.
    func testAudienceAcceptedInBothStringAndArrayForms() async throws {
        var single = validClaims()
        single["aud"] = Self.audience
        try await expectAcceptance(signer.makeJWT(claims: single), expectedAudience: Self.audience)

        var array = validClaims()
        array["aud"] = ["another-api", Self.audience]
        try await expectAcceptance(signer.makeJWT(claims: array), expectedAudience: Self.audience)
    }

    /// A wrong-typed `aud` must fail the decode rather than read as "no audience".
    func testWrongTypedAudienceRejected() async throws {
        var claims = validClaims()
        claims["aud"] = 7
        try await expectRejection(signer.makeJWT(claims: claims), expectedAudience: Self.audience)
    }

    // MARK: - rule 7: a named, bounded clock skew

    func testClockSkewIsANamedBoundedConstant() {
        XCTAssertEqual(AxiamRequestAuthenticator.clockSkewTolerance, 60)
    }

    func testExpAndNbfAreComparedWithinTheNamedLeeway() async throws {
        var claims = validClaims()
        // 10s past `exp` and 10s short of `nbf` both fall inside the 60s constant.
        claims["exp"] = Date().addingTimeInterval(-10).timeIntervalSince1970
        claims["nbf"] = Date().addingTimeInterval(10).timeIntervalSince1970
        try await expectAcceptance(signer.makeJWT(claims: claims))
    }

    // MARK: - the full set applied together

    func testTokenSatisfyingEveryRuleIsAccepted() async throws {
        var claims = validClaims()
        claims["nbf"] = Date().addingTimeInterval(-60).timeIntervalSince1970
        claims["iss"] = Self.issuer
        claims["aud"] = [Self.audience]
        try await expectAcceptance(
            signer.makeJWT(claims: claims),
            expectedIssuer: Self.issuer,
            expectedAudience: Self.audience
        )
    }

    /// The signature-only primitive is deliberately blind to every claim.
    func testSignatureOnlyPrimitiveAcceptsWhatTheGuardRejects() async throws {
        var claims = validClaims()
        claims["tenant_id"] = "tenant-uuid-OTHER"
        claims.removeValue(forKey: "exp")
        let jwt = signer.makeJWT(claims: claims)

        try await withGuardClient { client, _ in
            let verified = try await client.jwks.verifySignatureOnlyUnchecked(token: jwt)
            XCTAssertEqual(verified.claims.sub, "user-42")
            XCTAssertNil(verified.claims.exp)

            // ...and the guard rejects exactly that token.
            let auth = client.makeAuthenticator()
            do {
                _ = try await auth.authenticate(AxiamRequestContext(cookies: ["axiam_access": jwt]))
                XCTFail("expected the guard to reject a permanent cross-tenant token")
            } catch is AuthError { /* ok */ }
        }
    }

    // MARK: - unit-level coverage of the conditional assertions

    func testAssertIssuerSemantics() throws {
        // Unset expectation: nothing is checked, whatever the token says.
        XCTAssertNoThrow(try AxiamRequestAuthenticator.assertIssuer(nil, expected: nil))
        XCTAssertNoThrow(try AxiamRequestAuthenticator.assertIssuer("anything", expected: nil))
        XCTAssertNoThrow(try AxiamRequestAuthenticator.assertIssuer("iss-1", expected: "iss-1"))
        XCTAssertThrowsError(try AxiamRequestAuthenticator.assertIssuer("iss-2", expected: "iss-1"))
        XCTAssertThrowsError(try AxiamRequestAuthenticator.assertIssuer(nil, expected: "iss-1"))
        XCTAssertThrowsError(try AxiamRequestAuthenticator.assertIssuer("", expected: "iss-1"))
    }

    func testAssertAudienceSemantics() throws {
        XCTAssertNoThrow(try AxiamRequestAuthenticator.assertAudience(nil, expected: nil))
        XCTAssertNoThrow(try AxiamRequestAuthenticator.assertAudience(.single("a"), expected: "a"))
        XCTAssertNoThrow(try AxiamRequestAuthenticator.assertAudience(.multiple(["a", "b"]), expected: "b"))
        XCTAssertThrowsError(try AxiamRequestAuthenticator.assertAudience(.single("a"), expected: "b"))
        XCTAssertThrowsError(try AxiamRequestAuthenticator.assertAudience(.multiple([]), expected: "b"))
        XCTAssertThrowsError(try AxiamRequestAuthenticator.assertAudience(nil, expected: "b"))
    }

    func testJwtAudienceDecodesBothShapesAndRejectsOthers() throws {
        struct Wrapper: Decodable { let aud: JwtAudience? }
        let decoder = JSONDecoder()
        XCTAssertEqual(
            try decoder.decode(Wrapper.self, from: Data(#"{"aud":"one"}"#.utf8)).aud?.values,
            ["one"]
        )
        XCTAssertEqual(
            try decoder.decode(Wrapper.self, from: Data(#"{"aud":["one","two"]}"#.utf8)).aud?.values,
            ["one", "two"]
        )
        XCTAssertNil(try decoder.decode(Wrapper.self, from: Data(#"{}"#.utf8)).aud)
        XCTAssertThrowsError(try decoder.decode(Wrapper.self, from: Data(#"{"aud":7}"#.utf8)))
    }

    // MARK: - §13.4 observation 7: key selection must be by `kid`, never by guess

    /// A token with no `kid` used to be verified against "the sole EdDSA key,
    /// when unambiguous". Kotlin, PHP and Java all reject that, and the fallback
    /// is fragile in exactly the situation key ids exist for: during a rotation
    /// the JWKS holds two keys, so a token that verified yesterday starts
    /// failing for a reason unrelated to the token.
    func testTokenWithNoKidIsRejected() async throws {
        try await expectRejection(
            signer.makeJWT(claims: validClaims(), includeKid: false),
            messageContains: "kid"
        )
    }

    /// Stricter than the observation asked for, and the case that mattered more:
    /// the old fallback was also reached when a `kid` WAS present but matched
    /// nothing, so a token naming a key the server does not publish was verified
    /// against whichever single key happened to be there.
    ///
    /// The token is signed with this signer's REAL key but names a `kid` the
    /// JWKS does not carry. That separation is what makes the test meaningful:
    /// a stranger-signed token would be refused by the signature check anyway,
    /// so it could not distinguish "selected no key" from "selected a key and
    /// the signature failed". Here the old fallback selects the sole published
    /// key, the signature genuinely verifies, and the token is **accepted** —
    /// confirmed by falsification.
    func testTokenNamingAnUnknownKidIsRejectedRatherThanGuessed() async throws {
        try await expectRejection(
            signer.makeJWT(claims: validClaims(), kidOverride: "a-key-id-the-jwks-does-not-have"),
            messageContains: "kid"
        )
    }

    /// The rejections above must come from key *selection*, not from anything
    /// incidental: a correctly-`kid`-ed token from the same signer still passes.
    func testAMatchingKidStillVerifies() async throws {
        try await expectAcceptance(signer.makeJWT(claims: validClaims()))
    }
}
