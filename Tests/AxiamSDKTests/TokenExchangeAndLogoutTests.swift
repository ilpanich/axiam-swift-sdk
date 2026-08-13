import XCTest
import Foundation
@testable import AxiamSDK

/// CONTRACT.md §15 (RFC 8693 token exchange) and §12.7 (RP-initiated and back-channel logout).
///
/// §15.6 names the tests it requires and every one of them is here; §12.7.3's six checks each
/// get a rejection test, because that half's input arrives unsolicited from the network and
/// instructs the relying party to end a session.
final class TokenExchangeAndLogoutTests: XCTestCase {
    let signer = TestSigner()

    private static let tenantUUID = "22222222-2222-2222-2222-222222222222"
    private static let clientID = "orders-service"
    private static let issuer = "https://iam.example.test"

    private func makeRouter(
        tokenStatus: Int = 200,
        tokenBody: [String: Any] = [:]
    ) -> TestRouter {
        let signer = self.signer
        return { request, state in
            if request.uri.hasSuffix("/oauth2/jwks") { return .json(200, signer.jwksJSON()) }
            if request.uri.contains("/.well-known/openid-configuration") {
                let base = "http://\(request.header("Host") ?? "127.0.0.1")"
                return .json(200, [
                    "issuer": TokenExchangeAndLogoutTests.issuer,
                    "authorization_endpoint": "\(base)/oauth2/authorize",
                    "token_endpoint": "\(base)/oauth2/token",
                    "jwks_uri": "\(base)/oauth2/jwks",
                    "end_session_endpoint": "\(base)/oauth2/end_session",
                ])
            }
            if request.uri.contains("/oauth2/token") {
                state.increment("token")
                return .json(tokenStatus, tokenBody)
            }
            return .json(404, [:])
        }
    }

    private func withServiceClient(
        router: @escaping TestRouter,
        body: (AxiamClient, TestHTTPServer) async throws -> Void
    ) async throws {
        try await withClient(
            makeConfig: { port in
                try AxiamConfig(
                    baseURL: URL(string: "http://127.0.0.1:\(port)")!,
                    tenantID: TokenExchangeAndLogoutTests.tenantUUID,
                    requestTimeout: 10,
                    oidcClientID: TokenExchangeAndLogoutTests.clientID,
                    oidcClientSecret: Sensitive("service-secret"))
            },
            router: router,
            body: body)
    }

    private var narrowedToken: [String: Any] {
        [
            "access_token": "the-narrower-token",
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "token_type": "Bearer",
            "expires_in": 300,
            "scope": "orders:read",
        ]
    }

    // MARK: - §15 token exchange

    func testDelegationSendsTheActorTokenAndSurfacesTheGrantedScope() async throws {
        try await withServiceClient(router: makeRouter(tokenBody: narrowedToken)) { client, server in
            let exchanged = try await client.tokenExchange(
                subjectToken: Sensitive("the-users-token"),
                actorToken: Sensitive("the-services-token"),
                scopes: ["orders:read", "orders:write"])

            // §15.2 rule 7: the response's scope is what was actually GRANTED, which may be
            // narrower than what was asked for even on success. Reading it is the point.
            XCTAssertEqual(exchanged.scope, "orders:read")
            // §15.2 rule 6: surfaced, never dropped.
            XCTAssertEqual(exchanged.issuedTokenType, "urn:ietf:params:oauth:token-type:access_token")

            let body = String(decoding:
                try XCTUnwrap(server.state.requests(pathContaining: "/oauth2/token").last).body,
                as: UTF8.self)
            XCTAssertTrue(body.contains("actor_token=the-services-token"))
            XCTAssertTrue(body.contains("actor_token_type="))
            XCTAssertTrue(body.contains("client_secret=service-secret"))
        }
    }

    func testImpersonationSendsNoActorTokenAndNoneIsInvented() async throws {
        // §15.2 rule 1: the absence of an actor token IS the request for impersonation. No
        // default, and no "helpfully" reusing the client's own session as the actor.
        try await withServiceClient(router: makeRouter(tokenBody: narrowedToken)) { client, server in
            _ = try await client.tokenExchange(subjectToken: Sensitive("the-users-token"))

            let body = String(decoding:
                try XCTUnwrap(server.state.requests(pathContaining: "/oauth2/token").last).body,
                as: UTF8.self)
            XCTAssertFalse(body.contains("actor_token"))
        }
    }

    func testOmittingScopeSendsNoScopeParameter() async throws {
        try await withServiceClient(router: makeRouter(tokenBody: narrowedToken)) { client, server in
            _ = try await client.tokenExchange(subjectToken: Sensitive("t"))
            let body = String(decoding:
                try XCTUnwrap(server.state.requests(pathContaining: "/oauth2/token").last).body,
                as: UTF8.self)
            XCTAssertFalse(body.contains("scope="))
        }
    }

    func testUnauthorizedClientSurfacesVerbatimWithNoRetryAndNoRewriting() async throws {
        // §15.2 rule 2: it means "this client may not exchange" or "may not impersonate". Both
        // are registration facts an operator must fix; retrying or reworking the request into a
        // delegation would send one the caller never wrote.
        let router = makeRouter(tokenStatus: 400, tokenBody: [
            "error": "unauthorized_client",
            "error_description": "client is not registered for impersonation",
        ])
        try await withServiceClient(router: router) { client, server in
            do {
                _ = try await client.tokenExchange(subjectToken: Sensitive("t"))
                XCTFail("expected unauthorized_client to surface")
            } catch let error as AxiamError {
                guard case let .auth(authError) = error else { return XCTFail("expected an AuthError") }
                XCTAssertEqual(authError.oauthError, "unauthorized_client")
            }
            XCTAssertEqual(server.state.count("token"), 1, "no retry, and no second, rewritten request")
        }
    }

    func testInvalidScopeIsNotAutoNarrowed() async throws {
        // §15.2 rule 3: the server refuses rather than silently narrowing precisely so the
        // caller finds out here. Exactly one request, and no re-send with fewer scopes.
        let router = makeRouter(tokenStatus: 400, tokenBody: ["error": "invalid_scope"])
        try await withServiceClient(router: router) { client, server in
            do {
                _ = try await client.tokenExchange(
                    subjectToken: Sensitive("t"), scopes: ["orders:read", "orders:write"])
                XCTFail("expected invalid_scope to surface")
            } catch let error as AxiamError {
                guard case let .auth(authError) = error else { return XCTFail("expected an AuthError") }
                XCTAssertEqual(authError.oauthError, "invalid_scope")
            }
            XCTAssertEqual(server.state.count("token"), 1)
        }
    }

    func testACrossTenantSubjectTokenSurfacesInvalidGrantUnrefined() async throws {
        // §15.3: the server collapses "wrong tenant" into "bad token" because telling them
        // apart is a tenant-enumeration signal. Re-deriving the distinction client-side would
        // hand back exactly what the server withheld.
        let router = makeRouter(tokenStatus: 400, tokenBody: ["error": "invalid_grant"])
        try await withServiceClient(router: router) { client, _ in
            do {
                _ = try await client.tokenExchange(subjectToken: Sensitive("a-token-from-another-tenant"))
                XCTFail("expected invalid_grant")
            } catch let error as AxiamError {
                guard case let .auth(authError) = error else { return XCTFail("expected an AuthError") }
                XCTAssertEqual(authError.oauthError, "invalid_grant")
                XCTAssertFalse(authError.message.lowercased().contains("tenant"))
            }
        }
    }

    func testTheExchangedTokenCarriesNoRefreshTokenAndIsNotAdopted() async throws {
        // §15.2 rules 4 and 5: no refresh token exists on the type at all, and the result is
        // never the client's own credential — a MUST NOT here where adoption elsewhere is a MAY.
        var body = narrowedToken
        body["refresh_token"] = "a-refresh-token-the-server-should-not-send"
        try await withServiceClient(router: makeRouter(tokenBody: body)) { client, server in
            let exchanged = try await client.tokenExchange(subjectToken: Sensitive("t"))
            XCTAssertEqual(exchanged.accessToken.expose(), "the-narrower-token")

            // The type has nowhere to put a refresh token, so a server that sends one cannot
            // make this SDK carry it forward. And the client's own session is untouched: the
            // next call still authenticates as before.
            _ = try await client.tokenExchange(subjectToken: Sensitive("t"))
            let second = try XCTUnwrap(server.state.requests(pathContaining: "/oauth2/token").last)
            let secondBody = String(decoding: second.body, as: UTF8.self)
            XCTAssertTrue(secondBody.contains("client_secret=service-secret"))
            XCTAssertFalse(secondBody.contains("the-narrower-token"))
        }
    }

    // MARK: - §15.7 external-IdP subject tokens (X4)
    //
    // No new operation: the same tokenExchange carries a partner IdP's token. What changes is
    // which subject tokens the server accepts and what its refusals mean, so these tests are
    // about not getting in the way of either.

    /// A token minted by a partner's IdP. Opaque to the SDK — deliberately not a well-formed
    /// JWT, because nothing here may decode it.
    private static let externalSubjectToken = "partner-idp-subject-token"

    /// The one normative `error_description` (§15.7). It means "fix the AXIAM trust
    /// configuration", not "fix your token".
    private static let issuerNotConfigured =
        "the subject token's issuer is not configured for token exchange"

    func testAnExternalSubjectTokenTypeIsSentVerbatimAndTheResultSurfacesUnchanged() async throws {
        var body = narrowedToken
        body["scope"] = "read:orders"
        try await withServiceClient(router: makeRouter(tokenBody: body)) { client, server in
            let exchanged = try await client.tokenExchange(
                subjectToken: Sensitive(Self.externalSubjectToken),
                subjectTokenType: AxiamClient.jwtTokenType,
                scopes: ["read:orders"],
                audience: "https://orders.internal")

            let requestBody = String(decoding:
                try XCTUnwrap(server.state.requests(pathContaining: "/oauth2/token").last).body,
                as: UTF8.self)
            // The caller named …:jwt, so …:jwt goes on the wire. §15.7: the SDK must not
            // inspect the subject token to pick this, and must not override it.
            XCTAssertTrue(
                requestBody.contains("subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt"),
                "the caller's …:jwt must reach the wire, got: \(requestBody)")
            // Delegation across a trust boundary is unsupported; nothing may add one.
            XCTAssertFalse(requestBody.contains("actor_token"))

            // The cross-domain path is not a different result shape, and §15.2 rules 6-7 hold.
            XCTAssertEqual(exchanged.accessToken.expose(), "the-narrower-token")
            XCTAssertEqual(exchanged.issuedTokenType, "urn:ietf:params:oauth:token-type:access_token")
            XCTAssertEqual(exchanged.scope, "read:orders")
        }
    }

    func testSubjectTokenTypeIsNeverInferredFromTheTokenItself() async throws {
        try await withServiceClient(router: makeRouter(tokenBody: narrowedToken)) { client, server in
            // A subject token that *looks* exactly like a JWT. An SDK that sniffed the token
            // would send …:jwt here; §15.7 says it must not look, so the caller's silence still
            // means the §15.1 same-domain default.
            let jwtShaped = "eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJodHRwczovL3BhcnRuZXIuZXhhbXBsZS8ifQ.sig"
            _ = try await client.tokenExchange(subjectToken: Sensitive(jwtShaped))

            let requestBody = String(decoding:
                try XCTUnwrap(server.state.requests(pathContaining: "/oauth2/token").last).body,
                as: UTF8.self)
            XCTAssertTrue(
                requestBody.contains("subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token"),
                "§15.7: the token's shape must not pick the type, got: \(requestBody)")
        }
    }

    func testAnActorTokenWithAnExternalSubjectTokenIsRefusedWithoutRetry() async throws {
        let router = makeRouter(tokenStatus: 400, tokenBody: [
            "error": "invalid_request",
            "error_description": "actor_token is not supported for an external subject token",
        ])
        try await withServiceClient(router: router) { client, server in
            do {
                _ = try await client.tokenExchange(
                    subjectToken: Sensitive(Self.externalSubjectToken),
                    subjectTokenType: AxiamClient.jwtTokenType,
                    actorToken: Sensitive("the-services-token"))
                XCTFail("expected invalid_request to surface")
            } catch let error as AxiamError {
                guard case let .auth(authError) = error else { return XCTFail("expected an AuthError") }
                XCTAssertEqual(authError.oauthError, "invalid_request")
            }

            // §15.7: no retry, and no rewriting. Dropping the actor token and re-sending would
            // turn a delegation the caller asked for into an impersonation they did not.
            XCTAssertEqual(server.state.count("token"), 1, "exactly one request")
            let requestBody = String(decoding:
                try XCTUnwrap(server.state.requests(pathContaining: "/oauth2/token").last).body,
                as: UTF8.self)
            XCTAssertTrue(requestBody.contains("actor_token=the-services-token"),
                          "the request must be sent as written, actor token included")
            XCTAssertTrue(
                requestBody.contains("subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt"),
                "subject_token_type must not be rewritten")
        }
    }

    func testARefusedSubjectTokenTypeIsNeverRetriedAsAnother() async throws {
        // A refresh token is a re-authentication credential and an ID token is an assertion to
        // a client about a login; neither is a bearer credential for an API, so both are
        // refused BY NAME. Retrying as …:jwt would present one as if it were.
        for refused in [
            "urn:ietf:params:oauth:token-type:refresh_token",
            "urn:ietf:params:oauth:token-type:id_token",
        ] {
            let router = makeRouter(tokenStatus: 400, tokenBody: [
                "error": "invalid_request",
                "error_description": "unsupported subject_token_type",
            ])
            try await withServiceClient(router: router) { client, server in
                do {
                    _ = try await client.tokenExchange(
                        subjectToken: Sensitive(Self.externalSubjectToken),
                        subjectTokenType: refused)
                    XCTFail("expected the refused type to surface")
                } catch let error as AxiamError {
                    guard case let .auth(authError) = error else { return XCTFail("expected an AuthError") }
                    XCTAssertEqual(authError.oauthError, "invalid_request")
                }

                XCTAssertEqual(server.state.count("token"), 1, "no retry after a refused type")
                let requestBody = String(decoding:
                    try XCTUnwrap(server.state.requests(pathContaining: "/oauth2/token").last).body,
                    as: UTF8.self)
                let encoded = refused.replacingOccurrences(of: ":", with: "%3A")
                XCTAssertTrue(requestBody.contains("subject_token_type=\(encoded)"),
                              "§15.7: the refused type must be sent as named, not swapped")
            }
        }
    }

    func testTheIssuerNotConfiguredDescriptionReachesTheCallerIntact() async throws {
        let router = makeRouter(tokenStatus: 400, tokenBody: [
            "error": "invalid_grant",
            "error_description": Self.issuerNotConfigured,
        ])
        try await withServiceClient(router: router) { client, _ in
            do {
                _ = try await client.tokenExchange(
                    subjectToken: Sensitive(Self.externalSubjectToken),
                    subjectTokenType: AxiamClient.jwtTokenType)
                XCTFail("expected invalid_grant to surface")
            } catch let error as AxiamError {
                guard case let .auth(authError) = error else { return XCTFail("expected an AuthError") }
                XCTAssertEqual(authError.oauthError, "invalid_grant")
                // This is the ONLY distinguishable external failure, and the whole point of it
                // is that an integrator can tell "fix the AXIAM trust config" from "fix your
                // token". Truncating or rewording it destroys that.
                XCTAssertEqual(authError.oauthErrorDescription, Self.issuerNotConfigured)
            }
        }
    }

    func testNoHelperReExchangesAnExternallyExchangedToken() async throws {
        // Tokens minted from an external subject token carry `ext_exchange`, and BOTH exchange
        // paths refuse a subject token bearing it: exchanges do not compose. The SDK's part is
        // to never feed a result back in by itself.
        try await withServiceClient(router: makeRouter(tokenBody: narrowedToken)) { client, server in
            let exchanged = try await client.tokenExchange(
                subjectToken: Sensitive(Self.externalSubjectToken),
                subjectTokenType: AxiamClient.jwtTokenType)

            XCTAssertEqual(exchanged.accessToken.expose(), "the-narrower-token")
            // Exactly one exchange happened: nothing looped the result back in. §15.2 rule 5 is
            // what stops it — had the result been adopted, the next exchange would carry it as
            // a *subject* token, which is exactly the re-exchange §15.7 forbids, arrived at by
            // accident rather than by decision.
            XCTAssertEqual(server.state.count("token"), 1,
                           "exactly one exchange — nothing re-exchanged the result")
        }
    }

    // MARK: - §12.7 logout

    private func logoutClaims(
        issuer: String = TokenExchangeAndLogoutTests.issuer,
        audience: Any = TokenExchangeAndLogoutTests.clientID,
        events: [String: Any]? = ["http://schemas.openid.net/event/backchannel-logout": [:]],
        sid: String? = "session-7",
        sub: String? = "user-42",
        nonce: String? = nil,
        iat: Double? = nil
    ) -> [String: Any] {
        var claims: [String: Any] = [
            "iss": issuer,
            "aud": audience,
            "jti": "logout-token-1",
            "iat": iat ?? Date().timeIntervalSince1970,
            "exp": Date().addingTimeInterval(120).timeIntervalSince1970,
        ]
        if let events { claims["events"] = events }
        if let sid { claims["sid"] = sid }
        if let sub { claims["sub"] = sub }
        if let nonce { claims["nonce"] = nonce }
        return claims
    }

    func testLogoutUrlComesFromDiscoveryAndPassesStateThrough() async throws {
        try await withServiceClient(router: makeRouter()) { client, _ in
            let url = try await client.logoutURL(
                idToken: Sensitive("the-id-token"),
                postLogoutRedirectURI: "https://app.test/bye",
                state: "caller-chosen-state")

            // §12.7.2 rule 1: from the discovery document, not concatenated onto the issuer.
            XCTAssertTrue(url.contains("/oauth2/end_session"))
            let items = URLComponents(string: url)!.queryItems!
            let map = Dictionary(uniqueKeysWithValues: items.map { ($0.name, $0.value ?? "") })
            XCTAssertEqual(map["id_token_hint"], "the-id-token")
            XCTAssertEqual(map["post_logout_redirect_uri"], "https://app.test/bye")
            // §12.7.2 rule 2: passed through, never invented.
            XCTAssertEqual(map["state"], "caller-chosen-state")
        }
    }

    func testLogoutUrlInventsNoStateWhenTheCallerSuppliedNone() async throws {
        try await withServiceClient(router: makeRouter()) { client, _ in
            let url = try await client.logoutURL(idToken: Sensitive("the-id-token"))
            XCTAssertFalse(url.contains("state="))
        }
    }

    func testVerifyLogoutTokenReturnsSidSubAndJti() async throws {
        try await withServiceClient(router: makeRouter()) { client, _ in
            let token = signer.makeJWT(claims: logoutClaims())
            let verified = try await client.verifyLogoutToken(token)

            // §12.7.3: never a bare boolean — the RP has to know WHICH session to end.
            XCTAssertEqual(verified.sid, "session-7")
            XCTAssertEqual(verified.subject, "user-42")
            XCTAssertEqual(verified.jwtID, "logout-token-1")
        }
    }

    func testVerifyLogoutTokenRejectsTheReplayedIdTokenShapes() async throws {
        // The two checks that distinguish a logout token from an ID token, and the four that
        // keep another RP's token or a stale one from ending a session here.
        let cases: [(String, [String: Any])] = [
            ("no backchannel-logout event", logoutClaims(events: nil)),
            ("a nonce, which Back-Channel Logout §2.4 forbids", logoutClaims(nonce: "n")),
            ("another RP's audience", logoutClaims(audience: "some-other-client")),
            ("a foreign issuer", logoutClaims(issuer: "https://evil.example")),
            ("neither sid nor sub", logoutClaims(sid: nil, sub: nil)),
            ("an iat in the future", logoutClaims(iat: Date().addingTimeInterval(3600).timeIntervalSince1970)),
        ]
        try await withServiceClient(router: makeRouter()) { client, _ in
            for (label, claims) in cases {
                let token = self.signer.makeJWT(claims: claims)
                do {
                    _ = try await client.verifyLogoutToken(token)
                    XCTFail("expected rejection: \(label)")
                } catch let error as AxiamError {
                    // §12.7.3 rule 8: a typed error, and one that never echoes the token.
                    guard case let .auth(authError) = error else {
                        return XCTFail("expected an AuthError for \(label)")
                    }
                    XCTAssertFalse(authError.message.contains(token))
                }
            }
        }
    }
}
