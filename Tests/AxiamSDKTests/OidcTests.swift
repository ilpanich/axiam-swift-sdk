import XCTest
import Foundation
@testable import AxiamSDK

/// CONTRACT.md §12 — the OIDC/SSO relying-party helpers, ported to this SDK in contract 1.11
/// (§12.6).
///
/// The §12.4 block below is the one the contract names explicitly: *"every SDK MUST carry one
/// failing test per requirement"*. There are seven rules and there are seven failing tests, plus
/// the all-or-nothing assertion rule 7 adds on top of them — a validation failure must discard
/// the access and refresh tokens from the same response, not just the ID token.
final class OidcTests: XCTestCase {
    // The harness below is static, and deliberately so. Every router this file builds is a
    // `@Sendable` closure, which cannot capture an `XCTestCase` — `self` is not `Sendable`
    // and never will be. Hanging the fixtures off the type instead of the instance removes
    // the capture at the source, rather than smuggling `self` across with an unsafe
    // annotation. `TestSigner` is a `Sendable` value type, so one shared signer is safe;
    // each test still serves that signer's JWKS from its own server, so nothing is coupled
    // between tests beyond the key material itself.
    private static let signer = TestSigner()

    private static let tenantUUID = "22222222-2222-2222-2222-222222222222"
    private static let clientID = "invoices-client"
    private static let issuer = "https://iam.example.test"
    private static let nonce = "the-nonce-from-begin"

    // MARK: - Harness

    /// The discovery document, with every endpoint absolute and pointing back at the test server.
    private static func discoveryJSON(base: String) -> [String: Any] {
        [
            "issuer": Self.issuer,
            "authorization_endpoint": "\(base)/oauth2/authorize",
            "token_endpoint": "\(base)/oauth2/token",
            "jwks_uri": "\(base)/oauth2/jwks",
            "introspection_endpoint": "\(base)/oauth2/introspect",
            "revocation_endpoint": "\(base)/oauth2/revoke",
            "end_session_endpoint": "\(base)/oauth2/end_session",
            "device_authorization_endpoint": "\(base)/oauth2/device_authorization",
        ]
    }

    /// Claims for a valid ID token. Individual tests break exactly one field.
    private static func idClaims(
        issuer: String = OidcTests.issuer,
        audience: Any = OidcTests.clientID,
        exp: Double? = nil,
        iat: Double? = nil,
        nonce: String? = OidcTests.nonce,
        extra: [String: Any] = [:]
    ) -> [String: Any] {
        var claims: [String: Any] = [
            "sub": "user-42",
            "iss": issuer,
            "aud": audience,
            "tenant_id": Self.tenantUUID,
        ]
        claims["exp"] = exp ?? Date().addingTimeInterval(3600).timeIntervalSince1970
        claims["iat"] = iat ?? Date().addingTimeInterval(-10).timeIntervalSince1970
        if let nonce { claims["nonce"] = nonce }
        for (key, value) in extra { claims[key] = value }
        return claims
    }

    /// A router serving discovery, JWKS and the token endpoint, with `tokenBody` as the grant's
    /// answer. Records what reached the wire so the §12.1/§12.3 rules can be asserted on it.
    private func makeRouter(
        tokenStatus: Int = 200,
        tokenBody: @escaping @Sendable (String) -> [String: Any],
        extra: (@Sendable (TestRequest, TestServerState) -> TestResponse?)? = nil
    ) -> TestRouter {
        let signer = OidcTests.signer
        let discovery: @Sendable (String) -> [String: Any] = { OidcTests.discoveryJSON(base: $0) }
        return { request, state in
            if let extra, let response = extra(request, state) { return response }
            if request.uri.hasSuffix("/oauth2/jwks") {
                return .json(200, signer.jwksJSON())
            }
            if request.uri.contains("/.well-known/openid-configuration") {
                state.increment("discovery")
                let base = "http://\(request.header("Host") ?? "127.0.0.1")"
                return .json(200, discovery(base))
            }
            if request.uri.contains("/oauth2/token") {
                state.increment("token")
                let base = "http://\(request.header("Host") ?? "127.0.0.1")"
                return .json(tokenStatus, tokenBody(base))
            }
            return .json(404, [:])
        }
    }

    private func withOidcClient(
        clientSecret: String? = "client-secret",
        tenantID: String? = OidcTests.tenantUUID,
        router: @escaping TestRouter,
        body: (AxiamClient, TestHTTPServer) async throws -> Void
    ) async throws {
        try await withClient(
            makeConfig: { port in
                try AxiamConfig(
                    baseURL: URL(string: "http://127.0.0.1:\(port)")!,
                    tenantID: tenantID,
                    tenantSlug: tenantID == nil ? "acme" : nil,
                    requestTimeout: 10,
                    oidcClientID: OidcTests.clientID,
                    oidcClientSecret: clientSecret.map(Sensitive.init))
            },
            router: router,
            body: body)
    }

    /// A token response carrying a signed ID token built from `claims`.
    private static func tokenResponse(_ claims: [String: Any]) -> [String: Any] {
        [
            "access_token": "the-access-token",
            "token_type": "Bearer",
            "expires_in": 900,
            "scope": "openid profile",
            "refresh_token": "the-refresh-token",
            "id_token": signer.makeJWT(claims: claims),
        ]
    }

    // MARK: - §12.1 oidc_discover

    func testDiscoveryIsCachedPerClient() async throws {
        try await withOidcClient(router: makeRouter(tokenBody: { _ in [:] })) { client, server in
            _ = try await client.oidcDiscover()
            _ = try await client.oidcDiscover()
            // An endpoint map is not a credential; re-fetching it per call is a self-inflicted
            // round trip (§12.3 rule 6).
            XCTAssertEqual(server.state.count("discovery"), 1)
        }
    }

    // MARK: - §12.1 oidc_begin

    func testBeginBuildsAPkceRedirectAndStoresNothing() async throws {
        try await withOidcClient(router: makeRouter(tokenBody: { _ in [:] })) { client, server in
            let first = try await client.oidcBegin(redirectURI: "https://app.test/cb")
            let second = try await client.oidcBegin(redirectURI: "https://app.test/cb")

            let components = URLComponents(string: first.url)!
            let items = Dictionary(
                uniqueKeysWithValues: components.queryItems!.map { ($0.name, $0.value ?? "") })
            XCTAssertEqual(items["response_type"], "code")
            XCTAssertEqual(items["client_id"], Self.clientID)
            XCTAssertEqual(items["code_challenge_method"], "S256")
            XCTAssertEqual(items["state"], first.state)
            XCTAssertEqual(items["nonce"], first.nonce)
            // The challenge is the hash, never the verifier itself — `plain` protects nothing.
            XCTAssertNotEqual(items["code_challenge"], first.codeVerifier.expose())
            XCTAssertEqual(items["code_challenge"], OidcPkce.challenge(for: first.codeVerifier.expose()))

            // §12.3 rule 1: nothing is retained, so two calls share nothing.
            XCTAssertNotEqual(first.state, second.state)
            XCTAssertNotEqual(first.nonce, second.nonce)
            XCTAssertNotEqual(first.codeVerifier.expose(), second.codeVerifier.expose())

            // No authorization-request I/O of its own: only the cached discovery fetch.
            XCTAssertEqual(server.state.count("token"), 0)
        }
    }

    // MARK: - §12.1 oidc_exchange (happy path + wire rules)

    func testExchangePostsFormEncodedWithTenantIdAsAQueryParameter() async throws {
        let router = makeRouter(tokenBody: { _ in OidcTests.tokenResponse(OidcTests.idClaims()) })
        try await withOidcClient(router: router) { client, server in
            let tokens = try await client.oidcExchange(
                code: "the-code", redirectURI: "https://app.test/cb",
                codeVerifier: Sensitive("verifier"), nonce: Self.nonce)

            XCTAssertEqual(tokens.accessToken.expose(), "the-access-token")
            XCTAssertEqual(tokens.idClaims?.subject, "user-42")

            let request = try XCTUnwrap(server.state.requests(pathContaining: "/oauth2/token").last)
            // §12.1 note 1: form-encoded, not JSON.
            XCTAssertEqual(request.header("Content-Type"), "application/x-www-form-urlencoded")
            // §12.1 note 2: tenant_id is a QUERY parameter, never a body field.
            XCTAssertTrue(request.uri.contains("tenant_id=\(Self.tenantUUID)"))
            let body = String(decoding: request.body, as: UTF8.self)
            XCTAssertFalse(body.contains("tenant_id"))
            // §12.1 note 3: client_secret_post, never HTTP Basic.
            XCTAssertNil(request.header("Authorization"))
            XCTAssertTrue(body.contains("client_secret=client-secret"))
        }
    }

    func testASlugOnlyClientCannotReachTheTokenEndpointAndSendsNothing() async throws {
        let router = makeRouter(tokenBody: { _ in OidcTests.tokenResponse(OidcTests.idClaims()) })
        try await withOidcClient(tenantID: nil, router: router) { client, server in
            do {
                _ = try await client.oidcExchange(
                    code: "c", redirectURI: "https://app.test/cb",
                    codeVerifier: Sensitive("v"), nonce: Self.nonce)
                XCTFail("expected a client-side refusal")
            } catch {
                // §12.3 rule 4: raised client-side, with NO wire call — a slug must never reach
                // the tenant_id query parameter.
                XCTAssertEqual(server.state.count("token"), 0)
            }
        }
    }

    // MARK: - §12.4 — one failing test per rule

    /// Rule 1: `alg` is pinned to EdDSA before any key lookup. `none` is rejected outright.
    func testRule1AlgNoneIsRejected() async throws {
        let router = makeRouter(tokenBody: { _ in
            let claims = OidcTests.idClaims()
            var body = OidcTests.tokenResponse(claims)
            body["id_token"] = OidcTests.signer.makeAlgNoneJWT(claims: claims)
            return body
        })
        try await assertExchangeRejects(router: router)
    }

    /// Rule 2: an unknown `kid` is rejected after the single re-fetch.
    func testRule2UnknownKidIsRejected() async throws {
        let router = makeRouter(tokenBody: { _ in
            let claims = OidcTests.idClaims()
            var body = OidcTests.tokenResponse(claims)
            body["id_token"] = OidcTests.signer.makeJWT(
                claims: claims, kidOverride: "a-kid-nobody-published")
            return body
        })
        try await assertExchangeRejects(router: router)
    }

    /// Rule 3: `iss` must equal the discovery issuer by exact string comparison — no
    /// trailing-slash tolerance, which is why this test appends exactly one.
    func testRule3IssuerMismatchIsRejected() async throws {
        let router = makeRouter(tokenBody: { _ in
            OidcTests.tokenResponse(OidcTests.idClaims(issuer: OidcTests.issuer + "/"))
        })
        try await assertExchangeRejects(router: router, expecting: "invalid_issuer")
    }

    /// Rule 4: `aud` must contain this client's `client_id`.
    func testRule4AudienceMismatchIsRejected() async throws {
        let router = makeRouter(tokenBody: { _ in
            OidcTests.tokenResponse(OidcTests.idClaims(audience: "some-other-client"))
        })
        try await assertExchangeRejects(router: router, expecting: "invalid_audience")
    }

    /// Rule 4, second half: multiple audiences require an `azp` naming this client.
    func testRule4MultipleAudiencesWithoutAzpIsRejected() async throws {
        let router = makeRouter(tokenBody: { _ in
            OidcTests.tokenResponse(OidcTests.idClaims(audience: [OidcTests.clientID, "another-client"]))
        })
        try await assertExchangeRejects(router: router, expecting: "invalid_audience")
    }

    /// Rule 5: an expired token. Every rule-5 failure reports the one code `token_expired`.
    func testRule5ExpiredTokenIsRejected() async throws {
        let router = makeRouter(tokenBody: { _ in
            OidcTests.tokenResponse(OidcTests.idClaims(exp: Date().addingTimeInterval(-3600).timeIntervalSince1970))
        })
        try await assertExchangeRejects(router: router, expecting: "token_expired")
    }

    /// Rule 5, and the clarification that makes it awkward: an **absent** `exp` is also
    /// `token_expired`, not a decode error with some other code.
    func testRule5AbsentExpIsAlsoTokenExpired() async throws {
        let router = makeRouter(tokenBody: { _ in
            var claims = OidcTests.idClaims()
            claims.removeValue(forKey: "exp")
            return OidcTests.tokenResponse(claims)
        })
        try await assertExchangeRejects(router: router, expecting: "token_expired")
    }

    /// Rule 6: the nonce must match the one `oidcBegin` produced.
    func testRule6NonceMismatchIsRejected() async throws {
        let router = makeRouter(tokenBody: { _ in
            OidcTests.tokenResponse(OidcTests.idClaims(nonce: "a-different-nonce"))
        })
        try await assertExchangeRejects(router: router, expecting: "nonce_mismatch")
    }

    /// Rule 6: an absent nonce is a mismatch, not a skip. `oidc_exchange` always requests
    /// `openid`, so the server always issues one.
    func testRule6AbsentNonceIsRejected() async throws {
        let router = makeRouter(tokenBody: { _ in
            OidcTests.tokenResponse(OidcTests.idClaims(nonce: nil))
        })
        try await assertExchangeRejects(router: router, expecting: "nonce_mismatch")
    }

    /// Rule 7: all-or-nothing. The access and refresh tokens from the same response must not
    /// reach the caller — there is no partial success and no "skip validation" option.
    func testRule7AValidationFailureDiscardsTheWholeTokenSet() async throws {
        let router = makeRouter(tokenBody: { _ in
            OidcTests.tokenResponse(OidcTests.idClaims(nonce: "wrong"))
        })
        try await withOidcClient(router: router) { client, _ in
            do {
                let tokens = try await client.oidcExchange(
                    code: "c", redirectURI: "https://app.test/cb",
                    codeVerifier: Sensitive("v"), nonce: Self.nonce)
                XCTFail("expected rejection, got a token set with \(tokens.accessToken)")
            } catch {
                // The only observable outcome is the throw: there is no path on which the
                // access_token from that response is returned, adopted, or stored.
                XCTAssertTrue(error is AxiamError)
            }
        }
    }

    /// Rule 6 does **not** apply to a refresh-issued ID token (OIDC Core §12.2), so a token set
    /// with no nonce is accepted there while the same one is rejected by `oidcExchange` above.
    func testRefreshSkipsTheNonceRule() async throws {
        let router = makeRouter(tokenBody: { _ in
            OidcTests.tokenResponse(OidcTests.idClaims(nonce: nil))
        })
        try await withOidcClient(router: router) { client, _ in
            let tokens = try await client.oidcRefresh(refreshToken: Sensitive("the-refresh-token"))
            XCTAssertEqual(tokens.idClaims?.subject, "user-42")
        }
    }

    // MARK: - §12.1 introspect / revoke

    func testRevokeTreatsAnUnknownTokenAsSuccess() async throws {
        // RFC 7009 idempotence, which §12.1 note 5 requires a test for: the server answers 200
        // for a token it never issued, and that is success.
        let router = makeRouter(tokenBody: { _ in [:] }, extra: { request, state in
            if request.uri.contains("/oauth2/revoke") {
                state.increment("revoke")
                return TestResponse(status: 200, headers: [], body: Data())
            }
            return nil
        })
        try await withOidcClient(router: router) { client, server in
            try await client.revoke(token: Sensitive("a-token-nobody-issued"))
            XCTAssertEqual(server.state.count("revoke"), 1)
        }
    }

    func testRevokeDoesNotTreatAServerErrorAsSuccess() async throws {
        // Returning void does not make a 5xx a success (§12.1 note 5, corrected in contract 1.5).
        let router = makeRouter(tokenBody: { _ in [:] }, extra: { request, _ in
            request.uri.contains("/oauth2/revoke") ? .json(500, ["error": "server_error"]) : nil
        })
        try await withOidcClient(router: router) { client, _ in
            do {
                try await client.revoke(token: Sensitive("t"))
                XCTFail("expected a 500 to surface")
            } catch {
                XCTAssertTrue(error is AxiamError)
            }
        }
    }

    func testIntrospectRequiresAClientSecret() async throws {
        // §12.1 note 4: a public client cannot call it, and finding out client-side beats a 401.
        let router = makeRouter(tokenBody: { _ in [:] })
        try await withOidcClient(clientSecret: nil, router: router) { client, server in
            do {
                _ = try await client.introspect(token: Sensitive("t"))
                XCTFail("expected a client-side refusal")
            } catch {
                XCTAssertEqual(server.state.requests(pathContaining: "/oauth2/introspect").count, 0)
            }
        }
    }

    // MARK: - §12.3 rule 3 — the OAuth2 error taxonomy

    func testATokenEndpoint400SurfacesAsAnOAuthProtocolError() async throws {
        let router = makeRouter(tokenStatus: 400, tokenBody: { _ in
            ["error": "invalid_grant", "error_description": "authorization code expired"]
        })
        try await withOidcClient(router: router) { client, _ in
            do {
                _ = try await client.oidcExchange(
                    code: "c", redirectURI: "https://app.test/cb",
                    codeVerifier: Sensitive("v"), nonce: Self.nonce)
                XCTFail("expected the 400 to surface")
            } catch let error as AxiamError {
                guard case let .auth(authError) = error else {
                    return XCTFail("a token-endpoint 400 must not surface as the generic §2 400 row")
                }
                XCTAssertEqual(authError.oauthError, "invalid_grant")
                XCTAssertEqual(authError.oauthErrorDescription, "authorization code expired")
            }
        }
    }

    // MARK: - Helpers

    /// Runs an exchange that must fail validation, optionally asserting the §12.3 rule 3 code.
    private func assertExchangeRejects(
        router: @escaping TestRouter,
        expecting code: String? = nil,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async throws {
        try await withOidcClient(router: router) { client, _ in
            do {
                _ = try await client.oidcExchange(
                    code: "c", redirectURI: "https://app.test/cb",
                    codeVerifier: Sensitive("v"), nonce: Self.nonce)
                XCTFail("expected the id_token to be rejected", file: file, line: line)
            } catch let error as AxiamError {
                guard case let .auth(authError) = error else {
                    return XCTFail("expected an AuthError", file: file, line: line)
                }
                if let code {
                    XCTAssertEqual(authError.oauthError, code, file: file, line: line)
                }
            }
        }
    }

    // MARK: - §12.6 client-credentials grant

    /// The §12.6 embedded-consumer path: a token with no `openid` scope, so no ID token comes
    /// back and none is demanded. The rest of the OIDC suite drives the authorization-code
    /// flow, which meant this whole method was never executed.
    func testClientCredentialsReturnsATokenSetWithNoIdToken() async throws {
        let router = makeRouter(tokenBody: { _ in
            ["access_token": "cc-access", "token_type": "Bearer", "expires_in": 900,
             "scope": "invoices:read"]
        })
        try await withOidcClient(router: router) { client, _ in
            let set = try await client.loginClientCredentials(scope: "invoices:read")
            XCTAssertEqual(set.accessToken.wrapped, "cc-access")
            XCTAssertNil(set.idClaims, "a client-credentials grant carries no ID token")
        }
    }

    func testClientCredentialsWithoutAClientSecretIsRefusedBeforeTheWire() async throws {
        let router = makeRouter(tokenBody: { _ in [:] })
        try await withOidcClient(clientSecret: nil, router: router) { client, server in
            do {
                _ = try await client.loginClientCredentials()
                XCTFail("a public client cannot use the client-credentials grant")
            } catch {
                // The check is that nothing reached the token endpoint: a missing secret must
                // fail locally rather than by sending an unauthenticated grant request.
                XCTAssertEqual(server.state.count("token"), 0)
            }
        }
    }

    // MARK: - §12.1 introspect

    func testIntrospectReturnsTheParsedResult() async throws {
        let router = makeRouter(
            tokenBody: { _ in [:] },
            extra: { request, state in
                guard request.uri.contains("/oauth2/introspect") else { return nil }
                state.increment("introspect")
                return .json(200, [
                    "active": true, "scope": "invoices:read", "client_id": "invoices-client",
                    "username": "alice", "token_type": "Bearer", "sub": "user-42",
                ])
            })
        try await withOidcClient(router: router) { client, _ in
            let result = try await client.introspect(
                token: Sensitive("some-token"), tokenTypeHint: "access_token")
            XCTAssertTrue(result.active)
            XCTAssertEqual(result.subject, "user-42")
            XCTAssertEqual(result.clientID, "invoices-client")
        }
    }

    /// RFC 7662 says an inactive token is a 200 with `active: false`, not an error. Worth
    /// pinning: treating it as a failure would make "this token is not valid" indistinguishable
    /// from "introspection is broken", and callers would fail open on the wrong one.
    func testIntrospectReportsAnInactiveTokenAsASuccessfulAnswer() async throws {
        let router = makeRouter(
            tokenBody: { _ in [:] },
            extra: { request, _ in
                guard request.uri.contains("/oauth2/introspect") else { return nil }
                return .json(200, ["active": false])
            })
        try await withOidcClient(router: router) { client, _ in
            let result = try await client.introspect(token: Sensitive("revoked"))
            XCTAssertFalse(result.active)
            XCTAssertNil(result.subject)
        }
    }

    // MARK: - §12.1 sso_start

    func testSsoStartSendsTenantContextAndReturnsTheAuthorizeURL() async throws {
        let router = makeRouter(
            tokenBody: { _ in [:] },
            extra: { request, state in
                guard request.uri.contains("/auth/federation/oidc/start") else { return nil }
                state.increment("sso_start")
                return .json(200, [
                    "authorize_url": "https://idp.example.test/authorize?state=abc",
                    "state": "abc",
                    "expires_in_secs": 300,
                ])
            })
        try await withOidcClient(router: router) { client, server in
            let result = try await client.ssoStart(
                federationConfigID: "fed-1", redirectURI: "https://app.test/cb")
            XCTAssertEqual(result.state, "abc")
            XCTAssertEqual(result.expiresInSecs, 300)
            XCTAssertTrue(result.authorizeURL.hasPrefix("https://idp.example.test/"))
            // §5.1: the tenant travels in the JSON body here, not as a query parameter.
            let sent = server.state.requests(pathContaining: "/oidc/start").first
            let body = String(data: sent?.body ?? Data(), encoding: .utf8) ?? ""
            XCTAssertTrue(body.contains(Self.tenantUUID), "sso_start must carry tenant context")
        }
    }

    // MARK: - discovery documents that omit an endpoint

    /// A router whose discovery document contains ONLY the keys in `keep`.
    ///
    /// Every optional endpoint in the document is a branch: the SDK has to
    /// refuse the operation rather than construct a URL from nil. These were
    /// the last uncovered lines in Oidc.swift, Logout.swift and
    /// DeviceGrant.swift, and they are the ones a server misconfiguration
    /// actually hits.
    private func routerWithPartialDiscovery(keep: [String]) -> TestRouter {
        let signer = OidcTests.signer
        let full: @Sendable (String) -> [String: Any] = { OidcTests.discoveryJSON(base: $0) }
        return { request, state in
            if request.uri.hasSuffix("/oauth2/jwks") { return .json(200, signer.jwksJSON()) }
            if request.uri.contains("/.well-known/openid-configuration") {
                state.increment("discovery")
                let base = "http://\(request.header("Host") ?? "127.0.0.1")"
                let complete = full(base)
                var trimmed: [String: Any] = ["issuer": complete["issuer"] ?? ""]
                for key in keep { trimmed[key] = complete[key] }
                return .json(200, trimmed)
            }
            return .json(404, [:])
        }
    }

    func testIntrospectRefusesWhenDiscoveryAdvertisesNoIntrospectionEndpoint() async throws {
        try await withOidcClient(
            router: routerWithPartialDiscovery(keep: ["token_endpoint"])
        ) { client, _ in
            do {
                _ = try await client.introspect(token: Sensitive("t"))
                XCTFail("introspection without an endpoint must not be attempted")
            } catch let error as AxiamError {
                guard case .network = error else { return XCTFail("expected a NetworkError") }
            }
        }
    }

    func testRevokeRefusesWhenDiscoveryAdvertisesNoRevocationEndpoint() async throws {
        try await withOidcClient(
            router: routerWithPartialDiscovery(keep: ["token_endpoint"])
        ) { client, _ in
            do {
                try await client.revoke(token: Sensitive("t"))
                XCTFail("revocation without an endpoint must not be attempted")
            } catch let error as AxiamError {
                guard case .network = error else { return XCTFail("expected a NetworkError") }
            }
        }
    }

    func testEndSessionRefusesWhenDiscoveryAdvertisesNoEndSessionEndpoint() async throws {
        try await withOidcClient(
            router: routerWithPartialDiscovery(keep: ["token_endpoint"])
        ) { client, _ in
            do {
                _ = try await client.logoutURL(idToken: Sensitive("t"))
                XCTFail("a logout URL cannot be built without an end_session_endpoint")
            } catch let error as AxiamError {
                guard case .network = error else { return XCTFail("expected a NetworkError") }
            }
        }
    }

    func testDeviceAuthorizationRefusesWhenDiscoveryAdvertisesNoDeviceEndpoint() async throws {
        try await withOidcClient(
            router: routerWithPartialDiscovery(keep: ["token_endpoint"])
        ) { client, _ in
            do {
                _ = try await client.deviceAuthorize()
                XCTFail("the device grant cannot start without its endpoint")
            } catch let error as AxiamError {
                guard case .network = error else { return XCTFail("expected a NetworkError") }
            }
        }
    }
}
