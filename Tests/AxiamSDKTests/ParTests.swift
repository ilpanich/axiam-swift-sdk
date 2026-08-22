import XCTest
import Foundation
@testable import AxiamSDK

/// CONTRACT.md §26 — Pushed Authorization Requests (RFC 9126).
///
/// Two assertions carry the section:
///
/// - `testASuccessfulPushAnswers201` — RFC 9126 §2.2 specifies *Created*. A success
///   predicate written `== 200` passes every other test in this file and treats every real
///   push as a failure.
/// - `testTheRedirectUrlCarriesExactlyTwoParameters` — the server refuses a request that
///   mixes a `request_uri` with inline authorization parameters rather than merging them,
///   and merging is where parameter confusion lives (§26.2 rule 2).
final class ParTests: XCTestCase {

    private static let tenantUUID = "22222222-2222-2222-2222-222222222222"
    private static let clientID = "test-relying-party"
    private static let clientSecret = "test-client-secret"
    private static let redirectURI = "https://app.example.com/callback"
    private static let requestURI =
        "urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c"

    private func discoveryJSON(base: String, withPar: Bool = true) -> [String: Any] {
        var document: [String: Any] = [
            "issuer": base,
            "authorization_endpoint": "\(base)/oauth2/authorize",
            "token_endpoint": "\(base)/oauth2/token",
            "jwks_uri": "\(base)/oauth2/jwks",
            "introspection_endpoint": "\(base)/oauth2/introspect",
            "revocation_endpoint": "\(base)/oauth2/revoke",
        ]
        if withPar {
            document["pushed_authorization_request_endpoint"] = "\(base)/oauth2/par"
        }
        return document
    }

    private func router(
        withPar: Bool = true,
        parStatus: Int = 201,
        parBody: [String: Any]? = nil
    ) -> TestRouter {
        let discovery = discoveryJSON
        let body = parBody ?? ["request_uri": Self.requestURI, "expires_in": 90]
        return { request, _ in
            let base = "http://\(request.header("Host") ?? "127.0.0.1")"
            if request.uri.contains("/.well-known/openid-configuration") {
                return .json(200, discovery(base, withPar))
            }
            if request.uri.contains("/oauth2/par") {
                return .json(parStatus, body)
            }
            return .json(404, [:])
        }
    }

    private func withParClient(
        clientSecret: String? = ParTests.clientSecret,
        router: @escaping TestRouter,
        body: (AxiamClient, TestHTTPServer) async throws -> Void
    ) async throws {
        try await withClient(
            makeConfig: { port in
                try AxiamConfig(
                    baseURL: URL(string: "http://127.0.0.1:\(port)")!,
                    tenantID: ParTests.tenantUUID,
                    requestTimeout: 10,
                    oidcClientID: ParTests.clientID,
                    oidcClientSecret: clientSecret.map(Sensitive.init)
                )
            },
            router: router,
            body: body
        )
    }

    private func formFields(_ request: TestRequest) -> [String: String] {
        var fields: [String: String] = [:]
        for pair in String(decoding: request.body, as: UTF8.self).split(separator: "&") {
            let parts = pair.split(separator: "=", maxSplits: 1).map(String.init)
            guard parts.count == 2 else { continue }
            fields[parts[0].removingPercentEncoding ?? parts[0]] =
                parts[1].replacingOccurrences(of: "+", with: " ").removingPercentEncoding ?? parts[1]
        }
        return fields
    }

    // MARK: - §26.1 the push

    func testASuccessfulPushAnswers201() async throws {
        try await withParClient(router: router()) { client, _ in
            let config = try await client.oidcDiscover()
            let begun = try await client.oidcBegin(
                redirectURI: Self.redirectURI,
                scope: "openid profile",
                configuration: config
            )

            let pushed = try await client.oidcPar(
                request: begun,
                redirectURI: Self.redirectURI,
                scope: "openid profile",
                configuration: config
            )

            XCTAssertEqual(pushed.requestURI.expose(), Self.requestURI)
            XCTAssertEqual(pushed.expiresIn, 90)
        }
    }

    func testThePushGoesToTheDiscoveredEndpointWithTheTenantQuery() async throws {
        try await withParClient(router: router()) { client, server in
            let config = try await client.oidcDiscover()
            let begun = try await client.oidcBegin(
                redirectURI: Self.redirectURI, configuration: config)

            _ = try await client.oidcPar(
                request: begun, redirectURI: Self.redirectURI, configuration: config)

            let sent = try XCTUnwrap(server.state.requests(pathContaining: "/oauth2/par").first)
            XCTAssertEqual(sent.method, "POST")
            // §12.1 rule 2: the /oauth2 endpoints carry the tenant as a query parameter,
            // and PAR is one of those.
            XCTAssertTrue(sent.uri.contains("tenant_id=\(Self.tenantUUID)"), sent.uri)
        }
    }

    func testThePushCarriesEverythingOidcBeginComputed() async throws {
        try await withParClient(router: router()) { client, server in
            let config = try await client.oidcDiscover()
            let begun = try await client.oidcBegin(
                redirectURI: Self.redirectURI,
                scope: "openid profile",
                configuration: config
            )

            let pushed = try await client.oidcPar(
                request: begun,
                redirectURI: Self.redirectURI,
                scope: "openid profile",
                configuration: config
            )

            let sent = try XCTUnwrap(server.state.requests(pathContaining: "/oauth2/par").first)
            let form = formFields(sent)
            // §26.2 rule 1: no second generator. state, nonce and the PKCE pair all come
            // from the AuthorizationRequest that was pushed — two sources for any of them
            // are two things that can disagree.
            XCTAssertEqual(form["state"], begun.state)
            XCTAssertEqual(form["nonce"], begun.nonce)
            XCTAssertEqual(pushed.state, begun.state)
            XCTAssertEqual(pushed.nonce, begun.nonce)
            XCTAssertEqual(pushed.codeVerifier.expose(), begun.codeVerifier.expose())

            XCTAssertEqual(form["client_id"], Self.clientID)
            XCTAssertEqual(form["response_type"], "code")
            XCTAssertEqual(form["redirect_uri"], Self.redirectURI)
            XCTAssertEqual(form["scope"], "openid profile")
            XCTAssertEqual(form["code_challenge_method"], "S256")
            XCTAssertEqual(
                form["code_challenge"],
                OidcPkce.challenge(for: begun.codeVerifier.expose())
            )
        }
    }

    func testAConfidentialClientAuthenticatesThePush() async throws {
        try await withParClient(router: router()) { client, server in
            let config = try await client.oidcDiscover()
            let begun = try await client.oidcBegin(
                redirectURI: Self.redirectURI, configuration: config)

            _ = try await client.oidcPar(
                request: begun, redirectURI: Self.redirectURI, configuration: config)

            let sent = try XCTUnwrap(server.state.requests(pathContaining: "/oauth2/par").first)
            XCTAssertEqual(formFields(sent)["client_secret"], Self.clientSecret)
        }
    }

    func testAPublicClientPushesWithoutASecret() async throws {
        try await withParClient(clientSecret: nil, router: router()) { client, server in
            let config = try await client.oidcDiscover()
            let begun = try await client.oidcBegin(
                redirectURI: Self.redirectURI, configuration: config)

            _ = try await client.oidcPar(
                request: begun, redirectURI: Self.redirectURI, configuration: config)

            let sent = try XCTUnwrap(server.state.requests(pathContaining: "/oauth2/par").first)
            XCTAssertNil(formFields(sent)["client_secret"])
        }
    }

    func testParDiscoversWhenGivenNoConfiguration() async throws {
        try await withParClient(router: router()) { client, server in
            let config = try await client.oidcDiscover()
            let begun = try await client.oidcBegin(
                redirectURI: Self.redirectURI, configuration: config)

            _ = try await client.oidcPar(request: begun, redirectURI: Self.redirectURI)

            // The document is cached per client (§12.3 rule 6), so passing nil costs no
            // second fetch.
            XCTAssertEqual(
                server.state.requests(pathContaining: "openid-configuration").count,
                1
            )
            XCTAssertEqual(server.state.requests(pathContaining: "/oauth2/par").count, 1)
        }
    }

    // MARK: - §26.2 rule 2: the redirect URL

    func testTheRedirectUrlCarriesExactlyTwoParameters() async throws {
        try await withParClient(router: router()) { client, _ in
            let config = try await client.oidcDiscover()
            let begun = try await client.oidcBegin(
                redirectURI: Self.redirectURI, configuration: config)

            let pushed = try await client.oidcPar(
                request: begun, redirectURI: Self.redirectURI, configuration: config)

            let components = try XCTUnwrap(URLComponents(string: pushed.url))
            let items = components.queryItems ?? []
            // The server REFUSES a request_uri mixed with inline parameters rather than
            // merging them — re-adding scope/state/redirect_uri here restores the
            // parameter-confusion attack (§26.2 rule 2).
            XCTAssertEqual(Set(items.map(\.name)), ["client_id", "request_uri"])
            XCTAssertEqual(items.first { $0.name == "client_id" }?.value, Self.clientID)
            XCTAssertEqual(items.first { $0.name == "request_uri" }?.value, Self.requestURI)
            XCTAssertEqual(components.path, "/oauth2/authorize")
        }
    }

    func testTheRedirectUrlDropsAnyQueryTheDiscoveredEndpointCarried() async throws {
        // An authorization_endpoint that already carries a query is legal, and its
        // parameters are exactly the ones rule 2 forbids travelling alongside a request_uri.
        let discovery = discoveryJSON
        let noisy: TestRouter = { request, _ in
            let base = "http://\(request.header("Host") ?? "127.0.0.1")"
            if request.uri.contains("/.well-known/openid-configuration") {
                var document = discovery(base, true)
                document["authorization_endpoint"] = "\(base)/oauth2/authorize?audience=legacy&scope=all"
                return .json(200, document)
            }
            if request.uri.contains("/oauth2/par") {
                return .json(201, ["request_uri": ParTests.requestURI, "expires_in": 90])
            }
            return .json(404, [:])
        }

        try await withParClient(router: noisy) { client, _ in
            let config = try await client.oidcDiscover()
            let begun = try await client.oidcBegin(
                redirectURI: Self.redirectURI, configuration: config)

            let pushed = try await client.oidcPar(
                request: begun, redirectURI: Self.redirectURI, configuration: config)

            let items = try XCTUnwrap(URLComponents(string: pushed.url)?.queryItems)
            XCTAssertEqual(Set(items.map(\.name)), ["client_id", "request_uri"])
        }
    }

    // MARK: - refusals

    func testAServerWithoutParIsRefusedClientSideWithNoWireCall() async throws {
        try await withParClient(router: router(withPar: false)) { client, server in
            let config = try await client.oidcDiscover()
            let begun = try await client.oidcBegin(
                redirectURI: Self.redirectURI, configuration: config)

            do {
                _ = try await client.oidcPar(
                    request: begun, redirectURI: Self.redirectURI, configuration: config)
                XCTFail("expected an auth error")
            } catch let AxiamError.auth(error) {
                XCTAssertTrue(
                    error.message.contains("pushed_authorization_request_endpoint"),
                    error.message
                )
            }

            // §12.7.2 rule 1's discipline: no URL is concatenated onto the issuer.
            XCTAssertEqual(server.state.requests(pathContaining: "/oauth2/par").count, 0)
        }
    }

    func testAnOAuthErrorBodyBecomesAnOAuthProtocolError() async throws {
        try await withParClient(
            router: router(
                parStatus: 400,
                parBody: ["error": "invalid_request_uri", "error_description": "bad request_uri"]
            )
        ) { client, _ in
            let config = try await client.oidcDiscover()
            let begun = try await client.oidcBegin(
                redirectURI: Self.redirectURI, configuration: config)

            do {
                _ = try await client.oidcPar(
                    request: begun, redirectURI: Self.redirectURI, configuration: config)
                XCTFail("expected an OAuth protocol error")
            } catch let AxiamError.auth(error) {
                XCTAssertEqual(error.oauthError, "invalid_request_uri")
            }
        }
    }

    func testA503IsNotRetried() async throws {
        try await withParClient(router: router(parStatus: 503, parBody: [:])) { client, server in
            let config = try await client.oidcDiscover()
            let begun = try await client.oidcBegin(
                redirectURI: Self.redirectURI, configuration: config)

            do {
                _ = try await client.oidcPar(
                    request: begun, redirectURI: Self.redirectURI, configuration: config)
                XCTFail("expected a failure")
            } catch {
                // expected
            }

            // §26.2 rule 4: a POST that creates server state falls outside §16.2's
            // read-only eligibility. The safe recovery is a fresh push, which cannot
            // double-consume anything.
            XCTAssertEqual(
                server.state.requests(pathContaining: "/oauth2/par").count,
                1,
                "the push must not be retried"
            )
        }
    }

    func testAResponseWithNoRequestUriIsAFailure() async throws {
        try await withParClient(
            router: router(parBody: ["expires_in": 90])
        ) { client, _ in
            let config = try await client.oidcDiscover()
            let begun = try await client.oidcBegin(
                redirectURI: Self.redirectURI, configuration: config)

            do {
                _ = try await client.oidcPar(
                    request: begun, redirectURI: Self.redirectURI, configuration: config)
                XCTFail("expected a failure")
            } catch AxiamError.network {
                // expected
            }
        }
    }

    // MARK: - §26.5 / discovery

    func testTheRequestUriIsSensitive() async throws {
        try await withParClient(router: router()) { client, _ in
            let config = try await client.oidcDiscover()
            let begun = try await client.oidcBegin(
                redirectURI: Self.redirectURI, configuration: config)

            let pushed = try await client.oidcPar(
                request: begun, redirectURI: Self.redirectURI, configuration: config)

            // Between the push and the redirect it is a bearer handle to a fully-formed
            // authorization request (§26.5). The URL it goes into is not secret; the bare
            // handle in a log line is.
            XCTAssertEqual("\(pushed.requestURI)", "[SENSITIVE]")
            XCTAssertFalse("\(pushed.requestURI)".contains(Self.requestURI))
            let items = try XCTUnwrap(URLComponents(string: pushed.url)?.queryItems)
            XCTAssertEqual(items.first { $0.name == "request_uri" }?.value, Self.requestURI)
        }
    }

    func testDiscoveryExposesThePushedAuthorizationRequestEndpoint() async throws {
        try await withParClient(router: router()) { client, _ in
            let config = try await client.oidcDiscover()
            XCTAssertTrue(
                try XCTUnwrap(config.pushedAuthorizationRequestEndpoint).hasSuffix("/oauth2/par")
            )
        }
    }

    func testADiscoveryDocumentWithoutParParsesWithANilEndpoint() async throws {
        try await withParClient(router: router(withPar: false)) { client, _ in
            // Absent, not empty: §26 is optional, and an SDK that synthesised an endpoint
            // here would POST a fully-formed authorization request at a 404.
            let config = try await client.oidcDiscover()
            XCTAssertNil(config.pushedAuthorizationRequestEndpoint)
        }
    }
}
