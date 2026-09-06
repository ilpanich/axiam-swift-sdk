import XCTest
import Foundation
@testable import AxiamSDK

/// RFC 8705 §5 `mtls_endpoint_aliases` — CONTRACT.md §21.3 rule 2 (contract 1.40).
///
/// The rule has one sentence and three named ways to get it wrong, and this file is organised
/// around them rather than around the SDK's method list:
///
/// - a call going over mTLS prefers the alias;
/// - a call NOT going over mTLS keeps the top-level entry;
/// - an ABSENT member means "no separate mTLS host", never "unsupported";
/// - only the six listed endpoints are ever aliased — not `authorization_endpoint`,
///   `end_session_endpoint` or `jwks_uri`;
/// - `issuer` is not an endpoint, does not move, and still governs `iss` validation by exact
///   string.
///
/// Two `TestHTTPServer`s stand in for the two listeners a deployment runs. Both speak plain
/// HTTP, so no handshake occurs — what is under test is *which URL the SDK chooses*, which the
/// configured identity and the document decide, not the socket. The §6.1 identity comes from
/// `OpenSSLPKI`, exactly as the other mTLS-shaped tests get theirs.
final class MtlsEndpointAliasesTests: XCTestCase {

    private static let tenantUUID = "22222222-2222-2222-2222-222222222222"
    private static let clientID = "invoices-client"
    private static let issuer = "https://iam.example.test"

    // MARK: - Harness

    /// The discovery document served by the conventional host, optionally carrying the six
    /// aliases on `mtlsBase`. `partial` publishes only `token_endpoint`.
    private static func discoveryJSON(
        base: String,
        mtlsBase: String?,
        partial: Bool = false
    ) -> [String: Any] {
        var document: [String: Any] = [
            "issuer": Self.issuer,
            "authorization_endpoint": "\(base)/oauth2/authorize",
            "token_endpoint": "\(base)/oauth2/token",
            "jwks_uri": "\(base)/oauth2/jwks",
            "introspection_endpoint": "\(base)/oauth2/introspect",
            "revocation_endpoint": "\(base)/oauth2/revoke",
            "end_session_endpoint": "\(base)/oauth2/end_session",
            "device_authorization_endpoint": "\(base)/oauth2/device_authorization",
            "pushed_authorization_request_endpoint": "\(base)/oauth2/par",
        ]
        if let mtlsBase {
            document["mtls_endpoint_aliases"] = partial
                ? ["token_endpoint": "\(mtlsBase)/oauth2/token"]
                : [
                    "token_endpoint": "\(mtlsBase)/oauth2/token",
                    "userinfo_endpoint": "\(mtlsBase)/oauth2/userinfo",
                    "revocation_endpoint": "\(mtlsBase)/oauth2/revoke",
                    "introspection_endpoint": "\(mtlsBase)/oauth2/introspect",
                    "device_authorization_endpoint": "\(mtlsBase)/oauth2/device_authorization",
                    "pushed_authorization_request_endpoint": "\(mtlsBase)/oauth2/par",
                ]
        }
        return document
    }

    /// The reply each OAuth2 endpoint's caller will accept.
    private static func oauth2Response(_ uri: String) -> TestResponse {
        if uri.contains("/oauth2/device_authorization") {
            return .json(200, [
                "device_code": "device-code-value",
                "user_code": "WDJB-MJHT",
                "verification_uri": "https://example.test/device",
                "expires_in": 30,
                "interval": 1,
            ])
        }
        if uri.contains("/oauth2/par") {
            // RFC 9126 §2.2 specifies Created, and the SDK asserts exactly that.
            return .json(201, [
                "request_uri": "urn:ietf:params:oauth:request_uri:x",
                "expires_in": 60,
            ])
        }
        if uri.contains("/oauth2/introspect") { return .json(200, ["active": true]) }
        if uri.contains("/oauth2/revoke") { return .json(200, [:]) }
        return .json(200, [
            "access_token": "the-access-token",
            "token_type": "Bearer",
            "expires_in": 900,
        ])
    }

    /// A router that records which OAuth2 path it was asked for, under `label`.
    private static func oauth2Router() -> TestRouter {
        { request, state in
            for path in ["token", "introspect", "revoke", "device_authorization", "par"]
            where request.uri.contains("/oauth2/\(path)") {
                state.increment(path)
                return Self.oauth2Response(request.uri)
            }
            return .json(404, [:])
        }
    }

    /// Stand up the mTLS listener, then the conventional one, run `body`, and tear both down.
    ///
    /// Both serve every OAuth2 path, so choosing the wrong host is a *recorded* call rather
    /// than a 404 — the assertion then names the host that was used.
    private func withTwoListeners(
        mtls: Bool,
        aliases: Bool,
        partialAliases: Bool = false,
        withoutDeviceEndpoint: Bool = false,
        body: (AxiamClient, TestHTTPServer, TestHTTPServer, Int) async throws -> Void
    ) async throws {
        let mtlsServer = TestHTTPServer(router: Self.oauth2Router())
        let mtlsPort = try mtlsServer.start()
        let mtlsBase = "http://127.0.0.1:\(mtlsPort)"

        let conventionalRouter: TestRouter = { request, state in
            if request.uri.contains("/.well-known/openid-configuration") {
                state.increment("discovery")
                let base = "http://\(request.header("Host") ?? "127.0.0.1")"
                var document = Self.discoveryJSON(
                    base: base,
                    mtlsBase: aliases ? mtlsBase : nil,
                    partial: partialAliases)
                if withoutDeviceEndpoint {
                    document.removeValue(forKey: "device_authorization_endpoint")
                    if var published = document["mtls_endpoint_aliases"] as? [String: Any] {
                        published.removeValue(forKey: "device_authorization_endpoint")
                        document["mtls_endpoint_aliases"] = published
                    }
                }
                return .json(200, document)
            }
            return Self.oauth2Router()(request, state)
        }
        let conventional = TestHTTPServer(router: conventionalRouter)
        let conventionalPort = try conventional.start()

        let identity = mtls ? OpenSSLPKI.generateSelfSigned() : nil
        if mtls, identity == nil {
            conventional.stop()
            mtlsServer.stop()
            throw XCTSkip("openssl is required to generate the §6.1 test client identity")
        }

        let client = try AxiamClient(config: AxiamConfig(
            baseURL: URL(string: "http://127.0.0.1:\(conventionalPort)")!,
            tenantID: Self.tenantUUID,
            clientCertificate: identity.map {
                ClientCertificate.pem(certificate: $0.certificatePEM, privateKey: $0.keyPEM)
            },
            requestTimeout: 10,
            oidcClientID: Self.clientID,
            oidcClientSecret: Sensitive("client-secret")))

        do {
            try await body(client, conventional, mtlsServer, mtlsPort)
        } catch {
            try? await client.shutdown()
            conventional.stop()
            mtlsServer.stop()
            throw error
        }
        try? await client.shutdown()
        conventional.stop()
        mtlsServer.stop()
    }

    // MARK: - The document round-trips the member

    func testDiscoveryExposesTheMemberWhenPublished() async throws {
        try await withTwoListeners(mtls: false, aliases: true) { client, _, _, mtlsPort in
            let document = try await client.oidcDiscover()

            let aliases = try XCTUnwrap(
                document.mtlsEndpointAliases,
                "the member the server published must survive decoding")
            let aliasToken = try XCTUnwrap(aliases.tokenEndpoint)
            XCTAssertTrue(
                aliasToken.contains(":\(mtlsPort)"),
                "the alias must name the mTLS listener: \(aliasToken)")
            // Alongside, never instead of: the conventional entry is untouched.
            XCTAssertFalse(document.tokenEndpoint.contains(":\(mtlsPort)"))
        }
    }

    func testAnAbsentMemberDecodesToNilRatherThanFailing() async throws {
        try await withTwoListeners(mtls: true, aliases: false) { client, _, _, _ in
            let document = try await client.oidcDiscover()
            XCTAssertNil(
                document.mtlsEndpointAliases,
                "a document with no aliases is valid, not an error")
        }
    }

    // MARK: - A call over mTLS prefers the alias

    func testEveryAliasableEndpointGoesToTheAliasHost() async throws {
        try await withTwoListeners(mtls: true, aliases: true) { client, conventional, mtlsServer, _ in
            _ = try await client.loginClientCredentials()
            _ = try await client.introspect(token: Sensitive("t"))
            try await client.revoke(token: Sensitive("t"))
            _ = try await client.deviceAuthorize()
            let document = try await client.oidcDiscover()
            let request = try await client.oidcBegin(
                redirectURI: "https://app.example.com/cb", configuration: document)
            _ = try await client.oidcPar(
                request: request,
                redirectURI: "https://app.example.com/cb",
                configuration: document)

            for path in ["token", "introspect", "revoke", "device_authorization", "par"] {
                XCTAssertEqual(mtlsServer.state.count(path), 1, "\(path) must use its alias")
                XCTAssertEqual(
                    conventional.state.count(path), 0,
                    "\(path) must not reach the conventional host")
            }
        }
    }

    // MARK: - Consequence 1: absence means "no separate host"

    func testAnMtlsClientWithNoAliasesKeepsTheTopLevelEndpoints() async throws {
        try await withTwoListeners(mtls: true, aliases: false) { client, conventional, mtlsServer, _ in
            // Not an error, and not the alias origin: a deployment running
            // `client_auth = optional` on one listener serves both populations at the
            // conventional endpoints and correctly publishes nothing.
            _ = try await client.introspect(token: Sensitive("t"))

            XCTAssertEqual(conventional.state.count("introspect"), 1)
            XCTAssertEqual(mtlsServer.state.count("introspect"), 0)
        }
    }

    func testAClientNotDoingMtlsKeepsTheTopLevelEndpoints() async throws {
        try await withTwoListeners(mtls: false, aliases: true) { client, conventional, mtlsServer, _ in
            try await client.revoke(token: Sensitive("t"))

            XCTAssertEqual(conventional.state.count("revoke"), 1)
            XCTAssertEqual(mtlsServer.state.count("revoke"), 0)
        }
    }

    func testAPartialAliasObjectFallsBackPerEndpoint() async throws {
        // RFC 8705 §5 does not require an OP to alias all six, and the shape of this member
        // must never be why a client stops working: an object naming only `token_endpoint` is
        // a valid document, and every endpoint it does not name falls back.
        try await withTwoListeners(mtls: true, aliases: true, partialAliases: true) {
            client, conventional, mtlsServer, _ in
            _ = try await client.loginClientCredentials()
            _ = try await client.introspect(token: Sensitive("t"))

            XCTAssertEqual(mtlsServer.state.count("token"), 1, "the one aliased endpoint")
            XCTAssertEqual(
                conventional.state.count("introspect"), 1,
                "an endpoint the object does not name falls back to the top level")
            XCTAssertEqual(mtlsServer.state.count("introspect"), 0)
        }
    }

    func testAnUnsupportedGrantIsStillReportedWhenNeitherLevelNamesIt() async throws {
        try await withTwoListeners(mtls: true, aliases: true, withoutDeviceEndpoint: true) {
            client, _, _, _ in
            // Neither level names the endpoint, so the answer is still "this server does not
            // support the device grant" — never a URL built by concatenation.
            do {
                _ = try await client.deviceAuthorize()
                XCTFail("expected an error when neither level advertises the device endpoint")
            } catch {
                // The SDK raises rather than synthesising a URL; which taxonomy arm it uses
                // is settled elsewhere, and asserting it here would duplicate that test.
            }
        }
    }

    // MARK: - Consequence 2: no alias is ever synthesised

    func testTheFrontChannelAndJwksEndpointsAreNeverAliased() async throws {
        try await withTwoListeners(mtls: true, aliases: true) { client, _, _, mtlsPort in
            let document = try await client.oidcDiscover()
            let mtlsMarker = ":\(mtlsPort)"

            // A browser sent to an mTLS host raises a native certificate-chooser dialog most
            // users cannot answer, and jwks_uri is public key material that gains nothing from
            // a handshake.
            let request = try await client.oidcBegin(
                redirectURI: "https://app.example.com/cb", configuration: document)
            XCTAssertFalse(
                request.url.contains(mtlsMarker),
                "authorization_endpoint must stay on the conventional host: \(request.url)")

            let logout = try await client.logoutURL(
                idToken: Sensitive("not-a-real-token"), configuration: document)
            XCTAssertFalse(
                logout.contains(mtlsMarker),
                "end_session_endpoint must stay on the conventional host: \(logout)")

            XCTAssertFalse(
                document.jwksURI.contains(mtlsMarker),
                "jwks_uri must stay on the conventional host")
        }
    }

    // MARK: - Consequence 3: issuer is never aliased

    func testTheIssuerDoesNotMoveWithTheEndpoints() async throws {
        try await withTwoListeners(mtls: true, aliases: true) { client, _, _, mtlsPort in
            let document = try await client.oidcDiscover()

            // §12.4 rule 3 compares `iss` against THIS value by exact string, for every token
            // — including one minted at an alias endpoint. An SDK that derived an expected
            // issuer from the host it called would reject every token it obtains over mTLS.
            XCTAssertEqual(document.issuer, Self.issuer)
            XCTAssertFalse(document.issuer.contains(":\(mtlsPort)"))
        }
    }
}
