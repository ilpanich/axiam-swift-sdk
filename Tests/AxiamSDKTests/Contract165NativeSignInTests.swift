import XCTest
import Crypto
import Foundation
@testable import AxiamSDK

/// A scriptable in-memory transport that records every request it is handed, whatever its path
/// (discovery is never fetched here: each test passes the document in, so a request count is the
/// count of the call under test and nothing else).
final class Contract165Transport: HTTPTransport, @unchecked Sendable {
    private let lock = NSLock()
    private var recorded: [HTTPRequestSpec] = []
    private let handler: @Sendable (HTTPRequestSpec) async throws -> HTTPResponseData

    init(_ handler: @escaping @Sendable (HTTPRequestSpec) async throws -> HTTPResponseData) {
        self.handler = handler
    }

    var requests: [HTTPRequestSpec] { lock.locked { recorded } }
    var tokenRequests: [HTTPRequestSpec] { requests.filter { $0.url.path.hasSuffix("/oauth2/token") } }

    func execute(_ spec: HTTPRequestSpec, timeout: TimeInterval) async throws -> HTTPResponseData {
        lock.locked { recorded.append(spec) }
        return try await handler(spec)
    }

    func shutdown() async throws {}

    static func bytes(_ object: [String: Any]) -> Data {
        (try? JSONSerialization.data(withJSONObject: object)) ?? Data()
    }

    static func reply(_ status: Int, _ data: Data, headers: [(String, String)] = []) -> HTTPResponseData {
        HTTPResponseData(
            status: status, headers: [("Content-Type", "application/json")] + headers, body: data)
    }

    static func json(_ status: Int, _ object: [String: Any], headers: [(String, String)] = [])
        -> HTTPResponseData
    {
        reply(status, bytes(object), headers: headers)
    }
}

/// CONTRACT.md §37 (native sign-in with a provider ID token), §12.1 `idp_hint`, §26.2 rule 8 and
/// the §9 confirmation test — contract 1.65. Test names are the contract's, so the eleven SDKs'
/// suites can be compared.
final class Contract165NativeSignInTests: XCTestCase {

    private static let tenant = "22222222-2222-2222-2222-222222222222"
    private static let clientID = "native-app"
    private static let issuer = "https://iam.example.test"
    private static let base = "https://iam.example.test"
    private static let rawNonce = "n-0S6_WzA2Mj"
    private static let rawNonceHash =
        "0823a09b54cb9381561068b00aaf4e539b3f54604631d3e6a820879b6b04cc19"
    private static let providerToken = "eyJhbGciOiJSUzI1NiJ9.PROVIDER-TOKEN-PAYLOAD.PROVIDER-SIG"
    private static let signer = TestSigner()

    private static var configuration: OidcConfiguration {
        let json: [String: Any] = [
            "issuer": issuer,
            "authorization_endpoint": "\(base)/oauth2/authorize",
            "token_endpoint": "\(base)/oauth2/token",
            "jwks_uri": "\(base)/oauth2/jwks",
            "pushed_authorization_request_endpoint": "\(base)/oauth2/par",
        ]
        // The fixture is a literal above; decoding it cannot fail.
        return try! JSONDecoder().decode(
            OidcConfiguration.self, from: JSONSerialization.data(withJSONObject: json))
    }

    private func makeClient(
        transport: Contract165Transport,
        tenantID: String? = Contract165NativeSignInTests.tenant,
        secret: String? = nil,
        hook: TelemetryHook? = nil
    ) throws -> AxiamClient {
        let config = try AxiamConfig(
            baseURL: URL(string: Self.base)!,
            tenantID: tenantID,
            tenantSlug: tenantID == nil ? "acme" : nil,
            requestTimeout: 10,
            telemetryHook: hook,
            oidcClientID: Self.clientID,
            oidcClientSecret: secret.map(Sensitive.init))
        return AxiamClient(config: config, transport: transport)
    }

    private static func okBody() -> [String: Any] {
        ["access_token": "the-access-token", "token_type": "Bearer", "expires_in": 900]
    }

    private func okTransport(_ body: [String: Any] = Contract165NativeSignInTests.okBody())
        -> Contract165Transport
    {
        let data = Contract165Transport.bytes(body)
        return Contract165Transport { _ in Contract165Transport.reply(200, data) }
    }

    /// The form's pairs in wire order, percent-decoded.
    private func form(_ spec: HTTPRequestSpec) -> [(String, String)] {
        String(decoding: spec.body ?? Data(), as: UTF8.self).split(separator: "&").map { pair in
            let parts = pair.split(separator: "=", maxSplits: 1).map(String.init)
            let decode: (String) -> String = {
                $0.replacingOccurrences(of: "+", with: " ").removingPercentEncoding ?? $0
            }
            return (decode(parts[0]), parts.count > 1 ? decode(parts[1]) : "")
        }
    }

    private func fields(_ spec: HTTPRequestSpec) -> [String: String] {
        Dictionary(form(spec), uniquingKeysWith: { first, _ in first })
    }

    private func header(_ spec: HTTPRequestSpec, _ name: String) -> String? {
        spec.headers.first { $0.0.lowercased() == name.lowercased() }?.1
    }

    private func login(
        _ client: AxiamClient,
        provider: String = "corp-okta",
        idToken: String = Contract165NativeSignInTests.providerToken,
        nonce: String = Contract165NativeSignInTests.rawNonce,
        scopes: [String]? = nil,
        resource: String? = nil
    ) async throws -> OidcTokenSet {
        try await client.loginWithProviderIdToken(
            provider: provider, idToken: Sensitive(idToken), nonce: Sensitive(nonce),
            scopes: scopes, resource: resource, configuration: Self.configuration)
    }

    private static func oauthError(_ error: Error) -> AuthError? {
        guard let axiam = error as? AxiamError, case let .auth(auth) = axiam else { return nil }
        return auth
    }

    // MARK: - §37.9 1

    func testRequestBodyExact() async throws {
        let transport = okTransport()
        let client = try makeClient(transport: transport, secret: nil)
        _ = try await login(client, scopes: ["openid", "profile"], resource: "https://api.example.test")

        let sent = try XCTUnwrap(transport.tokenRequests.first)
        XCTAssertEqual(transport.requests.count, 1)
        XCTAssertEqual(sent.method.rawValue, "POST")
        let query = URLComponents(url: sent.url, resolvingAgainstBaseURL: false)?.queryItems ?? []
        XCTAssertEqual(query.first { $0.name == "tenant_id" }?.value, Self.tenant)
        XCTAssertEqual(header(sent, "Content-Type"), "application/x-www-form-urlencoded")
        let keys = Set(form(sent).map { $0.0 })
        XCTAssertEqual(form(sent).count, keys.count, "no key repeated")
        XCTAssertEqual(
            keys,
            ["grant_type", "client_id", "provider", "id_token", "nonce", "scope", "resource"])
        let body = fields(sent)
        XCTAssertEqual(body["grant_type"], "urn:axiam:params:oauth:grant-type:provider-id-token")
        XCTAssertEqual(body["scope"], "openid profile")
        XCTAssertNil(body["tenant_id"], "tenant_id is a query parameter, never a body field")
        for forbidden in ["authorization", "cookie", "x-csrf-token"] {
            XCTAssertNil(header(sent, forbidden), forbidden)
        }

        // No scopes and no resource: neither key, and `openid` is not added.
        let bare = okTransport()
        _ = try await login(try makeClient(transport: bare))
        let bareSent = try XCTUnwrap(bare.tokenRequests.first)
        XCTAssertEqual(
            Set(form(bareSent).map { $0.0 }),
            ["grant_type", "client_id", "provider", "id_token", "nonce"])
        XCTAssertFalse(String(decoding: bareSent.body ?? Data(), as: UTF8.self).contains("openid"))

        // An empty list is "none" too: never `scope=`.
        let empty = okTransport()
        _ = try await login(try makeClient(transport: empty), scopes: [], resource: "")
        XCTAssertEqual(
            Set(form(try XCTUnwrap(empty.tokenRequests.first)).map { $0.0 }),
            ["grant_type", "client_id", "provider", "id_token", "nonce"])
    }

    // MARK: - 2

    func testRawNonceSentNotHash() async throws {
        let transport = okTransport()
        let client = try makeClient(transport: transport)
        // A fixture provider token whose payload carries the hash as its `nonce` claim.
        let claims = TestBase64URL.encode(
            try JSONSerialization.data(withJSONObject: ["nonce": Self.rawNonceHash, "sub": "u"]))
        let providerToken = "eyJhbGciOiJSUzI1NiJ9.\(claims).sig"
        _ = try await login(client, idToken: providerToken)

        let sent = try XCTUnwrap(transport.tokenRequests.first)
        XCTAssertEqual(fields(sent)["nonce"], Self.rawNonce)
        XCTAssertEqual(
            Self.hex(SHA256.hash(data: Data(Self.rawNonce.utf8))), Self.rawNonceHash,
            "the §37.4 vector")
        let wire = String(decoding: sent.body ?? Data(), as: UTF8.self)
        XCTAssertFalse(wire.contains(Self.rawNonceHash))
        XCTAssertFalse(wire.localizedCaseInsensitiveContains(Self.rawNonceHash))
    }

    // MARK: - 3

    func testProviderSentVerbatim() async throws {
        for provider in [
            "5b0c3f0e-1d57-4f4c-9d3a-0f0f0f0f0f0f", "Corp-Okta", "google", " padded ",
        ] {
            let transport = okTransport()
            _ = try await login(try makeClient(transport: transport), provider: provider)
            XCTAssertEqual(fields(try XCTUnwrap(transport.tokenRequests.first))["provider"], provider)
            // One request in total: no sso_providers lookup, no discovery fetch.
            XCTAssertEqual(transport.requests.count, 1, provider)
        }
    }

    // MARK: - 4

    func testPublicClientSendsClientIdOnly() async throws {
        let transport = okTransport()
        _ = try await login(try makeClient(transport: transport, secret: nil))
        let sent = try XCTUnwrap(transport.tokenRequests.first)
        XCTAssertEqual(fields(sent)["client_id"], Self.clientID)
        XCTAssertNil(fields(sent)["client_secret"])
        XCTAssertNil(fields(sent)["client_assertion"])
        XCTAssertNil(header(sent, "Authorization"))
    }

    func testConfidentialClientSendsItsCredential() async throws {
        let transport = okTransport()
        _ = try await login(try makeClient(transport: transport, secret: "s3cret"))
        let sent = try XCTUnwrap(transport.tokenRequests.first)
        XCTAssertEqual(fields(sent)["client_secret"], "s3cret")
        XCTAssertNil(header(sent, "Authorization"), "never Authorization: Basic")
    }

    // MARK: - 5

    func testEmptyInputsRefusedLocally() async throws {
        let cases: [(String, String, String)] = [
            ("", "tok", "nonce"), ("p", "", "nonce"), ("p", "tok", ""),
        ]
        for (provider, token, nonce) in cases {
            let transport = okTransport()
            let client = try makeClient(transport: transport)
            do {
                _ = try await client.loginWithProviderIdToken(
                    provider: provider, idToken: Sensitive(token), nonce: Sensitive(nonce),
                    configuration: Self.configuration)
                XCTFail("expected a local refusal")
            } catch let AxiamError.network(error) {
                XCTAssertTrue(error.isValidation)
            }
            XCTAssertEqual(transport.requests.count, 0)
        }

        // A slug-only client (§12.3 rule 4): refused with no request — not even discovery,
        // although this call passes no document.
        let transport = okTransport()
        let slugOnly = try makeClient(transport: transport, tenantID: nil)
        do {
            _ = try await slugOnly.loginWithProviderIdToken(
                provider: "p", idToken: Sensitive("tok"), nonce: Sensitive("n"))
            XCTFail("expected a client-side refusal")
        } catch let AxiamError.auth(error) {
            XCTAssertTrue(error.message.contains("§12.3 rule 4"))
        }
        XCTAssertEqual(transport.requests.count, 0)
    }

    // MARK: - 6

    func testGenericInvalidGrantMapped() async throws {
        let transport = Contract165Transport { _ in
            Contract165Transport.json(
                400,
                ["error": "invalid_grant",
                 "error_description": "the provider ID token is not acceptable"])
        }
        let client = try makeClient(transport: transport)
        do {
            _ = try await login(client)
            XCTFail("expected invalid_grant")
        } catch {
            let auth = try XCTUnwrap(Self.oauthError(error))
            XCTAssertEqual(auth.oauthError, "invalid_grant")
            XCTAssertEqual(auth.oauthErrorDescription, "the provider ID token is not acceptable")
            XCTAssertEqual(auth.message, "invalid_grant: the provider ID token is not acceptable")
        }
        // One request: no retry, no regenerated nonce, nothing else (and no cookie-session
        // refresh — the §9 guard is not entered).
        XCTAssertEqual(transport.requests.count, 1)
        XCTAssertTrue(transport.requests.allSatisfy { !$0.url.path.contains("/auth/refresh") })
    }

    // MARK: - 7

    func testConsentRequiredMapped() async throws {
        let transport = Contract165Transport { _ in
            Contract165Transport.json(
                400, ["error": "consent_required", "error_description": "consent is needed"])
        }
        do {
            _ = try await login(try makeClient(transport: transport), scopes: ["profile"])
            XCTFail("expected consent_required")
        } catch {
            XCTAssertEqual(try XCTUnwrap(Self.oauthError(error)).oauthError, "consent_required")
        }
        XCTAssertEqual(transport.requests.count, 1)
    }

    // MARK: - 8

    func testClientAndScopeRefusalsSurfaced() async throws {
        let cases: [(Int, String, [(String, String)])] = [
            (400, "unauthorized_client", []),
            (401, "invalid_client", [("WWW-Authenticate", "Basic realm=\"axiam\"")]),
            (400, "invalid_scope", []),
            (400, "invalid_target", []),
        ]
        for (status, code, headers) in cases {
            let transport = Contract165Transport { _ in
                Contract165Transport.json(
                    status, ["error": code, "error_description": "no"], headers: headers)
            }
            do {
                _ = try await login(
                    try makeClient(transport: transport), scopes: ["openid", "address"])
                XCTFail("expected \(code)")
            } catch {
                XCTAssertEqual(try XCTUnwrap(Self.oauthError(error)).oauthError, code)
            }
            // One request each: invalid_scope is not narrowed and re-sent, and the 401 does
            // not enter the cookie-session refresh guard.
            XCTAssertEqual(transport.requests.count, 1, code)
            XCTAssertEqual(
                fields(try XCTUnwrap(transport.tokenRequests.first))["scope"], "openid address")
        }
    }

    // MARK: - 9

    func testRateLimitWithRetryAfterMapped() async throws {
        let transport = Contract165Transport { _ in
            Contract165Transport.json(
                429, ["error": "rate_limit_exceeded"], headers: [("Retry-After", "7")])
        }
        do {
            _ = try await login(try makeClient(transport: transport))
            XCTFail("expected rate_limit_exceeded")
        } catch {
            // C165-17: the server's wait is reachable on the error (additive `retryAfter`).
            let auth = try XCTUnwrap(Self.oauthError(error))
            XCTAssertEqual(auth.oauthError, "rate_limit_exceeded")
            XCTAssertEqual(auth.retryAfter, 7)
        }
        XCTAssertEqual(transport.requests.count, 1)
    }

    // MARK: - 10

    func testServerErrorNotRetried() async throws {
        let withBody = Contract165Transport { _ in
            Contract165Transport.json(
                500, ["error": "server_error", "error_description": "datastore unavailable"])
        }
        do {
            _ = try await login(try makeClient(transport: withBody))
            XCTFail("expected server_error")
        } catch {
            XCTAssertEqual(try XCTUnwrap(Self.oauthError(error)).oauthError, "server_error")
        }
        XCTAssertEqual(withBody.requests.count, 1)

        let bodyless = Contract165Transport { _ in HTTPResponseData(status: 500, headers: [], body: Data()) }
        do {
            _ = try await login(try makeClient(transport: bodyless))
            XCTFail("expected a NetworkError")
        } catch let AxiamError.network(error) {
            XCTAssertEqual(error.statusCode, 500)
        }
        XCTAssertEqual(bodyless.requests.count, 1)

        let dropped = Contract165Transport { _ in throw AxiamError.network(NetworkError("connection reset")) }
        do {
            _ = try await login(try makeClient(transport: dropped))
            XCTFail("expected a NetworkError")
        } catch AxiamError.network {
        }
        XCTAssertEqual(dropped.requests.count, 1)
    }

    // MARK: - 11

    private func openidBody(nonceClaim: String, tokenType: String = "DPoP") -> [String: Any] {
        let claims: [String: Any] = [
            "sub": "user-42", "iss": Self.issuer, "aud": Self.clientID,
            "exp": Date().addingTimeInterval(3600).timeIntervalSince1970,
            "iat": Date().addingTimeInterval(-10).timeIntervalSince1970,
            "nonce": nonceClaim,
        ]
        return [
            "access_token": "the-access-token", "token_type": tokenType, "expires_in": 900,
            "scope": "openid profile", "refresh_token": "the-refresh-token",
            "id_token": Self.signer.makeIDToken(claims: claims),
        ]
    }

    private func jwksAware(_ token: [String: Any]) -> Contract165Transport {
        let jwks = Contract165Transport.bytes(Self.signer.jwksJSON())
        let data = Contract165Transport.bytes(token)
        return Contract165Transport { spec in
            Contract165Transport.reply(200, spec.url.path.hasSuffix("/oauth2/jwks") ? jwks : data)
        }
    }

    func testResultIsTheOrdinaryTokenSet() async throws {
        // The AXIAM ID token carries the RAW nonce, and is validated against it.
        let transport = jwksAware(openidBody(nonceClaim: Self.rawNonce))
        let client = try makeClient(transport: transport)
        let set = try await login(client, scopes: ["openid", "profile"])
        XCTAssertEqual(set.tokenType, "DPoP", "read, not assumed")
        XCTAssertEqual(set.scope, "openid profile")
        XCTAssertEqual(set.accessToken.expose(), "the-access-token")
        XCTAssertEqual(set.refreshToken?.expose(), "the-refresh-token")
        XCTAssertEqual(set.idClaims?.subject, "user-42")
        XCTAssertEqual(set.idClaims?.nonce, Self.rawNonce)

        // A claim holding the HASH (what the provider's token carries) is a mismatch.
        let mismatching = jwksAware(openidBody(nonceClaim: Self.rawNonceHash))
        do {
            _ = try await login(try makeClient(transport: mismatching), scopes: ["openid"])
            XCTFail("expected nonce_mismatch")
        } catch {
            XCTAssertEqual(try XCTUnwrap(Self.oauthError(error)).oauthError, "nonce_mismatch")
        }

        // A 200 without refresh_token and id_token decodes with both absent.
        let plain = okTransport()
        let bare = try await login(try makeClient(transport: plain))
        XCTAssertNil(bare.refreshToken)
        XCTAssertNil(bare.idToken)
        XCTAssertNil(bare.idClaims)
        XCTAssertEqual(bare.tokenType, "Bearer")

        // Adoption posture (rule 9): this SDK, like loginClientCredentials and deviceLogin,
        // returns the set and installs nothing — so no request carried a credential of ours.
        let carried = transport.requests.contains {
            header($0, "Authorization") != nil || header($0, "Cookie") != nil
        }
        XCTAssertFalse(carried)
    }

    // MARK: - 12

    func testNoSecretInLogsOrErrors() async throws {
        let idToken = "FIXTURE-PROVIDER-ID-TOKEN-7f3a"
        let nonce = "FIXTURE-RAW-NONCE-91bc"
        let recorder = EventRecorder()

        let failures: [(Int, [String: Any])] = [
            (400, ["error": "invalid_grant", "error_description": "the provider ID token is not acceptable"]),
            (400, ["error": "consent_required"]),
            (400, ["error": "unauthorized_client"]),
            (401, ["error": "invalid_client"]),
            (400, ["error": "invalid_scope"]),
            (400, ["error": "invalid_target"]),
            (429, ["error": "rate_limit_exceeded"]),
            (500, ["error": "server_error", "error_description": "boom"]),
            (500, [:]),
        ]
        var rendered: [String] = []
        func capture(_ error: Error) {
            rendered.append(String(describing: error))
            rendered.append(String(reflecting: error))
            rendered.append("\(error)")
            rendered.append(error.localizedDescription)
            var dumped = ""
            dump(error, to: &dumped)
            rendered.append(dumped)
        }

        for (status, body) in failures {
            let data = body.isEmpty ? Data() : Contract165Transport.bytes(body)
            let transport = Contract165Transport { _ in Contract165Transport.reply(status, data) }
            let client = try makeClient(transport: transport, hook: recorder.hook)
            do {
                _ = try await client.loginWithProviderIdToken(
                    provider: "p", idToken: Sensitive(idToken), nonce: Sensitive(nonce),
                    configuration: Self.configuration)
                XCTFail("expected a failure")
            } catch { capture(error) }
        }
        // A transport failure, and the local refusals of test 5.
        let dropped = Contract165Transport { _ in throw AxiamError.network(NetworkError("reset")) }
        do {
            _ = try await makeClient(transport: dropped, hook: recorder.hook)
                .loginWithProviderIdToken(
                    provider: "p", idToken: Sensitive(idToken), nonce: Sensitive(nonce),
                    configuration: Self.configuration)
        } catch { capture(error) }
        do {
            _ = try await makeClient(transport: okTransport(), hook: recorder.hook)
                .loginWithProviderIdToken(
                    provider: "", idToken: Sensitive(idToken), nonce: Sensitive(nonce),
                    configuration: Self.configuration)
        } catch { capture(error) }
        do {
            _ = try await makeClient(transport: okTransport(), tenantID: nil, hook: recorder.hook)
                .loginWithProviderIdToken(
                    provider: "p", idToken: Sensitive(idToken), nonce: Sensitive(nonce))
        } catch { capture(error) }
        // A success with a validation failure on the AXIAM token's own nonce.
        do {
            _ = try await makeClient(
                transport: jwksAware(openidBody(nonceClaim: "other")), hook: recorder.hook)
                .loginWithProviderIdToken(
                    provider: "p", idToken: Sensitive(idToken), nonce: Sensitive(nonce),
                    scopes: ["openid"], configuration: Self.configuration)
        } catch { capture(error) }

        // The Sensitive wrappers and ProviderNonce render redacted.
        let pair = try makeClient(transport: okTransport()).nativeNonce()
        let rawValue = pair.raw.expose()
        var dumpedPair = ""
        dump(pair, to: &dumpedPair)
        rendered.append(contentsOf: [
            String(describing: pair), String(reflecting: pair), "\(pair)", "\(pair.raw)",
            dumpedPair, String(describing: Sensitive(idToken)), String(describing: Sensitive(nonce)),
        ])

        XCTAssertGreaterThan(rendered.count, 40)
        let telemetry = recorder.events.map { String(reflecting: $0) }
        XCTAssertFalse(telemetry.isEmpty, "telemetry was exercised")
        for text in rendered + telemetry {
            XCTAssertFalse(text.contains(idToken), "provider ID token leaked: \(text)")
            XCTAssertFalse(text.contains(nonce), "raw nonce leaked: \(text)")
            XCTAssertFalse(text.contains(rawValue), "ProviderNonce.raw leaked: \(text)")
        }
    }

    // MARK: - 13

    func testNativeNoncePair() throws {
        let client = try makeClient(transport: okTransport())
        let first = client.nativeNonce()
        let second = client.nativeNonce()

        let raw = first.raw.expose()
        XCTAssertFalse(raw.contains("="))
        XCTAssertNil(raw.range(of: "[^A-Za-z0-9_-]", options: .regularExpression))
        var padded = raw.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while padded.count % 4 != 0 { padded += "=" }
        let decoded = try XCTUnwrap(Data(base64Encoded: padded))
        XCTAssertGreaterThanOrEqual(decoded.count, 32)

        XCTAssertEqual(first.hashed.count, 64)
        XCTAssertNil(first.hashed.range(of: "[^0-9a-f]", options: .regularExpression))
        XCTAssertEqual(first.hashed, Self.hex(SHA256.hash(data: Data(raw.utf8))))
        // The fixed vector for the hashing step.
        XCTAssertEqual(AxiamClient.nativeNonceHash(of: Self.rawNonce), Self.rawNonceHash)

        XCTAssertNotEqual(first.raw.expose(), second.raw.expose())
        XCTAssertNotEqual(first.hashed, second.hashed)
        XCTAssertEqual(String(describing: first.raw), "[SENSITIVE]")
        XCTAssertFalse(String(describing: first).contains(raw))
    }

    private static func hex(_ digest: SHA256.Digest) -> String {
        digest.map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - §12.1 idp_hint

    private func queryItems(_ url: String) -> [URLQueryItem] {
        URLComponents(string: url)?.queryItems ?? []
    }

    private func begin(
        _ client: AxiamClient, hint: String? = nil,
        configuration: OidcConfiguration = Contract165NativeSignInTests.configuration
    ) async throws -> AuthorizationRequest {
        try await client.oidcBegin(
            redirectURI: "https://app.example.test/cb", idpHint: hint, configuration: configuration)
    }

    private func configuration(authorizationEndpoint: String) -> OidcConfiguration {
        let json: [String: Any] = [
            "issuer": Self.issuer, "authorization_endpoint": authorizationEndpoint,
            "token_endpoint": "\(Self.base)/oauth2/token", "jwks_uri": "\(Self.base)/oauth2/jwks",
        ]
        return try! JSONDecoder().decode(
            OidcConfiguration.self, from: JSONSerialization.data(withJSONObject: json))
    }

    func testIdpHintEmittedOnce() async throws {
        let client = try makeClient(transport: okTransport())
        let others = [
            "response_type", "client_id", "redirect_uri", "scope", "state", "nonce",
            "code_challenge", "code_challenge_method",
        ]
        let hints = ["corp-okta", "5b0c3f0e-1d57-4f4c-9d3a-0f0f0f0f0f0f", "Google", "a b&c=d/é+ü"]
        for hint in hints {
            let url = try await begin(client, hint: hint).url
            let items = queryItems(url)
            XCTAssertEqual(items.filter { $0.name == "axiam_idp_hint" }.map { $0.value }, [hint])
            XCTAssertEqual(Set(items.map { $0.name }), Set(others + ["axiam_idp_hint"]))
            XCTAssertEqual(items.count, 9)
        }
    }

    func testIdpHintOmittedWhenUnset() async throws {
        let client = try makeClient(transport: okTransport())
        let url = try await begin(client).url
        let items = queryItems(url)
        XCTAssertFalse(items.contains { $0.name == "axiam_idp_hint" })
        XCTAssertFalse(items.contains { $0.name == "kc_idp_hint" })
        XCTAssertEqual(items.count, 8)
    }

    func testIdpHintNotDuplicated() async throws {
        // This SDK takes no caller-supplied extras; the only other source of a query parameter
        // is the discovery document's own authorization_endpoint. The option wins there.
        let client = try makeClient(transport: okTransport())
        let document = configuration(
            authorizationEndpoint: "\(Self.base)/oauth2/authorize?axiam_idp_hint=other")
        let hinted = try await begin(client, hint: "corp-okta", configuration: document).url
        let set = queryItems(hinted)
        XCTAssertEqual(set.filter { $0.name == "axiam_idp_hint" }.map { $0.value }, ["corp-okta"])
        // Unset: the endpoint's own parameter passes through, still once.
        let plain = try await begin(client, configuration: document).url
        let unset = queryItems(plain)
        XCTAssertEqual(unset.filter { $0.name == "axiam_idp_hint" }.map { $0.value }, ["other"])
    }

    func testIdpHintBounds() async throws {
        let client = try makeClient(transport: okTransport())
        for bad in ["", String(repeating: "a", count: 257), String(repeating: "é", count: 129)] {
            do {
                _ = try await begin(client, hint: bad)
                XCTFail("expected a refusal for \(bad.utf8.count) bytes")
            } catch let AxiamError.network(error) {
                XCTAssertTrue(error.isValidation)
            }
        }
        for ok in [String(repeating: "a", count: 256), String(repeating: "é", count: 128)] {
            let url = try await begin(client, hint: ok).url
            let items = queryItems(url)
            XCTAssertEqual(items.first { $0.name == "axiam_idp_hint" }?.value, ok)
        }
        // Nothing but emptiness and length is judged: no trimming, folding or kind-name check.
        let odd = " Not A Provider "
        let oddURL = try await begin(client, hint: odd).url
        XCTAssertEqual(
            queryItems(oddURL).first { $0.name == "axiam_idp_hint" }?.value, odd)
    }

    func testParIdpHintInPushedBody() async throws {
        let transport = Contract165Transport { spec in
            if spec.url.path.hasSuffix("/oauth2/par") {
                return Contract165Transport.json(201, ["request_uri": "urn:par:abc", "expires_in": 90])
            }
            return Contract165Transport.json(404, [:])
        }
        let client = try makeClient(transport: transport)
        let begun = try await begin(client)

        let withHint = try await client.oidcPar(
            request: begun, redirectURI: "https://app.example.test/cb", idpHint: "corp-okta",
            configuration: Self.configuration)
        let pushed = try XCTUnwrap(transport.requests.first)
        XCTAssertEqual(form(pushed).filter { $0.0 == "axiam_idp_hint" }.map { $0.1 }, ["corp-okta"])
        XCTAssertFalse(form(pushed).contains { $0.0 == "kc_idp_hint" })
        // The redirect is exactly client_id, request_uri and the routing tenant_id.
        XCTAssertEqual(
            Set(queryItems(withHint.url).map { $0.name }), ["client_id", "request_uri", "tenant_id"])

        let without = try await client.oidcPar(
            request: begun, redirectURI: "https://app.example.test/cb",
            configuration: Self.configuration)
        XCTAssertFalse(form(try XCTUnwrap(transport.requests.last)).contains { $0.0 == "axiam_idp_hint" })
        XCTAssertEqual(
            Set(queryItems(without.url).map { $0.name }), ["client_id", "request_uri", "tenant_id"])

        // Bounds are §12.1's, checked before the push.
        let count = transport.requests.count
        do {
            _ = try await client.oidcPar(
                request: begun, redirectURI: "https://app.example.test/cb", idpHint: "",
                configuration: Self.configuration)
            XCTFail("expected a refusal")
        } catch let AxiamError.network(error) {
            XCTAssertTrue(error.isValidation)
        }
        XCTAssertEqual(transport.requests.count, count)
    }

    // MARK: - §9 confirmation (contract 1.65)

    /// `oidcRefresh` against a mocked `400 invalid_grant`: ONE wire call for a burst of N ≥ 5,
    /// every waiter gets that one error, and the spent token is never presented again.
    func testRefreshInvalidGrantIsOneWireCallSharedByEveryWaiter() async throws {
        let started = ProbeLatch()
        let release = ProbeLatch()
        let transport = Contract165Transport { _ in
            started.signal()
            await release.wait()
            return Contract165Transport.json(
                400, ["error": "invalid_grant", "error_description": "refresh token reuse"])
        }
        let client = try makeClient(transport: transport)
        let burst = 8

        let outcomes = try await withThrowingTaskGroup(of: String?.self) { group in
            for _ in 0..<burst {
                group.addTask {
                    do {
                        _ = try await client.oidcRefresh(
                            refreshToken: Sensitive("spent-refresh-token"),
                            configuration: Self.configuration)
                        return nil
                    } catch {
                        return Contract165NativeSignInTests.oauthError(error)?.oauthError
                    }
                }
            }
            await started.wait()
            // Give the rest of the burst time to reach the guard while the call is parked.
            try await Task.sleep(nanoseconds: 200_000_000)
            release.signal()
            var results: [String?] = []
            for try await outcome in group { results.append(outcome) }
            return results
        }

        XCTAssertEqual(outcomes.count, burst)
        XCTAssertTrue(outcomes.allSatisfy { $0 == "invalid_grant" }, "\(outcomes)")
        XCTAssertEqual(transport.tokenRequests.count, 1, "one wire call for the whole burst")
        // Nothing presents the spent token again on its own: no retry, no fallback.
        try await Task.sleep(nanoseconds: 100_000_000)
        XCTAssertEqual(transport.tokenRequests.count, 1)

        // A call that starts after the slot is vacated is the caller's own, fresh attempt.
        _ = try? await client.oidcRefresh(
            refreshToken: Sensitive("a-new-token"), configuration: Self.configuration)
        XCTAssertEqual(transport.tokenRequests.count, 2)
    }

    func testSequentialRefreshesEachMakeTheirOwnWireCall() async throws {
        let transport = okTransport()
        let client = try makeClient(transport: transport)
        for _ in 0..<3 {
            _ = try await client.oidcRefresh(
                refreshToken: Sensitive("rt"), configuration: Self.configuration)
        }
        XCTAssertEqual(transport.tokenRequests.count, 3)
    }

    // MARK: - §9 rule 7 (contract 1.69): the flight key carries the normalised resolved tenant

    /// Both contain hex letters, so upper- and lower-case spellings really differ.
    private static let hexTenant = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    private static let otherTenant = "ffffffff-1111-4222-9333-abcdefabcdef"

    /// What a burst of held `oidcRefresh` calls did.
    private struct RefreshBurst {
        var wireCalls: Int
        /// The `tenant_id` query value of each token-endpoint call, in arrival order.
        var wireTenants: [String]
        /// Each caller's access token (`at-<refresh token it presented>`), in call order.
        var results: [String]
        var slotsAfter: Int
    }

    /// One refresh per `(token, tenantID)` pair, run concurrently. The first call is parked on the
    /// wire before any other starts. The wire is released only when the burst has reached its
    /// expected shape: `expectedJoins` callers have committed to the live flight (a hook fired in
    /// the join branch) and `expectedWire` calls are parked on the transport. No sleeps: a shape
    /// that is never reached gives up after a bounded poll, so a regression fails an assertion
    /// instead of hanging the suite.
    private func heldRefreshBurst(
        _ calls: [(token: String, tenant: String?)],
        clientTenant: String? = Contract165NativeSignInTests.tenant,
        expectedWire: Int,
        expectedJoins: Int
    ) async throws -> RefreshBurst {
        let arrivals = ProbeCounter()
        let joins = ProbeCounter()
        let release = ProbeLatch()
        let transport = Contract165Transport { spec in
            arrivals.increment()
            await release.wait()
            let token = Contract165NativeSignInTests.refreshToken(in: spec)
            return Contract165Transport.json(
                200,
                ["access_token": "at-\(token)", "token_type": "Bearer", "expires_in": 900])
        }
        let client = try makeClient(transport: transport, tenantID: clientTenant)
        await client._setOidcRefreshTestHook { phase in
            if phase == .waiterJoining { joins.increment() }
        }
        let results = try await withThrowingTaskGroup(of: (Int, String).self) { group in
            for (index, call) in calls.enumerated() {
                group.addTask {
                    let set = try await client.oidcRefresh(
                        refreshToken: Sensitive(call.token), tenantID: call.tenant,
                        configuration: Self.configuration)
                    return (index, set.accessToken.wrapped)
                }
                // The first call is on the wire before any other starts.
                if index == 0 { _ = await arrivals.wait(atLeast: 1) }
            }
            _ = await joins.wait(atLeast: expectedJoins)
            _ = await arrivals.wait(atLeast: expectedWire)
            release.signal()
            var out = [String](repeating: "", count: calls.count)
            for try await (index, token) in group { out[index] = token }
            return out
        }
        await client._setOidcRefreshTestHook(nil)
        let tenants = transport.tokenRequests.map { spec in
            (URLComponents(url: spec.url, resolvingAgainstBaseURL: false)?.queryItems ?? [])
                .first { $0.name == "tenant_id" }?.value ?? ""
        }
        return RefreshBurst(
            wireCalls: transport.tokenRequests.count, wireTenants: tenants, results: results,
            slotsAfter: await client._oidcRefreshFlightCount())
    }

    private static func refreshToken(in spec: HTTPRequestSpec) -> String {
        String(decoding: spec.body ?? Data(), as: UTF8.self).split(separator: "&")
            .first { $0.hasPrefix("refresh_token=") }
            .map { String($0.dropFirst("refresh_token=".count)) } ?? ""
    }

    func testRefreshTenantCaseAndOmittedDefaultShareOneFlight() async throws {
        let lower = Self.hexTenant
        let upper = Self.hexTenant.uppercased()
        XCTAssertNotEqual(lower, upper)
        XCTAssertNotEqual(Self.otherTenant, Self.otherTenant.uppercased())
        // The leader passes the tenant in upper case: the wire still gets the canonical form.
        let leaderUpper = try await heldRefreshBurst(
            [("rt", upper), ("rt", lower), ("rt", nil)], clientTenant: lower,
            expectedWire: 1, expectedJoins: 2)
        XCTAssertEqual(leaderUpper.wireCalls, 1)
        XCTAssertEqual(leaderUpper.wireTenants, [lower.lowercased()])
        // The client's default tenant, spelled lower, upper and not at all, concurrently.
        let burst = try await heldRefreshBurst(
            [("rt", lower), ("rt", upper), ("rt", nil)], clientTenant: lower,
            expectedWire: 1, expectedJoins: 2)
        XCTAssertEqual(burst.wireCalls, 1, "same token, same effective tenant: one flight")
        XCTAssertEqual(burst.wireTenants, [lower], "the canonical lower-case value goes on the wire")
        XCTAssertEqual(burst.results, ["at-rt", "at-rt", "at-rt"])
        XCTAssertEqual(burst.slotsAfter, 0, "the slot is removed once vacated")

        // The default itself configured in upper case, the others lower case and omitted.
        let mixed = try await heldRefreshBurst(
            [("rt", nil), ("rt", lower), ("rt", upper)], clientTenant: upper,
            expectedWire: 1, expectedJoins: 2)
        XCTAssertEqual(mixed.wireCalls, 1)
        XCTAssertEqual(mixed.wireTenants, [lower])
        XCTAssertEqual(mixed.slotsAfter, 0)
    }

    func testRefreshDifferentTenantSeparateFlights() async throws {
        let burst = try await heldRefreshBurst(
            [("rt", Self.hexTenant), ("rt", Self.otherTenant)], clientTenant: Self.hexTenant,
            expectedWire: 2, expectedJoins: 0)
        XCTAssertEqual(burst.wireCalls, 2, "same token, different tenant: separate flights")
        XCTAssertEqual(Set(burst.wireTenants), [Self.hexTenant, Self.otherTenant],
                       "each wire call carries its own tenant_id")
        XCTAssertEqual(burst.results, ["at-rt", "at-rt"])
        XCTAssertEqual(burst.slotsAfter, 0)

        // The other tenant spelled in upper case is still the other tenant: separate flights.
        let upper = try await heldRefreshBurst(
            [("rt", nil), ("rt", Self.otherTenant.uppercased())], clientTenant: Self.hexTenant,
            expectedWire: 2, expectedJoins: 0)
        XCTAssertEqual(upper.wireCalls, 2)
        XCTAssertEqual(upper.slotsAfter, 0)
    }

    func testRefreshDifferentTokenSeparateFlights() async throws {
        let burst = try await heldRefreshBurst(
            [("rt-a", nil), ("rt-a", nil), ("rt-b", nil)], expectedWire: 2, expectedJoins: 1)
        XCTAssertEqual(burst.wireCalls, 2, "different token, same tenant: separate flights")
        XCTAssertEqual(
            burst.results, ["at-rt-a", "at-rt-a", "at-rt-b"],
            "a second caller of A shares A's call; B gets its own outcome")
        XCTAssertEqual(burst.slotsAfter, 0)
    }

    /// Contract 1.69, the publish-before-vacate window. Owner A's outcome is settled but its slot
    /// is not yet vacated (the `.ownerPublished` hook parks it there). A different token B makes
    /// its own wire call and gets its own result; the same token A, arriving in that window,
    /// joins A's outcome without a new wire call.
    func testRefreshDifferentTokenInPublishBeforeVacateWindowGetsItsOwnCall() async throws {
        let transport = Contract165Transport { spec in
            let token = Contract165NativeSignInTests.refreshToken(in: spec)
            return Contract165Transport.json(
                200, ["access_token": "at-\(token)", "token_type": "Bearer", "expires_in": 900])
        }
        let client = try makeClient(transport: transport)
        // Captured explicitly below: Swift 6.2's region-based isolation checker cannot check an
        // unstructured Task that reaches `Self.configuration` (it implicitly captures `self`).
        let configuration = Self.configuration
        let parked = ProbeCounter()
        let open = ProbeLatch()
        let once = ProbeLatch()
        let joined = ProbeCounter()
        await client._setOidcRefreshTestHook { phase in
            switch phase {
            case .ownerPublished:
                if once.claimOnce() {  // only A's owner parks; B's vacate passes straight through
                    parked.increment()
                    await open.wait()
                }
            case .waiterJoining:
                joined.increment()
            }
        }
        let a = Task { [client, configuration] in
            try await client.oidcRefresh(
                refreshToken: Sensitive("rt-a"), configuration: configuration)
        }
        // A's wire call is done and its outcome settled; the slot is not vacated.
        let isParked = await parked.wait(atLeast: 1)
        XCTAssertTrue(isParked, "owner A reached the publish-before-vacate window")
        XCTAssertEqual(transport.tokenRequests.count, 1)

        let b = try await client.oidcRefresh(
            refreshToken: Sensitive("rt-b"), configuration: configuration)
        XCTAssertEqual(b.accessToken.wrapped, "at-rt-b", "B's own result")
        XCTAssertEqual(transport.tokenRequests.count, 2, "B made its own wire call")

        let aAgain = Task { [client, configuration] in
            try await client.oidcRefresh(
                refreshToken: Sensitive("rt-a"), configuration: configuration)
        }
        // The same token commits to the settled flight in the window (bounded: a regression that
        // starts a second flight fails here instead of hanging).
        let didJoin = await joined.wait(atLeast: 1)
        XCTAssertTrue(didJoin, "the same token joined the settled flight")
        open.signal()
        let first = try await a.value
        let second = try await aAgain.value
        XCTAssertEqual(first.accessToken.wrapped, "at-rt-a")
        XCTAssertEqual(second.accessToken.wrapped, "at-rt-a", "the same token joined A's outcome")
        XCTAssertEqual(transport.tokenRequests.count, 2, "no wire call for the joiner")
        let slots = await client._oidcRefreshFlightCount()
        XCTAssertEqual(slots, 0)
        await client._setOidcRefreshTestHook(nil)
    }

    func testRefreshFlightKeyNormalisesTenantAndIsAHexDigest() {
        let token = "rt-secret"
        let lower = AxiamClient.oidcRefreshFlightKey(tenant: Self.hexTenant, refreshToken: token)
        XCTAssertEqual(
            lower,
            AxiamClient.oidcRefreshFlightKey(tenant: Self.hexTenant.uppercased(), refreshToken: token))
        XCTAssertNotEqual(
            lower, AxiamClient.oidcRefreshFlightKey(tenant: Self.otherTenant, refreshToken: token))
        XCTAssertEqual(lower.count, 64, "a SHA-256 hex digest, never the token")
        XCTAssertTrue(lower.allSatisfy { $0.isHexDigit && !$0.isUppercase })
    }

    /// An invalid tenant is refused before keying and before any request, with or without a
    /// supplied discovery document: zero requests of any kind.
    func testRefreshInvalidTenantIsRefusedWithNoRequestAtAll() async throws {
        for bad in ["not-a-uuid", Self.tenant + "\nx", ""] {
            let transport = okTransport()
            let client = try makeClient(transport: transport)
            let configurations: [OidcConfiguration?] = [Self.configuration, nil]
            for configuration in configurations {
                do {
                    _ = try await client.oidcRefresh(
                        refreshToken: Sensitive("rt"), tenantID: bad, configuration: configuration)
                    XCTFail("an invalid tenant must be refused: \(bad.debugDescription)")
                } catch {
                    XCTAssertNotNil(Self.oauthError(error), "\(error)")
                }
            }
            XCTAssertEqual(transport.requests.count, 0, "no request of any kind: \(bad.debugDescription)")
            let slots = await client._oidcRefreshFlightCount()
            XCTAssertEqual(slots, 0)
        }
    }

    // MARK: - §26.6 par_idp_hint_from_begin_url_pushed / par_idp_hint_argument_wins (D-N36)

    private func parTransport() -> Contract165Transport {
        Contract165Transport { spec in
            if spec.url.path.hasSuffix("/oauth2/par") {
                return Contract165Transport.json(201, ["request_uri": "urn:par:abc", "expires_in": 90])
            }
            return Contract165Transport.json(404, [:])
        }
    }

    func testParIdpHintFromBeginURLPushed() async throws {
        let transport = parTransport()
        let client = try makeClient(transport: transport)
        let begun = try await begin(client, hint: "corp-okta")

        // No `idpHint` argument: the begin URL's hint is pushed, exactly once.
        let pushedRedirect = try await client.oidcPar(
            request: begun, redirectURI: "https://app.example.test/cb",
            configuration: Self.configuration)
        let pushed = try XCTUnwrap(transport.requests.first)
        XCTAssertEqual(form(pushed).filter { $0.0 == "axiam_idp_hint" }.map { $0.1 }, ["corp-okta"])
        XCTAssertFalse(form(pushed).contains { $0.0 == "kc_idp_hint" })
        // The redirect is still exactly client_id, request_uri and the routing tenant_id.
        XCTAssertEqual(
            Set(queryItems(pushedRedirect.url).map { $0.name }),
            ["client_id", "request_uri", "tenant_id"])

        // A begin without a hint pushes none.
        let plain = try await begin(client)
        _ = try await client.oidcPar(
            request: plain, redirectURI: "https://app.example.test/cb",
            configuration: Self.configuration)
        XCTAssertFalse(
            form(try XCTUnwrap(transport.requests.last)).contains { $0.0 == "axiam_idp_hint" })
    }

    func testParIdpHintArgumentWins() async throws {
        let transport = parTransport()
        let client = try makeClient(transport: transport)
        let begun = try await begin(client, hint: "corp-okta")

        let redirect = try await client.oidcPar(
            request: begun, redirectURI: "https://app.example.test/cb", idpHint: "other",
            configuration: Self.configuration)
        let pushed = try XCTUnwrap(transport.requests.first)
        XCTAssertEqual(form(pushed).filter { $0.0 == "axiam_idp_hint" }.map { $0.1 }, ["other"])
        XCTAssertFalse(form(pushed).contains { $0.1 == "corp-okta" })
        XCTAssertEqual(
            Set(queryItems(redirect.url).map { $0.name }), ["client_id", "request_uri", "tenant_id"])
    }

    // MARK: - C165-14 / §12.1 rule 3: no redirect from an /oauth2/* POST

    /// A mocked `307 Location: http://other.example.test/…` is a `NetworkError`, on the native
    /// call and on the pre-existing token POSTs alike, and is not retried. A mock transport
    /// follows nothing, so "the other host sees no request" is the next test's job, over sockets.
    func testRedirectFromOAuth2PostIsNetworkError() async throws {
        let transport = Contract165Transport { _ in
            Contract165Transport.reply(
                307, Data(), headers: [("Location", "http://other.example.test/oauth2/token")])
        }
        let client = try makeClient(transport: transport, secret: "the-client-secret")

        for status in [301, 302, 303, 307, 308] {
            let t = Contract165Transport { _ in
                Contract165Transport.reply(
                    status, Data(), headers: [("Location", "http://other.example.test/x")])
            }
            let c = try makeClient(transport: t)
            do {
                _ = try await login(c)
                XCTFail("expected a NetworkError for \(status)")
            } catch let AxiamError.network(error) {
                XCTAssertEqual(error.statusCode, status)
                XCTAssertFalse("\(error)".contains("other.example.test"))
                XCTAssertFalse("\(error)".contains(Self.providerToken))
            }
            XCTAssertEqual(t.requests.count, 1, "a refused redirect is not retried")
            XCTAssertTrue(t.requests.allSatisfy { $0.url.host == "iam.example.test" })
        }

        // The ordinary token POST (code exchange / refresh) takes the same path.
        do {
            _ = try await client.oidcRefresh(
                refreshToken: Sensitive("rt"), configuration: Self.configuration)
            XCTFail("expected a NetworkError")
        } catch let AxiamError.network(error) {
            XCTAssertEqual(error.statusCode, 307)
        }
        XCTAssertEqual(transport.tokenRequests.count, 1)
        XCTAssertTrue(transport.requests.allSatisfy { $0.url.host == "iam.example.test" })
    }

    /// Over real sockets and the production `AsyncHTTPClientTransport`: a `307` to another
    /// host gives a `NetworkError`, and the other host is never contacted.
    func testRedirectToOtherHostIsNotFollowedOverTheWire() async throws {
        let other = TestHTTPServer(router: { _, _ in TestResponse.json(200, Self.okBody()) })
        let otherPort = try other.start()
        defer { other.stop() }

        let server = TestHTTPServer(router: { request, _ in
            TestResponse(
                status: 307,
                headers: [("Location", "http://127.0.0.1:\(otherPort)\(request.uri)")])
        })
        let port = try server.start()
        defer { server.stop() }

        let base = "http://127.0.0.1:\(port)"
        let json: [String: Any] = [
            "issuer": base, "authorization_endpoint": "\(base)/oauth2/authorize",
            "token_endpoint": "\(base)/oauth2/token", "jwks_uri": "\(base)/oauth2/jwks",
        ]
        let document = try JSONDecoder().decode(
            OidcConfiguration.self, from: JSONSerialization.data(withJSONObject: json))
        let client = try AxiamClient(config: try AxiamConfig(
            baseURL: URL(string: base)!, tenantID: Self.tenant, requestTimeout: 10,
            oidcClientID: Self.clientID))
        do {
            do {
                _ = try await client.loginWithProviderIdToken(
                    provider: "corp-okta", idToken: Sensitive(Self.providerToken),
                    nonce: Sensitive(Self.rawNonce), configuration: document)
                XCTFail("expected a NetworkError")
            } catch let AxiamError.network(error) {
                XCTAssertEqual(error.statusCode, 307)
            }
            XCTAssertEqual(server.state.requests(pathContaining: "/oauth2/token").count, 1)
            XCTAssertEqual(other.state.requests.count, 0)
        } catch {
            try? await client.shutdown()
            throw error
        }
        try? await client.shutdown()
    }
}

