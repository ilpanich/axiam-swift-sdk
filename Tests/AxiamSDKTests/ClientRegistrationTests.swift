import XCTest
@testable import AxiamSDK

/// CONTRACT.md §28.12 — RFC 7592 client configuration, the five required tests of §28.12.6
/// (split across eight cases, as the reference port does).
///
/// Every token here is generated at run time: a literal would be a credential in the
/// repository, and the redaction test needs a value no fixture shares.
final class ClientRegistrationTests: XCTestCase {

    private static let base = "https://iam.example.test"
    private static let tenantID = "6f3e0a5c-1b2d-4e8f-9a7b-0c1d2e3f4a5b"
    private static let clientID = "dcr-client-1"
    private static let registrationPath = "/oauth2/register/dcr-client-1"

    private static var registrationURI: String {
        "\(base)\(registrationPath)?tenant_id=\(tenantID)"
    }

    /// A client over `transport`, retry ENABLED (a "not retried" assertion against a client
    /// that never retries anything would prove nothing), with §16's waits taken instantly.
    private func makeClient(
        _ transport: RoutedTransport,
        base: String = ClientRegistrationTests.base
    ) async throws -> AxiamClient {
        let config = try AxiamConfig(
            baseURL: URL(string: base)!, tenantID: Self.tenantID, retryEnabled: true)
        let client = AxiamClient(config: config, transport: transport)
        await client._setRetryTestSeams(jitter: { 0 }, sleep: { _ in })
        return client
    }

    /// A client holding a real SDK session — a session cookie in its jar and a CSRF token —
    /// so "the session is not attached" is a claim about something that exists.
    private func makeSignedInClient(
        _ transport: RoutedTransport,
        sessionCookie: String
    ) async throws -> AxiamClient {
        transport.route("POST", "/auth/login", [
            .json(200, object: TestKit.loginSuccessBody(), headers: [
                ("Set-Cookie", "axiam_access=\(sessionCookie); Path=/; Secure; HttpOnly"),
                ("X-CSRF-Token", "csrf-\(SecretKit.random())"),
            ]),
        ])
        let client = try await makeClient(transport)
        _ = try await client.login(email: "admin@acme.test", password: SecretKit.random())
        let cookies = await client._cookieCount()
        XCTAssertGreaterThan(cookies, 0, "the fixture must hold a real session cookie")
        return client
    }

    private static func registrationJSON(_ extra: [String: Any] = [:]) -> [String: Any] {
        var body: [String: Any] = [
            "client_id": clientID,
            "client_id_issued_at": 1_700_000_000,
            "client_name": "Agent",
            "redirect_uris": ["https://agent.example.test/cb"],
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "private_key_jwt",
            "scope": "openid",
            "registration_client_uri": registrationURI,
            "jwks_uri": "https://agent.example.test/jwks",
        ]
        for (key, value) in extra { body[key] = value }
        return body
    }

    private static func registration(_ extra: [String: Any] = [:]) throws -> ClientRegistration {
        let data = try JSONSerialization.data(withJSONObject: registrationJSON(extra))
        return try ClientRegistration(json: data)
    }

    private static func isValidation(_ error: Error) -> Bool {
        if case AxiamError.network(let network) = error { return network.isValidation }
        return false
    }

    // MARK: - 1. Origin refusal

    func testAURIAtAnotherOriginIsRefusedLocallyAndNothingIsSent() async throws {
        let transport = RoutedTransport()
        transport.route(nil, Self.registrationPath, [.json(200, object: Self.registrationJSON())])
        let client = try await makeClient(transport)
        let token = Sensitive(SecretKit.random())
        let metadata = ClientRegistration(clientID: Self.clientID)

        for uri in [
            "https://evil.example.test\(Self.registrationPath)",
            "https://iam.example.test:8443\(Self.registrationPath)",
            "http://iam.example.test\(Self.registrationPath)",
            "ftp://iam.example.test/x",
            Self.registrationPath,
        ] {
            do {
                _ = try await client.readClientRegistration(
                    registrationClientURI: uri, registrationAccessToken: token)
                XCTFail("a read at another origin must be refused")
            } catch {
                XCTAssertTrue(Self.isValidation(error), "expected the local ValidationError")
            }
            do {
                try await client.deleteClientRegistration(
                    registrationClientURI: uri, registrationAccessToken: token)
                XCTFail("a delete at another origin must be refused")
            } catch {
                XCTAssertTrue(Self.isValidation(error), "expected the local ValidationError")
            }
            do {
                _ = try await client.updateClientRegistration(
                    registrationClientURI: uri, registrationAccessToken: token,
                    metadata: metadata)
                XCTFail("an update at another origin must be refused")
            } catch {
                XCTAssertTrue(Self.isValidation(error), "expected the local ValidationError")
            }
        }
        XCTAssertEqual(transport.requests.count, 0, "nothing reaches the wire")
    }

    func testHttpIsAcceptedOnlyAgainstAnHttpLoopbackBaseAndTheQueryIsKept() async throws {
        let transport = RoutedTransport()
        let loopback = try await makeClient(transport, base: "http://127.0.0.1:8080")
        let local = try await loopback.checkRegistrationURI(
            "http://127.0.0.1:8080/oauth2/register/c1", "op")
        XCTAssertEqual(local.port, 8080)

        let https = try await makeClient(transport)
        let accepted = try await https.checkRegistrationURI(
            "https://IAM.example.test:443\(Self.registrationPath)?tenant_id=t", "op")
        XCTAssertEqual(accepted.query, "tenant_id=t", "the URI is used verbatim, query kept")
        XCTAssertEqual(transport.requests.count, 0)
    }

    // MARK: - 2. Header only

    func testReadAndDeleteSendTheBearerOnlyAndKeepTheQueryVerbatim() async throws {
        let transport = RoutedTransport()
        let sessionCookie = SecretKit.random()
        let client = try await makeSignedInClient(transport, sessionCookie: sessionCookie)
        transport.route("GET", Self.registrationPath, [.json(200, object: Self.registrationJSON())])
        transport.route("DELETE", Self.registrationPath, [.empty(204)])
        let token = SecretKit.random()

        let read = try await client.readClientRegistration(
            registrationClientURI: Self.registrationURI,
            registrationAccessToken: Sensitive(token))
        XCTAssertEqual(read.clientID, Self.clientID)
        XCTAssertNil(read.registrationAccessToken)
        try await client.deleteClientRegistration(
            registrationClientURI: Self.registrationURI,
            registrationAccessToken: Sensitive(token))

        let sent = transport.requests(Self.registrationPath)
        XCTAssertEqual(sent.map(\.method), ["GET", "DELETE"])
        for request in sent {
            XCTAssertEqual(request.headerValues("Authorization"), ["Bearer \(token)"])
            XCTAssertTrue(request.headerValues("Cookie").isEmpty, "no session cookie")
            XCTAssertTrue(request.headerValues("X-CSRF-Token").isEmpty, "no session CSRF token")
            XCTAssertFalse(
                request.headers.contains { $0.1.contains(sessionCookie) },
                "never the SDK's session credential")
            XCTAssertTrue(request.body?.isEmpty ?? true, "no body on GET/DELETE")
            XCTAssertEqual(
                request.query, "tenant_id=\(Self.tenantID)",
                "the URI's own query, verbatim, and the token never in it")
        }
    }

    // MARK: - 3. Update body

    func testUpdateDropsTheFiveServerStatedMembersAndReturnsTheRotatedToken() async throws {
        let transport = RoutedTransport()
        let rotated = SecretKit.random()
        transport.route("PUT", Self.registrationPath, [
            .json(200, object: Self.registrationJSON(["registration_access_token": rotated])),
        ])
        let client = try await makeClient(transport)

        var metadata = try Self.registration([
            "registration_access_token": SecretKit.random(),
            "client_secret": SecretKit.random(),
            "client_secret_expires_at": 0,
            "backchannel_token_delivery_mode": "poll",
        ])
        metadata.clientName = "Agent v2"

        let updated = try await client.updateClientRegistration(
            registrationClientURI: Self.registrationURI,
            registrationAccessToken: Sensitive(SecretKit.random()),
            metadata: metadata)
        XCTAssertEqual(updated.registrationAccessToken?.expose(), rotated)

        let sent = transport.requests(Self.registrationPath)
        XCTAssertEqual(sent.count, 1)
        let body = try XCTUnwrap(sent.first?.jsonBody)
        for gone in [
            "registration_access_token", "registration_client_uri",
            "client_secret_expires_at", "client_id_issued_at", "client_secret",
        ] {
            XCTAssertNil(body[gone], "\(gone) must not be sent")
        }
        XCTAssertEqual(body["client_id"] as? String, Self.clientID)
        XCTAssertEqual(body["client_name"] as? String, "Agent v2")
        XCTAssertEqual(body["jwks_uri"] as? String, "https://agent.example.test/jwks")
        XCTAssertEqual(
            body["backchannel_token_delivery_mode"] as? String, "poll",
            "an unknown member round-trips")
        XCTAssertEqual(sent.first?.header("Content-Type"), "application/json")
    }

    func testAnUpdateAnswered503IsNotRetried() async throws {
        let transport = RoutedTransport()
        transport.route("PUT", Self.registrationPath, [.empty(503)])
        let client = try await makeClient(transport)

        do {
            _ = try await client.updateClientRegistration(
                registrationClientURI: Self.registrationURI,
                registrationAccessToken: Sensitive(SecretKit.random()),
                metadata: try Self.registration())
            XCTFail("a 503 must surface")
        } catch AxiamError.network(_) {
            // expected: §2 maps a 503 to NetworkError
        }
        XCTAssertEqual(transport.requests(Self.registrationPath).count, 1, "exactly one request")
    }

    func testADeleteAnswered503IsNotRetriedAndAReadIs() async throws {
        let transport = RoutedTransport()
        transport.route(nil, Self.registrationPath, [.empty(503)])
        let client = try await makeClient(transport)
        let token = Sensitive(SecretKit.random())

        await XCTAssertThrowsErrorAsync(try await client.deleteClientRegistration(
            registrationClientURI: Self.registrationURI, registrationAccessToken: token))
        XCTAssertEqual(transport.requests(Self.registrationPath).count, 1)

        await XCTAssertThrowsErrorAsync(try await client.readClientRegistration(
            registrationClientURI: Self.registrationURI, registrationAccessToken: token))
        XCTAssertEqual(
            transport.requests(Self.registrationPath).count, 1 + Retry.maxAttempts,
            "the read MAY be retried per §16")
    }

    func testAReadAnswered400IsNotRetried() async throws {
        // §28.12.2 rule 5 lets a read follow §16 — and §16 retries no 4xx but 408 / 429.
        let transport = RoutedTransport()
        transport.route("GET", Self.registrationPath, [.empty(400)])
        let client = try await makeClient(transport)

        await XCTAssertThrowsErrorAsync(try await client.readClientRegistration(
            registrationClientURI: Self.registrationURI,
            registrationAccessToken: Sensitive(SecretKit.random())))
        XCTAssertEqual(transport.requests(Self.registrationPath).count, 1)
    }

    // MARK: - 4. Errors

    func testA401InvalidTokenIsAnOAuthProtocolErrorAndRefreshesNothing() async throws {
        let transport = RoutedTransport()
        let client = try await makeSignedInClient(transport, sessionCookie: SecretKit.random())
        transport.route("POST", "/auth/refresh", [.empty(500)])
        transport.route("GET", Self.registrationPath, [
            .json(401, #"{"error": "invalid_token", "error_description": "no"}"#,
                  headers: [("WWW-Authenticate", #"Bearer error="invalid_token""#)]),
        ])

        do {
            _ = try await client.readClientRegistration(
                registrationClientURI: Self.registrationURI,
                registrationAccessToken: Sensitive(SecretKit.random()))
            XCTFail("a 401 must surface")
        } catch AxiamError.auth(let error) {
            XCTAssertEqual(error.oauthError, "invalid_token")
        }
        XCTAssertTrue(transport.requests("/auth/refresh").isEmpty, "§9 is not entered")
        XCTAssertEqual(transport.requests(Self.registrationPath).count, 1)
    }

    func testA400InvalidClientMetadataIsAnOAuthProtocolErrorAndA204DeletesNormally() async throws {
        let transport = RoutedTransport()
        transport.route("PUT", Self.registrationPath, [
            .json(400, #"{"error": "invalid_client_metadata", "error_description": "scope"}"#),
        ])
        transport.route("DELETE", Self.registrationPath, [.empty(204)])
        let client = try await makeClient(transport)

        do {
            _ = try await client.updateClientRegistration(
                registrationClientURI: Self.registrationURI,
                registrationAccessToken: Sensitive(SecretKit.random()),
                metadata: try Self.registration())
            XCTFail("a 400 must surface")
        } catch AxiamError.auth(let error) {
            XCTAssertEqual(error.oauthError, "invalid_client_metadata")
            XCTAssertEqual(error.oauthErrorDescription, "scope")
        }

        try await client.deleteClientRegistration(
            registrationClientURI: Self.registrationURI,
            registrationAccessToken: Sensitive(SecretKit.random()))
    }

    func testAnErrorBodyWithoutADescriptionIsStillAnOAuthProtocolError() async throws {
        let transport = RoutedTransport()
        transport.route("GET", Self.registrationPath, [.json(401, #"{"error": "invalid_token"}"#)])
        let client = try await makeClient(transport)

        do {
            _ = try await client.readClientRegistration(
                registrationClientURI: Self.registrationURI,
                registrationAccessToken: Sensitive(SecretKit.random()))
            XCTFail("a 401 must surface")
        } catch AxiamError.auth(let error) {
            XCTAssertEqual(error.oauthError, "invalid_token")
            XCTAssertNil(error.oauthErrorDescription)
        }
    }

    // MARK: - 5. Redaction

    func testNeitherTheTokenNorTheSecretReachesAnyRendering() async throws {
        let token = SecretKit.random()
        let secret = SecretKit.random()
        let registration = try Self.registration([
            "registration_access_token": token, "client_secret": secret,
        ])
        XCTAssertEqual(registration.registrationAccessToken?.expose(), token)
        XCTAssertEqual(registration.clientSecret?.expose(), secret)

        for rendering in SecretKit.renderings(registration) + [registration.debugDescription] {
            XCTAssertFalse(SecretKit.leaks(rendering, token), "the token leaked into a rendering")
            XCTAssertFalse(SecretKit.leaks(rendering, secret), "the secret leaked into a rendering")
        }

        // An error raised by an operation given the token.
        let transport = RoutedTransport()
        transport.route("GET", Self.registrationPath, [.json(401, #"{"error": "invalid_token"}"#)])
        let client = try await makeClient(transport)
        for uri in [Self.registrationURI, "https://elsewhere.example.test/r"] {
            do {
                _ = try await client.readClientRegistration(
                    registrationClientURI: uri, registrationAccessToken: Sensitive(token))
                XCTFail("expected an error")
            } catch {
                let rendering = SecretKit.renderings(error).joined(separator: "\n")
                XCTAssertFalse(SecretKit.leaks(rendering, token), "the token leaked into an error")
            }
        }
    }

    func testDecodingKeepsUnknownAndMistypedMembersAndRefusesAResponseWithoutAClientID() throws {
        let registration = try Self.registration([
            "client_id_issued_at": "not-a-number",
            "backchannel_token_delivery_mode": "poll",
            "jwks": ["keys": [Any]()],
        ])
        XCTAssertEqual(registration.extra["backchannel_token_delivery_mode"], .string("poll"))
        XCTAssertEqual(registration.extra["client_id_issued_at"], .string("not-a-number"))
        XCTAssertNil(registration.clientIDIssuedAt)
        XCTAssertEqual(registration.jwks, .object(["keys": .array([])]))

        let body = registration.updateBody()
        XCTAssertNil(body["client_id_issued_at"], "a mistyped server-stated member is dropped too")
        XCTAssertEqual(body["backchannel_token_delivery_mode"], .string("poll"))
        XCTAssertEqual(body["jwks"], .object(["keys": .array([])]))

        XCTAssertThrowsError(try ClientRegistration(json: Data("[]".utf8)))
        XCTAssertThrowsError(try ClientRegistration(json: Data(#"{"x": 1}"#.utf8)))
    }
}
