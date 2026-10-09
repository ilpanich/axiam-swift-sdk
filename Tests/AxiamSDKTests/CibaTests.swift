import XCTest
import Crypto
@testable import AxiamSDK

/// CIBA — CONTRACT.md §33.8's sixteen required tests (nine initiation and polling, four ping,
/// three signed request), t01–t16 one-to-one with the reference port.
///
/// No credential, key or token literal: the client secret, the `auth_req_id`, the
/// notification token and every signing key are generated at run time.
final class CibaTests: XCTestCase {

    private static let base = "https://iam.example.test"
    private static let issuer = "https://iam.example.test"
    private static let tenantID = "22222222-2222-4222-8222-222222222222"
    private static let clientID = "ciba-client"
    private static let signer = TestSigner(kid: "ciba-id-token-key")

    // MARK: - Harness

    private static func configuration(
        backchannel: String? = "https://iam.example.test/oauth2/bc-authorize"
    ) throws -> OidcConfiguration {
        var document: [String: Any] = [
            "issuer": issuer,
            "authorization_endpoint": "\(base)/oauth2/authorize",
            "token_endpoint": "\(base)/oauth2/token",
            "jwks_uri": "\(base)/oauth2/jwks",
            "backchannel_token_delivery_modes_supported": ["poll", "ping"],
            "backchannel_authentication_request_signing_alg_values_supported":
                ["PS256", "ES256", "EdDSA"],
            "backchannel_user_code_parameter_supported": false,
        ]
        if let backchannel { document["backchannel_authentication_endpoint"] = backchannel }
        return try JSONDecoder().decode(
            OidcConfiguration.self, from: try JSONSerialization.data(withJSONObject: document))
    }

    /// A client over `transport`: confidential (a run-time secret) unless `secret` is nil, and
    /// holding a §6.1 identity when `certificate` is set. Retry ENABLED, waits instant.
    private func makeClient(
        _ transport: RoutedTransport,
        secret: String? = SecretKit.random(),
        certificate: Bool = false
    ) async throws -> AxiamClient {
        let config = try AxiamConfig(
            baseURL: URL(string: Self.base)!,
            tenantID: Self.tenantID,
            clientCertificate: certificate
                ? ClientCertificate.pem(
                    certificate: Data("certificate".utf8),
                    privateKey: Data(SecretKit.random().utf8))
                : nil,
            retryEnabled: true,
            oidcClientID: Self.clientID,
            oidcClientSecret: secret.map { Sensitive($0) })
        let client = AxiamClient(config: config, transport: transport)
        await client._setRetryTestSeams(jitter: { 0 }, sleep: { _ in })
        return client
    }

    private static func request() -> CibaInitiateRequest {
        CibaInitiateRequest(scope: "openid profile", hint: .loginHint("ada"))
    }

    private static func initiated(_ body: [String: Any]) -> RoutedTransport.Reply {
        .json(200, object: body)
    }

    private static func oauthError(_ status: Int, _ code: String) -> RoutedTransport.Reply {
        .json(status, object: ["error": code, "error_description": "\(code) here"])
    }

    /// A `200` token response whose `id_token` the client's §12.4 checks accept; mounts the
    /// JWKS that verifies it.
    private static func tokens(_ transport: RoutedTransport) -> RoutedTransport.Reply {
        transport.route("GET", "/oauth2/jwks", [.json(200, object: signer.jwksJSON())])
        let now = Date().timeIntervalSince1970
        let idToken = signer.makeJWT(claims: [
            "iss": issuer, "aud": clientID, "sub": UUID().uuidString.lowercased(),
            "iat": Int(now), "exp": Int(now) + 600,
        ])
        return .json(200, object: [
            "access_token": SecretKit.random(), "token_type": "Bearer", "expires_in": 900,
            "scope": "openid profile", "id_token": idToken,
        ])
    }

    private static func response(
        _ authReqID: String = SecretKit.random(),
        expiresIn: Int,
        interval: Int,
        at: Date
    ) -> CibaInitiateResponse {
        CibaInitiateResponse(
            authReqID: Sensitive(authReqID), expiresIn: expiresIn, interval: interval,
            receivedAt: at)
    }

    private static func isValidation(_ error: Error) -> Bool {
        if case AxiamError.network(let network) = error { return network.isValidation }
        return false
    }

    // MARK: - 1. Redaction

    func testT01TheThreeValuesAreOnTheWireAndInNoRendering() async throws {
        let notification = SecretKit.random()
        let authReqID = SecretKit.random()
        let transport = RoutedTransport()
        transport.route("POST", "/oauth2/bc-authorize", [
            Self.initiated(["auth_req_id": authReqID, "expires_in": 120, "interval": 5]),
            Self.oauthError(400, "invalid_binding_message"),
        ])
        let client = try await makeClient(transport)

        var request = Self.request()
        request.delivery = .ping(clientNotificationToken: Sensitive(notification))
        for rendering in SecretKit.renderings(request) {
            XCTAssertFalse(SecretKit.leaks(rendering, notification), "the notification token leaked")
        }

        let response = try await client.cibaInitiate(request, configuration: Self.configuration())
        for rendering in SecretKit.renderings(response) {
            XCTAssertFalse(SecretKit.leaks(rendering, authReqID), "the auth_req_id leaked")
        }
        XCTAssertEqual(response.authReqID.expose(), authReqID)
        XCTAssertEqual(
            transport.requests("/oauth2/bc-authorize").first?.form["client_notification_token"],
            notification, "but it is on the wire")

        do {
            _ = try await client.cibaInitiate(request, configuration: Self.configuration())
            XCTFail("an invalid_binding_message must surface")
        } catch {
            let rendering = SecretKit.renderings(error).joined(separator: "\n")
            XCTAssertFalse(SecretKit.leaks(rendering, notification), "the token leaked into an error")
            guard case AxiamError.auth(let auth) = error else {
                return XCTFail("an OAuth2ErrorResponse is an OAuthProtocolError")
            }
            XCTAssertEqual(auth.oauthError, "invalid_binding_message")
            XCTAssertEqual(auth.oauthErrorDescription, "invalid_binding_message here")
        }
    }

    // MARK: - 2. Client authentication is mandatory

    func testT02NoCredentialIsRefusedLocallyAndOneIsSentWithTenantInTheQuery() async throws {
        let transport = RoutedTransport()
        transport.route("POST", "/oauth2/bc-authorize", [
            Self.initiated(["auth_req_id": SecretKit.random(), "expires_in": 120]),
        ])
        transport.route("POST", "/oauth2/token", [Self.oauthError(400, "authorization_pending")])

        let publicClient = try await makeClient(transport, secret: nil)
        do {
            _ = try await publicClient.cibaInitiate(Self.request(), configuration: Self.configuration())
            XCTFail("a public client must be refused")
        } catch AxiamError.auth(_) {
            // expected
        }
        do {
            _ = try await publicClient.cibaPoll(
                authReqID: Sensitive(SecretKit.random()), configuration: Self.configuration())
            XCTFail("a public client must be refused")
        } catch AxiamError.auth(_) {
            // expected
        }
        XCTAssertEqual(transport.requests.count, 0, "nothing reaches the wire")

        let secret = SecretKit.random()
        let client = try await makeClient(transport, secret: secret)
        _ = try await client.cibaInitiate(Self.request(), configuration: Self.configuration())
        _ = try? await client.cibaPoll(
            authReqID: Sensitive(SecretKit.random()), configuration: Self.configuration())
        let initiate = try XCTUnwrap(transport.requests("/oauth2/bc-authorize").first)
        let poll = try XCTUnwrap(transport.requests("/oauth2/token").first)
        for request in [initiate, poll] {
            XCTAssertEqual(request.form["client_id"], Self.clientID)
            XCTAssertEqual(request.form["client_secret"], secret)
            XCTAssertNil(request.form["tenant_id"], "never a body field")
            XCTAssertEqual(request.queryValue("tenant_id"), Self.tenantID)
            XCTAssertTrue(request.headerValues("Cookie").isEmpty)
        }

        // A tls_client_auth client: the certificate is the credential, client_id alone goes.
        let mtls = try await makeClient(transport, secret: nil, certificate: true)
        _ = try await mtls.cibaInitiate(Self.request(), configuration: Self.configuration())
        let form = try XCTUnwrap(transport.requests("/oauth2/bc-authorize").last?.form)
        XCTAssertEqual(form["client_id"], Self.clientID)
        XCTAssertNil(form["client_secret"])
    }

    // MARK: - 3. The initiate request

    func testT03ExactlyTheMembersSetAreSent() async throws {
        let transport = RoutedTransport()
        transport.route("POST", "/oauth2/bc-authorize", [
            Self.initiated(["auth_req_id": SecretKit.random(), "expires_in": 120]),
        ])
        let client = try await makeClient(transport)

        _ = try await client.cibaInitiate(Self.request(), configuration: Self.configuration())
        let token = SecretKit.random()
        let full = CibaInitiateRequest(
            scope: "openid profile",
            hint: .idTokenHint("an.id.token"),
            bindingMessage: "W4SCT",
            requestedExpiry: 120,
            acrValues: "urn:axiam:acr:mfa",
            resource: "https://api.example.test",
            delivery: .ping(clientNotificationToken: Sensitive(token)))
        _ = try await client.cibaInitiate(full, configuration: Self.configuration())

        let sent = transport.requests("/oauth2/bc-authorize")
        XCTAssertEqual(sent.count, 2)
        XCTAssertEqual(
            Set(sent[0].form.keys), ["client_id", "client_secret", "login_hint", "scope"])
        XCTAssertEqual(
            Set(sent[1].form.keys),
            [
                "acr_values", "binding_message", "client_id", "client_notification_token",
                "client_secret", "id_token_hint", "requested_expiry", "resource", "scope",
            ])
        XCTAssertEqual(sent[1].form["requested_expiry"], "120")
        XCTAssertEqual(sent[1].form["client_notification_token"], token)
        XCTAssertEqual(sent[1].header("Content-Type"), "application/x-www-form-urlencoded")
        for forbidden in ["login_hint_token", "user_code", "request_uri", "request"] {
            XCTAssertNil(sent[1].form[forbidden], "\(forbidden) must never be sent")
        }

        // `login_hint_token`, `user_code` and `request_uri` have no parameter, and
        // `CibaUserHint` holds one hint: both at once cannot be written. A ping request with
        // an empty token is refused before any request.
        var ping = Self.request()
        ping.delivery = .ping(clientNotificationToken: Sensitive(""))
        do {
            _ = try await client.cibaInitiate(ping, configuration: Self.configuration())
            XCTFail("a ping request without a token must be refused")
        } catch {
            XCTAssertTrue(Self.isValidation(error), "expected the local ValidationError")
        }
        XCTAssertEqual(transport.requests("/oauth2/bc-authorize").count, 2)
    }

    func testADocumentWithoutTheEndpointMeansNoCibaAndNoSynthesisedURL() async throws {
        let transport = RoutedTransport()
        let client = try await makeClient(transport)
        do {
            _ = try await client.cibaInitiate(
                Self.request(), configuration: Self.configuration(backchannel: nil))
            XCTFail("a server that advertises no endpoint does not support CIBA")
        } catch AxiamError.auth(let error) {
            XCTAssertTrue(error.message.contains("does not support CIBA"))
        }
        XCTAssertEqual(transport.requests.count, 0)
    }

    // MARK: - 4. No retry on initiate

    func testT04InitiateIsSentOnceOn503And429AndADroppedConnection() async throws {
        let cases: [(RoutedTransport.Reply?, String)] = [
            (.empty(503), "503"),
            (Self.oauthError(429, "rate_limit_exceeded"), "429"),
            (nil, "dropped connection"),
        ]
        for (reply, label) in cases {
            let transport = RoutedTransport()
            transport.route("POST", "/oauth2/bc-authorize", [reply])
            let client = try await makeClient(transport)
            do {
                _ = try await client.cibaInitiate(Self.request(), configuration: Self.configuration())
                XCTFail("\(label): expected an error")
            } catch let error as AxiamError {
                switch label {
                case "429":
                    // §2's /oauth2 row: a body with an `error` member is an OAuthProtocolError.
                    XCTAssertEqual(error.oauthErrorCode, "rate_limit_exceeded")
                default:
                    guard case .network = error else { return XCTFail("\(label): a NetworkError") }
                }
            }
            XCTAssertEqual(
                transport.requests("/oauth2/bc-authorize").count, 1, "\(label): exactly one request")
        }
    }

    // MARK: - 5. Poll outcomes

    func testT05PendingLoopsSlowDownPersistsAndTheTerminalAnswersAreDistinct() async throws {
        let clock = TestCibaClock()
        let transport = RoutedTransport(stamp: { clock.elapsed })
        let client = try await makeClient(transport)
        let tokens = Self.tokens(transport)
        transport.route("POST", "/oauth2/token", [
            Self.oauthError(400, "slow_down"),
            Self.oauthError(400, "slow_down"),
            Self.oauthError(400, "authorization_pending"),
            tokens,
        ])
        let id = SecretKit.random()

        let set = try await client.cibaAwait(
            Self.response(id, expiresIn: 600, interval: 5, at: clock.start),
            configuration: Self.configuration(),
            clock: clock)
        XCTAssertNotNil(set.idClaims)
        XCTAssertEqual(clock.sleeps, [5, 10, 15, 15], "+5 s twice, and pending lowers nothing")
        for poll in transport.requests("/oauth2/token") {
            XCTAssertEqual(poll.form["grant_type"], "urn:openid:params:grant-type:ciba")
            XCTAssertEqual(poll.form["auth_req_id"], id)
        }

        for code in ["access_denied", "expired_token", "invalid_grant", "a_code_nobody_defined"] {
            let clock = TestCibaClock()
            let transport = RoutedTransport()
            transport.route("POST", "/oauth2/token", [Self.oauthError(400, code)])
            let client = try await makeClient(transport)
            do {
                _ = try await client.cibaAwait(
                    Self.response(expiresIn: 600, interval: 5, at: clock.start),
                    configuration: Self.configuration(),
                    clock: clock)
                XCTFail("\(code) is terminal")
            } catch let error as AxiamError {
                guard case .auth = error else { return XCTFail("\(code): an AuthError") }
                XCTAssertEqual(error.oauthErrorCode, code)
                XCTAssertEqual(error.isAccessDenied, code == "access_denied")
                XCTAssertEqual(error.isExpiredToken, code == "expired_token")
            }
            XCTAssertEqual(transport.requests("/oauth2/token").count, 1, "\(code) is terminal")
        }
    }

    // MARK: - 6. The first poll waits

    func testT06TheFirstPollWaitsTheIntervalOrFiveSeconds() async throws {
        for (given, expected) in [(7, 7), (nil, 5), (0, 5)] as [(Int?, Int)] {
            let clock = TestCibaClock()
            let transport = RoutedTransport(stamp: { clock.elapsed })
            var body: [String: Any] = ["auth_req_id": SecretKit.random(), "expires_in": 300]
            if let given { body["interval"] = given }
            transport.route("POST", "/oauth2/bc-authorize", [Self.initiated(body)])
            transport.route("POST", "/oauth2/token", [Self.oauthError(400, "access_denied")])
            let client = try await makeClient(transport)

            let initiated = try await client.cibaInitiate(
                Self.request(), configuration: Self.configuration())
            XCTAssertEqual(initiated.interval, expected)
            _ = try? await client.cibaAwait(
                Self.response(
                    initiated.authReqID.expose(), expiresIn: initiated.expiresIn,
                    interval: initiated.interval, at: clock.start),
                configuration: Self.configuration(),
                clock: clock)
            XCTAssertEqual(
                transport.requests("/oauth2/token").first?.stamp, expected,
                "the first poll is sent only after the interval")
        }
    }

    // MARK: - 7. Deadline

    func testT07NoRequestAfterExpiresInAndExpiredTokenIsRaisedLocally() async throws {
        let clock = TestCibaClock()
        let transport = RoutedTransport(stamp: { clock.elapsed })
        transport.route("POST", "/oauth2/token", [Self.oauthError(400, "authorization_pending")])
        let client = try await makeClient(transport)

        do {
            _ = try await client.cibaAwait(
                Self.response(expiresIn: 12, interval: 5, at: clock.start),
                configuration: Self.configuration(),
                clock: clock)
            XCTFail("the deadline must end the loop")
        } catch let error as AxiamError {
            XCTAssertTrue(error.isExpiredToken)
        }
        XCTAssertEqual(
            transport.requests("/oauth2/token").map(\.stamp), [5, 10],
            "nothing at 15 s, past the 12 s deadline")
    }

    // MARK: - 8. Transient failure is not terminal

    /// §33.8 test 8 as amended by contract 1.59 (§34.2 P8): the mid-loop `500` carries the
    /// server's own `{"error":"server_error"}` body, and is retried — a `5xx` on `ciba_poll` is
    /// never terminal, with or without an `error` member.
    func testT08A500AndA429MidLoopAreSurvived() async throws {
        let clock = TestCibaClock()
        let transport = RoutedTransport()
        let client = try await makeClient(transport)
        let tokens = Self.tokens(transport)
        transport.route("POST", "/oauth2/token", [
            Self.oauthError(400, "authorization_pending"),
            Self.oauthError(500, "server_error"),
            Self.oauthError(429, "rate_limit_exceeded"),
            tokens,
        ])

        let set = try await client.cibaAwait(
            Self.response(expiresIn: 600, interval: 5, at: clock.start),
            configuration: Self.configuration(),
            clock: clock)
        XCTAssertFalse(set.accessToken.expose().isEmpty)
        XCTAssertNotNil(set.idToken)
        XCTAssertNotNil(set.idClaims)
        XCTAssertEqual(transport.requests("/oauth2/token").count, 4)

        // The same 500 to one `cibaPoll` is retried within the call (§16), not surfaced.
        let single = RoutedTransport()
        let retrying = try await makeClient(single)
        let redeemed = Self.tokens(single)
        single.route("POST", "/oauth2/token", [Self.oauthError(500, "server_error"), redeemed])
        _ = try await retrying.cibaPoll(
            authReqID: Sensitive(SecretKit.random()), configuration: Self.configuration())
        XCTAssertEqual(single.requests("/oauth2/token").count, 2, "§16 retried the 500")
    }

    // MARK: - After the 200 (§33.7 rule 7, §34.2 P9; R-12, SW-3)

    /// A failure after a `2xx` is terminal: the redemption is spent, and polling again could
    /// only earn `invalid_grant`. A body that does not decode, and an ID token whose key fetch
    /// fails, each end the loop after ONE token request.
    func testAFailureAfterThe200EndsTheLoopWithoutAnotherPoll() async throws {
        let undecodable = RoutedTransport.Reply.json(200, #"{"access_token": 42}"#)
        let now = Date().timeIntervalSince1970
        let unverifiable = RoutedTransport.Reply.json(200, object: [
            "access_token": SecretKit.random(), "token_type": "Bearer", "expires_in": 900,
            "id_token": Self.signer.makeJWT(claims: [
                "iss": Self.issuer, "aud": Self.clientID, "sub": UUID().uuidString.lowercased(),
                "iat": Int(now), "exp": Int(now) + 600,
            ]),
        ])
        for (label, reply) in [("an undecodable body", undecodable), ("a JWKS outage", unverifiable)] {
            let clock = TestCibaClock()
            let transport = RoutedTransport()
            transport.route("GET", "/oauth2/jwks", [.empty(503)])
            transport.route("POST", "/oauth2/token", [
                reply, Self.oauthError(400, "invalid_grant"),
            ])
            let client = try await makeClient(transport)
            do {
                _ = try await client.cibaAwait(
                    Self.response(expiresIn: 600, interval: 5, at: clock.start),
                    configuration: Self.configuration(),
                    clock: clock)
                XCTFail("\(label): the failure after the 200 must surface")
            } catch let error as AxiamError {
                XCTAssertNotEqual(
                    error.oauthErrorCode, "invalid_grant",
                    "\(label): the real failure, not the re-poll's invalid_grant")
            }
            XCTAssertEqual(
                transport.requests("/oauth2/token").count, 1,
                "\(label): the redemption is spent — no second poll")
        }
    }

    func testABodiless429IsRetriedWithinOnePollAndANon408ClientErrorIsNot() async throws {
        let transport = RoutedTransport()
        let client = try await makeClient(transport)
        let tokens = Self.tokens(transport)
        transport.route("POST", "/oauth2/token", [.empty(429), tokens])
        _ = try await client.cibaPoll(
            authReqID: Sensitive(SecretKit.random()), configuration: Self.configuration())
        XCTAssertEqual(transport.requests("/oauth2/token").count, 2, "§16 retried the bodiless 429")

        let other = RoutedTransport()
        other.route("POST", "/oauth2/token", [.empty(400)])
        let second = try await makeClient(other)
        await XCTAssertThrowsErrorAsync(try await second.cibaPoll(
            authReqID: Sensitive(SecretKit.random()), configuration: Self.configuration()))
        XCTAssertEqual(other.requests("/oauth2/token").count, 1, "a 400 is decisive")
    }

    // MARK: - 9. Single use

    func testT09ASecondRedemptionIsInvalidGrantAndNotRetried() async throws {
        let transport = RoutedTransport()
        let client = try await makeClient(transport)
        let tokens = Self.tokens(transport)
        transport.route("POST", "/oauth2/token", [tokens, Self.oauthError(400, "invalid_grant")])
        let id = SecretKit.random()

        _ = try await client.cibaPoll(authReqID: Sensitive(id), configuration: Self.configuration())
        do {
            _ = try await client.cibaPoll(authReqID: Sensitive(id), configuration: Self.configuration())
            XCTFail("a request is redeemed once")
        } catch let error as AxiamError {
            XCTAssertEqual(error.oauthErrorCode, "invalid_grant")
        }
        XCTAssertEqual(transport.requests("/oauth2/token").count, 2, "no retry of the second")
    }

    // MARK: - 10–13. The ping

    private static func ping(_ authorization: [String]) -> [(String, String)] {
        [("content-type", "application/json")] + authorization.map { ("Authorization", $0) }
    }

    private static func pingBody(_ object: Any) -> Data {
        try! JSONSerialization.data(withJSONObject: object)
    }

    func testT10AValidPingReturnsItsAuthReqIDInAnySchemeCase() async throws {
        let client = try await makeClient(RoutedTransport())
        let token = SecretKit.random()
        let id = SecretKit.random()
        for scheme in ["Bearer", "bearer", "BEARER"] {
            let got = try client.cibaHandlePing(
                headers: Self.ping(["\(scheme) \(token)"]),
                body: Self.pingBody(["auth_req_id": id]),
                expectedToken: Sensitive(token))
            XCTAssertEqual(got.expose(), id)
            XCTAssertFalse(SecretKit.leaks(SecretKit.renderings(got).joined(separator: "\n"), id), "the id leaked")
        }
        // The header NAME is matched case-insensitively too.
        let lower = try client.cibaHandlePing(
            headers: [("authorization", "Bearer \(token)")],
            body: Self.pingBody(["auth_req_id": id]),
            expectedToken: Sensitive(token))
        XCTAssertEqual(lower.expose(), id)
    }

    func testT11AWrongAbsentEmptyDuplicateOrBasicAuthorizationIsRefused() async throws {
        let client = try await makeClient(RoutedTransport())
        let token = SecretKit.random()
        var lastDiffers = token
        let last = lastDiffers.removeLast()
        let replacement: Character = last == "a" ? "b" : "a"
        lastDiffers.append(replacement)
        let body = Self.pingBody(["auth_req_id": SecretKit.random()])

        let cases: [[String]] = [
            ["Bearer \(SecretKit.random())"],
            [],
            [""],
            ["Bearer "],
            ["Bearer \(token)", "Bearer \(token)"],
            ["Basic \(token)"],
            ["Bearer \(lastDiffers)"],
            ["Bearer  \(token)"],
        ]
        for (index, authorization) in cases.enumerated() {
            do {
                _ = try client.cibaHandlePing(
                    headers: Self.ping(authorization), body: body, expectedToken: Sensitive(token))
                XCTFail("case \(index) must be refused")
            } catch let error as AxiamError {
                guard case .auth = error else { return XCTFail("case \(index): an AuthError") }
                let rendering = SecretKit.renderings(error).joined(separator: "\n")
                XCTAssertFalse(SecretKit.leaks(rendering, token), "case \(index): the token leaked")
            }
        }

        // The comparison is ConstantTime.equals (Sources/AxiamSDK/ConstantTime.swift): XCTest has
        // no timing harness, so §33.8 test 11 is asserted structurally, on the source.
        let source = try String(contentsOf: URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()  // AxiamSDKTests
            .deletingLastPathComponent()  // Tests
            .deletingLastPathComponent()  // repository root
            .appendingPathComponent("Sources/AxiamSDK/Oidc/Ciba.swift"), encoding: .utf8)
        XCTAssertTrue(source.contains("ConstantTime.equals(Array(token.utf8), Array(expected.utf8))"))
    }

    func testT12AMalformedBodyIsAValidationErrorAndExtrasAreIgnored() async throws {
        let client = try await makeClient(RoutedTransport())
        let token = SecretKit.random()
        let headers = Self.ping(["Bearer \(token)"])
        for body in [
            Data("not json".utf8),
            Self.pingBody([String: Any]()),
            Self.pingBody(["auth_req_id": ""]),
            Self.pingBody(["auth_req_id": 42]),
            Self.pingBody(["auth_req_id"]),
        ] {
            do {
                _ = try client.cibaHandlePing(headers: headers, body: body, expectedToken: Sensitive(token))
                XCTFail("a malformed body must be refused")
            } catch {
                XCTAssertTrue(Self.isValidation(error), "expected the local ValidationError")
            }
        }
        let id = SecretKit.random()
        let got = try client.cibaHandlePing(
            headers: headers,
            body: Self.pingBody(["auth_req_id": id, "status": "approved", "access_token": "x"]),
            expectedToken: Sensitive(token))
        XCTAssertEqual(got.expose(), id, "extras ignored")
    }

    func testT13ThePingHelperMakesNoNetworkCall() async throws {
        let transport = RoutedTransport()
        let client = try await makeClient(transport)
        let token = SecretKit.random()
        _ = try client.cibaHandlePing(
            headers: Self.ping(["Bearer \(token)"]),
            body: Self.pingBody(["auth_req_id": SecretKit.random()]),
            expectedToken: Sensitive(token))
        XCTAssertEqual(transport.requests.count, 0, "the transport was never touched")
    }

    // MARK: - 14–16. The signed form

    /// A fresh Ed25519 key: the PKCS#8 PEM (assembled at run time — no key literal) and the
    /// public key.
    private static func ed25519Key() -> (pem: String, publicKey: Curve25519.Signing.PublicKey) {
        let key = Curve25519.Signing.PrivateKey()
        let prefix: [UInt8] = [
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
            0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
        ]
        let der = Data(prefix) + key.rawRepresentation
        let label = "PRIVATE " + "KEY"
        let pem = "-----BEGIN \(label)-----\n\(der.base64EncodedString())\n-----END \(label)-----\n"
        return (pem, key.publicKey)
    }

    private static func decodePart(_ part: Substring) throws -> [String: Any] {
        let data = try XCTUnwrap(Base64URL.decode(String(part)))
        return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    func testT14TheSignedRequestIsOneMemberWithTheRegisteredAlgAndAFreshJti() async throws {
        let transport = RoutedTransport()
        transport.route("POST", "/oauth2/bc-authorize", [
            Self.initiated(["auth_req_id": SecretKit.random(), "expires_in": 120]),
        ])
        let secret = SecretKit.random()
        let client = try await makeClient(transport, secret: secret)
        let (pem, publicKey) = Self.ed25519Key()
        let signer = try CibaRequestSigner(
            algorithm: .edDSA, privateKeyPEM: Sensitive(pem), keyID: "client-key-1")
        let notification = SecretKit.random()

        var request = Self.request()
        request.bindingMessage = "W4SCT"
        request.requestedExpiry = 90
        request.delivery = .ping(clientNotificationToken: Sensitive(notification))
        request.signer = signer
        _ = try await client.cibaInitiate(request, configuration: Self.configuration())
        _ = try await client.cibaInitiate(request, configuration: Self.configuration())

        var jtis: [String] = []
        for sent in transport.requests("/oauth2/bc-authorize") {
            XCTAssertEqual(
                Set(sent.form.keys), ["client_id", "client_secret", "request"],
                "nothing beside request")
            XCTAssertEqual(sent.form["client_secret"], secret)
            let jws = try XCTUnwrap(sent.form["request"])
            let parts = jws.split(separator: ".", omittingEmptySubsequences: false)
            XCTAssertEqual(parts.count, 3)
            let header = try Self.decodePart(parts[0])
            XCTAssertEqual(header["alg"] as? String, "EdDSA")
            XCTAssertEqual(header["kid"] as? String, "client-key-1")

            // The caller's key signed it.
            let signature = try XCTUnwrap(Base64URL.decode(String(parts[2])))
            XCTAssertTrue(publicKey.isValidSignature(
                signature, for: Data("\(parts[0]).\(parts[1])".utf8)))

            let claims = try Self.decodePart(parts[1])
            XCTAssertEqual(claims["iss"] as? String, Self.clientID)
            XCTAssertEqual(claims["aud"] as? String, Self.issuer)
            let exp = try XCTUnwrap(claims["exp"] as? Int)
            let nbf = try XCTUnwrap(claims["nbf"] as? Int)
            XCTAssertNotNil(claims["iat"] as? Int)
            XCTAssertTrue(exp > nbf && exp - nbf <= 3600)
            XCTAssertEqual(claims["login_hint"] as? String, "ada")
            XCTAssertEqual(claims["binding_message"] as? String, "W4SCT")
            XCTAssertEqual(claims["requested_expiry"] as? Int, 90, "a number inside the JWT")
            XCTAssertEqual(claims["client_notification_token"] as? String, notification)
            jtis.append(try XCTUnwrap(claims["jti"] as? String))
        }
        XCTAssertEqual(jtis.count, 2)
        XCTAssertNotEqual(jtis.first, jtis.last, "a fresh jti per request")
        XCTAssertGreaterThanOrEqual(jtis.first?.count ?? 0, 32, "at least 128 bits")

        // ES256 signs under ES256 only, and verifies with the caller's public key.
        let ec = P256.Signing.PrivateKey()
        let es256 = try CibaRequestSigner(
            algorithm: .es256, privateKeyPEM: Sensitive(ec.pemRepresentation))
        XCTAssertEqual(es256.algorithm, .es256)
        var ecRequest = Self.request()
        ecRequest.signer = es256
        _ = try await client.cibaInitiate(ecRequest, configuration: Self.configuration())
        let last = try XCTUnwrap(transport.requests("/oauth2/bc-authorize").last?.form["request"])
        let parts = last.split(separator: ".", omittingEmptySubsequences: false)
        XCTAssertEqual(try Self.decodePart(parts[0])["alg"] as? String, "ES256")
        let ecSignature = try P256.Signing.ECDSASignature(
            rawRepresentation: try XCTUnwrap(Base64URL.decode(String(parts[2]))))
        XCTAssertTrue(ec.publicKey.isValidSignature(
            ecSignature, for: Data("\(parts[0]).\(parts[1])".utf8)))
    }

    func testT15NoKeyOrAKeyForAnotherAlgorithmIsRefusedBeforeAnyRequest() async throws {
        let transport = RoutedTransport()
        let (edPEM, _) = Self.ed25519Key()
        let ecPEM = P256.Signing.PrivateKey().pemRepresentation
        let cases: [(CibaSigningAlgorithm, String)] = [
            (.edDSA, ""),
            (.es256, ""),
            (.ps256, ""),
            (.es256, edPEM),
            (.ps256, ecPEM),
            (.edDSA, ecPEM),
        ]
        for (index, (algorithm, pem)) in cases.enumerated() {
            XCTAssertThrowsError(
                try CibaRequestSigner(algorithm: algorithm, privateKeyPEM: Sensitive(pem)),
                "case \(index)"
            ) { error in
                XCTAssertTrue(Self.isValidation(error), "case \(index): the local ValidationError")
            }
        }
        // The algorithm and the key are the constructor's two required arguments, so "no
        // algorithm" cannot be written; and with a signer set, every member travels inside
        // `request` — there is no channel for a form parameter beside it (t14 asserts the
        // form).
        XCTAssertEqual(transport.requests.count, 0)
    }

    func testT16TheKeyAndTheRequestAppearInNoRendering() async throws {
        let transport = RoutedTransport()
        transport.route("POST", "/oauth2/bc-authorize", [Self.oauthError(400, "invalid_request")])
        let client = try await makeClient(transport)
        let (pem, _) = Self.ed25519Key()
        let keyLine = pem.components(separatedBy: "\n")[1]
        let signer = try CibaRequestSigner(algorithm: .edDSA, privateKeyPEM: Sensitive(pem))
        var request = Self.request()
        request.signer = signer

        var rendered: [String] = SecretKit.renderings(signer) + SecretKit.renderings(request)
        do {
            _ = try await client.cibaInitiate(request, configuration: Self.configuration())
            XCTFail("expected the scripted 400")
        } catch {
            rendered.append(SecretKit.renderings(error).joined(separator: "\n"))
        }
        let jws = try XCTUnwrap(transport.requests("/oauth2/bc-authorize").first?.form["request"])
        // The signer holds the 32-byte seed, not the PEM: `dump` and `Mirror` would print the
        // seed's bytes, which the walk renders as hex.
        let seed = try XCTUnwrap(CibaRequestSigner.ed25519Seed(fromPKCS8PEM: pem))
        let seedHex = seed.map { String(format: "%02x", $0) }.joined()
        for rendering in rendered {
            XCTAssertFalse(SecretKit.leaks(rendering, keyLine), "the key material leaked")
            XCTAssertFalse(SecretKit.leaks(rendering, seedHex), "the key seed leaked")
            XCTAssertFalse(SecretKit.leaks(rendering, jws), "the signed request leaked")
        }
    }

    // MARK: - The loop's classification

    func testTheClassificationFollowsSection33Rule6() {
        let cases: [(String, AxiamClient.CibaStep)] = [
            ("authorization_pending", .pending),
            ("slow_down", .slowDown),
            ("rate_limit_exceeded", .transient),
            ("access_denied", .terminal),
            ("expired_token", .terminal),
            ("invalid_grant", .terminal),
            ("something_new", .terminal),
        ]
        for (code, step) in cases {
            XCTAssertEqual(
                AxiamClient.cibaStep(.auth(AuthError(code, oauthError: code))), step, code)
        }
        XCTAssertEqual(AxiamClient.cibaStep(.network(NetworkError("reset"))), .transient)
        XCTAssertEqual(
            AxiamClient.cibaStep(.network(NetworkError("down", statusCode: 503))), .transient)
        XCTAssertEqual(
            AxiamClient.cibaStep(.network(NetworkError("bad", statusCode: 400))), .terminal)
        XCTAssertEqual(AxiamClient.cibaStep(.auth(AuthError("no"))), .terminal)
        XCTAssertEqual(AxiamClient.cibaStep(.authz(AuthzError("no"))), .terminal)
    }
}

/// A clock that never sleeps: `sleep` advances it and records the wait.
final class TestCibaClock: CibaClock, @unchecked Sendable {
    let start = Date(timeIntervalSince1970: 1_800_000_000)
    private let lock = NSLock()
    private var offset = 0
    private var waits: [Int] = []

    /// Seconds slept so far.
    var elapsed: Int { lock.locked { offset } }

    /// Every wait, in order.
    var sleeps: [Int] { lock.locked { waits } }

    func now() -> Date {
        start.addingTimeInterval(TimeInterval(elapsed))
    }

    func sleep(seconds: Int) async throws {
        lock.locked {
            offset += seconds
            waits.append(seconds)
        }
    }
}
