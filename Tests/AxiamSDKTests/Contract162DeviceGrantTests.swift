import XCTest
import Foundation
@testable import AxiamSDK

/// CONTRACT.md §14.1 rules 1–4 and §14.6 (contract 1.62, §34.6 items (m) and (t)): the device
/// grant authenticates its client.
///
/// A client configured with a credential sends it at **both** `device_authorize` and the poll,
/// by the rules of its other token requests — a client secret in the form body, never as
/// `Authorization: Basic`, whichever of `client_secret_post` and `client_secret_basic` the client
/// is registered for (the SDK cannot tell, and does not need to: both are the form body). A
/// public client sends none and is not refused client-side. The poll names its client on every
/// poll. A `401` `invalid_client` is one request, terminal, and never reaches the §9 refresh
/// guard.
///
/// This SDK does not generate `private_key_jwt` assertions (§21.8) or DPoP proofs (§21.9), so
/// the two forms that need them have no test here; the document says so beside each operation.
final class Contract162DeviceGrantTests: XCTestCase {

    private static let tenantUUID = "22222222-2222-2222-2222-222222222222"
    private static let clientID = "tv-app"
    private static let secret = "device-client-secret"

    // MARK: - Harness

    /// One discovery document, one authorize answer, and a scripted poll. `pollAnswers` are
    /// served in order and the last one repeats; the authorize answer is `authorizeStatus`.
    private static func makeRouter(
        authorizeStatus: Int = 200,
        authorizeBody: [String: Any] = [:],
        pollAnswers: [(Int, [String: Any])]
    ) -> TestRouter {
        let authorizeData = TestResponse.jsonBody(
            authorizeBody.isEmpty
                ? [
                    "device_code": "the-device-code",
                    "user_code": "WDJB-MJHT",
                    "verification_uri": "https://id.example/device",
                    "expires_in": 600,
                    "interval": 1,
                ]
                : authorizeBody)
        let answers: [(Int, Data)] = pollAnswers.map { ($0.0, TestResponse.jsonBody($0.1)) }
        return { request, state in
            if request.uri.contains("/.well-known/openid-configuration") {
                let base = "http://\(request.header("Host") ?? "127.0.0.1")"
                return .json(200, [
                    "issuer": base,
                    "authorization_endpoint": "\(base)/oauth2/authorize",
                    "token_endpoint": "\(base)/oauth2/token",
                    "jwks_uri": "\(base)/oauth2/jwks",
                    "device_authorization_endpoint": "\(base)/oauth2/device_authorization",
                ])
            }
            if request.uri.contains("/oauth2/device_authorization") {
                state.increment("authorize")
                return TestResponse(status: authorizeStatus, body: authorizeData)
            }
            if request.uri.contains("/oauth2/token") {
                let index = state.increment("poll") - 1
                let answer = answers[min(index, answers.count - 1)]
                return TestResponse(status: answer.0, body: answer.1)
            }
            return .json(404, [:])
        }
    }

    /// A computed property, not a stored one: the test target builds in Swift 6 language mode,
    /// where a `static let` holding `[String: Any]` is a concurrency error.
    private static var successAnswer: (Int, [String: Any]) {
        (200, ["access_token": "the-access-token", "token_type": "Bearer", "expires_in": 900])
    }

    /// A client for the grant: public when `secret` is nil, otherwise confidential by secret;
    /// `certificate` adds a §6.1 identity (the mTLS form).
    private func withDeviceClient(
        secret: String?,
        certificate: ClientCertificate? = nil,
        router: @escaping TestRouter,
        body: (AxiamClient, TestHTTPServer) async throws -> Void
    ) async throws {
        try await withClient(
            makeConfig: { port in
                try AxiamConfig(
                    baseURL: URL(string: "http://127.0.0.1:\(port)")!,
                    tenantID: Contract162DeviceGrantTests.tenantUUID,
                    clientCertificate: certificate,
                    requestTimeout: 10,
                    oidcClientID: Contract162DeviceGrantTests.clientID,
                    oidcClientSecret: secret.map { Sensitive($0) })
            },
            router: router,
            body: body)
    }

    /// The decoded `application/x-www-form-urlencoded` body of one request.
    private static func form(_ request: TestRequest) -> [String: String] {
        var out: [String: String] = [:]
        for pair in String(decoding: request.body, as: UTF8.self).split(separator: "&") {
            let parts = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard parts.count == 2 else { continue }
            let rawKey = String(parts[0])
            let rawValue = String(parts[1])
            out[rawKey.removingPercentEncoding ?? rawKey] = rawValue.removingPercentEncoding ?? rawValue
        }
        return out
    }

    private static func authorizeRequests(_ server: TestHTTPServer) -> [TestRequest] {
        server.state.requests(pathContaining: "/oauth2/device_authorization")
    }

    private static func pollRequests(_ server: TestHTTPServer) -> [TestRequest] {
        server.state.requests(pathContaining: "/oauth2/token")
    }

    // MARK: - A confidential client sends its secret at both endpoints

    func testASecretIsSentInTheFormBodyAtDeviceAuthorizeAndAtEveryPollAndNeverAsBasicAuth() async throws {
        let router = Self.makeRouter(pollAnswers: [
            (400, ["error": "authorization_pending"]),
            Self.successAnswer,
        ])
        try await withDeviceClient(secret: Self.secret, router: router) { client, server in
            let authorization = try await client.deviceAuthorize(scope: "openid")
            // Two polls: the first is told to keep waiting, the second succeeds.
            do {
                _ = try await client.devicePoll(deviceCode: authorization.deviceCode)
                XCTFail("the first poll was answered authorization_pending")
            } catch let error as AxiamError {
                guard case let .auth(authError) = error else { return XCTFail("expected an AuthError") }
                XCTAssertEqual(authError.oauthError, "authorization_pending")
            }
            let tokens = try await client.devicePoll(deviceCode: authorization.deviceCode)
            XCTAssertEqual(tokens.accessToken.expose(), "the-access-token")

            let authorizes = Self.authorizeRequests(server)
            XCTAssertEqual(authorizes.count, 1)
            let authorizeForm = Self.form(authorizes[0])
            XCTAssertEqual(authorizeForm["client_id"], Self.clientID)
            XCTAssertEqual(authorizeForm["client_secret"], Self.secret)
            XCTAssertEqual(authorizeForm["scope"], "openid")

            let polls = Self.pollRequests(server)
            XCTAssertEqual(polls.count, 2)
            for poll in polls {
                let pollForm = Self.form(poll)
                XCTAssertEqual(pollForm["grant_type"], AxiamClient.deviceCodeGrantType)
                XCTAssertEqual(pollForm["client_id"], Self.clientID, "§14.1 rule 3: every poll names its client")
                XCTAssertEqual(pollForm["client_secret"], Self.secret)
            }

            // §14.1 rule 2 / §14.6 (maintainer, 2026-10-16): no Authorization header at either
            // endpoint, whichever of client_secret_post and client_secret_basic the client is
            // registered for. §12.1 rule 3 stands for these two routes.
            for request in authorizes + polls {
                XCTAssertNil(request.header("Authorization"), "no Authorization: Basic at \(request.uri)")
            }
        }
    }

    // MARK: - A public client sends none, and is not refused

    func testAPublicClientSendsNoCredentialAtEitherEndpointAndIsNotRefusedClientSide() async throws {
        let router = Self.makeRouter(pollAnswers: [Self.successAnswer])
        try await withDeviceClient(secret: nil, router: router) { client, server in
            let authorization = try await client.deviceAuthorize()
            let tokens = try await client.devicePoll(deviceCode: authorization.deviceCode)
            XCTAssertEqual(tokens.accessToken.expose(), "the-access-token")

            let authorizes = Self.authorizeRequests(server)
            let polls = Self.pollRequests(server)
            XCTAssertEqual(authorizes.count, 1)
            XCTAssertEqual(polls.count, 1)
            for request in authorizes + polls {
                let sent = Self.form(request)
                XCTAssertEqual(sent["client_id"], Self.clientID)
                XCTAssertNil(sent["client_secret"], "a public client sends no secret")
                XCTAssertNil(sent["client_assertion"])
                XCTAssertNil(sent["client_assertion_type"])
                XCTAssertNil(request.header("Authorization"))
            }
        }
    }

    // MARK: - An mTLS client presents its certificate and sends no secret

    func testAnMtlsClientPresentsItsCertificateAndSendsNoSecretOrAuthorizationHeader() async throws {
        guard let identity = OpenSSLPKI.generateSelfSigned() else {
            throw XCTSkip("openssl is required to generate the §6.1 test client identity")
        }
        let certificate = ClientCertificate.pem(
            certificate: identity.certificatePEM, privateKey: identity.keyPEM)
        let router = Self.makeRouter(pollAnswers: [Self.successAnswer])
        try await withDeviceClient(secret: nil, certificate: certificate, router: router) { client, server in
            let authorization = try await client.deviceAuthorize()
            _ = try await client.devicePoll(deviceCode: authorization.deviceCode)

            // The certificate is the credential (§21.3), presented on the connection; the form
            // carries `client_id` alone. The test server speaks plain HTTP, so what is asserted
            // is what this SDK chooses to put on the wire, which is the whole of its part.
            for request in Self.authorizeRequests(server) + Self.pollRequests(server) {
                let sent = Self.form(request)
                XCTAssertEqual(sent["client_id"], Self.clientID)
                XCTAssertNil(sent["client_secret"])
                XCTAssertNil(sent["client_assertion"])
                XCTAssertNil(request.header("Authorization"))
            }
        }
    }

    // MARK: - 401 invalid_client is terminal, one request, no refresh

    func testInvalidClientAtDeviceAuthorizeIsOneRequestAndNotARefresh() async throws {
        let router = Self.makeRouter(
            authorizeStatus: 401,
            authorizeBody: ["error": "invalid_client", "error_description": "client authentication failed"],
            pollAnswers: [Self.successAnswer])
        try await withDeviceClient(secret: Self.secret, router: router) { client, server in
            do {
                _ = try await client.deviceAuthorize()
                XCTFail("expected invalid_client")
            } catch let error as AxiamError {
                guard case let .auth(authError) = error else { return XCTFail("expected an AuthError") }
                XCTAssertEqual(authError.oauthError, "invalid_client")
                XCTAssertEqual(error.oauthErrorCode, "invalid_client")
            }
            XCTAssertEqual(server.state.count("authorize"), 1, "never retried")
            XCTAssertTrue(
                server.state.requests(pathContaining: "/auth/refresh").isEmpty,
                "a failed client authentication is not an expired session: no §9 refresh")
        }
    }

    func testInvalidClientAtTheDevicePollIsOneRequestAndTerminalInDeviceLogin() async throws {
        let router = Self.makeRouter(pollAnswers: [
            (401, ["error": "invalid_client", "error_description": "client authentication failed"]),
        ])
        try await withDeviceClient(secret: Self.secret, router: router) { client, server in
            do {
                _ = try await client.deviceLogin { _ in }
                XCTFail("expected invalid_client")
            } catch let error as AxiamError {
                guard case let .auth(authError) = error else { return XCTFail("expected an AuthError") }
                XCTAssertEqual(authError.oauthError, "invalid_client")
            }
            XCTAssertEqual(server.state.count("poll"), 1, "invalid_client is terminal: polling stops")
            XCTAssertTrue(server.state.requests(pathContaining: "/auth/refresh").isEmpty)
        }
    }

    // MARK: - A token_type the server names is surfaced as it said it

    func testATokenTypeOfDPoPIsSurfacedAsTheServerSaidIt() async throws {
        let router = Self.makeRouter(pollAnswers: [
            (200, ["access_token": "bound-access-token", "token_type": "DPoP", "expires_in": 900]),
        ])
        try await withDeviceClient(secret: Self.secret, router: router) { client, _ in
            let authorization = try await client.deviceAuthorize()
            let tokens = try await client.devicePoll(deviceCode: authorization.deviceCode)
            // §14.2 rule 8 / §21.7.1: never assumed to be Bearer. This SDK does not generate the
            // proof (§21.9), so it surfaces a bound token's type and leaves the proofs to the caller.
            XCTAssertEqual(tokens.tokenType, "DPoP")
        }
    }
}
