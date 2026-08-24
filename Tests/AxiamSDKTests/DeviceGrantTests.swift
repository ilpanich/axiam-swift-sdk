import XCTest
import Foundation
@testable import AxiamSDK

/// CONTRACT.md §14 — the RFC 8628 device grant, and §14.2's four polling rules, which the
/// contract itself calls "the part implementations get wrong".
final class DeviceGrantTests: XCTestCase {
    let signer = TestSigner()

    private static let tenantUUID = "22222222-2222-2222-2222-222222222222"
    private static let clientID = "tv-app"

    /// One scripted answer per poll, consumed in order; the last one repeats.
    private func makeRouter(
        interval: Int?,
        expiresIn: Int,
        pollAnswers: [(Int, [String: Any])]
    ) -> TestRouter {
        let signer = self.signer
        // Serialized up front: the router closure is `@Sendable` and cannot capture the
        // `[String: Any]` payloads, only the bytes they encode to.
        let answers: [(Int, Data)] = pollAnswers.map { ($0.0, TestResponse.jsonBody($0.1)) }
        return { request, state in
            if request.uri.hasSuffix("/oauth2/jwks") { return .json(200, signer.jwksJSON()) }
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
                var body: [String: Any] = [
                    "device_code": "the-device-code",
                    "user_code": "WDJB-MJHT",
                    "verification_uri": "https://id.example/device",
                    "expires_in": expiresIn,
                ]
                if let interval { body["interval"] = interval }
                return .json(200, body)
            }
            if request.uri.contains("/oauth2/token") {
                let index = state.increment("poll") - 1
                let answer = answers[min(index, answers.count - 1)]
                return TestResponse(status: answer.0, body: answer.1)
            }
            return .json(404, [:])
        }
    }

    private func withDeviceClient(
        router: @escaping TestRouter,
        body: (AxiamClient, TestHTTPServer) async throws -> Void
    ) async throws {
        try await withClient(
            makeConfig: { port in
                try AxiamConfig(
                    baseURL: URL(string: "http://127.0.0.1:\(port)")!,
                    tenantID: DeviceGrantTests.tenantUUID,
                    requestTimeout: 10,
                    oidcClientID: DeviceGrantTests.clientID)
            },
            router: router,
            body: body)
    }

    private var successBody: [String: Any] {
        ["access_token": "the-access-token", "token_type": "Bearer", "expires_in": 900]
    }

    // MARK: - §14.1 device_authorize

    func testAuthorizeSendsNoClientSecretAndWorksWithoutOne() async throws {
        let router = makeRouter(interval: 3, expiresIn: 600, pollAnswers: [(200, successBody)])
        try await withDeviceClient(router: router) { client, server in
            let authorization = try await client.deviceAuthorize()

            XCTAssertEqual(authorization.userCode, "WDJB-MJHT")
            XCTAssertEqual(authorization.interval, 3)
            // §14.1: a device that cannot show a browser cannot hold a secret. The SDK must not
            // send one, and must not refuse to call this from a client built without one.
            let request = try XCTUnwrap(
                server.state.requests(pathContaining: "/oauth2/device_authorization").last)
            let body = String(decoding: request.body, as: UTF8.self)
            XCTAssertFalse(body.contains("client_secret"))
            XCTAssertTrue(body.contains("client_id=tv-app"))
        }
    }

    func testAnOmittedIntervalDefaultsToFiveSeconds() async throws {
        // §14.2 rule 2: the initial interval comes from the response, and RFC 8628 §3.2's
        // default is 5 s. No SDK may hard-code a faster floor.
        let router = makeRouter(interval: nil, expiresIn: 600, pollAnswers: [(200, successBody)])
        try await withDeviceClient(router: router) { client, _ in
            let authorization = try await client.deviceAuthorize()
            XCTAssertEqual(authorization.interval, 5)
        }
    }

    func testVerificationUriCompleteIsNeverSynthesised() async throws {
        // §14.3: surfaced when present, and NOT concatenated when absent — its format is the
        // server's to choose.
        let router = makeRouter(interval: 3, expiresIn: 600, pollAnswers: [(200, successBody)])
        try await withDeviceClient(router: router) { client, _ in
            let authorization = try await client.deviceAuthorize()
            XCTAssertNil(authorization.verificationURIComplete)
        }
    }

    // MARK: - §14.2 the five poll answers

    func testAccessDeniedAndExpiredTokenAreDistinct() async throws {
        // §14.2 rule 3: one means a human said no, the other that nobody answered. Collapsing
        // them loses the only information the device can act on — retry versus stop asking.
        for code in ["access_denied", "expired_token", "invalid_grant"] {
            let router = makeRouter(
                interval: 1, expiresIn: 600,
                pollAnswers: [(400, ["error": code, "error_description": "no"])])
            try await withDeviceClient(router: router) { client, _ in
                do {
                    _ = try await client.devicePoll(deviceCode: Sensitive("the-device-code"))
                    XCTFail("expected \(code) to surface")
                } catch let error as AxiamError {
                    guard case let .auth(authError) = error else {
                        return XCTFail("\(code) must not surface as the generic §2 400 row")
                    }
                    XCTAssertEqual(authError.oauthError, code)
                }
            }
        }
    }

    func testDeviceLoginSurfacesTheCodesBeforePollingAndReturnsTheTokens() async throws {
        let router = makeRouter(
            interval: 1, expiresIn: 600,
            pollAnswers: [
                (400, ["error": "authorization_pending"]),
                (200, successBody),
            ])
        try await withDeviceClient(router: router) { client, server in
            let box = CodeBox()
            let tokens = try await client.deviceLogin { authorization in
                box.record(authorization.userCode, pollsSoFar: server.state.count("poll"))
            }

            XCTAssertEqual(tokens.accessToken.expose(), "the-access-token")
            // §14.3 rule 2: the caller had the codes BEFORE the first poll — a device must be
            // able to display them, and the SDK must not print them on the caller's behalf.
            XCTAssertEqual(box.userCode, "WDJB-MJHT")
            XCTAssertEqual(box.pollsWhenSurfaced, 0)
            XCTAssertEqual(server.state.count("poll"), 2, "one pending answer, then success")
        }
    }

    func testSlowDownRaisesTheIntervalPermanently() async throws {
        // §14.2 rule 1, asserted through the deadline rather than a stopwatch: interval 1 s and
        // a 3 s grant. The first poll lands at t≈1 and is told to slow down, which takes the
        // interval to 6 s — past the deadline, so the loop stops after exactly ONE poll.
        //
        // An SDK that reset the interval to 1 s after backing off would poll again at t≈2 and
        // t≈3, and this assertion is what catches it.
        let router = makeRouter(
            interval: 1, expiresIn: 3,
            pollAnswers: [(400, ["error": "slow_down"])])
        try await withDeviceClient(router: router) { client, server in
            do {
                _ = try await client.deviceLogin { _ in }
                XCTFail("expected the grant to expire")
            } catch let error as AxiamError {
                guard case let .auth(authError) = error else { return XCTFail("expected an AuthError") }
                XCTAssertEqual(authError.oauthError, "expired_token")
            }
            XCTAssertEqual(server.state.count("poll"), 1, "slow_down must not reset the interval")
        }
    }

    func testPollingStopsAtTheDeadlineEvenWithoutAnExpiredTokenAnswer() async throws {
        // §14.2 rule 4: the deadline is authoritative. The server here never says expired_token
        // — it answers authorization_pending forever — and the loop must stop anyway.
        let router = makeRouter(
            interval: 1, expiresIn: 2,
            pollAnswers: [(400, ["error": "authorization_pending"])])
        try await withDeviceClient(router: router) { client, server in
            do {
                _ = try await client.deviceLogin { _ in }
                XCTFail("expected the grant to expire")
            } catch let error as AxiamError {
                guard case let .auth(authError) = error else { return XCTFail("expected an AuthError") }
                XCTAssertEqual(authError.oauthError, "expired_token")
            }
            XCTAssertLessThanOrEqual(server.state.count("poll"), 2)
        }
    }
}

/// Records what the `onAuthorization` callback saw, and when.
private final class CodeBox: @unchecked Sendable {
    private let lock = NSLock()
    private var _userCode: String?
    private var _polls = -1

    func record(_ code: String, pollsSoFar: Int) {
        lock.lock(); defer { lock.unlock() }
        _userCode = code
        _polls = pollsSoFar
    }

    var userCode: String? { lock.lock(); defer { lock.unlock() }; return _userCode }
    var pollsWhenSurfaced: Int { lock.lock(); defer { lock.unlock() }; return _polls }
}
