import XCTest
import Foundation
@testable import AxiamSDK

/// CONTRACT.md §14.6 and §14.2 rule 9, last paragraph (contract 1.64; §34.8 (b)): a
/// `429 rate_limit_exceeded` on a device-code poll is waited out.
///
/// The loop waits `Retry-After` (a minimum, capped at the `expires_in` deadline), counts the wait
/// as one interval, does not raise the interval for it, and polls again. The waits are recorded
/// through the client's sleep seam rather than taken, so the schedule is asserted exactly and the
/// suite does not sleep.
final class Contract164DeviceGrantRateLimitTests: XCTestCase {

    private static let tenantUUID = "22222222-2222-2222-2222-222222222222"

    /// Every wait the loop asked for, in order.
    private final class Sleeps: @unchecked Sendable {
        private let lock = NSLock()
        private var seen: [TimeInterval] = []
        func record(_ seconds: TimeInterval) { lock.locked { seen.append(seconds) } }
        var values: [TimeInterval] { lock.locked { seen } }
    }

    /// Computed properties: the test target builds in Swift 6 language mode, where a `static
    /// let` holding `[String: Any]` is a concurrency error.
    private typealias Answer = (Int, [(String, String)], Data)

    private static func answer(_ status: Int, _ headers: [(String, String)] = [], _ body: [String: Any]) -> Answer {
        (status, headers, TestResponse.jsonBody(body))
    }

    /// The server's own `429` body: no `error_description` (§14.6, contract 1.64 amended).
    private static var rateLimited: Answer {
        answer(429, [("Retry-After", "7")], ["error": "rate_limit_exceeded"])
    }

    private static var pending: Answer { answer(400, [], ["error": "authorization_pending"]) }

    private static var success: Answer {
        answer(200, [], ["access_token": "the-access-token", "token_type": "Bearer", "expires_in": 900])
    }

    /// Discovery, an authorize answer (`interval` and `expires_in` as given) and a scripted poll;
    /// the last answer repeats.
    private static func makeRouter(
        interval: Int,
        expiresIn: Int,
        pollAnswers: [Answer]
    ) -> TestRouter {
        let authorize = TestResponse.jsonBody([
            "device_code": "the-device-code",
            "user_code": "WDJB-MJHT",
            "verification_uri": "https://id.example/device",
            "expires_in": expiresIn,
            "interval": interval,
        ])
        let answers = pollAnswers
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
                return TestResponse(status: 200, body: authorize)
            }
            if request.uri.contains("/oauth2/token") {
                let index = state.increment("poll") - 1
                let answer = answers[min(index, answers.count - 1)]
                return TestResponse(status: answer.0, headers: answer.1, body: answer.2)
            }
            return .json(404, [:])
        }
    }

    private func withDeviceClient(
        router: @escaping TestRouter,
        sleeps: Sleeps,
        retryEnabled: Bool = true,
        jitter: Double = 0,
        recorder: EventRecorder? = nil,
        body: (AxiamClient, TestHTTPServer) async throws -> Void
    ) async throws {
        try await withClient(
            makeConfig: { port in
                try AxiamConfig(
                    baseURL: URL(string: "http://127.0.0.1:\(port)")!,
                    tenantID: Contract164DeviceGrantRateLimitTests.tenantUUID,
                    requestTimeout: 10,
                    retryEnabled: retryEnabled,
                    telemetryHook: recorder?.hook,
                    oidcClientID: "tv-app")
            },
            router: router,
            body: { client, server in
                await client._setRetryTestSeams(jitter: { jitter }, sleep: { sleeps.record($0) })
                try await body(client, server)
            })
    }

    // MARK: - §14.6

    func testA429WithRetryAfterIsWaitedOutAndTheIntervalIsUnchanged() async throws {
        // One poll answered `429` + `Retry-After: 7`, then `authorization_pending`, then the
        // tokens. Interval 1: the first wait is the interval, the wait after the `429` is the
        // `Retry-After` (7, which stands in for one interval), and the wait after that is 1
        // again — NOT 6, which is what reading the `429` as `slow_down` would give.
        let sleeps = Sleeps()
        let router = Self.makeRouter(
            interval: 1, expiresIn: 600,
            pollAnswers: [Self.rateLimited, Self.pending, Self.success])
        try await withDeviceClient(router: router, sleeps: sleeps) { client, server in
            let tokens = try await client.deviceLogin { _ in }

            XCTAssertEqual(tokens.accessToken.expose(), "the-access-token")
            XCTAssertEqual(server.state.count("poll"), 3, "the 429 was polled past, not raised")
            XCTAssertEqual(sleeps.values, [1, 7, 1])
        }
    }

    func testRetryAfterIsAMinimumNotAReplacementForALongerInterval() async throws {
        // `Retry-After: 7` against a 9 s interval: the wait is the interval, because
        // `Retry-After` is a floor. It is still one slot, and the interval stays 9.
        let sleeps = Sleeps()
        let router = Self.makeRouter(
            interval: 9, expiresIn: 600,
            pollAnswers: [Self.rateLimited, Self.success])
        try await withDeviceClient(router: router, sleeps: sleeps) { client, _ in
            _ = try await client.deviceLogin { _ in }
            XCTAssertEqual(sleeps.values, [9, 9])
        }
    }

    func testARetryAfterPastTheDeadlineExpiresTheGrantAndSendsNothingAfterIt() async throws {
        // `Retry-After` of an hour against a 600 s grant: capped at the deadline, which the loop
        // reports as `expired_token` at once (§33.7 rule 5 allows either), with no further poll.
        let sleeps = Sleeps()
        let router = Self.makeRouter(
            interval: 1, expiresIn: 600,
            pollAnswers: [Self.answer(429, [("Retry-After", "3600")], ["error": "rate_limit_exceeded"]), Self.success])
        try await withDeviceClient(router: router, sleeps: sleeps) { client, server in
            do {
                _ = try await client.deviceLogin { _ in }
                XCTFail("expected the grant to expire")
            } catch let error as AxiamError {
                guard case let .auth(authError) = error else { return XCTFail("expected an AuthError") }
                XCTAssertEqual(authError.oauthError, "expired_token")
            }
            XCTAssertEqual(server.state.count("poll"), 1, "nothing is sent after the deadline")
            XCTAssertEqual(sleeps.values, [1])
        }
    }

    func testTheSinglePollStillRaisesTheRateLimitError() async throws {
        // §14.2 rule 9, first paragraph, unchanged: the one `device_poll` call is not the loop.
        let router = Self.makeRouter(interval: 1, expiresIn: 600, pollAnswers: [Self.rateLimited])
        try await withDeviceClient(router: router, sleeps: Sleeps()) { client, _ in
            do {
                _ = try await client.devicePoll(deviceCode: Sensitive("the-device-code"))
                XCTFail("expected rate_limit_exceeded to surface")
            } catch let error as AxiamError {
                guard case let .auth(authError) = error else { return XCTFail("expected an AuthError") }
                XCTAssertEqual(authError.oauthError, "rate_limit_exceeded")
            }
        }
    }

    // MARK: - §14.6, contract 1.64 (amended): the status decides

    func testA429SlowDownIsTheWaitAndDoesNotRaiseTheInterval() async throws {
        // C164-04: a `429` whose body says `slow_down` (a server before 1.1.2, or an
        // intermediary) is the rule-9 wait. Interval 1, `Retry-After: 1`: the waits stay at the
        // interval — a `slow_down` read from the body would give `[1, 6, 6]`.
        let sleeps = Sleeps()
        let router = Self.makeRouter(
            interval: 1, expiresIn: 600,
            pollAnswers: [
                Self.answer(429, [("Retry-After", "1")], ["error": "slow_down"]),
                Self.pending,
                Self.success,
            ])
        try await withDeviceClient(router: router, sleeps: sleeps) { client, server in
            _ = try await client.deviceLogin { _ in }
            XCTAssertEqual(server.state.count("poll"), 3)
            XCTAssertEqual(sleeps.values, [1, 1, 1])
        }
    }

    func testABodilessA429StillHonoursItsRetryAfterAsAFloor() async throws {
        // C164-17: a proxy's `429` names no OAuth error. The status still decides, so the
        // `Retry-After` is the floor of the next wait: `[interval, 7]`.
        let sleeps = Sleeps()
        let router = Self.makeRouter(
            interval: 1, expiresIn: 600,
            pollAnswers: [(429, [("Retry-After", "7")], Data("<html>slow down</html>".utf8)), Self.success])
        try await withDeviceClient(router: router, sleeps: sleeps) { client, _ in
            _ = try await client.deviceLogin { _ in }
            XCTAssertEqual(sleeps.values, [1, 7])
        }
    }

    // MARK: - §14.2 rule 6: a 5xx is a transport failure whatever its body

    func testA500WithTheServersOwnBodyMidPollIsNotTerminal() async throws {
        // C164-03: AXIAM answers a datastore fault `500 {"error":"server_error",…}`. The status
        // is read before the body, so the poll is retried under §16 and the approved grant is not
        // lost. Pending, then the second poll meets two 500s and a 200 inside ONE attempt: four
        // requests, two loop waits of the interval, and two in-poll waits (jitter 0, so 0 s).
        let sleeps = Sleeps()
        let serverError = Self.answer(
            500, [], ["error": "server_error", "error_description": "db"])
        let router = Self.makeRouter(
            interval: 1, expiresIn: 600,
            pollAnswers: [Self.pending, serverError, serverError, Self.success])
        try await withDeviceClient(router: router, sleeps: sleeps) { client, server in
            let tokens = try await client.deviceLogin { _ in }
            XCTAssertEqual(tokens.accessToken.expose(), "the-access-token")
            XCTAssertEqual(server.state.count("poll"), 4)
            XCTAssertEqual(sleeps.values, [1, 1, 0, 0])
        }
    }

    func testASingleA500PollIsANetworkErrorWhateverItsBody() async throws {
        let router = Self.makeRouter(
            interval: 1, expiresIn: 600,
            pollAnswers: [Self.answer(503, [], ["error": "temporarily_unavailable"])])
        try await withDeviceClient(router: router, sleeps: Sleeps()) { client, _ in
            do {
                _ = try await client.devicePoll(deviceCode: Sensitive("the-device-code"))
                XCTFail("expected a transport failure")
            } catch let error as AxiamError {
                guard case let .network(networkError) = error else {
                    return XCTFail("a 5xx is the §2 NetworkError, not an AuthError")
                }
                XCTAssertEqual(networkError.statusCode, 503)
            }
        }
    }

    // MARK: - §14.6 (C164-25): the poll is §16-retried inside the attempt on a 5xx, never a 429

    private static var serverError: Answer {
        answer(500, [], ["error": "server_error", "error_description": "db"])
    }

    func testASingleDevicePollRetriesTwo500sInsideTheAttemptAndReturnsTheTokens() async throws {
        let router = Self.makeRouter(
            interval: 1, expiresIn: 600,
            pollAnswers: [Self.serverError, Self.serverError, Self.success])
        try await withDeviceClient(router: router, sleeps: Sleeps()) { client, server in
            let tokens = try await client.devicePoll(deviceCode: Sensitive("the-device-code"))
            XCTAssertEqual(tokens.accessToken.expose(), "the-access-token")
            XCTAssertEqual(server.state.count("poll"), 3, "the attempt cap of §16.1 is 3 in total")
        }
    }

    func testAThird500ExhaustsTheCapAndTheLoopTakesItsNextInterval() async throws {
        // Three 500s are one poll's whole budget; `deviceLogin` surfaces nothing and takes the
        // next interval, where the fourth request is answered with the tokens. Two retry events.
        let sleeps = Sleeps()
        let recorder = EventRecorder()
        let router = Self.makeRouter(
            interval: 1, expiresIn: 600,
            pollAnswers: [Self.serverError, Self.serverError, Self.serverError, Self.success])
        try await withDeviceClient(router: router, sleeps: sleeps, recorder: recorder) { client, server in
            _ = try await client.deviceLogin { _ in }
            XCTAssertEqual(server.state.count("poll"), 4)
            XCTAssertEqual(sleeps.values, [1, 0, 0, 1])
            XCTAssertEqual(recorder.kinds.filter { $0 == "retry" }.count, 2)
        }
    }

    func testAThird500InASinglePollSurfacesTheNetworkErrorAfterThreeRequests() async throws {
        let router = Self.makeRouter(
            interval: 1, expiresIn: 600,
            pollAnswers: [Self.serverError, Self.serverError, Self.serverError, Self.success])
        try await withDeviceClient(router: router, sleeps: Sleeps()) { client, server in
            do {
                _ = try await client.devicePoll(deviceCode: Sensitive("the-device-code"))
                XCTFail("expected the exhausted budget to surface")
            } catch let error as AxiamError {
                guard case let .network(networkError) = error else { return XCTFail("expected a NetworkError") }
                XCTAssertEqual(networkError.statusCode, 500)
            }
            XCTAssertEqual(server.state.count("poll"), 3)
        }
    }

    func testWithRetryDisabledAFiveHundredMakesOneRequestPerPoll() async throws {
        let sleeps = Sleeps()
        let router = Self.makeRouter(
            interval: 1, expiresIn: 600, pollAnswers: [Self.serverError, Self.success])
        try await withDeviceClient(router: router, sleeps: sleeps, retryEnabled: false) { client, server in
            _ = try await client.deviceLogin { _ in }
            XCTAssertEqual(server.state.count("poll"), 2)
            XCTAssertEqual(sleeps.values, [1, 1], "no in-poll wait: the loop's intervals only")
        }
    }

    func testTheInPollWaitIsJitteredAndRetryAfterIsItsFloor() async throws {
        // §16.1: full jitter over the 0.2 s base (jitter pinned to 1 gives 0.2), and a
        // `Retry-After` on the 500 is a floor under it.
        for (headers, expected) in [([], 0.2), ([("Retry-After", "2")], 2.0)] as [([(String, String)], TimeInterval)] {
            let sleeps = Sleeps()
            let router = Self.makeRouter(
                interval: 1, expiresIn: 600,
                pollAnswers: [Self.answer(500, headers, ["error": "server_error"]), Self.success])
            try await withDeviceClient(router: router, sleeps: sleeps, jitter: 1) { client, _ in
                _ = try await client.devicePoll(deviceCode: Sensitive("the-device-code"))
                XCTAssertEqual(sleeps.values, [expected])
            }
        }
    }

    func testA429IsNeverRetriedInsideThePoll() async throws {
        // A bodiless `429` + `Retry-After: 7`: one request in the poll, then the LOOP's 7 s wait
        // (rule 9). An in-poll retry would wait twice.
        let sleeps = Sleeps()
        let router = Self.makeRouter(
            interval: 1, expiresIn: 600,
            pollAnswers: [(429, [("Retry-After", "7")], Data("<html>slow down</html>".utf8)), Self.success])
        try await withDeviceClient(router: router, sleeps: sleeps) { client, server in
            _ = try await client.deviceLogin { _ in }
            XCTAssertEqual(server.state.count("poll"), 2)
            XCTAssertEqual(sleeps.values, [1, 7])
        }
    }

    func testAnInPollWaitThatWouldPassTheDeadlineIsNotTaken() async throws {
        // §14.2 rule 4: a 500 with `Retry-After: 30` against a deadline one second away surfaces
        // at once; nothing is slept into the deadline and no second request is sent.
        let sleeps = Sleeps()
        let router = Self.makeRouter(
            interval: 1, expiresIn: 600,
            pollAnswers: [Self.answer(500, [("Retry-After", "30")], ["error": "server_error"]), Self.success])
        try await withDeviceClient(router: router, sleeps: sleeps) { client, server in
            let url = await client.config.baseURL.appendingPathComponent("oauth2/token")
            let response = try await client.bareSend(
                operation: "device_poll", pathTemplate: "/oauth2/token", method: .post, url: url,
                headers: [], body: Data(), retry: .section16TransportOnly,
                deadline: Date().addingTimeInterval(1))
            XCTAssertEqual(response.status, 500)
            XCTAssertEqual(server.state.count("poll"), 1)
            XCTAssertEqual(sleeps.values, [])
        }
    }

    func testASingleDevicePollOnA429SlowDownSurfacesRateLimitExceeded() async throws {
        // C164-33: a caller driving its own loop reads `slow_down` as the polling signal, so the
        // single call must not hand it one from a `429`.
        let router = Self.makeRouter(
            interval: 1, expiresIn: 600,
            pollAnswers: [Self.answer(429, [("Retry-After", "1")], ["error": "slow_down"])])
        try await withDeviceClient(router: router, sleeps: Sleeps()) { client, _ in
            do {
                _ = try await client.devicePoll(deviceCode: Sensitive("the-device-code"))
                XCTFail("expected rate_limit_exceeded to surface")
            } catch let error as AxiamError {
                guard case let .auth(authError) = error else { return XCTFail("expected an AuthError") }
                XCTAssertEqual(authError.oauthError, "rate_limit_exceeded")
            }
        }
    }
}
