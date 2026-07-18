import XCTest
import Foundation
@testable import AxiamSDK

final class RefreshSingleFlightTests: XCTestCase {

    /// Fire N (>=5) concurrent authorized calls that all hit a 401, and assert exactly one
    /// refresh call is made (§9 single-flight guard + Phase-18 success criterion #2).
    ///
    /// Uses a mock transport whose single refresh parks until `release()`, so every concurrent
    /// caller is provably waiting on the one in-flight refresh before it resolves — deterministic,
    /// no wall-clock reliance.
    func testConcurrent401sTriggerExactlyOneRefresh() async throws {
        let mock = MockTransport()
        let client = AxiamClient(config: try TestKit.makeConfig(port: 0), transport: mock)

        _ = try await client.login(email: "a@b.c", password: "pw")

        // Release the parked refresh after all 8 callers have certainly reached the guard
        // (mock has zero latency, so they park effectively immediately).
        let releaser = Task {
            try? await Task.sleep(nanoseconds: 150_000_000)
            mock.release()
        }

        let results = try await withThrowingTaskGroup(of: Bool.self) { group -> [Bool] in
            for _ in 0..<8 {
                group.addTask { try await client.can("read", resource: "r") }
            }
            var collected: [Bool] = []
            for try await value in group { collected.append(value) }
            return collected
        }
        await releaser.value

        XCTAssertEqual(results.count, 8)
        XCTAssertTrue(results.allSatisfy { $0 })
        XCTAssertEqual(mock.count("refresh"), 1, "exactly one refresh should occur")
        try await client.shutdown()
    }

    /// A 401 on the refresh call itself surfaces as AuthError with no retry loop (§9.3).
    func testRefreshFailureSurfacesAuthErrorNoRetry() async throws {
        try await withClient(router: { request, state in
            if request.uri.hasSuffix("/login") {
                return .json(200, TestKit.loginSuccessBody(), headers: [
                    ("Set-Cookie", "axiam_access=stale; Path=/; HttpOnly"),
                ])
            }
            if request.uri.hasSuffix("/auth/refresh") {
                state.increment("refresh")
                return .json(401, ["error": "invalid_refresh", "message": "re-auth required"])
            }
            return .json(401, ["message": "expired"])
        }) { client, server in
            _ = try await client.login(email: "a@b.c", password: "pw")
            do {
                _ = try await client.can("read", resource: "r")
                XCTFail("expected auth error")
            } catch let AxiamError.auth(error) {
                XCTAssertTrue(error.message.contains("re-auth"))
            }
            XCTAssertEqual(server.state.count("refresh"), 1, "no refresh retry loop")
        }
    }
}
