import Foundation
@testable import AxiamSDK

/// A deterministic in-memory `HTTPTransport` for the single-flight refresh test.
///
/// `authz/check` returns 401 until a refresh has completed, then 200. The single refresh call
/// parks on a continuation until `release()` is called, so the test can guarantee every
/// concurrent caller is waiting on the one in-flight refresh before it resolves — no reliance on
/// wall-clock timing. Being a pure mock, there is no `HTTPClient` to shut down.
final class MockTransport: HTTPTransport, @unchecked Sendable {
    private let lock = NSLock()
    private var counts: [String: Int] = [:]
    private var refreshed = false
    private var parked: CheckedContinuation<Void, Never>?

    func count(_ key: String) -> Int {
        lock.lock(); defer { lock.unlock() }
        return counts[key, default: 0]
    }

    private func increment(_ key: String) {
        lock.lock(); defer { lock.unlock() }
        counts[key, default: 0] += 1
    }

    private var isRefreshed: Bool {
        lock.lock(); defer { lock.unlock() }
        return refreshed
    }

    /// Release the single parked refresh call, letting it (and all waiters) complete.
    func release() {
        lock.lock()
        let continuation = parked
        parked = nil
        lock.unlock()
        continuation?.resume()
    }

    func execute(_ spec: HTTPRequestSpec, timeout: TimeInterval) async throws -> HTTPResponseData {
        let path = spec.url.path

        if path.hasSuffix("/auth/login") {
            increment("login")
            return json(200, TestKit.loginSuccessBody())
        }

        if path.hasSuffix("/auth/refresh") {
            increment("refresh")
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                lock.lock()
                parked = continuation
                lock.unlock()
            }
            lock.lock(); refreshed = true; lock.unlock()
            return json(200, ["expires_in": 900])
        }

        if path.contains("/authz/check") {
            increment("check")
            return isRefreshed ? json(200, ["allowed": true]) : json(401, ["message": "expired"])
        }

        return json(404, [:])
    }

    func shutdown() async throws {}

    private func json(_ status: Int, _ object: [String: Any]) -> HTTPResponseData {
        let body = (try? JSONSerialization.data(withJSONObject: object)) ?? Data()
        return HTTPResponseData(status: status, headers: [("Content-Type", "application/json")], body: body)
    }
}
