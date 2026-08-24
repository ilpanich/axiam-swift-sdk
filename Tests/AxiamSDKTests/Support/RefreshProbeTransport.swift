import Foundation
@testable import AxiamSDK

/// A deterministic in-memory `HTTPTransport` for the CONTRACT.md §9 rule 6 tests.
///
/// It counts refresh wire calls and hands out a *distinguishable* `axiam_access` cookie per call
/// (`refresh-1`, `refresh-2`, …) so a test can prove which call's outcome a given caller received —
/// not merely that it received one. The first refresh can be parked until `release()`, and
/// `awaitRefreshStarted()` resolves the moment that call actually reaches the wire, so tests order
/// events by signalling rather than by sleeping.
final class RefreshProbeTransport: HTTPTransport, @unchecked Sendable {
    private let lock = NSLock()
    private var counts: [String: Int] = [:]
    private var parked: CheckedContinuation<Void, Never>?
    private var startedWaiter: CheckedContinuation<Void, Never>?
    private var refreshStarted = false
    private var released = false

    /// Park the *first* refresh wire call until ``release()`` is called.
    private let parkFirstRefresh: Bool
    /// Answer every refresh with 401 (the §9.3 "no retry, re-authenticate" path).
    private let failRefresh: Bool

    init(parkFirstRefresh: Bool = false, failRefresh: Bool = false) {
        self.parkFirstRefresh = parkFirstRefresh
        self.failRefresh = failRefresh
    }

    func count(_ key: String) -> Int {
        lock.lock(); defer { lock.unlock() }
        return counts[key, default: 0]
    }

    /// Suspend until the first refresh wire call has begun (i.e. the guard has published its slot
    /// and the refresh is genuinely on the wire).
    func awaitRefreshStarted() async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            lock.lock()
            if refreshStarted {
                lock.unlock()
                continuation.resume()
                return
            }
            startedWaiter = continuation
            lock.unlock()
        }
    }

    /// Let the parked refresh wire call complete.
    func release() {
        lock.lock()
        released = true
        let continuation = parked
        parked = nil
        lock.unlock()
        continuation?.resume()
    }

    func execute(_ spec: HTTPRequestSpec, timeout: TimeInterval) async throws -> HTTPResponseData {
        let path = spec.url.path

        if path.hasSuffix("/auth/login") {
            lock.locked { counts["login", default: 0] += 1 }
            return json(200, TestKit.loginSuccessBody(), cookie: "login")
        }

        if path.hasSuffix("/auth/refresh") {
            // Snapshot everything this call needs, then leave the lock before resuming a
            // continuation or suspending: the parking `await` below must never run under it.
            let (generation, shouldPark, waiter) = lock.locked {
                () -> (Int, Bool, CheckedContinuation<Void, Never>?) in
                counts["refresh", default: 0] += 1
                let generation = counts["refresh", default: 0]
                let shouldPark = parkFirstRefresh && generation == 1 && !released
                let waiter = startedWaiter
                startedWaiter = nil
                refreshStarted = true
                return (generation, shouldPark, waiter)
            }
            waiter?.resume()

            if shouldPark {
                await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                    lock.lock()
                    if released {
                        lock.unlock()
                        continuation.resume()
                        return
                    }
                    parked = continuation
                    lock.unlock()
                }
            }

            if failRefresh {
                return json(401, ["error": "invalid_grant", "message": "re-auth required"])
            }
            return json(200, ["expires_in": 900], cookie: "refresh-\(generation)")
        }

        if path.contains("/authz/check") {
            lock.locked { counts["check", default: 0] += 1 }
            return json(200, ["allowed": true])
        }

        return json(404, [:])
    }

    func shutdown() async throws {}

    private func json(_ status: Int, _ object: [String: Any], cookie: String? = nil) -> HTTPResponseData {
        let body = (try? JSONSerialization.data(withJSONObject: object)) ?? Data()
        var headers: [(String, String)] = [("Content-Type", "application/json")]
        if let cookie {
            headers.append(("Set-Cookie", "axiam_access=\(cookie); Path=/; HttpOnly"))
        }
        return HTTPResponseData(status: status, headers: headers, body: body)
    }
}

/// A minimal thread-safe box for values a `@Sendable` test hook records for its test body.
final class ProbeBox<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: Value

    init(_ initial: Value) { storage = initial }

    var value: Value {
        get { lock.lock(); defer { lock.unlock() }; return storage }
        set { lock.lock(); storage = newValue; lock.unlock() }
    }
}

/// A one-shot latch: `signal()` may be called before or after `wait()`.
final class ProbeLatch: @unchecked Sendable {
    private let lock = NSLock()
    private var signalled = false
    private var claimed = false
    private var waiter: CheckedContinuation<Void, Never>?

    func signal() {
        lock.lock()
        signalled = true
        let continuation = waiter
        waiter = nil
        lock.unlock()
        continuation?.resume()
    }

    func wait() async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            lock.lock()
            if signalled {
                lock.unlock()
                continuation.resume()
                return
            }
            waiter = continuation
            lock.unlock()
        }
    }

    /// True the first time it is called, false afterwards — for hooks that must act only once.
    func claimOnce() -> Bool {
        lock.lock(); defer { lock.unlock() }
        if claimed { return false }
        claimed = true
        return true
    }
}
