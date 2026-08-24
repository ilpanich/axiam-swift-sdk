import Foundation
@testable import AxiamSDK

/// A counting, scriptable `HTTPTransport` for the D5 conformance suite.
///
/// The point of this harness is the **request count**. Contract 1.8.1 made wire-counting
/// normative because two SDKs shipped a retry surface that was exported, documented, unit-tested
/// and green while no production path called it — a passing suite is exactly what stopped anyone
/// from looking. Every §16 assertion here therefore drives a real ``AxiamClient`` and counts what
/// reached this transport.
final class ScriptedTransport: HTTPTransport, @unchecked Sendable {
    private let lock = NSLock()

    /// Statuses to serve in order; the last entry repeats once exhausted. A `nil` entry means a
    /// transport failure — no HTTP response arrived at all.
    private var statuses: [Int?]
    private var body: [String: Any]
    private var retryAfter: String?

    private(set) var requestCount = 0
    private(set) var paths: [String] = []
    private(set) var shutdownCount = 0

    init(statuses: [Int?] = [200], body: [String: Any] = ["allowed": true, "reason_code": "allowed"],
         retryAfter: String? = nil) {
        self.statuses = statuses
        self.body = body
        self.retryAfter = retryAfter
    }

    func setBody(_ body: [String: Any]) {
        lock.lock(); defer { lock.unlock() }
        self.body = body
    }

    func execute(_ spec: HTTPRequestSpec, timeout: TimeInterval) async throws -> HTTPResponseData {
        // One synchronous critical section producing a snapshot: nothing below this point
        // reads mutable state, so no lock is held across the `throw`/return path.
        let (status, currentBody, hint) = lock.locked { () -> (Int?, [String: Any], String?) in
            let index = min(requestCount, statuses.count - 1)
            let status = statuses.isEmpty ? 200 : statuses[index]
            requestCount += 1
            paths.append(spec.url.path)
            return (status, body, retryAfter)
        }

        guard let status else {
            throw AxiamError.network(NetworkError("connection refused"))
        }

        var headers: [(String, String)] = [("Content-Type", "application/json")]
        if let hint { headers.append(("Retry-After", hint)) }
        let data = (try? JSONSerialization.data(withJSONObject: currentBody)) ?? Data()
        return HTTPResponseData(status: status, headers: headers, body: data)
    }

    func shutdown() async throws {
        lock.locked { shutdownCount += 1 }
    }
}

/// A thread-safe recorder for §19 events. `TelemetryHook` is `@Sendable` and fires from inside the
/// client actor, so the sink has to be safe to call from there.
final class EventRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [TelemetryEvent] = []

    var events: [TelemetryEvent] {
        lock.lock(); defer { lock.unlock() }
        return storage
    }

    func record(_ event: TelemetryEvent) {
        lock.lock(); defer { lock.unlock() }
        storage.append(event)
    }

    /// A hook closure bound to this recorder.
    var hook: TelemetryHook {
        { [self] event in record(event) }
    }

    /// Compact kind labels, for asserting ordering without spelling out every payload.
    var kinds: [String] {
        events.map {
            switch $0 {
            case .requestStart: return "start"
            case .requestEnd: return "end"
            case .retry: return "retry"
            case .refresh: return "refresh"
            case .configClamped: return "clamped"
            }
        }
    }

    var startAttempts: [Int] {
        events.compactMap {
            if case let .requestStart(_, _, _, attempt) = $0 { return attempt }
            return nil
        }
    }

    var clamps: [TelemetryEvent] {
        events.filter { if case .configClamped = $0 { return true } else { return false } }
    }
}

/// A recorder for the §16 sleeps a client would have taken, so a delay can be asserted without
/// waiting for it. §16.7: a test that really waits 200 ms is a test nobody runs.
final class SleepRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [TimeInterval] = []

    var delays: [TimeInterval] {
        lock.lock(); defer { lock.unlock() }
        return storage
    }

    func record(_ delay: TimeInterval) {
        lock.lock(); defer { lock.unlock() }
        storage.append(delay)
    }
}
