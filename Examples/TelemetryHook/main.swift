// TelemetryHook — wiring metrics to an AXIAM client WITHOUT this package depending on
// any metrics library (CONTRACT.md §19).
//
// Demonstrates the whole D5 surface in one run: §16 bounded read-only retry, §17 the
// opt-in decision memo and its clamp, §18 `close()`, and §19 the hook itself. The sink
// aggregates in-process, so the example needs no extra dependency and no reachable
// server — the failure path emits exactly the same events as the success path, which is
// the property that makes the telemetry worth having.
//
// Build:  swift build --target TelemetryHookExample
// Run:    swift run TelemetryHookExample

import Foundation
import AxiamSDK

func env(_ key: String, default fallback: String) -> String {
    ProcessInfo.processInfo.environment[key] ?? fallback
}

/// In-process aggregation.
///
/// A `final class` with a lock rather than a bare closure over `var`s: ``TelemetryHook`` is
/// `@Sendable` because ``AxiamClient`` is an actor and the hook is invoked from inside it, so
/// captured mutable state has to be safe to touch from whatever task the SDK is running on.
/// An `actor` would be the other choice, but an actor's methods are `async` and §19.2 rule 4
/// says a sink must not block the calling path — so a plain lock, held for the few
/// instructions an increment takes, is the closer fit.
final class Metrics: @unchecked Sendable {
    private let lock = NSLock()
    private var requests: [String: (count: Int, totalMs: Double)] = [:]
    private var retries: [String: Int] = [:]
    private var refreshes = 0

    func record(_ event: TelemetryEvent) {
        switch event {
        // One pair per ATTEMPT, not per logical call (§19.2 rule 5), so counting these
        // gives the real number of wire calls — including the ones a retry made on your
        // behalf.
        //
        // `.requestStart` is deliberately unhandled: `.requestEnd` carries the same
        // identity plus the outcome, so counting both double-counts.
        case let .requestEnd(operation, _, _, _, _, duration, outcome):
            lock.lock()
            defer { lock.unlock() }
            let key = "\(operation)/\(outcome.rawValue)"
            var stat = requests[key] ?? (0, 0)
            stat.count += 1
            stat.totalMs += duration * 1000
            requests[key] = stat

        // §16.5 — the reason this event exists. A retried-then-succeeded operation is
        // otherwise invisible: the caller sees a slow success and no signal that the
        // server is failing. Alert on THIS rate, not on the error rate, or a degrading
        // server looks healthy right up until the retries stop being enough.
        case let .retry(operation, _, _, _):
            lock.lock()
            defer { lock.unlock() }
            retries[operation, default: 0] += 1

        case .refresh:
            lock.lock()
            defer { lock.unlock() }
            refreshes += 1

        // §19.2 rule 6 — fired at most once per clamped setting, at construction. Worth
        // logging loudly rather than counting: it means a value in your configuration is
        // not the value in force, and the gap is silent everywhere else.
        case let .configClamped(setting, requested, effective, contractReference):
            FileHandle.standardError.write(
                Data("WARN: \(setting)=\(requested) was clamped to \(effective) (\(contractReference))\n".utf8))

        case .requestStart:
            break
        }
    }

    func report() {
        lock.lock()
        defer { lock.unlock() }
        print("--- telemetry ---")
        for key in requests.keys.sorted() {
            let stat = requests[key]!
            let mean = stat.count == 0 ? 0 : stat.totalMs / Double(stat.count)
            print("  \(key): count=\(stat.count) mean=\(Int(mean))ms")
        }
        if retries.isEmpty {
            print("  retries: (none)")
        }
        for operation in retries.keys.sorted() {
            print("  retries \(operation): \(retries[operation]!)")
        }
        print("  refreshes: \(refreshes)")
    }
}

let metrics = Metrics()

let baseURLString = env("AXIAM_BASE_URL", default: "https://127.0.0.1:59999")
guard let baseURL = URL(string: baseURLString) else {
    fatalError("Invalid AXIAM_BASE_URL: \(baseURLString)")
}

let config = try AxiamConfig(
    baseURL: baseURL,
    tenantSlug: env("AXIAM_TENANT_SLUG", default: "acme"),
    orgSlug: env("AXIAM_ORG_SLUG", default: "acme"),
    // Deliberately above the §17.1 rule 2 ceiling, so the run demonstrates the
    // `.configClamped` warning above rather than leaving it theoretical.
    decisionMemoTtl: 60,
    telemetryHook: { metrics.record($0) }
)

let client = try AxiamClient(config: config)

do {
    let result = try await client.checkAccess(
        "documents:read",
        resource: env("AXIAM_RESOURCE_ID", default: "00000000-0000-0000-0000-000000000000"))
    print("allowed=\(result.allowed) reasonCode=\(result.reasonCode ?? "(absent)")")
} catch let error as AxiamError {
    // Expected without a reachable server. The point of this example is the telemetry
    // below, which is emitted on this path exactly as it would be on the success path.
    print("check failed: \(error)")
}

metrics.report()

// §18: releases the HTTP client and its connection pool and clears the session state. It
// issues NO request — it does not log out, because the server-side session deliberately
// outlives the client object. Idempotent, and any call afterwards throws rather than
// silently reconnecting.
//
// In Swift this call is REQUIRED rather than a courtesy: `deinit` cannot `await`, and
// releasing an AsyncHTTPClient is async, so deallocation alone cannot complete the
// shutdown the way it can in the SDKs with synchronous destructors.
try await client.close()

/*
 * Mapping onto a real backend — replace Metrics.record's body, nothing else:
 *
 *   .requestEnd    → histogram "axiam.request.duration"
 *                    labels: operation, pathTemplate, status, outcome, attempt
 *   .retry         → counter   "axiam.request.retries"   labels: operation
 *   .refresh       → counter   "axiam.token.refresh"     labels: role
 *   .configClamped → a log line at warning, not a metric: it fires once at construction
 *                    and its whole value is being READ.
 *
 * Label with `pathTemplate`, never with the request URL: a metric label carrying a UUID
 * is a cardinality bomb. The hook runs on the calling task, so it must not block — every
 * mature metrics library already buffers, which is why §19.2 rule 4 leaves that choice to
 * you rather than making it here.
 */
