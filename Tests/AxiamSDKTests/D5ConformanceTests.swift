import XCTest
@testable import AxiamSDK

/// D5 conformance — CONTRACT.md §16, §17, §18, §19.
///
/// These assert through the **public `checkAccess` surface**, counting requests that reach the
/// transport, rather than against the helpers in isolation. That distinction is normative as of
/// contract 1.8.1: the TypeScript SDK shipped a retry helper that was exported, unit-tested and
/// green while no production path called it, so that SDK performed no read-only retries at all and
/// every test passed. Counting on the wire is the only assertion that catches it.
final class D5ConformanceTests: XCTestCase {

    private func makeClient(
        transport: ScriptedTransport,
        retryEnabled: Bool = true,
        memoTtl: TimeInterval? = nil,
        hook: TelemetryHook? = nil,
        jitter: @escaping @Sendable () -> Double = { 1.0 },
        sleeps: SleepRecorder? = nil
    ) async throws -> AxiamClient {
        let config = try AxiamConfig(
            baseURL: URL(string: "https://iam.example.com")!,
            tenantSlug: "acme",
            retryEnabled: retryEnabled,
            decisionMemoTtl: memoTtl,
            telemetryHook: hook
        )
        let client = AxiamClient(config: config, transport: transport)
        // §16.7: an injected PRNG and an injected sleep. Never a real wait.
        await client._setRetryTestSeams(jitter: jitter, sleep: { delay in sleeps?.record(delay) })
        return client
    }

    // MARK: - §16 the policy, asserted through the public surface

    func testPersistent503MakesExactlyThreeAttempts() async throws {
        let transport = ScriptedTransport(statuses: [503])
        let client = try await makeClient(transport: transport)
        await XCTAssertThrowsErrorAsync(try await client.checkAccess("read", resource: "r-1"))
        // Not 2, not 4. The cap is the whole point of a bounded policy.
        XCTAssertEqual(transport.requestCount, 3)
    }

    func testTransientFailureIsRetriedAndTheSuccessReturned() async throws {
        let transport = ScriptedTransport(statuses: [503, 200])
        let client = try await makeClient(transport: transport)
        let result = try await client.checkAccess("read", resource: "r-1")
        XCTAssertTrue(result.allowed)
        XCTAssertEqual(transport.requestCount, 2)
    }

    func testATransportFailureIsRetried() async throws {
        // No HTTP response arrived at all, so the request may never have been seen.
        let transport = ScriptedTransport(statuses: [nil])
        let client = try await makeClient(transport: transport)
        await XCTAssertThrowsErrorAsync(try await client.checkAccess("read", resource: "r-1"))
        XCTAssertEqual(transport.requestCount, 3)
    }

    func testDecisiveStatusesMakeExactlyOneAttempt() async throws {
        // 401 reaches one attempt because no session is active — §9 owns the refresh path, and
        // §16 must not turn a decisive answer into three identical rejections.
        for status in [403, 401, 400, 404, 409] {
            let transport = ScriptedTransport(statuses: [status])
            let client = try await makeClient(transport: transport)
            await XCTAssertThrowsErrorAsync(try await client.checkAccess("read", resource: "r-1"))
            XCTAssertEqual(transport.requestCount, 1, "status \(status) must not be retried")
        }
    }

    func testRetryDisabledMakesExactlyOneAttempt() async throws {
        let transport = ScriptedTransport(statuses: [503])
        let client = try await makeClient(transport: transport, retryEnabled: false)
        await XCTAssertThrowsErrorAsync(try await client.checkAccess("read", resource: "r-1"))
        XCTAssertEqual(transport.requestCount, 1)
    }

    func testANonIdempotentOperationIsNeverRetried() async throws {
        // §16.2 and §16.7's named trap: this is the assertion that catches a retry wired at the
        // TRANSPORT layer instead of the operation layer. `login` is ineligible because it changes
        // state and because its credential is single-use — a silent replay turns a recoverable
        // blip into a hard rejection the caller cannot interpret.
        let transport = ScriptedTransport(statuses: [503])
        let client = try await makeClient(transport: transport)
        await XCTAssertThrowsErrorAsync(try await client.login(email: "u@example.com", password: "pw"))
        XCTAssertEqual(transport.requestCount, 1)
    }

    func testTheDelaySequenceWithJitterPinnedToMax() async throws {
        // §16.1: min(cap, base × 2^(attempt−1)) → 200 ms then 400 ms, both under the 5 s cap.
        let transport = ScriptedTransport(statuses: [503])
        let sleeps = SleepRecorder()
        let client = try await makeClient(transport: transport, jitter: { 1.0 }, sleeps: sleeps)
        await XCTAssertThrowsErrorAsync(try await client.checkAccess("read", resource: "r-1"))
        XCTAssertEqual(sleeps.delays, [0.2, 0.4])
    }

    func testJitterPinnedToZeroWaitsZero() async throws {
        // The range is [0, backoff], NOT backoff ± something. Asserting it through the client
        // rather than the pure function is what proves the injected PRNG is the one the retry
        // loop actually consults.
        let transport = ScriptedTransport(statuses: [503])
        let sleeps = SleepRecorder()
        let client = try await makeClient(transport: transport, jitter: { 0.0 }, sleeps: sleeps)
        await XCTAssertThrowsErrorAsync(try await client.checkAccess("read", resource: "r-1"))
        XCTAssertEqual(transport.requestCount, 3, "still three attempts")
        XCTAssertEqual(sleeps.delays, [0, 0])
    }

    func testBackoffDoublesFromTheBaseAndStopsAtTheCap() {
        XCTAssertEqual(Retry.backoff(attempt: 1), 0.2)
        XCTAssertEqual(Retry.backoff(attempt: 2), 0.4)
        XCTAssertEqual(Retry.backoff(attempt: 3), 0.8)
        XCTAssertEqual(Retry.backoff(attempt: 20), 5.0)
        // An attempt below 1 is the first attempt, not a shift by -1.
        XCTAssertEqual(Retry.backoff(attempt: 0), 0.2)
    }

    func testFullJitterSpansZeroToTheBackoff() {
        XCTAssertEqual(Retry.delay(attempt: 1, retryAfter: nil, fraction: 0), 0)
        XCTAssertEqual(Retry.delay(attempt: 1, retryAfter: nil, fraction: 1), 0.2)
        XCTAssertEqual(Retry.delay(attempt: 1, retryAfter: nil, fraction: 0.5), 0.1)
        // A fraction outside the unit interval is clamped rather than trusted.
        XCTAssertEqual(Retry.delay(attempt: 1, retryAfter: nil, fraction: -3), 0)
        XCTAssertEqual(Retry.delay(attempt: 1, retryAfter: nil, fraction: 9), 0.2)
    }

    func testRetryAfterIsAFloorNeverACeiling() {
        // Longer than the backoff: the server wins.
        XCTAssertEqual(Retry.delay(attempt: 1, retryAfter: 3, fraction: 1), 3)
        // Shorter than the backoff: it does NOT shorten the wait. `Retry-After: 0` replacing the
        // backoff is the shipped bug §16.1's wording describes.
        XCTAssertEqual(Retry.delay(attempt: 1, retryAfter: 0, fraction: 1), 0.2)
        XCTAssertEqual(Retry.delay(attempt: 1, retryAfter: 0.05, fraction: 1), 0.2)
    }

    func testRetryAfterHeaderParsing() throws {
        XCTAssertEqual(Retry.retryAfter("2"), 2)
        XCTAssertEqual(Retry.retryAfter("0"), 0)
        XCTAssertEqual(Retry.retryAfter("  2  "), 2)
        // An unparseable hint is ABSENT, not a zero-length floor.
        XCTAssertNil(Retry.retryAfter(nil))
        XCTAssertNil(Retry.retryAfter(""))
        XCTAssertNil(Retry.retryAfter("soon"))
        XCTAssertNil(Retry.retryAfter("2x"))
        XCTAssertNil(Retry.retryAfter("-5"))
        // A date already in the past is not a wait.
        XCTAssertNil(Retry.retryAfter("Wed, 21 Oct 2015 07:28:00 GMT"))
        // Bounded, so a hostile header cannot park a task for a day.
        XCTAssertEqual(Retry.retryAfter("999999"), 3600)
        // An HTTP-date in the future parses; both RFC 7231 forms appear in the wild, and an SDK
        // that read only delta-seconds would silently drop the hint from every server that sends
        // a date — which means retrying sooner than the server asked.
        let now = Date()
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss zzz"
        let header = formatter.string(from: now.addingTimeInterval(120))
        let parsed = try XCTUnwrap(Retry.retryAfter(header, now: now))
        XCTAssertEqual(parsed, 120, accuracy: 1.5)
    }

    func testRetryAfterHeaderReachesTheWait() async throws {
        // 429 is exactly where Retry-After usually arrives.
        let transport = ScriptedTransport(statuses: [429], retryAfter: "2")
        let sleeps = SleepRecorder()
        let client = try await makeClient(transport: transport, jitter: { 1.0 }, sleeps: sleeps)
        await XCTAssertThrowsErrorAsync(try await client.checkAccess("read", resource: "r-1"))
        XCTAssertEqual(transport.requestCount, 3)
        // Floors both the 200 ms and the 400 ms backoff.
        XCTAssertEqual(sleeps.delays, [2, 2])
    }

    func testWhichFailuresRetry() {
        XCTAssertTrue(Retry.shouldRetry(status: nil))
        XCTAssertTrue(Retry.shouldRetry(status: 408))
        XCTAssertTrue(Retry.shouldRetry(status: 429))
        XCTAssertTrue(Retry.shouldRetry(status: 500))
        XCTAssertTrue(Retry.shouldRetry(status: 599))
        XCTAssertFalse(Retry.shouldRetry(status: 200))
        XCTAssertFalse(Retry.shouldRetry(status: 401))
        XCTAssertFalse(Retry.shouldRetry(status: 403))
        XCTAssertFalse(Retry.shouldRetry(status: 400))
        XCTAssertFalse(Retry.shouldRetry(status: 404))
        XCTAssertFalse(Retry.shouldRetry(status: 409))
    }

    // MARK: - §17 client-side decision memo

    func testTheMemoIsOffByDefault() async throws {
        // With the default configuration EVERY repeat check reaches the wire. §11.2 rule 6's ban
        // is still the default behaviour.
        let transport = ScriptedTransport()
        let client = try await makeClient(transport: transport)
        for _ in 0..<3 { _ = try await client.checkAccess("read", resource: "r-1") }
        XCTAssertEqual(transport.requestCount, 3)
    }

    func testARepeatInsideTheTtlMakesNoSecondWireCall() async throws {
        let transport = ScriptedTransport()
        let client = try await makeClient(transport: transport, memoTtl: 5)
        let first = try await client.checkAccess("read", resource: "r-1")
        let second = try await client.checkAccess("read", resource: "r-1")
        XCTAssertEqual(transport.requestCount, 1)
        XCTAssertEqual(first.allowed, second.allowed)
        // §17.1 rule 5: the reason code comes back with the decision. A memo that returned
        // `allowed` while dropping the code would make the field intermittently absent — worse
        // than never having had it.
        XCTAssertEqual(second.reasonCode, "allowed")
    }

    func testDeniesAreMemoizedExactlyLikeAllows() async throws {
        // §17.1 rule 4. Asymmetric caching changes the TIMING of the two outcomes and so leaks
        // which one occurred to anyone who can observe latency.
        let transport = ScriptedTransport(body: ["allowed": false, "reason_code": "denied_by_rule"])
        let client = try await makeClient(transport: transport, memoTtl: 5)
        _ = try await client.checkAccess("read", resource: "r-1")
        let second = try await client.checkAccess("read", resource: "r-1")
        XCTAssertEqual(transport.requestCount, 1)
        XCTAssertFalse(second.allowed)
        XCTAssertEqual(second.reasonCode, "denied_by_rule")
    }

    func testAFailureIsNeverMemoized() async throws {
        // §17.1 rule 7. Memoizing a transport error as a deny would turn a blip into a TTL-long
        // outage; memoizing it as an allow is unthinkable.
        let transport = ScriptedTransport(statuses: [503])
        let client = try await makeClient(transport: transport, retryEnabled: false, memoTtl: 5)
        await XCTAssertThrowsErrorAsync(try await client.checkAccess("read", resource: "r-1"))
        await XCTAssertThrowsErrorAsync(try await client.checkAccess("read", resource: "r-1"))
        XCTAssertEqual(transport.requestCount, 2)
    }

    func testEveryKeyComponentIsDistinguished() {
        var keys = Set<String>()
        keys.insert(DecisionMemo.key(subjectID: nil, resource: "r1", action: "read", scope: nil))
        keys.insert(DecisionMemo.key(subjectID: "s1", resource: "r1", action: "read", scope: nil))
        keys.insert(DecisionMemo.key(subjectID: nil, resource: "r2", action: "read", scope: nil))
        keys.insert(DecisionMemo.key(subjectID: nil, resource: "r1", action: "write", scope: nil))
        keys.insert(DecisionMemo.key(subjectID: nil, resource: "r1", action: "read", scope: "sc"))
        XCTAssertEqual(keys.count, 5)
        // An absent scope must never collide with a present empty one: a memo that let them
        // collide would answer a narrower question with a broader answer.
        XCTAssertNotEqual(
            DecisionMemo.key(subjectID: nil, resource: "r1", action: "read", scope: nil),
            DecisionMemo.key(subjectID: nil, resource: "r1", action: "read", scope: "")
        )
    }

    func testDifferingComponentsMissRatherThanCollide() async throws {
        let transport = ScriptedTransport()
        let client = try await makeClient(transport: transport, memoTtl: 5)
        _ = try await client.checkAccess("read", resource: "r-1")
        _ = try await client.checkAccess("read", resource: "r-1", scope: "scope-a")
        _ = try await client.checkAccess("write", resource: "r-1")
        _ = try await client.checkAccess("read", resource: "r-2")
        XCTAssertEqual(transport.requestCount, 4)
    }

    func testATtlAboveTheCeilingIsClampedNotRejected() {
        XCTAssertEqual(DecisionMemo(requestedTTL: 3600).ttl, DecisionMemo.maxTTL)
        XCTAssertEqual(DecisionMemo(requestedTTL: 2).ttl, 2)
        XCTAssertFalse(DecisionMemo(requestedTTL: nil).enabled)
        XCTAssertFalse(DecisionMemo(requestedTTL: 0).enabled)
        // A negative TTL DISABLES rather than clamping up to the ceiling.
        XCTAssertFalse(DecisionMemo(requestedTTL: -5).enabled)
    }

    func testAnEntryExpiresAtExactlyTheTtl() {
        let clock = MutableClock(0)
        var memo = DecisionMemo(requestedTTL: 5, now: { clock.value })
        memo.put("k", AccessResult(allowed: true, reason: nil, reasonCode: "allowed"))

        clock.value = 4.999
        XCTAssertNotNil(memo.get("k"), "still live just before the TTL")
        clock.value = 5
        XCTAssertNil(memo.get("k"), "expired at exactly the TTL")
    }

    func testTheMemoEvictsRatherThanGrowingWithoutBound() {
        // §17.1 rule 8. An unbounded per-client cache keyed by (subject, resource, action, scope)
        // is a memory leak in any service that checks many resources.
        var memo = DecisionMemo(requestedTTL: 5)
        let decision = AccessResult(allowed: true, reason: nil, reasonCode: "allowed")
        for i in 0..<(DecisionMemo.maxEntries + 100) {
            memo.put("k-\(i)", decision)
        }
        XCTAssertEqual(memo.count, DecisionMemo.maxEntries)
    }

    func testTheMemoIsClearedOnACredentialChange() async throws {
        // §17.1 rule 9. Entries are keyed by subject, not by session, so a re-authentication as a
        // DIFFERENT principal would otherwise read the previous principal's decisions.
        let transport = ScriptedTransport()
        let client = try await makeClient(transport: transport, memoTtl: 5)
        _ = try await client.checkAccess("read", resource: "r-1")
        _ = try await client.checkAccess("read", resource: "r-1")
        XCTAssertEqual(transport.requestCount, 1, "the second check came from the memo")

        try await client.logout()
        let afterLogout = transport.requestCount

        _ = try await client.checkAccess("read", resource: "r-1")
        XCTAssertEqual(transport.requestCount, afterLogout + 1,
                       "the memo did not survive the credential change")
    }

    // MARK: - §18 deterministic shutdown

    func testCloseIsIdempotent() async throws {
        let transport = ScriptedTransport()
        let client = try await makeClient(transport: transport)
        try await client.close()
        try await client.close()
        try await client.close()
        // The second and third calls are no-ops, not repeated releases.
        XCTAssertEqual(transport.shutdownCount, 1)
    }

    func testCloseIssuesNoNetworkRequest() async throws {
        // §18.1 rule 5. The server-side session deliberately outlives the client object — that is
        // what lets a process restart and resume — so a close() that logged out would silently end
        // every user's session on each deploy. Asserted against the wire, because a logout wired
        // into close succeeds silently and would pass any return-value assertion.
        let transport = ScriptedTransport()
        let client = try await makeClient(transport: transport)
        try await client.close()
        XCTAssertEqual(transport.requestCount, 0)
    }

    func testUseAfterCloseThrowsRatherThanReconnecting() async throws {
        let transport = ScriptedTransport()
        let client = try await makeClient(transport: transport)
        _ = try await client.checkAccess("read", resource: "r-1")
        let before = transport.requestCount

        try await client.close()

        await XCTAssertThrowsErrorAsync(try await client.checkAccess("read", resource: "r-1"))
        await XCTAssertThrowsErrorAsync(try await client.login(email: "u", password: "p"))
        await XCTAssertThrowsErrorAsync(try await client.logout())
        await XCTAssertThrowsErrorAsync(try await client.refresh())
        await XCTAssertThrowsErrorAsync(try await client.batchCheck([]))
        XCTAssertEqual(transport.requestCount, before, "no request may reach the wire after close")
    }

    func testShutdownRemainsAnAliasForClose() async throws {
        // The pre-§18 spelling must keep working, or every existing call site breaks for a
        // rename that buys nothing.
        let transport = ScriptedTransport()
        let client = try await makeClient(transport: transport)
        try await client.shutdown()
        await XCTAssertThrowsErrorAsync(try await client.checkAccess("read", resource: "r-1"))
    }

    // MARK: - §19 telemetry

    func testOneRequestPairPerAttemptWithARetryBetween() async throws {
        let transport = ScriptedTransport(statuses: [503, 200])
        let recorder = EventRecorder()
        let client = try await makeClient(transport: transport, hook: recorder.hook)
        _ = try await client.checkAccess("read", resource: "r-1")

        XCTAssertEqual(recorder.kinds, ["start", "end", "retry", "start", "end"])
        // Emitting both pairs as attempt 1 would make a retried call indistinguishable from a
        // single slow one.
        XCTAssertEqual(recorder.startAttempts, [1, 2])

        guard case let .requestStart(operation, method, template, _) = recorder.events[0] else {
            return XCTFail("expected a requestStart")
        }
        XCTAssertEqual(operation, "checkAccess")
        XCTAssertEqual(method, "POST")
        // The path TEMPLATE, never a substituted URL — a metric label carrying a UUID is a
        // cardinality bomb.
        XCTAssertEqual(template, "/api/v1/authz/check")
    }

    func testAFailingCallStillEmitsRequestEnd() async throws {
        let transport = ScriptedTransport(statuses: [nil])
        let recorder = EventRecorder()
        let client = try await makeClient(transport: transport, retryEnabled: false, hook: recorder.hook)
        await XCTAssertThrowsErrorAsync(try await client.checkAccess("read", resource: "r-1"))

        XCTAssertEqual(recorder.kinds, ["start", "end"])
        guard case let .requestEnd(_, _, _, _, status, _, outcome) = recorder.events[1] else {
            return XCTFail("expected a requestEnd")
        }
        XCTAssertEqual(outcome, .failure)
        // A nil status means the call never got a response, which is a different fact from a 500
        // and must stay distinguishable in a metrics backend.
        XCTAssertNil(status)
    }

    func testNoHookInstalledBehavesIdentically() async throws {
        // §19.2 rule 1, and §19.4's "a client with no hook installed behaves identically to one
        // before this section existed".
        let transport = ScriptedTransport(statuses: [503, 200])
        let client = try await makeClient(transport: transport)
        let result = try await client.checkAccess("read", resource: "r-1")
        XCTAssertTrue(result.allowed)
        XCTAssertEqual(transport.requestCount, 2)
    }

    func testNoEventPayloadCarriesAToken() async throws {
        // §19.2 rule 3. This surface exists to be shipped to a metrics backend, which is the last
        // place a bearer token should land.
        let transport = ScriptedTransport(
            statuses: [503],
            body: ["access_token": "eyJhbGciOiJFZERTQSJ9.secret.sig"])
        let recorder = EventRecorder()
        let client = try await makeClient(transport: transport, hook: recorder.hook)
        await XCTAssertThrowsErrorAsync(try await client.checkAccess("read", resource: "r-1"))

        XCTAssertFalse(recorder.events.isEmpty)
        let rendered = String(describing: recorder.events).lowercased()
        XCTAssertFalse(rendered.contains("eyj"), "no JWT-shaped string in telemetry")
        XCTAssertFalse(rendered.contains("secret"))
        XCTAssertFalse(rendered.contains("authorization"))
    }

    func testAClampedSettingIsReportedNotSwallowed() async throws {
        // §19.2 rule 6. An operator who set a 60-second memo TTL believes their staleness bound is
        // 60 seconds. It is five. Clamping is right; doing it silently leaves their revocation
        // reasoning wrong by a factor of twelve with nothing anywhere to say so.
        let recorder = EventRecorder()
        _ = try await makeClient(transport: ScriptedTransport(), memoTtl: 60, hook: recorder.hook)

        XCTAssertEqual(recorder.clamps.count, 1)
        guard case let .configClamped(setting, requested, effective, reference) = recorder.clamps[0] else {
            return XCTFail("expected a configClamped")
        }
        XCTAssertEqual(setting, "decisionMemoTtl")
        XCTAssertEqual(requested, "60.0s")
        XCTAssertEqual(effective, "5.0s")
        XCTAssertEqual(reference, "§17.1 rule 2")
    }

    func testAValueInsideItsLimitReportsNothing() async throws {
        // An event that fires when nothing happened trains its reader to ignore it, which costs
        // exactly the case above.
        let inRange = EventRecorder()
        _ = try await makeClient(transport: ScriptedTransport(), memoTtl: 2, hook: inRange.hook)
        XCTAssertTrue(inRange.clamps.isEmpty, "2s is inside the 5s ceiling")

        let boundary = EventRecorder()
        _ = try await makeClient(transport: ScriptedTransport(),
                                 memoTtl: DecisionMemo.maxTTL, hook: boundary.hook)
        XCTAssertTrue(boundary.clamps.isEmpty, "the ceiling exactly is not a clamp")

        let disabled = EventRecorder()
        _ = try await makeClient(transport: ScriptedTransport(), hook: disabled.hook)
        XCTAssertTrue(disabled.clamps.isEmpty, "the disabled default is not a clamped setting")

        let negative = EventRecorder()
        _ = try await makeClient(transport: ScriptedTransport(), memoTtl: -5, hook: negative.hook)
        XCTAssertTrue(negative.clamps.isEmpty,
                      "a negative TTL disables the memo; it is not clamped up to the ceiling")
    }

    func testAnUninstalledDispatcherIsInert() {
        let dispatcher = TelemetryDispatcher(nil)
        XCTAssertFalse(dispatcher.installed)
        // Must not trap, and must reach no hook that is not there.
        dispatcher.emit(.refresh(role: .leader, duration: 0.001))
        dispatcher.emit(.requestStart(operation: "op", method: "POST",
                                      pathTemplate: "/api/v1/authz/check", attempt: 1))
    }
}

/// A mutable clock, so the TTL boundary can be crossed without waiting.
private final class MutableClock: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: TimeInterval
    init(_ value: TimeInterval) { storage = value }
    var value: TimeInterval {
        get { lock.lock(); defer { lock.unlock() }; return storage }
        set { lock.lock(); storage = newValue; lock.unlock() }
    }
}

/// `XCTAssertThrowsError` has no async overload on Linux's swift-corelibs-xctest, and every
/// assertion in this file is on an `actor` method.
func XCTAssertThrowsErrorAsync<T>(
    _ expression: @autoclosure () async throws -> T,
    _ message: String = "expected an error",
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        _ = try await expression()
        XCTFail(message, file: file, line: line)
    } catch {
        // expected
    }
}
