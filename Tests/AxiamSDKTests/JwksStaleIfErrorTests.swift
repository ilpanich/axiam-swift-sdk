import XCTest
import Foundation
@testable import AxiamSDK

/// CONTRACT.md §12.4 rule 2, "Stale-if-error, bounded" (contract 1.69; D-10) — the conformance
/// test, with an injected clock and a counting mock endpoint. Nothing sleeps.
///
/// The verifier already conformed on the stale bound and on treating an empty set as a failed
/// refresh; those tests are pins. The TTL clamp is the one behaviour this change adds.
final class JwksStaleIfErrorTests: XCTestCase {
    private typealias Clock = JwksUnknownKidCooldownTests.TestClock
    private typealias Transport = JwksUnknownKidCooldownTests.CountingJwksTransport

    private func claims() -> [String: Any] {
        ["sub": "user-42", "exp": Date().addingTimeInterval(3600).timeIntervalSince1970]
    }

    private func makeVerifier(
        _ transport: Transport, clock: Clock, cacheTTL: TimeInterval = 300
    ) -> JwksVerifier {
        JwksVerifier(
            transport: transport,
            baseURL: URL(string: "http://127.0.0.1:1")!,
            tenantHeaderValue: "tenant",
            cacheTTL: cacheTTL,
            unknownKidCooldown: 60,
            now: { clock.now() })
    }

    private func accepts(_ verifier: JwksVerifier, _ token: String) async -> Bool {
        let accepted: Bool
        do { _ = try await verifier.verifySignatureOnlyUnchecked(token: token); accepted = true } catch { accepted = false }
        // A refresh started in the background is not part of the answer; let it settle so the
        // fetch counts that follow are deterministic.
        await verifier.awaitInFlight()
        return accepted
    }

    /// Fill at t0, every later fetch fails: held kid accepted at TTL+1, unknown kid refused and
    /// held kid accepted at TTL+250, held kid refused at TTL+301, accepted after one successful
    /// fetch once the window has passed.
    func testHeldKeysServeUntilTtlPlus300ThenRefuseUntilAFetchSucceeds() async throws {
        let signer = TestSigner(kid: "held-key")
        let transport = Transport(signers: [signer])
        let clock = Clock()
        let verifier = makeVerifier(transport, clock: clock)

        let ok = await accepts(verifier, signer.makeJWT(claims: claims()))
        XCTAssertTrue(ok)
        XCTAssertEqual(transport.fetchCount, 1)
        transport.setOutage(true)

        clock.advance(by: 301)   // TTL + 1
        let atTtlPlus1 = await accepts(verifier, signer.makeJWT(claims: claims()))
        XCTAssertTrue(atTtlPlus1, "held kid accepted at TTL + 1 s")
        XCTAssertEqual(transport.fetchCount, 2, "one failed refresh was attempted")

        clock.advance(by: 249)   // TTL + 250
        let unknown = await accepts(verifier, signer.makeJWT(claims: claims(), kidOverride: "unknown"))
        XCTAssertFalse(unknown, "unknown kid refused at TTL + 250 s")
        let held = await accepts(verifier, signer.makeJWT(claims: claims()))
        XCTAssertTrue(held, "held kid still accepted at TTL + 250 s")

        clock.advance(by: 51)    // TTL + 301
        let past = await accepts(verifier, signer.makeJWT(claims: claims()))
        XCTAssertFalse(past, "held kid refused at TTL + 301 s")

        // The mock serves the set again; past the window the held kid is accepted after one fetch.
        transport.setOutage(false)
        clock.advance(by: 61)
        let before = transport.fetchCount
        let recovered = await accepts(verifier, signer.makeJWT(claims: claims()))
        XCTAssertTrue(recovered, "accepted again after one successful fetch")
        XCTAssertEqual(transport.fetchCount - before, 1)
    }

    /// The same first half with the mock answering `200 {"keys":[]}`: the empty set is a failed
    /// refresh, not a replacement, so the held kid is still accepted at TTL + 1 s and the
    /// anchor does not move (still refused at TTL + 301 s).
    func testAnEmptyKeySetIsAFailedRefreshThatNeitherReplacesNorMovesTheAnchor() async throws {
        let signer = TestSigner(kid: "held-key")
        let transport = Transport(signers: [signer])
        let clock = Clock()
        let verifier = makeVerifier(transport, clock: clock)

        let ok = await accepts(verifier, signer.makeJWT(claims: claims()))
        XCTAssertTrue(ok)
        transport.publish([])    // 200 {"keys":[]}

        clock.advance(by: 301)   // TTL + 1
        let held = await accepts(verifier, signer.makeJWT(claims: claims()))
        XCTAssertTrue(held, "an empty set leaves the held kid accepted")
        XCTAssertEqual(transport.fetchCount, 2, "the empty response was fetched")

        clock.advance(by: 300)   // TTL + 301
        let past = await accepts(verifier, signer.makeJWT(claims: claims()))
        XCTAssertFalse(past, "an empty set does not extend the stale window")
    }

    /// A TTL larger than 300 s is clamped to 300 s: with a requested one hour, the refresh is
    /// still due at 301 s and the held keys still stop at 600 s.
    func testACacheTtlAbove300SecondsIsClampedTo300() async throws {
        let signer = TestSigner(kid: "held-key")
        let transport = Transport(signers: [signer])
        let clock = Clock()
        let verifier = makeVerifier(transport, clock: clock, cacheTTL: 3600)

        let ok = await accepts(verifier, signer.makeJWT(claims: claims()))
        XCTAssertTrue(ok)
        transport.setOutage(true)

        clock.advance(by: 301)
        let atTtlPlus1 = await accepts(verifier, signer.makeJWT(claims: claims()))
        XCTAssertTrue(atTtlPlus1)
        XCTAssertEqual(transport.fetchCount, 2, "a refresh is due past 300 s, not past the requested 3600 s")

        clock.advance(by: 300)   // 601 s after the fill
        let past = await accepts(verifier, signer.makeJWT(claims: claims()))
        XCTAssertFalse(past, "the stale bound is 300 + 300 s, not requested TTL + 300 s")
    }

    /// A TTL below 300 s is honoured, not raised.
    func testACacheTtlBelow300SecondsIsHonoured() async throws {
        let signer = TestSigner(kid: "held-key")
        let transport = Transport(signers: [signer])
        let clock = Clock()
        let verifier = makeVerifier(transport, clock: clock, cacheTTL: 10)

        let ok = await accepts(verifier, signer.makeJWT(claims: claims()))
        XCTAssertTrue(ok)
        clock.advance(by: 11)
        let again = await accepts(verifier, signer.makeJWT(claims: claims()))
        XCTAssertTrue(again)
        XCTAssertEqual(transport.fetchCount, 2, "refreshed after the 10 s TTL")
    }

    /// The unknown-kid refresh is itself the failing fetch: it is refused, the held kid still
    /// verifies, and the anchor does not move (the held kid is refused 601 s after the fill).
    func testAFailedUnknownKidRefreshNeverMovesTheAnchor() async throws {
        let signer = TestSigner(kid: "held-key")
        let transport = Transport(signers: [signer])
        let clock = Clock()
        let verifier = makeVerifier(transport, clock: clock)

        let ok = await accepts(verifier, signer.makeJWT(claims: claims()))
        XCTAssertTrue(ok)
        transport.setOutage(true)

        clock.advance(by: 100)   // still inside the TTL: the unknown kid triggers the refresh
        let unknown = await accepts(verifier, signer.makeJWT(claims: claims(), kidOverride: "unknown"))
        XCTAssertFalse(unknown)
        XCTAssertEqual(transport.fetchCount, 2, "the unknown-kid refresh was attempted and failed")
        let held = await accepts(verifier, signer.makeJWT(claims: claims()))
        XCTAssertTrue(held, "the held kid still verifies")

        clock.advance(by: 501)   // t0 + 601
        let past = await accepts(verifier, signer.makeJWT(claims: claims()))
        XCTAssertFalse(past, "the failed refresh did not move the anchor")
    }

    /// A transport that answers 200 with the set first, then a configurable non-200 status with
    /// keys in the body.
    private final class StatusTransport: HTTPTransport, @unchecked Sendable {
        private let lock = NSLock()
        private let signer: TestSigner
        private var status = 200
        private var fetches = 0
        init(signer: TestSigner) { self.signer = signer }
        var fetchCount: Int { lock.locked { fetches } }
        func setStatus(_ code: Int) { lock.locked { status = code } }
        func execute(_ spec: HTTPRequestSpec, timeout: TimeInterval) async throws -> HTTPResponseData {
            let code = lock.locked { () -> Int in fetches += 1; return status }
            let body = try JSONSerialization.data(withJSONObject: TestSigner.jwksJSON(of: [signer]))
            return HTTPResponseData(status: code, headers: [("Content-Type", "application/json")], body: body)
        }
        func shutdown() async throws {}
    }

    /// Only a `200` is a successful fetch: a `203` or `206` carrying keys is a failed refresh, so
    /// it leaves the anchor where it was. (On the former `200..<300` check the 203 at t0 + 301
    /// counted as a success, moved the anchor, and the held kid was still accepted at t0 + 601.)
    func testANon200SuccessStatusIsAFailedRefresh() async throws {
        for code in [203, 206] {
            let signer = TestSigner(kid: "held-key")
            let transport = StatusTransport(signer: signer)
            let clock = Clock()
            let verifier = JwksVerifier(
                transport: transport,
                baseURL: URL(string: "http://127.0.0.1:1")!,
                tenantHeaderValue: "tenant",
                unknownKidCooldown: 60,
                now: { clock.now() })

            let ok = await accepts(verifier, signer.makeJWT(claims: claims()))
            XCTAssertTrue(ok)
            transport.setStatus(code)

            clock.advance(by: 301)
            let held = await accepts(verifier, signer.makeJWT(claims: claims()))
            XCTAssertTrue(held, "\(code): the held set is kept")
            XCTAssertEqual(transport.fetchCount, 2, "\(code): a refresh was attempted")

            clock.advance(by: 300)   // t0 + 601
            let past = await accepts(verifier, signer.makeJWT(claims: claims()))
            XCTAssertFalse(past, "\(code): the anchor did not move")
        }
    }

    // MARK: - Verification never waits for a refresh while usable keys are held (reading 8)

    /// Past the TTL with the held keys inside TTL + 300 s, the refresh is started but not awaited:
    /// the verification returns while the fetch is still held open.
    func testAUsableHeldSetNeverWaitsForAnInFlightRefresh() async throws {
        let signer = TestSigner(kid: "held-key")
        let transport = Transport(signers: [signer])
        let clock = Clock()
        let verifier = makeVerifier(transport, clock: clock)

        let ok = await accepts(verifier, signer.makeJWT(claims: claims()))
        XCTAssertTrue(ok)
        clock.advance(by: 301)
        transport.armGate()

        // Not through `accepts`: that would wait for the held-open fetch.
        _ = try await verifier.verifySignatureOnlyUnchecked(token: signer.makeJWT(claims: claims()))
        try await transport.waitUntilGateEntered()
        _ = try await verifier.verifySignatureOnlyUnchecked(token: signer.makeJWT(claims: claims()))
        XCTAssertEqual(transport.fetchCount, 2, "one refresh, shared, still held open")

        transport.release()
        await verifier.awaitInFlight()
        // The flight recorded its own outcome: the new anchor serves a fetch-free verification.
        clock.advance(by: 250)
        let served = await accepts(verifier, signer.makeJWT(claims: claims()))
        XCTAssertTrue(served)
        XCTAssertEqual(transport.fetchCount, 2)
    }

    // MARK: - Total deadline and body cap

    /// A transport whose request never completes, as one that drips its body would: it sleeps
    /// until it is cancelled.
    private final class DrippingTransport: HTTPTransport, @unchecked Sendable {
        private let lock = NSLock()
        private var calls = 0
        var callCount: Int { lock.locked { calls } }
        func execute(_ spec: HTTPRequestSpec, timeout: TimeInterval) async throws -> HTTPResponseData {
            lock.locked { calls += 1 }
            while true { try await Task.sleep(nanoseconds: 1_000_000_000) }
        }
        func shutdown() async throws {}
    }

    func testADrippedBodyIsCutOffByATotalDeadlineAndCountsAsAFailedRefresh() async throws {
        let transport = DrippingTransport()
        let verifier = JwksVerifier(
            transport: transport,
            baseURL: URL(string: "http://127.0.0.1:1")!,
            tenantHeaderValue: "tenant",
            requestTimeout: 0.2,
            unknownKidCooldown: 60)
        let signer = TestSigner(kid: "k")
        do {
            _ = try await verifier.verifySignatureOnlyUnchecked(token: signer.makeJWT(claims: claims()))
            XCTFail("a fetch that never completes must fail at the deadline")
        } catch let error as AuthError {
            XCTAssertTrue(error.message.contains("no complete response"), error.message)
        }
        // The failure is recorded: the next verification replays it with no second fetch.
        do {
            _ = try await verifier.verifySignatureOnlyUnchecked(token: signer.makeJWT(claims: claims()))
            XCTFail("must be refused")
        } catch is AuthError {}
        XCTAssertEqual(transport.callCount, 1)
    }

    /// A transport answering 200 with an oversized body.
    private final class OversizedTransport: HTTPTransport, @unchecked Sendable {
        func execute(_ spec: HTTPRequestSpec, timeout: TimeInterval) async throws -> HTTPResponseData {
            HTTPResponseData(status: 200, headers: [], body: Data(count: JwksVerifier.maxBodyBytes + 1))
        }
        func shutdown() async throws {}
    }

    func testAnOversizedJwksBodyIsAFailedRefresh() async throws {
        let verifier = JwksVerifier(
            transport: OversizedTransport(),
            baseURL: URL(string: "http://127.0.0.1:1")!,
            tenantHeaderValue: "tenant")
        let signer = TestSigner(kid: "k")
        do {
            _ = try await verifier.verifySignatureOnlyUnchecked(token: signer.makeJWT(claims: claims()))
            XCTFail("an oversized body must be refused")
        } catch let error as AuthError {
            XCTAssertTrue(error.message.contains("too large"), error.message)
        }
    }

    // MARK: - A clock stepped back (readings 7 and 9)

    /// A negative age is not trusted: with the clock behind the last successful fetch the held
    /// keys do not verify and a refresh is due.
    func testANegativeAgeDistrustsTheHeldKeysAndDuesARefresh() async throws {
        let signer = TestSigner(kid: "held-key")
        let transport = Transport(signers: [signer])
        let clock = Clock()
        let verifier = makeVerifier(transport, clock: clock)

        let ok = await accepts(verifier, signer.makeJWT(claims: claims()))
        XCTAssertTrue(ok)
        clock.advance(by: -10)
        transport.setOutage(true)

        let refused = await accepts(verifier, signer.makeJWT(claims: claims()))
        XCTAssertFalse(refused, "held keys are not trusted on a negative age")
        XCTAssertEqual(transport.fetchCount, 2, "a refresh was due and attempted")
    }

    /// A cooldown window whose start lies in the future is over: after a failed first fetch, with
    /// the clock stepped back, the next verification fetches again instead of replaying the failure.
    func testAWindowStartingInTheFutureIsOver() async throws {
        let signer = TestSigner(kid: "held-key")
        let transport = Transport(signers: [signer])
        transport.setOutage(true)
        let clock = Clock()
        let verifier = makeVerifier(transport, clock: clock)

        let first = await accepts(verifier, signer.makeJWT(claims: claims()))
        XCTAssertFalse(first)
        XCTAssertEqual(transport.fetchCount, 1)
        clock.advance(by: -100)
        transport.setOutage(false)

        let second = await accepts(verifier, signer.makeJWT(claims: claims()))
        XCTAssertTrue(second, "the stale window is over, so the fetch is attempted and succeeds")
        XCTAssertEqual(transport.fetchCount, 2)
    }
}
