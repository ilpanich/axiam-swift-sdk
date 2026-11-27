import XCTest
import Foundation
@testable import AxiamSDK

/// CONTRACT.md §12.4 rule 2 (contract 1.68; C5): an unknown `kid` causes **at most one** JWKS
/// re-fetch per cooldown window, and the rule is not weakened into "never re-fetch".
///
/// The clock is injected and held still; nothing sleeps.
final class JwksUnknownKidCooldownTests: XCTestCase {

    /// A clock the test moves by hand.
    final class TestClock: @unchecked Sendable {
        private let lock = NSLock()
        private var current = Date(timeIntervalSince1970: 1_800_000_000)

        func now() -> Date { lock.locked { current } }
        func advance(by seconds: TimeInterval) { lock.locked { current = current.addingTimeInterval(seconds) } }
    }

    /// A counting JWKS endpoint whose published keys the test can swap (a rotation).
    final class CountingJwksTransport: HTTPTransport, @unchecked Sendable {
        private let lock = NSLock()
        private var signers: [TestSigner]
        private var fetches = 0
        private var outage = false
        private var gateArmed = false
        private var gateEntered = false
        private var releaseRequested = false
        private var gateContinuation: CheckedContinuation<Void, Never>?

        init(signers: [TestSigner]) { self.signers = signers }

        var fetchCount: Int { lock.locked { fetches } }
        /// While `true`, every fetch fails as a transport error.
        func setOutage(_ down: Bool) { lock.locked { outage = down } }
        struct Outage: Error {}

        /// The next fetch blocks inside `execute` (after being counted) until ``release()``.
        func armGate() { lock.locked { gateArmed = true } }

        func waitUntilGateEntered() async throws {
            while !lock.locked({ gateEntered }) { try await Task.sleep(nanoseconds: 1_000_000) }
        }

        func release() {
            let continuation = lock.locked { () -> CheckedContinuation<Void, Never>? in
                releaseRequested = true
                let held = gateContinuation
                gateContinuation = nil
                return held
            }
            continuation?.resume()
        }
        func publish(_ signers: [TestSigner]) { lock.locked { self.signers = signers } }

        func execute(_ spec: HTTPRequestSpec, timeout: TimeInterval) async throws -> HTTPResponseData {
            let (published, down) = lock.locked { () -> ([TestSigner], Bool) in
                fetches += 1
                return (signers, outage)
            }
            let block = lock.locked { () -> Bool in
                if gateArmed { gateArmed = false; gateEntered = true; return true }
                return false
            }
            if block {
                await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                    let resumeNow = lock.locked { () -> Bool in
                        if releaseRequested { return true }
                        gateContinuation = continuation
                        return false
                    }
                    if resumeNow { continuation.resume() }
                }
            }
            if down { throw Outage() }
            let body = try JSONSerialization.data(withJSONObject: TestSigner.jwksJSON(of: published))
            return HTTPResponseData(status: 200, headers: [("Content-Type", "application/json")], body: body)
        }

        func shutdown() async throws {}
    }

    private func claims() -> [String: Any] {
        ["sub": "user-42", "exp": Date().addingTimeInterval(3600).timeIntervalSince1970]
    }

    private func makeVerifier(
        _ transport: CountingJwksTransport, clock: TestClock
    ) -> JwksVerifier {
        JwksVerifier(
            transport: transport,
            baseURL: URL(string: "http://127.0.0.1:1")!,
            tenantHeaderValue: "tenant",
            unknownKidCooldown: 60,
            now: { clock.now() })
    }

    /// Fifty tokens with fifty different unknown `kid`s inside one window, against a warm cache,
    /// cause at most one fetch and are all refused; then, with the clock past the window and a
    /// rotated set published, a token with the new `kid` is accepted after one fetch.
    func testFiftyUnknownKidsInOneWindowCauseAtMostOneFetchAndARotatedKeyIsAcceptedAfterOne() async throws {
        let signer = TestSigner(kid: "current-key")
        let transport = CountingJwksTransport(signers: [signer])
        let clock = TestClock()
        let verifier = makeVerifier(transport, clock: clock)

        // Warm the cache with one token carrying the served `kid`.
        _ = try await verifier.verifySignatureOnlyUnchecked(token: signer.makeJWT(claims: claims()))
        XCTAssertEqual(transport.fetchCount, 1)

        for index in 0..<50 {
            let token = signer.makeJWT(claims: claims(), kidOverride: "unknown-kid-\(index)")
            do {
                _ = try await verifier.verifySignatureOnlyUnchecked(token: token)
                XCTFail("unknown kid \(index) must be refused")
            } catch let error as AuthError {
                XCTAssertEqual(error.oauthError, "unknown_kid")
            }
        }
        XCTAssertLessThanOrEqual(
            transport.fetchCount - 1, 1, "fifty unknown kids in one window may cause at most one re-fetch")

        // Past the window, with a rotated set published: accepted after exactly one fetch.
        clock.advance(by: 61)
        let rotated = TestSigner(kid: "rotated-key")
        transport.publish([signer, rotated])
        let before = transport.fetchCount
        let verified = try await verifier.verifySignatureOnlyUnchecked(
            token: rotated.makeJWT(claims: claims()))
        XCTAssertEqual(verified.claims.sub, "user-42")
        XCTAssertEqual(transport.fetchCount - before, 1, "the rule is not 'never re-fetch'")
    }

    /// A token with no `kid` is refused without any fetch beyond the cache fill: there is nothing
    /// to look for, so it cannot be used to drive fetching either.
    func testAKidlessTokenIsRefusedAndNeverTriggersARefetch() async throws {
        let signer = TestSigner(kid: "current-key")
        let transport = CountingJwksTransport(signers: [signer])
        let verifier = makeVerifier(transport, clock: TestClock())

        _ = try await verifier.verifySignatureOnlyUnchecked(token: signer.makeJWT(claims: claims()))
        for _ in 0..<5 {
            do {
                _ = try await verifier.verifySignatureOnlyUnchecked(
                    token: signer.makeJWT(claims: claims(), includeKid: false))
                XCTFail("a kid-less token must be refused")
            } catch let error as AuthError {
                XCTAssertEqual(error.oauthError, "unknown_kid")
            }
        }
        XCTAssertEqual(transport.fetchCount, 1)
    }

    /// A token whose key arrives while a re-fetch is in flight is not refused from the stale
    /// snapshot it started with: with the window open it waits for that fetch and re-selects from
    /// the set it brought. One fetch only (no second one is started for it).
    func testARotatedKeyArrivingDuringAnInFlightRefetchIsAccepted() async throws {
        let signer = TestSigner(kid: "current-key")
        let rotated = TestSigner(kid: "rotated-key")
        let transport = CountingJwksTransport(signers: [signer])
        let verifier = makeVerifier(transport, clock: TestClock())

        _ = try await verifier.verifySignatureOnlyUnchecked(token: signer.makeJWT(claims: claims()))
        transport.publish([signer, rotated])
        transport.armGate()

        let unknownToken = signer.makeJWT(claims: claims(), kidOverride: "unknown")
        let rotatedToken = rotated.makeJWT(claims: claims())
        let first = Task { () -> Bool in
            do { _ = try await verifier.verifySignatureOnlyUnchecked(token: unknownToken); return true } catch { return false }
        }
        try await transport.waitUntilGateEntered()
        // The second verification starts from the old set with the window open and the fetch in flight.
        let second = Task { () -> Bool in
            do { _ = try await verifier.verifySignatureOnlyUnchecked(token: rotatedToken); return true } catch { return false }
        }
        try await Task.sleep(nanoseconds: 50_000_000)
        transport.release()

        let firstAccepted = await first.value
        let secondAccepted = await second.value
        XCTAssertFalse(firstAccepted, "the unknown kid stays refused")
        XCTAssertTrue(secondAccepted, "the rotated kid is accepted from the set the in-flight fetch brought")
        XCTAssertEqual(transport.fetchCount, 2)
    }

    /// One transient failed refresh of an expired cache must not refuse every token: the keys
    /// already held keep verifying, and the endpoint is fetched at most once in the window.
    func testAFailedRefreshOfAnExpiredCacheKeepsServingTheHeldKeys() async throws {
        let signer = TestSigner(kid: "current-key")
        let transport = CountingJwksTransport(signers: [signer])
        let clock = TestClock()
        let verifier = makeVerifier(transport, clock: clock)

        _ = try await verifier.verifySignatureOnlyUnchecked(token: signer.makeJWT(claims: claims()))
        clock.advance(by: 301)   // past the 300 s cache TTL
        transport.setOutage(true)

        for _ in 0..<10 {
            let verified = try await verifier.verifySignatureOnlyUnchecked(token: signer.makeJWT(claims: claims()))
            XCTAssertEqual(verified.claims.sub, "user-42")
        }
        do {
            _ = try await verifier.verifySignatureOnlyUnchecked(
                token: signer.makeJWT(claims: claims(), kidOverride: "unknown"))
            XCTFail("an unknown kid is still refused")
        } catch let error as AuthError {
            XCTAssertEqual(error.oauthError, "unknown_kid")
        }
        XCTAssertEqual(transport.fetchCount, 2, "the warm fetch and one failed refresh, nothing more")
    }

    /// The stale fallback is bounded: keys loaded at t=0 with the endpoint failing afterwards
    /// verify at t=301 and t=599, are refused at t=601, and the endpoint is still fetched at most
    /// once per window.
    func testTheStaleFallbackIsBoundedToTtlPlusMaxStale() async throws {
        let signer = TestSigner(kid: "current-key")
        let transport = CountingJwksTransport(signers: [signer])
        let clock = TestClock()
        let verifier = makeVerifier(transport, clock: clock)

        _ = try await verifier.verifySignatureOnlyUnchecked(token: signer.makeJWT(claims: claims()))
        XCTAssertEqual(transport.fetchCount, 1)
        transport.setOutage(true)

        clock.advance(by: 301)
        for _ in 0..<5 {
            _ = try await verifier.verifySignatureOnlyUnchecked(token: signer.makeJWT(claims: claims()))
        }
        XCTAssertEqual(transport.fetchCount, 2, "one failed refresh in the window")

        clock.advance(by: 298)   // t = 599, a new window
        for _ in 0..<5 {
            _ = try await verifier.verifySignatureOnlyUnchecked(token: signer.makeJWT(claims: claims()))
        }
        XCTAssertEqual(transport.fetchCount, 3, "one more failed refresh, in its own window")

        clock.advance(by: 2)     // t = 601: older than 300 + 300
        for _ in 0..<5 {
            do {
                _ = try await verifier.verifySignatureOnlyUnchecked(token: signer.makeJWT(claims: claims()))
                XCTFail("keys older than the stale bound must not verify")
            } catch is CountingJwksTransport.Outage { /* the recorded failure */ }
        }
        XCTAssertEqual(transport.fetchCount, 3, "the recorded failure is replayed, no fetch per token")
    }

    /// An unavailable JWKS endpoint costs one fetch per window, not one per presented token.
    func testAFailingJwksEndpointIsFetchedAtMostOncePerWindow() async throws {
        let signer = TestSigner(kid: "current-key")
        let transport = CountingJwksTransport(signers: [signer])
        transport.setOutage(true)
        let clock = TestClock()
        let verifier = makeVerifier(transport, clock: clock)

        for _ in 0..<20 {
            do {
                _ = try await verifier.verifySignatureOnlyUnchecked(token: signer.makeJWT(claims: claims()))
                XCTFail("must be refused during an outage")
            } catch is CountingJwksTransport.Outage { /* the recorded failure */ }
        }
        XCTAssertEqual(transport.fetchCount, 1)

        // Past the window, and recovered, the next token fetches once and verifies.
        clock.advance(by: 61)
        transport.setOutage(false)
        _ = try await verifier.verifySignatureOnlyUnchecked(token: signer.makeJWT(claims: claims()))
        XCTAssertEqual(transport.fetchCount, 2)
    }

    /// A JWKS document with no keys is rate-limited the same way.
    func testAnEmptyJwksIsFetchedAtMostOncePerWindow() async throws {
        let signer = TestSigner(kid: "current-key")
        let transport = CountingJwksTransport(signers: [])
        let verifier = makeVerifier(transport, clock: TestClock())
        for _ in 0..<20 {
            do {
                _ = try await verifier.verifySignatureOnlyUnchecked(token: signer.makeJWT(claims: claims()))
                XCTFail("must be refused with no keys")
            } catch let error as AuthError {
                XCTAssertTrue(error.message.contains("no keys"), error.message)
            }
        }
        XCTAssertEqual(transport.fetchCount, 1)
    }
}
