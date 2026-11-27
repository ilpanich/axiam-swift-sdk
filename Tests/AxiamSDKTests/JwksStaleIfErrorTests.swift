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
        do { _ = try await verifier.verifySignatureOnlyUnchecked(token: token); return true } catch { return false }
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
}
