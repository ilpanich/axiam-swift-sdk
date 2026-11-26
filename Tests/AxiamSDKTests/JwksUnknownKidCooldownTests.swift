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

        init(signers: [TestSigner]) { self.signers = signers }

        var fetchCount: Int { lock.locked { fetches } }
        func publish(_ signers: [TestSigner]) { lock.locked { self.signers = signers } }

        func execute(_ spec: HTTPRequestSpec, timeout: TimeInterval) async throws -> HTTPResponseData {
            let published = lock.locked { () -> [TestSigner] in
                fetches += 1
                return signers
            }
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
}
