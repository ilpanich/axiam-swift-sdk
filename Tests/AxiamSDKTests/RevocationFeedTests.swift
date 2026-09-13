import Foundation
import XCTest

@testable import AxiamSDK

/// CONTRACT.md §10.4 — the optional session-revocation feed (contract 1.44, AXIAM threats
/// T-39 and T-143).
///
/// The feature is a narrowing, not a control, and the tests are organised around the five
/// rules that make that true rather than around the type's method list:
///
/// - **Default off** — a client built as every caller builds one today fetches nothing,
///   asserted by counting requests on the wire rather than by inspecting a flag.
/// - **Never on the request path** — a revoked session is rejected *after one poll and not
///   before*, which pins that the guard is not fetching per request.
/// - **Never fail closed** — unreachable, non-`200`, unparseable and wrong-`alg` each behave
///   as no feed at all, and specifically NOT as an empty list.
/// - **Only ever rejects** — a token that fails a §10.1 rule is rejected whatever the feed
///   says, and the feed is not even consulted for it.
/// - **No `sid`, never matched** — a client-credentials token, an RPT or a token exchange has
///   no session behind it.
final class RevocationFeedTests: XCTestCase {
    let signer = TestSigner()

    static let tenantUUID = "tenant-uuid-1"

    /// The §10.4 pinned vector: this `sid` hashes to this entry. Pinned rather than computed
    /// so a change to ``RevocationFeed/entry(for:)`` is a test failure and not a
    /// silently-agreeing round trip.
    static let pinnedSid = "6f3e0a5c-1b2d-4e8f-9a7b-0c1d2e3f4a5b"

    static let pinnedEntry = "i9N2lYMTV4FhA0husWjGYCqJXXTb7_fMBuomhWjSsgQ"

    /// A claim set that satisfies every §10.1 rule, optionally carrying `sid`.
    private func claims(sid: String? = nil, expiresIn: TimeInterval = 3600) -> [String: Any] {
        var claims: [String: Any] = [
            "sub": "user-42",
            "tenant_id": Self.tenantUUID,
            "roles": ["admin"],
            "exp": Date().addingTimeInterval(expiresIn).timeIntervalSince1970,
        ]
        if let sid {
            claims["sid"] = sid
        }
        return claims
    }

    /// The feed document, serialized ahead of the router closure.
    ///
    /// `Data` and not `[String: Any]`: `TestRouter` is `@Sendable`, and `Any` defeats
    /// `Sendable` checking, so a fixture has to become bytes before the closure captures it.
    private func feedBody(_ entries: [String]) -> Data {
        TestResponse.jsonBody([
            "alg": "SHA-256",
            "issued_at": Int(Date().timeIntervalSince1970),
            "ttl": 900,
            "revoked": entries,
        ])
    }

    /// A client whose server serves the JWKS and, at `/oauth2/revocations`, whatever
    /// `feed` returns — counting both so "did not fetch" can be proven rather than asserted.
    private func withFeedClient(
        enabled: Bool,
        feed: @escaping @Sendable (Int) -> TestResponse,
        body: (AxiamClient, TestHTTPServer) async throws -> Void
    ) async throws {
        let signer = self.signer
        try await withClient(
            makeConfig: {
                try TestKit.makeConfig(
                    port: $0,
                    tenantSlug: nil,
                    tenantID: Self.tenantUUID,
                    revocationFeedEnabled: enabled
                )
            },
            router: { request, state in
                if request.uri.hasSuffix("/oauth2/jwks") {
                    state.increment("jwks")
                    return .json(200, signer.jwksJSON())
                }
                if request.uri.contains("/oauth2/revocations") {
                    state.increment("feed")
                    return feed(state.count("feed"))
                }
                return .json(404, [:])
            },
            body: body
        )
    }

    private func authenticate(_ client: AxiamClient, _ jwt: String) async throws -> AxiamUser {
        try await client.makeAuthenticator()
            .authenticate(AxiamRequestContext(cookies: ["axiam_access": jwt]))
    }

    // MARK: - The entry encoding is pinned

    func testEntryForMatchesThePinnedVector() {
        XCTAssertEqual(RevocationFeed.entry(for: Self.pinnedSid), Self.pinnedEntry)
    }

    func testEntryForHashesTheClaimAsReadNotAReRenderedUuid() {
        // Upper-case is a DIFFERENT string and must hash differently: §10.4 says hash the
        // claim as read, precisely so the answer does not depend on a UUID parser.
        XCTAssertNotEqual(
            RevocationFeed.entry(for: Self.pinnedSid),
            RevocationFeed.entry(for: Self.pinnedSid.uppercased())
        )
    }

    func testEntryForIsBase64UrlUnpadded() {
        let entry = RevocationFeed.entry(for: Self.pinnedSid)
        XCTAssertFalse(entry.contains("="))
        XCTAssertFalse(entry.contains("+"))
        XCTAssertFalse(entry.contains("/"))
    }

    // MARK: - Default off

    func testNoFeedEnabledFetchesNothingAndAcceptsARevokedSession() async throws {
        // The I4 twin: a client built exactly as every caller builds one today. The session
        // IS revoked on the server, and this client neither knows nor asks.
        let body = feedBody([Self.pinnedEntry])
        try await withFeedClient(
            enabled: false,
            feed: { _ in TestResponse(status: 200, body: body) }
        ) { client, server in
            let jwt = self.signer.makeJWT(claims: self.claims(sid: Self.pinnedSid))
            let user = try await self.authenticate(client, jwt)
            XCTAssertEqual(user.userID, "user-42")
            XCTAssertEqual(server.state.count("feed"), 0)
        }
    }

    // MARK: - Never on the request path

    func testARevokedSessionIsRejectedAfterOnePollAndNotBefore() async throws {
        let body = feedBody([Self.pinnedEntry])
        try await withFeedClient(
            enabled: true,
            feed: { _ in TestResponse(status: 200, body: body) }
        ) { client, server in
            let jwt = self.signer.makeJWT(claims: self.claims(sid: Self.pinnedSid))

            do {
                _ = try await self.authenticate(client, jwt)
                XCTFail("a revoked session must be rejected")
            } catch let error as AuthError {
                XCTAssertTrue(error.message.contains("revoked"), "message was: \(error.message)")
            }
            XCTAssertEqual(server.state.count("feed"), 1)

            // Still rejected, and still exactly one fetch: the second answer came from the
            // cached set, which is what "never on the request path" means.
            do {
                _ = try await self.authenticate(client, jwt)
                XCTFail("a revoked session must stay rejected")
            } catch is AuthError {}
            XCTAssertEqual(server.state.count("feed"), 1)
        }
    }

    func testManyVerificationsPollOnceWithinOneInterval() async throws {
        let body = feedBody([Self.pinnedEntry])
        try await withFeedClient(
            enabled: true,
            feed: { _ in TestResponse(status: 200, body: body) }
        ) { client, server in
            let jwt = self.signer.makeJWT(claims: self.claims(sid: "some-other-session"))
            for _ in 0..<10 {
                _ = try await self.authenticate(client, jwt)
            }
            XCTAssertEqual(server.state.count("feed"), 1)
        }
    }

    func testAnUnlistedSessionIsAccepted() async throws {
        let body = feedBody([Self.pinnedEntry])
        try await withFeedClient(
            enabled: true,
            feed: { _ in TestResponse(status: 200, body: body) }
        ) { client, _ in
            let jwt = self.signer.makeJWT(claims: self.claims(sid: "a-session-nobody-revoked"))
            let user = try await self.authenticate(client, jwt)
            XCTAssertEqual(user.userID, "user-42")
        }
    }

    // MARK: - Never fail closed

    func testAFeedThatIsNotServedBehavesAsNoFeedAtAll() async throws {
        // The I4 twin for the feature ON: the feature is enabled and the deployment does not
        // publish the document. Every verification must succeed exactly as it does with the
        // feature off.
        try await withFeedClient(enabled: true, feed: { _ in .json(404, [:]) }) { client, server in
            let jwt = self.signer.makeJWT(claims: self.claims(sid: Self.pinnedSid))
            let user = try await self.authenticate(client, jwt)
            XCTAssertEqual(user.userID, "user-42")
            XCTAssertEqual(server.state.count("feed"), 1)
        }
    }

    func testAServerErrorBehavesAsNoFeedAtAll() async throws {
        try await withFeedClient(enabled: true, feed: { _ in .json(500, [:]) }) { client, _ in
            let jwt = self.signer.makeJWT(claims: self.claims(sid: Self.pinnedSid))
            _ = try await self.authenticate(client, jwt)
        }
    }

    func testAnUnparseableBodyBehavesAsNoFeedAtAll() async throws {
        try await withFeedClient(
            enabled: true,
            feed: { _ in TestResponse(status: 200, body: Data("{not json".utf8)) }
        ) { client, _ in
            let jwt = self.signer.makeJWT(claims: self.claims(sid: Self.pinnedSid))
            _ = try await self.authenticate(client, jwt)
        }
    }

    func testAnUnknownAlgBehavesAsNoFeedAtAllNotAsAnEmptyList() async throws {
        // The document lists this very session. An SDK that ignored `alg` would reject; one
        // that read the document as an empty list would accept for the WRONG reason.
        let body = TestResponse.jsonBody(["alg": "SHA-512", "revoked": [Self.pinnedEntry]])
        try await withFeedClient(
            enabled: true,
            feed: { _ in TestResponse(status: 200, body: body) }
        ) { client, _ in
            let jwt = self.signer.makeJWT(claims: self.claims(sid: Self.pinnedSid))
            _ = try await self.authenticate(client, jwt)
        }
    }

    func testAFailedPollDoesNotUnrevokeAnAlreadyKnownSession() async throws {
        // This is the difference between "unusable" and "empty", made observable: the first
        // poll succeeds and knows the session is revoked; the second fails. A feed that
        // collapsed failure into an empty list would now ADMIT a session it had already been
        // told was revoked.
        let good = feedBody([Self.pinnedEntry])
        try await withFeedClient(
            enabled: true,
            feed: { n in
                n == 1
                    ? TestResponse(status: 200, body: good)
                    : TestResponse(status: 500, body: Data())
            }
        ) { client, server in
            let jwt = self.signer.makeJWT(claims: self.claims(sid: Self.pinnedSid))

            do {
                _ = try await self.authenticate(client, jwt)
                XCTFail("a revoked session must be rejected")
            } catch is AuthError {}

            // Force the interval to have elapsed, so the next verification really re-polls.
            if let feed = client.revocationFeed {
                await feed.setClock { Date().addingTimeInterval(600) }
            } else {
                XCTFail("the feed should have been built when enabled")
            }

            do {
                _ = try await self.authenticate(client, jwt)
                XCTFail("a failed poll must not un-revoke a known session")
            } catch is AuthError {}

            XCTAssertEqual(server.state.count("feed"), 2)
        }
    }

    func testAnOverflowingDocumentIsDroppedWholeNotTruncated() async throws {
        var entries = [Self.pinnedEntry]
        for index in 0..<RevocationFeed.maxEntries {
            entries.append("entry-\(index)")
        }
        let body = feedBody(entries)

        try await withFeedClient(
            enabled: true,
            feed: { _ in TestResponse(status: 200, body: body) }
        ) { client, _ in
            // Listed in the document, and admitted — because the whole set was dropped. A
            // truncating implementation would admit some revoked sessions and report none.
            let jwt = self.signer.makeJWT(claims: self.claims(sid: Self.pinnedSid))
            _ = try await self.authenticate(client, jwt)
        }
    }

    // MARK: - It only ever rejects

    func testATokenFailingASection101RuleIsRejectedWithoutConsultingTheFeed() async throws {
        let body = feedBody([])
        try await withFeedClient(
            enabled: true,
            feed: { _ in TestResponse(status: 200, body: body) }
        ) { client, server in
            // Wrong tenant: rejected by §10.1 long before §10.4 could have an opinion.
            var claims = self.claims(sid: Self.pinnedSid)
            claims["tenant_id"] = "some-other-tenant"
            let jwt = self.signer.makeJWT(claims: claims)

            do {
                _ = try await self.authenticate(client, jwt)
                XCTFail("a cross-tenant token must be rejected")
            } catch is AuthError {}

            XCTAssertEqual(server.state.count("feed"), 0)
        }
    }

    func testAnExpiredTokenIsRejectedWithoutConsultingTheFeed() async throws {
        let body = feedBody([])
        try await withFeedClient(
            enabled: true,
            feed: { _ in TestResponse(status: 200, body: body) }
        ) { client, server in
            let jwt = self.signer.makeJWT(
                claims: self.claims(sid: Self.pinnedSid, expiresIn: -3600))

            do {
                _ = try await self.authenticate(client, jwt)
                XCTFail("an expired token must be rejected")
            } catch is AuthError {}

            XCTAssertEqual(server.state.count("feed"), 0)
        }
    }

    // MARK: - A token with no sid is never matched

    func testATokenWithoutSidIsNeverMatched() async throws {
        // A client-credentials token, an RPT or a token exchange. The feed happens to list
        // the hash of the empty string; nothing may match it.
        let body = feedBody([RevocationFeed.entry(for: "")])
        try await withFeedClient(
            enabled: true,
            feed: { _ in TestResponse(status: 200, body: body) }
        ) { client, _ in
            let jwt = self.signer.makeJWT(claims: self.claims(sid: nil))
            let user = try await self.authenticate(client, jwt)
            XCTAssertEqual(user.userID, "user-42")
        }
    }

    // MARK: - Bounds

    func testThePollIntervalIsClampedUpNotRefused() async throws {
        try await withFeedClient(
            enabled: true,
            feed: { _ in TestResponse(status: 200, body: Data()) }
        ) { client, _ in
            let feed = client.revocationFeed
            XCTAssertNotNil(feed)
            // The default, since withFeedClient does not name one.
            let interval = await feed?.effectivePollInterval
            XCTAssertEqual(interval, RevocationFeed.defaultPollInterval)
        }

        // A caller who asks for something faster gets the fastest thing on offer, rather
        // than an error.
        try await withClient(
            makeConfig: {
                try TestKit.makeConfig(
                    port: $0,
                    revocationFeedEnabled: true,
                    revocationPollInterval: 1
                )
            },
            router: { _, _ in .json(404, [:]) },
            body: { client, _ in
                let interval = await client.revocationFeed?.effectivePollInterval
                XCTAssertEqual(interval, RevocationFeed.minPollInterval)
            }
        )
    }

    func testTheFeedIsNotBuiltAtAllWhenDisabled() async throws {
        // "Default off" as a structural property: there is no poller to call, not a poller
        // that declines to fetch.
        try await withFeedClient(
            enabled: false,
            feed: { _ in TestResponse(status: 200, body: Data()) }
        ) { client, _ in
            let feed = client.revocationFeed
            XCTAssertNil(feed)
        }
    }

    func testTheFeedPathIsTheDocumentedOne() {
        XCTAssertEqual(RevocationFeed.feedPath, "/oauth2/revocations")
    }
}
