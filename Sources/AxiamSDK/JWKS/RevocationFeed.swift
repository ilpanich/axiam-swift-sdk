import Foundation

#if canImport(FoundationNetworking)
    import FoundationNetworking
#endif

import Crypto

/// The optional session-revocation feed poller (CONTRACT.md §10.4, contract 1.44 — AXIAM
/// threats T-39 and T-143).
///
/// ## What this narrows, and what it is not
///
/// An AXIAM access token is self-contained and valid for up to fifteen minutes, and this SDK
/// verifies it locally. A logout, a role removal or an account disable therefore does not
/// reach a token already in a caller's hands until it expires — §10.2 records that, and the
/// documented answer has been "route the decision through gRPC introspection instead", which
/// is correct and costs a round trip **per request**.
///
/// A deployment may publish `GET /oauth2/revocations`: the base64url-unpadded SHA-256 of
/// every session id revoked within the last access-token lifetime. A guard that polls it
/// rejects a revoked session within **one poll interval** instead of one token lifetime, for
/// one cacheable fetch per interval.
///
/// It is NOT a control, and every rule below follows from that:
///
/// - **Default off.** Nothing polls unless a caller constructs one and attaches it.
/// - **Never on the request path.** ``isRevoked(_:)`` answers from the cached set and, at
///   most, refreshes a set the *next* caller sees.
/// - **Never fail closed.** An unreachable feed, a non-`200`, a body that does not parse, an
///   `alg` this build does not know — every one of them behaves exactly as no feed at all.
///   Not as an empty list: an empty list asserts that nothing has been revoked, which is a
///   guard that silently honours no revocations while appearing to honour them.
/// - **It only ever rejects.** Every §10.1 rule runs first and still decides. The feed can
///   turn an accept into a reject and never the reverse.
/// - **A token with no `sid` is never matched.** There is no session behind a
///   client-credentials token, an RPT or a token exchange, and hashing `jti` instead would
///   match nothing while looking like it worked.
///
/// An `actor`, so one instance can be shared across guards and they poll once between them
/// rather than once each. Callers do not build one directly: set
/// ``AxiamConfig/revocationFeedEnabled`` and ``AxiamClient`` wires it to the same transport
/// every other call already uses.
public actor RevocationFeed {
    /// The published feed's path, resolved against a deployment's base URL.
    public static let feedPath = "/oauth2/revocations"

    /// The only digest the feed publishes, and the only one this poller accepts.
    ///
    /// A document naming anything else is treated as unusable — exactly as an unreachable
    /// feed is — rather than as a list of entries that happen not to match. Silently matching
    /// nothing is how a guard ends up reporting that it honours revocations while honouring
    /// none.
    private static let supportedAlg = "SHA-256"

    /// The shortest interval a caller may configure (§10.4 rule 2).
    ///
    /// Bounded because the feed is one deployment-wide document and a fleet of guards polling
    /// it at a hundred milliseconds is a load source rather than a security improvement. The
    /// floor is applied by **clamping**, not by refusing: a caller who asked for something
    /// faster gets the fastest thing on offer.
    public static let minPollInterval: TimeInterval = 15

    /// The interval §10.4 recommends, and the one a feed uses unless told otherwise.
    public static let defaultPollInterval: TimeInterval = 30

    /// The largest number of entries kept in the cache (§10.4 rule 2).
    ///
    /// The server bounds the document by its own revocation rate over one token lifetime, so
    /// this is defence against a server that stops doing so — a cache with no ceiling is an
    /// allocation an unauthenticated endpoint controls. Overflow drops the **whole** set
    /// rather than truncating it: a truncated set is a guard that admits some revoked
    /// sessions and reports none, which is worse than a guard that admits all of them and
    /// says the feed is unusable.
    public static let maxEntries = 100_000

    /// Caps what is read off the wire before the entry count can be known, since the count is
    /// only knowable after decoding. 64 bytes of entry plus JSON framing over
    /// ``maxEntries``, rounded up.
    private static let maxBodyBytes = 8 << 20

    /// The feed document as published. Only the two members the guard reads are modelled.
    private struct FeedDocument: Decodable {
        let alg: String?
        let revoked: [String]?
    }

    private let transport: HTTPTransport
    private let url: URL
    private let pollInterval: TimeInterval
    private let requestTimeout: TimeInterval

    /// `nil` means "never successfully fetched", which is NOT the same as an empty set, and is
    /// why this is compared against `nil` rather than by count.
    private var entries: Set<String>?

    private var lastAttempt: Date?

    /// A testing seam only; `nil` means the real clock. Not reachable from configuration.
    private var now: (@Sendable () -> Date)?

    /// Polls `{baseURL}/oauth2/revocations` through `transport`.
    ///
    /// A deployment that does not publish the feed is not an error here — that is discovered
    /// on the first poll, and behaves as no feed at all from then on.
    ///
    /// - Parameters:
    ///   - transport: the HTTP transport used to fetch the document — the same one every
    ///     other call already uses, so the feed inherits the client's TLS and §6.1 identity.
    ///   - baseURL: the AXIAM server base URL; the feed path is resolved against it.
    ///   - pollInterval: how long a fetched set is served before a refetch is attempted.
    ///     Clamped **up** to ``minPollInterval`` rather than refused; `nil` means
    ///     ``defaultPollInterval``.
    ///   - requestTimeout: the per-fetch timeout.
    init(
        transport: HTTPTransport,
        baseURL: URL,
        pollInterval: TimeInterval? = nil,
        requestTimeout: TimeInterval = 30
    ) {
        self.transport = transport
        // `feedPath` carries the leading slash the contract and every other SDK spell it
        // with; `appendingPathComponent` wants a bare component, and would otherwise produce
        // a doubled separator.
        self.url = baseURL.appendingPathComponent(
            String(Self.feedPath.drop(while: { $0 == "/" }))
        )
        let requested = pollInterval ?? Self.defaultPollInterval
        self.pollInterval = Swift.max(requested, Self.minPollInterval)
        self.requestTimeout = requestTimeout
    }

    /// The feed document's URL, for diagnostics.
    public var feedURL: URL { url }

    /// The interval actually in effect, after the ``minPollInterval`` clamp.
    public var effectivePollInterval: TimeInterval { pollInterval }

    /// Overrides the clock. Testing seam only.
    func setClock(_ clock: (@Sendable () -> Date)?) {
        now = clock
    }

    /// The feed entry for a `sid`, as the server computes it.
    ///
    /// Base64url without padding over the claim's **exact** string — never a
    /// parsed-and-re-rendered UUID, or the answer would depend on this type's UUID parser
    /// rather than on the feed.
    public static func entry(for sid: String) -> String {
        let digest = SHA256.hash(data: Data(sid.utf8))
        return Data(digest).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Reports whether this session has been revoked, as far as this poller knows.
    ///
    /// `false` whenever the answer is not a confident yes — a feed never fetched,
    /// unreachable, malformed, or simply not listing this session. The caller admits the
    /// request in all of those cases, which is §10.4 rule 3 and is the whole reason the
    /// feature is safe to turn on.
    ///
    /// - Parameter sid: the `sid` claim, or `nil`/empty for a token that carries none —
    ///   which is never matched (§10.4 rule 6).
    public func isRevoked(_ sid: String?) async -> Bool {
        guard let sid, !sid.isEmpty else { return false }
        await refreshIfStale()
        guard let entries else { return false }
        return entries.contains(Self.entry(for: sid))
    }

    /// Fetches now, whatever the interval says. For tests, and for a caller that wants the
    /// first poll to have happened before it starts serving.
    public func refresh() async {
        let fetched = await fetch()
        lastAttempt = currentDate()
        if let fetched {
            entries = fetched
        }
        // On failure the previous set is deliberately left in place: a blip must not
        // un-revoke a session the guard already knows about.
    }

    private func currentDate() -> Date { now?() ?? Date() }

    /// Refetches if the poll interval has elapsed since the last **attempt**.
    ///
    /// Attempt, not success: a feed that is down must not be retried on every request, which
    /// would put the request path back on the network — the cost §10.4 exists to avoid.
    private func refreshIfStale() async {
        if let lastAttempt, currentDate().timeIntervalSince(lastAttempt) < pollInterval {
            return
        }
        await refresh()
    }

    /// Performs one fetch. `nil` for every kind of failure, which the caller treats
    /// identically — see the type's documentation on why "unusable" must not collapse into
    /// "empty".
    private func fetch() async -> Set<String>? {
        let response: HTTPResponseData
        do {
            response = try await transport.execute(
                HTTPRequestSpec(method: .get, url: url, headers: [], body: nil),
                timeout: requestTimeout
            )
        } catch {
            return nil
        }

        guard response.status == 200 else { return nil }
        guard response.body.count <= Self.maxBodyBytes else { return nil }

        guard let document = try? JSONDecoder().decode(FeedDocument.self, from: response.body)
        else { return nil }

        guard let alg = document.alg, alg == Self.supportedAlg else { return nil }
        guard let revoked = document.revoked else { return nil }

        guard revoked.count <= Self.maxEntries else {
            // The WHOLE set, not a truncation — see `maxEntries`.
            return nil
        }

        return Set(revoked.filter { !$0.isEmpty })
    }
}
