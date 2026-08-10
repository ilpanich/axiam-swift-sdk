import Foundation

/// Client-side decision memo (CONTRACT.md §17).
///
/// **Disabled by default.** §11.2 rule 6's ban on caching allow/deny decisions is still the
/// default behaviour; this is the single opt-in exception that section carves out, and a caller
/// has to switch it on having read the cost.
///
/// ## What it costs
///
/// The staleness bound is the TTL, **in both directions**. A grant revoked on the server can still
/// read as allowed for up to the TTL, and a grant just added can still read as denied for up to
/// the TTL. That second direction is the one that surprises people: **read-your-own-writes is not
/// guaranteed.** An admin UI that grants a role and immediately re-checks is the case that breaks,
/// and it breaks silently.
///
/// This mirrors the server's own bound rather than inventing a second staleness story —
/// `AXIAM__AUTHZ__DECISION_CACHE_TTL_SECS` (default 5 s) makes the same trade server-side. One
/// deliberate difference: the server's setting is an unclamped integer, so an operator can
/// configure a multi-hour staleness window. ``maxTTL`` clamps this one at 5 s, because the client
/// has no reason to repeat that.
///
/// No lock, unlike the Go, Java and C memos: this type is only ever touched from inside
/// ``AxiamClient``, which is an `actor`, so actor isolation already serialises every access. A
/// lock here would be a second, weaker answer to a question the language has already settled.
struct DecisionMemo {

    /// The §17.1 rule 2 ceiling. A configured TTL above this is clamped, not rejected: a caller who
    /// asked for a minute wants caching, and silently giving them the maximum safe value beats
    /// failing construction.
    static let maxTTL: TimeInterval = 5

    /// Entry cap before FIFO eviction (§17.1 rule 8). The memo is a latency optimisation, so
    /// dropping an entry is always correct — but it must drop rather than grow without bound.
    static let maxEntries = 1024

    /// Joins the key components. U+001F (unit separator) cannot appear in an action, a UUID or a
    /// scope, so no combination of caller-supplied values can forge a collision.
    private static let separator = "\u{001F}"

    /// Marks an absent optional, which is why an absent scope can never collide with a present one
    /// — a memo that let them collide would answer a narrower question with a broader answer.
    private static let absent = "\u{0000}"

    /// The TTL after clamping. Zero means **disabled**, not "cache for zero seconds".
    let ttl: TimeInterval

    private struct Entry {
        let result: AccessResult
        let storedAt: TimeInterval
    }

    /// Insertion-ordered, so eviction is FIFO by age: entries expire on age, which makes the
    /// oldest the one that was going to expire first anyway.
    private var order: [String] = []
    private var entries: [String: Entry] = [:]

    /// Injected monotonic clock in seconds, so the TTL can be tested without waiting.
    private let now: @Sendable () -> TimeInterval

    /// Build a memo from a requested (unclamped) TTL.
    ///
    /// - Parameters:
    ///   - requestedTTL: `nil` or non-positive disables the memo; anything above ``maxTTL`` is
    ///     clamped to it.
    ///   - now: injected clock.
    init(requestedTTL: TimeInterval?, now: @escaping @Sendable () -> TimeInterval = { Date().timeIntervalSince1970 }) {
        if let requestedTTL, requestedTTL > 0 {
            self.ttl = min(requestedTTL, Self.maxTTL)
        } else {
            self.ttl = 0
        }
        self.now = now
    }

    /// Whether this memo does anything. `false` for the default configuration.
    var enabled: Bool { ttl > 0 }

    /// Entry count, for tests.
    var count: Int { entries.count }

    /// Build the §17.1 rule 3 key: all four components, absent distinguished from present.
    static func key(subjectID: String?, resource: String, action: String, scope: String?) -> String {
        [subjectID ?? absent, resource, action, scope ?? absent].joined(separator: separator)
    }

    /// A live decision for `key`, if one is memoized and unexpired.
    mutating func get(_ key: String) -> AccessResult? {
        guard enabled, let entry = entries[key] else { return nil }
        guard now() - entry.storedAt < ttl else {
            remove(key)
            return nil
        }
        // Returned whole, including `reasonCode`: §17.1 rule 5 forbids returning `allowed` while
        // dropping the code, which would make the field intermittently absent — worse than never
        // having had it.
        return entry.result
    }

    /// Memoize a decision the server actually returned.
    ///
    /// Callers must only reach here on success. §17.1 rule 7 forbids negative-caching a failure:
    /// memoizing a transport error as a deny would turn a blip into a TTL-long outage, and
    /// memoizing it as an allow is unthinkable.
    mutating func put(_ key: String, _ result: AccessResult) {
        guard enabled else { return }
        remove(key)
        entries[key] = Entry(result: result, storedAt: now())
        order.append(key)
        while order.count > Self.maxEntries {
            remove(order[0])
        }
    }

    /// Drop every entry (§17.1 rule 9).
    ///
    /// Called on login, verifyMfa, refresh and logout. Entries are keyed by subject, not by
    /// session, so a re-authentication as a *different* principal would otherwise read the
    /// previous principal's decisions.
    mutating func clear() {
        entries.removeAll()
        order.removeAll()
    }

    private mutating func remove(_ key: String) {
        guard entries.removeValue(forKey: key) != nil else { return }
        if let index = order.firstIndex(of: key) {
            order.remove(at: index)
        }
    }
}
