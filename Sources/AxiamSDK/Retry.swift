import Foundation

/// Bounded read-only retry (CONTRACT.md §16).
///
/// The policy is machinery, not surface: the only public knob is ``AxiamConfig/retryEnabled``.
/// §16.1 permits lowering the budget or turning it off, never raising it — a caller who can raise
/// the cap turns one client into the herd the backoff exists to prevent, so there is deliberately
/// no property for the attempt count, the base delay or the delay cap.
///
/// Everything here is a pure function of `(attempt, header, fraction)`, so §16.7's "injected clock
/// and injected PRNG — never by sleeping" is achievable: a test that really waits 200 ms is a test
/// nobody runs.
enum Retry {

    /// §16.1: 1 initial attempt + 2 retries. Bounds worst-case added latency at ~10 s; a caller
    /// who needs more retries at their own layer knows their own deadline.
    static let maxAttempts = 3

    /// §16.1 base delay. Long enough that a retry is not simply re-entering the same overload,
    /// short enough to be invisible on a recovery from a single dropped packet.
    static let baseDelay: TimeInterval = 0.2

    /// §16.1 ceiling on any single wait.
    static let maxDelay: TimeInterval = 5.0

    /// §16.1 backoff before jitter: `min(cap, base × 2^(attempt−1))`.
    static func backoff(attempt: Int) -> TimeInterval {
        let n = max(attempt, 1)
        var delay = baseDelay
        var i = 1
        while i < n && delay < maxDelay {
            delay *= 2
            i += 1
        }
        return min(delay, maxDelay)
    }

    /// §16.1 wait for `attempt`, given a uniform `fraction` in `[0, 1]` and an optional
    /// `Retry-After`.
    ///
    /// **Full jitter**: the wait is `backoff × fraction`, i.e. uniform over `[0, backoff]` — not
    /// `backoff ± something`. Partial jitter keeps every client's retries clustered around the
    /// same instant, which is the failure mode retries cause rather than fix.
    ///
    /// **`Retry-After` is a floor, never a ceiling.** The server is telling you when it will be
    /// ready, so retrying sooner is not permitted; and because the hint only ever lengthens the
    /// wait, a `Retry-After: 0` cannot defeat the backoff. Replacing the backoff with the hint —
    /// which is what a `retryAfter ?? backoff` idiom does — is the shipped bug this wording names.
    static func delay(attempt: Int, retryAfter: TimeInterval?, fraction: Double) -> TimeInterval {
        let clamped = min(max(fraction, 0), 1)
        let jittered = backoff(attempt: attempt) * clamped
        guard let retryAfter else { return jittered }
        return max(jittered, retryAfter)
    }

    /// §16.3: whether a completed exchange should be retried. `status` is `nil` when no HTTP
    /// response arrived at all.
    static func shouldRetry(status: Int?) -> Bool {
        // Connection refused / DNS / TLS / read timeout: no response arrived, so the request may
        // never have been seen.
        guard let status else { return true }
        // 429 is exactly where `Retry-After` usually arrives.
        if status == 408 || status == 429 { return true }
        if (500..<600).contains(status) { return true }
        // Everything else is decisive: 401 belongs to §9's refresh path, 403 is the server having
        // decided, and every other 4xx would produce an identical rejection on a second attempt.
        return false
    }

    /// Parse a `Retry-After` header. RFC 7231 allows either delta-seconds or an HTTP-date and both
    /// appear in the wild, so both are parsed.
    ///
    /// Returns `nil` — absent — for anything unparseable, rather than `0`: an unparseable hint
    /// must not become a zero-length floor.
    static func retryAfter(_ value: String?, now: Date = Date()) -> TimeInterval? {
        guard let raw = value?.trimmingCharacters(in: .whitespaces), !raw.isEmpty else { return nil }

        if raw.allSatisfy(\.isNumber), let seconds = TimeInterval(raw) {
            // Clamped at an hour so a hostile or broken header cannot park a task for a day. The
            // §16.1 cap governs the backoff, not the floor, so without this the floor would be
            // unbounded.
            return min(seconds, 3600)
        }

        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss zzz"
        guard let when = formatter.date(from: raw) else { return nil }
        let delta = when.timeIntervalSince(now)
        // A date already in the past is not a wait.
        guard delta > 0 else { return nil }
        return min(delta, 3600)
    }
}
