import Foundation

// The "bare" request path: one request to an absolute URL, carrying exactly the headers the
// caller names and NONE of this client's session — no cookie jar, no CSRF token, no device
// bearer — with an explicit retry posture.
//
// Three contract sections need precisely that and nothing else:
//
// - §28.12 (RFC 7592): a registration access token is a bearer for ONE registration, and
//   rule 3 forbids attaching the SDK's own session beside it;
// - §32.7: the SSF receiver's JWKS fetch and its RFC 8936 poll, authenticated by a token the
//   caller's provider supplies;
// - §33: the CIBA calls, which authenticate the CLIENT through the form body, as every other
//   `/oauth2/*` call here does.
//
// It sits on `umaSendAbsolute`, so it is the SAME transport — §6's TLS policy, the redirect
// posture (`AsyncHTTPClientTransport` follows none) and the §5 tenant header on a same-origin
// request — and §16's retry and §19's telemetry are reached rather than re-implemented.

/// How a bare request may be retried.
enum BareRetry: Sendable {
    /// Exactly one attempt, whatever happens: §28.12.2 rule 5's update and delete, §33.7
    /// rule 1's `ciba_initiate`.
    case never
    /// §16 as written: a transport failure, `408`, `429` or `5xx` is retried within the
    /// budget; every other status is decisive.
    case section16
    /// §16, except that a response carrying an OAuth2 `error` member is never retried — it is
    /// the server's answer, not a transient failure (§33.3 rule 6, §33.7 rule 5: a `429`
    /// with `rate_limit_exceeded` is surfaced to the polling loop, a bodiless one is retried).
    case section16UnlessOAuthError
}

extension AxiamClient {

    /// One request on the bare path (see the file comment), with `retry`'s posture.
    ///
    /// Returns the response whatever its status; mapping it is the caller's job, because the
    /// three sections that use this map differently. Throws only when no response arrived (or
    /// the call was cancelled).
    func bareSend(
        operation: String,
        pathTemplate: String,
        method: HTTPRequestMethod,
        url: URL,
        headers: [(String, String)],
        body: Data?,
        retry: BareRetry
    ) async throws -> HTTPResponseData {
        try ensureOpen()
        let retryable: Bool
        switch retry {
        case .never: retryable = false
        case .section16, .section16UnlessOAuthError: retryable = config.retryEnabled
        }
        let budget = retryable ? Retry.maxAttempts : 1

        for attempt in 1...budget {
            telemetry.emit(.requestStart(
                operation: operation, method: method.rawValue,
                pathTemplate: pathTemplate, attempt: attempt))
            let started = Date()

            var response: HTTPResponseData?
            var thrown: Error?
            do {
                response = try await umaSendAbsolute(
                    method: method, url: url, headers: headers, body: body)
            } catch is CancellationError {
                telemetry.emit(.requestEnd(
                    operation: operation, method: method.rawValue, pathTemplate: pathTemplate,
                    attempt: attempt, status: nil,
                    duration: Date().timeIntervalSince(started), outcome: .failure))
                throw CancellationError()
            } catch {
                thrown = error
            }

            let status = response?.status
            let succeeded = status.map { (200..<300).contains($0) } ?? false
            telemetry.emit(.requestEnd(
                operation: operation, method: method.rawValue, pathTemplate: pathTemplate,
                attempt: attempt, status: status,
                duration: Date().timeIntervalSince(started),
                outcome: succeeded ? .success : .failure))

            let isLast = attempt == budget
            if !isLast, Self.bareShouldRetry(response, retry: retry) {
                let hint = Retry.retryAfter(response?.firstHeader("retry-after"))
                let wait = Retry.delay(attempt: attempt, retryAfter: hint, fraction: _jitter())
                telemetry.emit(.retry(
                    operation: operation, attempt: attempt, delay: wait,
                    reason: status.map { "HTTP \($0)" } ?? "transport failure"))
                try await _sleep(wait)
                continue
            }

            if let thrown { throw thrown }
            guard let response else {
                throw AxiamError.network(NetworkError("no response from transport"))
            }
            return response
        }

        // Unreachable: the loop returns or throws on its final iteration.
        throw AxiamError.network(NetworkError("retry budget exhausted without a result"))
    }

    /// Whether one completed exchange should be retried under `retry`.
    static func bareShouldRetry(_ response: HTTPResponseData?, retry: BareRetry) -> Bool {
        switch retry {
        case .never:
            return false
        case .section16:
            return Retry.shouldRetry(status: response?.status)
        case .section16UnlessOAuthError:
            guard Retry.shouldRetry(status: response?.status) else { return false }
            guard let response else { return true }
            return !Self.carriesOAuthError(response.body)
        }
    }

    /// Whether `body` is an `OAuth2ErrorResponse` — a JSON object with a non-empty `error`.
    static func carriesOAuthError(_ body: Data) -> Bool {
        guard let wire = try? JSONDecoder().decode(OidcOAuth2ErrorWire.self, from: body) else {
            return false
        }
        return !wire.error.isEmpty
    }
}
