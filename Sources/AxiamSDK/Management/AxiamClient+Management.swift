import Foundation

// CONTRACT.md §27.8 — the one request path the 147 generated operations go through.
//
// Nothing below opens a connection or builds a client. It reaches the three seams declared
// in `AxiamClient.swift` and adds only what §27 itself specifies: rule 3's implicit
// `{org_id}`/`{tenant_id}`, rule 7's classification, rule 8's GET-only retry, and rule 11's
// path-template telemetry labels.

extension AxiamClient {

    /// Execute one management operation and return its response body.
    ///
    /// - Parameters:
    ///   - operation: The registry's `namespace.operation`, for §19 telemetry.
    ///   - method: The HTTP method the registry names.
    ///   - template: The route with its `{...}` placeholders still in it. This is what the
    ///     §19 events are labelled with (§27.4 rule 11): a label carrying the interpolated
    ///     id makes every request its own metric series, which is how a dashboard ends up
    ///     with a hundred thousand time series and no aggregate for the route.
    ///   - pathParameters: The caller-supplied `{...}` values. `{org_id}` and `{tenant_id}`
    ///     are NOT expected here — see `scope`.
    ///   - scope: Per-call overrides for the implicit identifiers (rule 3).
    ///   - implicitTenant: Whether `{tenant_id}` on this route names the CONTEXT (and so
    ///     defaults from the client) rather than the object being acted on.
    func managementSend(
        operation: String,
        method: HTTPRequestMethod,
        template: String,
        pathParameters: [String: String] = [:],
        query: [(String, String)] = [],
        body: Data? = nil,
        scope: CallScope,
        implicitTenant: Bool
    ) async throws -> Data {
        try ensureOpen()

        // §27.4 rule 1: no session, no wire call. An unauthenticated management call is a
        // programming error rather than a 401 to handle, and sending it would make the
        // server's audit log carry a rejected administrative request that never had a
        // chance of succeeding.
        guard managementHasSession() else {
            throw AxiamError.auth(AuthError(
                "\(operation) requires an authenticated session (§27.4 rule 1). "
                + "Call login() first; no request was sent."))
        }

        let path = try resolveManagementPath(
            template: template,
            pathParameters: pathParameters,
            scope: scope,
            implicitTenant: implicitTenant,
            operation: operation)

        // §27.4 rule 8: only GET is retried. Every other method on this surface changes
        // server state, and §16.2's eligibility rule is "changes no server state" — a
        // retried POST that the server did receive creates the object twice.
        let retryable = method == .get && config.retryEnabled
        let budget = retryable ? Retry.maxAttempts : 1

        for attempt in 1...budget {
            telemetry.emit(.requestStart(
                operation: operation, method: method.rawValue,
                pathTemplate: template, attempt: attempt))
            let started = Date()

            var status: Int?
            var thrown: Error?
            var response: HTTPResponseData?
            do {
                response = try await managementRawSend(
                    method: method, path: path, query: query, body: body)
                status = response?.status
            } catch is CancellationError {
                telemetry.emit(.requestEnd(
                    operation: operation, method: method.rawValue, pathTemplate: template,
                    attempt: attempt, status: nil,
                    duration: Date().timeIntervalSince(started), outcome: .failure))
                throw CancellationError()
            } catch {
                thrown = error
            }

            let succeeded = status.map { (200..<300).contains($0) } ?? false
            telemetry.emit(.requestEnd(
                operation: operation, method: method.rawValue, pathTemplate: template,
                attempt: attempt, status: status,
                duration: Date().timeIntervalSince(started),
                outcome: succeeded ? .success : .failure))

            let isLast = attempt == budget
            if !isLast, Retry.shouldRetry(status: status) {
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

            // The §9 refresh-then-retry-once path. §16.2: the two mechanisms compose in one
            // direction only — a refresh does NOT reset the §16 budget, so this is exactly
            // one further attempt.
            if response.status == 401, managementHasSession() {
                try await managementRefreshOnce()
                telemetry.emit(.requestStart(
                    operation: operation, method: method.rawValue,
                    pathTemplate: template, attempt: attempt + 1))
                let refreshStarted = Date()
                let retried = try await managementRawSend(
                    method: method, path: path, query: query, body: body)
                telemetry.emit(.requestEnd(
                    operation: operation, method: method.rawValue, pathTemplate: template,
                    attempt: attempt + 1, status: retried.status,
                    duration: Date().timeIntervalSince(refreshStarted),
                    outcome: (200..<300).contains(retried.status) ? .success : .failure))
                guard (200..<300).contains(retried.status) else {
                    throw managementError(retried, operation: operation)
                }
                return retried.body
            }

            guard (200..<300).contains(response.status) else {
                throw managementError(response, operation: operation)
            }
            return response.body
        }

        // Unreachable: the loop returns or throws on its final iteration. Present because
        // Swift cannot see that, and a `fatalError` would turn an exhausted budget into a
        // crash inside somebody's admin tool.
        throw AxiamError.network(NetworkError("retry budget exhausted without a result"))
    }

    /// §27.4 rule 3: substitute the route's placeholders, defaulting the implicit two.
    ///
    /// `{org_id}` always defaults from the client. `{tenant_id}` defaults from the client
    /// only where it names the CONTEXT — in the `tenants` namespace and the signing-CA
    /// routes it names the object being acted on, and defaulting it there would silently
    /// turn "read tenant X" into "read my own tenant".
    private func resolveManagementPath(
        template: String,
        pathParameters: [String: String],
        scope: CallScope,
        implicitTenant: Bool,
        operation: String
    ) throws -> String {
        var path = template
        for (name, value) in pathParameters {
            path = path.replacingOccurrences(of: "{\(name)}", with: encodeSegment(value))
        }

        if path.contains("{org_id}") {
            guard let org = scope.orgID ?? config.orgID, !org.isEmpty else {
                throw AxiamError.auth(AuthError(
                    "\(operation) substitutes {org_id}, and this client has no organization "
                    + "UUID. Configure `orgID`, or scope the call with `.inOrg(...)`. "
                    + "An org SLUG is not a path segment (§5); no request was sent."))
            }
            path = path.replacingOccurrences(of: "{org_id}", with: encodeSegment(org))
        }

        if implicitTenant, path.contains("{tenant_id}") {
            guard let tenant = scope.tenantID ?? config.tenantID, !tenant.isEmpty else {
                throw AxiamError.auth(AuthError(
                    "\(operation) substitutes {tenant_id}, and this client has no tenant "
                    + "UUID. Configure `tenantID`, or scope the call with `.forTenant(...)`. "
                    + "A tenant SLUG is not a path segment (§5); no request was sent."))
            }
            path = path.replacingOccurrences(of: "{tenant_id}", with: encodeSegment(tenant))
        }

        // A placeholder nobody filled would otherwise go to the server literally, as a
        // path segment reading `%7Bfoo%7D`, and come back a 404 that reads exactly like a
        // deleted object.
        if let open = path.firstIndex(of: "{") {
            let rest = path[open...]
            throw AxiamError.network(NetworkError(
                "\(operation): the route still contains an unsubstituted placeholder "
                + "\(rest.prefix(while: { $0 != "/" })). This is an SDK bug; no request was sent."))
        }

        return path.hasPrefix("/") ? String(path.dropFirst()) : path
    }

    /// Percent-escape one path segment.
    ///
    /// An id is server-supplied and normally a UUID, but "normally" is not a guarantee and a
    /// `/` inside one would silently re-route the request onto a different endpoint.
    private nonisolated func encodeSegment(_ value: String) -> String {
        value.addingPercentEncoding(withAllowedCharacters: .alphanumerics.union(
            CharacterSet(charactersIn: "-._~"))) ?? value
    }

    /// The §27.4 rule 7 classification, applied to a response already in hand.
    private nonisolated func managementError(
        _ response: HTTPResponseData,
        operation: String
    ) -> AxiamError {
        let errBody = try? JSONDecoder().decode(ErrorBody.self, from: response.body)
        let detail = errBody?.message ?? errBody?.error ?? "HTTP \(response.status)"
        return ErrorMapper.mapManagement(
            status: response.status,
            message: "\(operation): \(detail)",
            action: errBody?.action,
            resourceID: errBody?.resource_id)
    }
}
