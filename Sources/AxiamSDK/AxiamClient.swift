import Foundation

/// The AXIAM REST client (§1–§7, §9 of CONTRACT.md).
///
/// An `actor`, so its session state (cookie jar, CSRF token, in-flight refresh) is safe under
/// concurrent access. Tokens are delivered by the server via `httpOnly` cookies; this client
/// never sees or stores raw token strings itself (§7). Construction requires a tenant (§5).
///
/// Conforms to CONTRACT.md §1–§7, §9–§11 (including §6.1 mTLS). gRPC and §8 AMQP are out of
/// scope for this Swift v1 (documented as follow-ups in the README).
public actor AxiamClient {

    /// Points inside the §9 single-flight refresh guard at which ``AxiamClient/_refreshTestHook``
    /// fires. They exist purely so a test can pin open the narrow windows §9 rule 6 is about
    /// rather than race for them; no hook is ever installed in production.
    enum RefreshPhase {
        /// Owner: the refresh outcome has settled and is observable to every waiter, and the
        /// in-flight slot has *not* yet been vacated (rule 6a/6b's bookkeeping window).
        case ownerPublished
        /// Waiter: it has committed to the task currently in the slot and is about to await it.
        case waiterJoining
    }

    let config: AxiamConfig
    private let transport: HTTPTransport
    let jwks: JwksVerifier

    // Session state (actor-isolated).
    private var cookieJar = CookieJar()
    private var csrfToken: String?
    private var challengeToken: Sensitive<String>?
    private var sessionUser: AxiamUser?
    private var hasSession = false
    /// The one in-flight refresh's result-sharing channel (§9 rules 1–2). Populated for the
    /// duration of the wire call **and** for the brief bookkeeping window after that call's
    /// outcome has settled and before ``vacate(_:)`` clears it — so a non-`nil` value does *not*
    /// by itself mean a refresh is on the wire (§9 rule 6b). See ``refreshOnce()``.
    private var refreshTask: Task<Void, Error>?
    /// Visible-for-testing seam only; **never** assigned in production (nothing in `Sources/`
    /// writes it). Lets a test deterministically pin open the §9 rule 6 windows described on
    /// ``refreshOnce()`` instead of racing for them.
    var _refreshTestHook: (@Sendable (RefreshPhase) async -> Void)?
    /// Organization UUID resolved from the access-token `org_id` claim after login (D-14).
    /// The login response body carries `org_slug` but never `org_id`, and the config may hold
    /// only a slug — so this is the source of the UUID that `RefreshRequest` requires.
    private var resolvedOrgID: String?

    /// §19 dispatcher. Inert unless a hook was installed.
    let telemetry: TelemetryDispatcher
    /// §17 decision memo. Disabled unless the config carried a TTL. No lock: this actor's
    /// isolation already serialises every access.
    private var memo: DecisionMemo
    /// §18 shutdown flag, checked by every operation.
    private var closed = false

    /// §16 jitter source, injectable so a test can pin the range's ends (§16.7 requires an
    /// injected PRNG). Module-private on purpose: a public knob for the jitter would be an
    /// attractive nuisance next to §16.1's ban on raising the budget.
    var _jitter: @Sendable () -> Double = { Double.random(in: 0...1) }
    /// §16 sleep seam, so a test can observe a delay without taking it.
    var _sleep: @Sendable (TimeInterval) async throws -> Void = {
        try await Task.sleep(nanoseconds: UInt64(max($0, 0) * 1_000_000_000))
    }

    /// The §20 UMA discovery document and its expiry. An endpoint map is not a credential, and
    /// re-fetching it on every guarded request is a self-inflicted round trip — cached for the
    /// same five minutes §12.3 rule 6 sets as the floor for the OIDC document.
    var umaConfigurationCache: (document: Uma2Configuration, expiresAt: Date)?

    // MARK: - Construction

    /// Build a client from configuration, constructing the production HTTP transport with the
    /// config's TLS settings (§6/§6.1).
    ///
    /// - Throws: from ``AxiamConfig/makeTLSConfiguration()`` when PEM material is invalid.
    public convenience init(config: AxiamConfig) throws {
        let tls = try config.makeTLSConfiguration()
        self.init(config: config, transport: AsyncHTTPClientTransport(tls: tls))
    }

    /// Designated initializer with an injectable transport (used by tests).
    init(config: AxiamConfig, transport: HTTPTransport) {
        self.config = config
        self.transport = transport
        self.jwks = JwksVerifier(
            transport: transport,
            baseURL: config.baseURL,
            tenantHeaderValue: config.tenantHeaderValue,
            requestTimeout: config.requestTimeout
        )
        self.telemetry = TelemetryDispatcher(config.telemetryHook)
        self.memo = DecisionMemo(requestedTTL: config.decisionMemoTtl)

        // §19.2 rule 6: a setting we lowered is reported, not swallowed. An operator who set a
        // 60-second memo TTL believes their staleness bound is 60 seconds; it is five, and
        // without this nothing anywhere says so. Nothing is emitted when the request was already
        // inside the limit — an event that fires when nothing happened trains its reader to
        // ignore it. The memo TTL is the only clamped setting in this SDK: §16.1's table is not
        // configurable here, only switchable.
        if let requested = config.decisionMemoTtl, requested > 0, requested != memo.ttl {
            telemetry.emit(.configClamped(
                setting: "decisionMemoTtl",
                requested: "\(requested)s",
                effective: "\(memo.ttl)s",
                contractReference: "§17.1 rule 2"
            ))
        }
    }

    /// Deterministic shutdown (CONTRACT.md §18).
    ///
    /// Releases the HTTP client and its connection pool, and clears the cookie jar, the CSRF token
    /// and any retained ``Sensitive`` challenge token (§18.1 rule 6).
    ///
    /// - **Idempotent** (rule 2): calling it twice is a no-op the second time. Cleanup code runs
    ///   from error paths, and an error path that itself throws hides the original failure.
    /// - **Does not log out** (rule 5): it issues no request. The server-side session deliberately
    ///   outlives the client object — that is what lets a process restart and resume — so a
    ///   `close()` that logged out would silently end every user's session on each deploy.
    /// - **Use after close is an error, not undefined** (rule 4): every operation afterwards
    ///   throws ``NetworkError`` naming the cause rather than silently reopening.
    ///
    /// > Note: Swift's `deinit` cannot `await`, and releasing an `AsyncHTTPClient` is async, so
    /// > this SDK cannot make deallocation a complete shutdown the way §18.1 rule 1's "a `deinit`
    /// > plus explicit `close()`" suggests. `close()` is therefore the only complete form, and is
    /// > stated as required rather than implied.
    public func close() async throws {
        guard !closed else { return }
        closed = true
        cookieJar = CookieJar()
        csrfToken = nil
        challengeToken = nil
        sessionUser = nil
        hasSession = false
        memo.clear()
        try await transport.shutdown()
    }

    /// The pre-§18 spelling of ``close()``, kept so existing call sites keep working.
    public func shutdown() async throws {
        try await close()
    }

    /// §18.1 rule 4. Every operation runs this first, so a call on a closed client names its cause
    /// rather than silently reopening a connection the caller believes they released.
    func ensureOpen() throws {
        guard !closed else {
            throw AxiamError.network(NetworkError("client is closed (CONTRACT.md §18.1 rule 4)"))
        }
    }

    // MARK: - §1 Authentication

    /// Authenticate with email/username + password (§1 `login`).
    ///
    /// On success the session cookies are stored in this client's jar (§4). If the account
    /// needs MFA, the returned result is `.mfaRequired` and the challenge token is retained
    /// internally (as ``Sensitive``) for the subsequent ``verifyMfa(_:)`` call.
    public func login(email: String, password: String) async throws -> LoginResult {
        try ensureOpen()
        // §17.1 rule 9: cleared on the CALLER'S INTENT to change credentials, not on the server's
        // answer. Entries are keyed by subject rather than session, so a login that failed still
        // means this caller is done with the principal whose decisions are cached.
        memo.clear()
        let request = LoginRequest(
            username_or_email: email,
            password: password,
            tenant_id: config.tenantID,
            tenant_slug: config.tenantSlug,
            org_id: config.orgID,
            org_slug: config.orgSlug
        )
        let body = try encode(request)
        let response = try await rawSend(method: .post, path: "api/v1/auth/login", body: body)

        switch response.status {
        case 200:
            let success = try decode(LoginSuccessResponse.self, response.body)
            let user = success.toUser()
            hasSession = true
            sessionUser = user
            resolveOrgIDFromToken()
            challengeToken = nil
            return .authenticated(user)
        case 202:
            let mfa = try decode(MfaRequiredResponse.self, response.body)
            challengeToken = Sensitive(mfa.challenge_token)
            return .mfaRequired(availableMethods: mfa.available_methods)
        case 403:
            // A 403 here can be the login-flow "MFA enrolment required" response rather than a
            // genuine authorization denial — disambiguate on the body shape.
            if let setup = try? JSONDecoder().decode(MfaSetupRequiredResponse.self, from: response.body),
               setup.mfa_setup_required {
                return .mfaSetupRequired
            }
            throw mapError(response)
        default:
            throw mapError(response)
        }
    }

    /// Complete an MFA challenge with a TOTP code (§1 `verifyMfa`).
    ///
    /// Requires a prior ``login(email:password:)`` that returned `.mfaRequired`.
    public func verifyMfa(_ code: String) async throws {
        try ensureOpen()
        memo.clear() // §17.1 rule 9
        guard let challenge = challengeToken else {
            throw AxiamError.auth(AuthError("No MFA challenge in progress; call login first."))
        }
        let request = MfaVerifyRequest(challenge_token: challenge.wrapped, totp_code: code)
        let body = try encode(request)
        let response = try await rawSend(method: .post, path: "api/v1/auth/mfa/verify", body: body)
        guard response.status == 200 else { throw mapError(response) }
        let success = try decode(LoginSuccessResponse.self, response.body)
        hasSession = true
        sessionUser = success.toUser()
        resolveOrgIDFromToken()
        challengeToken = nil
    }

    /// Force a token refresh (§1 `refresh`). Routed through the single-flight guard (§9) so a
    /// manual refresh coalesces with any auto-refresh already in flight.
    public func refresh() async throws {
        try ensureOpen()
        try await refreshOnce()
    }

    /// End the session (§1 `logout`). Local session state is always cleared.
    public func logout() async throws {
        try ensureOpen()
        memo.clear() // §17.1 rule 9, before the wire
        let response = try await rawSend(method: .post, path: "api/v1/auth/logout", body: nil)
        hasSession = false
        sessionUser = nil
        challengeToken = nil
        csrfToken = nil
        guard (200..<300).contains(response.status) else { throw mapError(response) }
    }

    // MARK: - §1 Authorization

    /// Single access check (§1 `checkAccess`). Argument order is `(action, resource[, scope])`.
    public func checkAccess(_ action: String, resource: String, scope: String? = nil) async throws -> AccessResult {
        try await checkAccessInternal(action: action, resource: resource, scope: scope, subjectID: nil)
    }

    /// Browser/UI alias for ``checkAccess(_:resource:scope:)`` returning a plain `Bool` (§1 `can`).
    public func can(_ action: String, resource: String, scope: String? = nil) async throws -> Bool {
        try await checkAccess(action, resource: resource, scope: scope).allowed
    }

    /// Batch access check (§1 `batchCheck`). Results are returned in input order.
    public func batchCheck(_ checks: [AccessCheck]) async throws -> [AccessResult] {
        try ensureOpen()
        let bodies = checks.map {
            CheckAccessBody(action: $0.action, resource_id: $0.resource, scope: $0.scope, subject_id: $0.subjectID)
        }
        let body = try encode(BatchCheckAccessBody(checks: bodies))
        // Deliberately not memoized: the §17 key is per-check, so a batch would have to be split
        // into n entries with n keys — the right design, but it changes what a partial hit means
        // (some rows from the wire, some from the memo, one composite result). §17 says nothing
        // about batch, so this SDK does the conservative thing rather than inventing semantics.
        let response = try await retryingPOST(
            operation: "batchCheck", path: "api/v1/authz/check/batch", body: body)
        let decoded = try decode(BatchCheckAccessResponse.self, response.body)
        return decoded.results.map { AccessResult(allowed: $0.allowed, reason: $0.reason, reasonCode: $0.reason_code) }
    }

    /// Subject-aware access check used by the §11 guards (`subject_id` = authenticated end user).
    func checkAccessInternal(action: String, resource: String, scope: String?, subjectID: String?) async throws -> AccessResult {
        try ensureOpen()

        // §17: consulted before the wire, written only after a decision the server actually
        // returned.
        let key = memo.enabled
            ? DecisionMemo.key(subjectID: subjectID, resource: resource, action: action, scope: scope)
            : nil
        if let key, let cached = memo.get(key) { return cached }

        let body = try encode(CheckAccessBody(action: action, resource_id: resource, scope: scope, subject_id: subjectID))
        let response = try await retryingPOST(
            operation: "checkAccess", path: "api/v1/authz/check", body: body)
        let decoded = try decode(CheckAccessResponse.self, response.body)
        // §11 rule 9: the reason code is surfaced verbatim, including a value this SDK has
        // never heard of — the outcome is carried by `allowed` alone, so an unknown code
        // can never change it.
        let result = AccessResult(allowed: decoded.allowed, reason: decoded.reason, reasonCode: decoded.reason_code)

        // §17.1 rule 7: only a decision the server actually returned — a thrown NetworkError never
        // reaches here. Rule 4: allows and denies are stored identically, because asymmetric
        // caching changes the timing of the two outcomes and so leaks which one occurred to
        // anyone who can observe latency.
        if let key { memo.put(key, result) }
        return result
    }

    // MARK: - §10/§11 integration factories

    /// A framework-agnostic request authenticator (§10) verifying inbound sessions against the
    /// org JWKS and producing an ``AxiamUser``.
    public nonisolated func makeAuthenticator() -> AxiamRequestAuthenticator {
        AxiamRequestAuthenticator(
            jwks: jwks,
            tenantID: config.tenantHeaderValue,
            tenantSlug: config.tenantSlug,
            expectedIssuer: config.expectedIssuer,
            expectedAudience: config.expectedAudience
        )
    }

    /// Declarative authorization guard factories (§11): `requireAuth` / `requireAccess` /
    /// `requireRole`, built strictly on top of the §10 authenticator.
    public nonisolated func makeGuards() -> AxiamGuards {
        AxiamGuards(authenticator: makeAuthenticator(), client: self)
    }

    // MARK: - §9 single-flight refresh

    /// Single-flight token refresh (CONTRACT.md §9 rules 1–2): exactly one
    /// `POST /api/v1/auth/refresh` wire call per burst of concurrent callers, with *that* call's
    /// outcome delivered to every caller in the burst. A failure propagates as-is, once, to each
    /// of them and is never retried here (§9.3).
    ///
    /// ### §9 rule 6 invariants (contract 1.6) and why each holds for this mechanism
    ///
    /// The mechanism is the one §9's per-language table prescribes for Swift: this `actor`
    /// serializes access to `refreshTask`, which holds the one in-flight `Task` whose value every
    /// contending caller awaits. `refreshTask` is therefore a **result-sharing channel, not a busy
    /// flag** — the same invariant the Java/Go/C++/Rust guards document.
    ///
    /// - **(6a) Publish-before-vacate.** `Task` is value-retaining: the instant the refresh task
    ///   settles, its outcome is stored irrevocably and *every* caller suspended in
    ///   `existing.value` is guaranteed to be resumed with it. The slot is vacated only from the
    ///   owner's continuation, which by construction runs strictly after that settlement. So there
    ///   is no reachable instant at which a new caller sees an empty slot while a just-settled
    ///   outcome has not reached the waiters — the state that would let it start a **second** wire
    ///   call against an already-consumed, single-use refresh token.
    /// - **(6b) Occupancy is not liveness.** (6a) means the slot legitimately holds an
    ///   already-settled task for the bookkeeping window between settlement and the owner's
    ///   resumption on the actor. Callers landing in that window join the settled outcome, keeping
    ///   the wire count at one. Nothing else in this type reads `refreshTask`, so no unrelated
    ///   logic can misread occupancy as "a refresh is on the wire" (the Java SDK's bug). Any
    ///   future code that needs real liveness MUST test for it explicitly — never `refreshTask
    ///   != nil`, and note that `Task` exposes no "is still running" predicate.
    /// - **(6c) Only the current owner vacates, identity-checked.** ``vacate(_:)`` clears the slot
    ///   only while it still holds *this* attempt's task, so an attempt unwinding late can never
    ///   wipe a newer attempt's entry (the C++ SDK's bug) — which would again open the door to a
    ///   second concurrent wire call. Waiters never touch the slot at all: they do not own it.
    /// - **(6d) A caller arriving after full settlement refreshes itself.** Once vacated the slot
    ///   is `nil`, so the next caller takes ownership and performs its own wire call; a previous
    ///   burst's outcome is never handed out as if it were current.
    ///
    /// Cancellation (verified by `RefreshRule6Tests`): the shared refresh is an **unstructured**
    /// `Task`, so cancelling a caller neither cancels the refresh (which would strand the other
    /// waiters mid-burst and abandon a consumed refresh token) nor unblocks that caller early —
    /// `await task.value` is not a cancellation point. A cancelled caller therefore still runs the
    /// bookkeeping below, so cancellation can leave the slot neither permanently occupied nor
    /// cleared-while-live.
    ///
    /// The actor's exclusive execution is **not** held across the wire call: owner and waiters all
    /// suspend, releasing the actor, while the refresh is in flight (§9 rule 4).
    private func refreshOnce() async throws {
        // NOTE: the nil-check + task creation + assignment below run with no `await` between
        // them, so within the actor they are atomic — exactly one refresh Task is ever created,
        // and the sharing channel is published before the wire call can even start (the task body
        // first runs when this caller suspends below).
        if let existing = refreshTask {
            // A live *or* just-settled attempt (6b): join its single outcome (§9 rule 2).
            await fireRefreshTestHook(.waiterJoining)
            try await existing.value
            return
        }
        let task = Task<Void, Error> { [self] in
            try await self.doRefresh()
        }
        refreshTask = task
        do {
            try await task.value
            await vacate(task)
        } catch {
            await vacate(task)
            throw error // §9: no retry loop on refresh failure — surface AuthError to the caller.
        }
    }

    /// Release the single-flight slot — reached on both the success and the failure path, with the
    /// outcome already published to every waiter (6a), and clearing the slot only while it still
    /// holds *this* attempt's task (6c).
    private func vacate(_ task: Task<Void, Error>) async {
        await fireRefreshTestHook(.ownerPublished)
        if refreshTask == task {
            refreshTask = nil
        }
    }

    /// Fire the visible-for-testing phase hook. `_refreshTestHook` is always `nil` in production,
    /// so this introduces no suspension point on any production path.
    private func fireRefreshTestHook(_ phase: RefreshPhase) async {
        guard let hook = _refreshTestHook else { return }
        await hook(phase)
    }

    private func doRefresh() async throws {
        // RefreshRequest requires UUIDs. Prefer values resolved from the session/token;
        // fall back only to UUID-form config — never a slug, which the server would reject.
        let tenantID = sessionUser?.tenantID ?? config.tenantID ?? ""
        let orgID = resolvedOrgID ?? config.orgID ?? ""
        let body = try encode(RefreshRequest(tenant_id: tenantID, org_id: orgID))
        let response = try await rawSend(method: .post, path: "api/v1/auth/refresh", body: body)
        guard (200..<300).contains(response.status) else {
            if response.status == 401 { hasSession = false } // must re-authenticate (§9.3)
            throw mapError(response)
        }
    }

    /// Decode the `org_id` claim out of the `axiam_access` cookie the login response set and
    /// cache it in `resolvedOrgID` (D-14). Best-effort and unverified: the value is used only to
    /// populate the refresh body, which the server re-derives and re-validates authoritatively,
    /// so this carries no trust weight (the real credential is the httpOnly cookie the server
    /// verifies). A malformed token or missing claim leaves `resolvedOrgID` unchanged.
    private func resolveOrgIDFromToken() {
        guard let token = cookieJar.value(named: "axiam_access") else { return }
        let segments = token.split(separator: ".", omittingEmptySubsequences: false)
        guard segments.count == 3, let payload = Base64URL.decode(String(segments[1])) else { return }
        guard let object = try? JSONSerialization.jsonObject(with: payload) as? [String: Any],
              let orgID = object["org_id"] as? String, !orgID.isEmpty else { return }
        resolvedOrgID = orgID
    }

    // MARK: - Transport plumbing (§3 CSRF, §4 cookies, §5 tenant)

    /// POST that transparently refreshes once on a 401 when a session exists (§9), then retries.
    private func authorizedPOST(path: String, body: Data) async throws -> HTTPResponseData {
        let response = try await rawSend(method: .post, path: path, body: body)
        if response.status == 401, hasSession {
            try await refreshOnce()
            let retried = try await rawSend(method: .post, path: path, body: body)
            guard (200..<300).contains(retried.status) else { throw mapError(retried) }
            return retried
        }
        guard (200..<300).contains(response.status) else { throw mapError(response) }
        return response
    }

    /// One §16-eligible operation: the bounded retry budget plus the §19 pairs around it.
    ///
    /// §16.2: eligibility is "changes no server state", **not** "is a `GET`". The authorization
    /// check is a `POST` with a body and is the single most important operation in that section —
    /// an SDK that gated retry on the HTTP verb would retry nothing that matters. This method is
    /// therefore reached only from the authz paths; `login`, `verifyMfa`, `logout` and `refresh`
    /// call ``authorizedPOST(path:body:)`` (or `rawSend`) directly and make exactly one attempt.
    ///
    /// One `requestStart`/`requestEnd` pair **per attempt** (§19.2 rule 5), with a `retry` between
    /// consecutive pairs: a caller must be able to count real wire calls from the events, which
    /// one pair per logical operation would hide.
    private func retryingPOST(
        operation: String,
        path: String,
        body: Data
    ) async throws -> HTTPResponseData {
        let budget = config.retryEnabled ? Retry.maxAttempts : 1
        let template = "/" + path

        for attempt in 1...budget {
            telemetry.emit(.requestStart(
                operation: operation, method: "POST", pathTemplate: template, attempt: attempt))
            let started = Date()

            var status: Int?
            var thrown: Error?
            var response: HTTPResponseData?
            do {
                response = try await rawSend(method: .post, path: path, body: body)
                status = response?.status
            } catch is CancellationError {
                // Re-thrown, never retried. A cancelled task is the caller withdrawing their
                // request; retrying it would keep the work alive past the point its scope was
                // cancelled, which is a correctness bug rather than a transient failure.
                telemetry.emit(.requestEnd(
                    operation: operation, method: "POST", pathTemplate: template, attempt: attempt,
                    status: nil, duration: Date().timeIntervalSince(started), outcome: .failure))
                throw CancellationError()
            } catch {
                thrown = error
            }

            let succeeded = status.map { (200..<300).contains($0) } ?? false
            telemetry.emit(.requestEnd(
                operation: operation, method: "POST", pathTemplate: template, attempt: attempt,
                status: status, duration: Date().timeIntervalSince(started),
                outcome: succeeded ? .success : .failure))

            let isLast = attempt == budget
            if !isLast, Retry.shouldRetry(status: status) {
                let hint = Retry.retryAfter(response?.firstHeader("retry-after"))
                let wait = Retry.delay(attempt: attempt, retryAfter: hint, fraction: _jitter())
                // §16.5: a retried-then-succeeded operation is otherwise invisible. The reason
                // carries a status or a transport description, never a token — `NetworkError` is
                // redacted at construction.
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
            // direction only — the §16 budget is NOT reset by a §9 refresh occurring
            // mid-operation, so the post-refresh call below is exactly one attempt.
            if response.status == 401, hasSession {
                try await refreshOnce()
                telemetry.emit(.requestStart(
                    operation: operation, method: "POST", pathTemplate: template,
                    attempt: attempt + 1))
                let refreshStarted = Date()
                let retried = try await rawSend(method: .post, path: path, body: body)
                telemetry.emit(.requestEnd(
                    operation: operation, method: "POST", pathTemplate: template,
                    attempt: attempt + 1, status: retried.status,
                    duration: Date().timeIntervalSince(refreshStarted),
                    outcome: (200..<300).contains(retried.status) ? .success : .failure))
                guard (200..<300).contains(retried.status) else { throw mapError(retried) }
                return retried
            }
            guard (200..<300).contains(response.status) else { throw mapError(response) }
            return response
        }

        // Unreachable: the loop returns or throws on its final iteration. Present because Swift
        // cannot see that, and a fatalError here would turn an exhausted budget into a crash.
        throw AxiamError.network(NetworkError("retry budget exhausted without a result"))
    }

    /// Assemble headers (tenant §5, cookies §4, CSRF §3), execute, and capture response cookies
    /// and CSRF token. Does not map errors — callers decide (login has bespoke status handling).
    private func rawSend(method: HTTPRequestMethod, path: String, body: Data?) async throws -> HTTPResponseData {
        let url = config.baseURL.appendingPathComponent(path)

        var headers: [(String, String)] = [
            ("X-Tenant-ID", config.tenantHeaderValue), // §5: on every request
            ("Accept", "application/json"),
        ]
        if body != nil {
            headers.append(("Content-Type", "application/json"))
        }
        if let cookieHeader = cookieJar.cookieHeader(for: url) {
            headers.append(("Cookie", cookieHeader)) // §4: resend stored session cookies
        }
        if method.isStateChanging, let csrfToken {
            headers.append(("X-CSRF-Token", csrfToken)) // §3: echo on state-changing requests
        }

        let spec = HTTPRequestSpec(method: method, url: url, headers: headers, body: body)
        let response = try await transport.execute(spec, timeout: config.requestTimeout)

        // §4: persist any Set-Cookie the server issued.
        let setCookies = response.allHeaders("set-cookie")
        if !setCookies.isEmpty {
            cookieJar.store(setCookieLines: setCookies, requestURL: url)
        }
        // §3: capture the CSRF token the server echoes for later state-changing requests.
        if let csrf = response.firstHeader("x-csrf-token") {
            csrfToken = csrf
        }
        return response
    }

    /// Execute one request against an **absolute** URL — an endpoint read from a discovery
    /// document rather than joined onto `config.baseURL` — carrying exactly the headers given.
    ///
    /// Used only by §20. It deliberately attaches **no session cookie and no CSRF token**: every
    /// call that reaches it either authenticates with a caller-supplied PAT or authenticates the
    /// client through a form body, and sending this client's session alongside would put a second,
    /// unasked-for identity on the request. The §5 tenant header is still applied on a same-origin
    /// request, and only there — a discovery document naming a foreign host must not receive it.
    ///
    /// No retry wrapper, deliberately: §20.2 rule 6 makes the ticket grant the one operation in
    /// this SDK that must issue exactly one request.
    func umaSendAbsolute(
        method: HTTPRequestMethod,
        url: URL,
        headers: [(String, String)],
        body: Data?
    ) async throws -> HTTPResponseData {
        var allHeaders = headers
        if url.host == config.baseURL.host {
            allHeaders.append(("X-Tenant-ID", config.tenantHeaderValue))
        }
        let spec = HTTPRequestSpec(method: method, url: url, headers: allHeaders, body: body)
        return try await transport.execute(spec, timeout: config.requestTimeout)
    }

    private func mapError(_ response: HTTPResponseData) -> AxiamError {
        let errBody = try? JSONDecoder().decode(ErrorBody.self, from: response.body)
        let message = errBody?.message ?? errBody?.error ?? "HTTP \(response.status)"
        return ErrorMapper.map(
            status: response.status,
            message: message,
            action: errBody?.action,
            resourceID: errBody?.resource_id
        )
    }

    private func encode<T: Encodable>(_ value: T) throws -> Data {
        do {
            return try JSONEncoder().encode(value)
        } catch {
            throw AxiamError.network(NetworkError("Failed to encode request body", cause: error))
        }
    }

    private func decode<T: Decodable>(_ type: T.Type, _ data: Data) throws -> T {
        do {
            return try JSONDecoder().decode(type, from: data)
        } catch {
            throw AxiamError.network(NetworkError("Failed to decode response body", cause: error))
        }
    }
}

// MARK: - Internal test seams

extension AxiamClient {
    func _cookieCount() -> Int { cookieJar.count }
    func _cookieValue(_ name: String) -> String? { cookieJar.value(named: name) }
    func _csrfToken() -> String? { csrfToken }
    func _hasSession() -> Bool { hasSession }
    func _hasChallenge() -> Bool { challengeToken != nil }

    /// Install the §9 rule 6 phase hook (see ``AxiamClient/RefreshPhase``).
    func _setRefreshTestHook(_ hook: (@Sendable (RefreshPhase) async -> Void)?) {
        _refreshTestHook = hook
    }

    /// Whether the single-flight slot is populated at all — live **or** settled-but-not-yet-vacated
    /// (§9 rule 6b: this is occupancy, not liveness). Tests only.
    func _refreshSlotOccupied() -> Bool { refreshTask != nil }

    /// Force a foreign task into the single-flight slot, standing in for a *newer* leader that was
    /// elected while a lagging attempt was still unwinding. Used to construct §9 rule 6c's race
    /// deterministically; the natural race is unreachable through the public API because ownership
    /// is taken and released without an intervening suspension point. Tests only.
    func _installForeignRefreshTask(_ task: Task<Void, Error>) { refreshTask = task }

    /// Clear the slot unconditionally, so a rule 6c test can tidy up after itself. Tests only.
    func _clearRefreshSlot() { refreshTask = nil }

    /// Install the §16 test seams. §16.7 requires backoff and jitter to be tested with an injected
    /// clock and an injected PRNG rather than by sleeping — a test that really waits 200 ms is a
    /// test nobody runs. **Never called from `Sources/`.**
    func _setRetryTestSeams(
        jitter: @escaping @Sendable () -> Double,
        sleep: @escaping @Sendable (TimeInterval) async throws -> Void
    ) {
        _jitter = jitter
        _sleep = sleep
    }

    /// The §17 memo's entry count, for tests.
    func _memoCount() -> Int { memo.count }
}

private extension LoginSuccessResponse {
    func toUser() -> AxiamUser {
        AxiamUser(
            userID: user.id,
            tenantID: user.tenant_id,
            roles: [],
            username: user.username,
            email: user.email
        )
    }
}
