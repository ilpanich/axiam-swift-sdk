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
    /// The CONTRACT.md §10.4 revocation feed, or `nil` when the caller did not opt in
    /// (contract 1.44). `nil` is the default and means the feature is off entirely.
    let revocationFeed: RevocationFeed?

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

    /// The tenant this client currently acts on, as `X-Axiam-Tenant` (CONTRACT.md §5.2
    /// rule 1, contract 1.51). `nil` sends no header at all — byte for byte what every
    /// request sent before contract 1.51. Seeded from ``AxiamConfig/actingTenant`` and
    /// changed only through ``actingTenant(_:)``.
    private var actingTenant: String?

    /// The §6.1 device login's adopted credential, or `nil` on an ordinary cookie-based
    /// session. Once set, every REST request this client sends carries it as
    /// `Authorization: Bearer <token>` and withholds this client's own cookie jar (§6.1
    /// rule 6, read with the reference implementation's note: the server reads
    /// `axiam_access` before `Authorization`, so a client that kept a stale cookie
    /// beside a device token would silently run as the previous session's principal).
    /// There is no refresh token for it (rule 6), so ``canRefresh`` is `false` whenever
    /// this is set — a later `401` is surfaced as ``AuthError`` with no refresh attempt.
    private var deviceAccessToken: Sensitive<String>?

    /// Whether a `401` on this client's own credential should attempt the §9 single-flight
    /// refresh. `false` for a device-authenticated client (§6.1 rule 6: no refresh token
    /// exists for it), `hasSession` otherwise.
    private var canRefresh: Bool { hasSession && deviceAccessToken == nil }

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

    /// The §12.3 rule 6 discovery cache. Per **client instance**, which satisfies the
    /// origin-keying rule by construction: this client is bound to one base URL for its
    /// lifetime, so a document fetched from one origin can never be served for another.
    var oidcConfigurationCache: (document: OidcConfiguration, expiresAt: Date)?

    // MARK: - Construction

    /// Build a client from configuration, constructing the production HTTP transport with the
    /// config's TLS settings (§6/§6.1).
    ///
    /// - Throws: from ``AxiamConfig/makeTLSConfiguration()`` when PEM material is invalid.
    ///
    /// Not marked `convenience`: actors have no convenience initializers. Every actor
    /// initializer is designated and may delegate with `self.init`, so the keyword was
    /// never meaningful here — Swift 5 accepted it with a warning ("this is an error in
    /// Swift 6") and Swift 6 rejects it outright. Removing it compiles under both.
    public init(config: AxiamConfig) throws {
        let tls = try config.makeTLSConfiguration()
        self.init(config: config, transport: AsyncHTTPClientTransport(tls: tls))
    }

    /// Designated initializer with an injectable transport (used by tests).
    init(config: AxiamConfig, transport: HTTPTransport) {
        self.config = config
        self.transport = transport
        self.actingTenant = config.actingTenant?.uuidString
        self.jwks = JwksVerifier(
            transport: transport,
            baseURL: config.baseURL,
            tenantHeaderValue: config.tenantHeaderValue,
            requestTimeout: config.requestTimeout
        )
        // CONTRACT.md §10.4 (contract 1.44). Built only when the caller opted in, so a client
        // that did not ask for it holds no poller and issues no fetch — "default off" is a
        // structural property here, not a branch taken at verification time.
        self.revocationFeed = config.revocationFeedEnabled
            ? RevocationFeed(
                transport: transport,
                baseURL: config.baseURL,
                pollInterval: config.revocationPollInterval,
                requestTimeout: config.requestTimeout
            )
            : nil
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
        deviceAccessToken = nil
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
            // genuine authorization denial — disambiguate on the body shape (§25.2 rule 1).
            //
            // The setup token travels out with the outcome rather than being retained the way
            // the MFA challenge token is: unlike verifyMfa, forced enrolment is TWO calls with
            // a human step between them, and a caller that has to persist state across that
            // gap needs the token in hand.
            if let setup = try? JSONDecoder().decode(MfaSetupRequiredResponse.self, from: response.body),
               setup.mfa_setup_required, !setup.setup_token.isEmpty {
                return .mfaSetupRequired(setupToken: Sensitive(setup.setup_token))
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
        deviceAccessToken = nil
        guard (200..<300).contains(response.status) else { throw mapError(response) }
    }

    // MARK: - §6.1 rules 6-10: the mTLS device login

    /// The `authenticateDevice()` result (CONTRACT.md §6.1 rule 6).
    public struct DeviceLoginResult: Sendable, Equatable {
        /// The certificate-bound access token (§7 `Sensitive<T>`). There is no refresh
        /// token for it — see ``AxiamClient/authenticateDevice()``.
        public let accessToken: Sensitive<String>
        /// Always `"Bearer"`. NEVER a signal of `cnf` boundness (§1.1.1 rule 5) — when
        /// AXIAM itself terminated the TLS handshake this token carries `cnf.x5t#S256`
        /// whether or not `tokenType` says so.
        public let tokenType: String
        /// The access-token lifetime in seconds (server default 900).
        public let expiresIn: Int

        public init(accessToken: Sensitive<String>, tokenType: String, expiresIn: Int) {
            self.accessToken = accessToken
            self.tokenType = tokenType
            self.expiresIn = expiresIn
        }
    }

    private struct DeviceLoginWire: Decodable {
        let access_token: String
        let token_type: String
        let expires_in: Int
    }

    /// `authenticateDevice()` — the mTLS device login (CONTRACT.md §6.1 rules 6-10).
    ///
    /// Issues `POST /api/v1/auth/device` with no request body.
    ///
    /// **Reachable only on a client configured with a client certificate** (rule 7,
    /// ``AxiamConfig/clientCertificate``). On any other client this refuses
    /// CLIENT-SIDE with ``AxiamError/auth(_:)`` and **zero wire calls**: without a
    /// certificate the server would answer `401` regardless, so going to the wire would
    /// only turn a configuration mistake into an authentication failure.
    ///
    /// On success the returned token is **adopted as this client's credential**, exactly
    /// as a `login()` result is (rule 6): every subsequent REST call this client sends —
    /// including every `management()` operation — carries it as `Authorization: Bearer
    /// <token>` and withholds this client's own cookie jar, so a session cookie from an
    /// earlier `login()` can never ride alongside it. The server reads the
    /// `axiam_access` cookie before `Authorization`, so keeping a stale one would
    /// silently run every later request as the *previous* session's principal, defeating
    /// the point of authenticating fresh.
    ///
    /// **There is no refresh token** for this credential (rule 6, D-6 of the dogfooding
    /// plan): the §9 single-flight guard has nothing to spend on it, so a later `401` —
    /// on this call, or on any request this client sends afterward — is surfaced as
    /// ``AuthError`` with **no refresh attempt**. The caller recovers by calling
    /// `authenticateDevice()` again, which costs one TLS handshake.
    ///
    /// **Every refusal is a `401`** (rule 8, server T22.4): an unknown, untrusted,
    /// expired, revoked or unbound certificate, and a `Server`-type certificate, all map
    /// to ``AuthError``. A `429` from the route's per-IP rate limiter maps to
    /// ``NetworkError`` (§2), never ``AuthError`` — `mapError` already keeps the two
    /// apart, so this method adds no special-casing for it, and it is never retried
    /// here.
    ///
    /// The token is **certificate-bound** (`cnf.x5t#S256`) when AXIAM itself terminated
    /// the TLS handshake (rule 9); `DeviceLoginResult.tokenType` stays `"Bearer"` either
    /// way. A resource server verifying it locally MUST use
    /// `AxiamRequestAuthenticator.authenticateSenderConstrained(_:presentedThumbprint:)`
    /// (or thread `PresentedProofs` through `authenticate(_:presentedProofs:)`) rather
    /// than the plain `authenticate(_:)`, which — after this SDK's own §10.1 rule 9 fix
    /// — refuses a bound token with no evidence.
    ///
    /// - Throws: ``AxiamError/auth(_:)`` client-side (no certificate configured, zero
    ///   wire calls) or from the server's `401`; ``AxiamError/network(_:)`` for a `429`
    ///   or any other non-`200`.
    @discardableResult
    public func authenticateDevice() async throws -> DeviceLoginResult {
        try ensureOpen()
        // §6.1 rule 7: reachable only on a client configured with a certificate. Checked
        // BEFORE any wire call — without one the server would answer 401 regardless, so
        // reaching the wire would only turn a configuration mistake into an
        // authentication failure.
        guard config.clientCertificate != nil else {
            throw AxiamError.auth(AuthError(
                "authenticateDevice() requires a client certificate (CONTRACT.md §6.1 rule 7); "
                + "configure AxiamConfig.clientCertificate. No request was sent."))
        }
        memo.clear() // §17.1 rule 9: this is a login.
        let response = try await deviceRawSend()
        guard response.status == 200 else {
            // §6.1 rule 8: every refusal is a 401 (-> AuthError). A 429 (-> NetworkError)
            // is not an authentication failure and is not retried (§16).
            throw mapError(response)
        }
        let wire = try decode(DeviceLoginWire.self, response.body)
        let token = Sensitive(wire.access_token)

        // Adopt the token exactly as a login result is adopted (rule 6). A service
        // account has no LoginUserInfo, so `sessionUser` stays `nil` — nothing to gate
        // the acting tenant on (§5.2 rule 1: a client holding no login result sends the
        // header as asked and lets the server's 403 answer).
        hasSession = true
        sessionUser = nil
        challengeToken = nil
        deviceAccessToken = token
        resolveOrgIDFromToken(wire.access_token)

        return DeviceLoginResult(accessToken: token, tokenType: wire.token_type, expiresIn: wire.expires_in)
    }

    /// `POST /api/v1/auth/device`. Deliberately NOT `rawSend`: this call authenticates
    /// with the mTLS handshake alone, so it sends no `Cookie` and echoes no `X-CSRF-Token`
    /// — attaching this client's own session (if any) alongside a fresh certificate-based
    /// login would present two identities on one request.
    private func deviceRawSend() async throws -> HTTPResponseData {
        let url = config.baseURL.appendingPathComponent("api/v1/auth/device")
        var headers: [(String, String)] = [
            ("X-Tenant-ID", config.tenantHeaderValue), // §5 rule 2: unconditional
            ("Accept", "application/json"),
        ]
        if let actingTenantHeader {
            headers.append(actingTenantHeader) // §5.2 rule 1
        }
        let spec = HTTPRequestSpec(method: .post, url: url, headers: headers, body: nil)
        return try await transport.execute(spec, timeout: config.requestTimeout)
    }

    // MARK: - §5.2 rule 1: acting tenant

    /// Act on a different tenant (or clear it), CONTRACT.md §5.2 rule 1, contract 1.51.
    ///
    /// Pass `nil` to clear: the next request sends no `X-Axiam-Tenant` header at all,
    /// which is what "the header is sent only when set" requires and what every client
    /// that never calls this method already does.
    ///
    /// **Gated on what this client knows, and nothing more** (§5.2 rule 1's own words).
    /// A client holding a login result (``AxiamUser`` from `login`/`verifyMfa`/OPAQUE/an
    /// MFA or WebAuthn setup completion) is refused client-side, with **zero wire
    /// calls**, unless that principal is ``AxiamUser/organizationLevel`` — an ordinary
    /// tenant principal gets a `403` from the server for the same header change, and
    /// offering the switch anyway would turn a type-level distinction into a runtime
    /// failure the caller has to discover by trying. When
    /// ``AxiamUser/reachableTenantIDs`` narrows that reach (§5.2.3), a tenant outside it
    /// is refused the same way (rule 4).
    ///
    /// A client holding **no** login result — a service account from client credentials
    /// or the mTLS device login, or a token injected directly — has nothing to gate on.
    /// It sends the header as asked and lets the server's `403` answer: an
    /// **organization-level service account is a supported design** (§27.13 S-9 note 2),
    /// and this client cannot tell the difference from here.
    ///
    /// - Throws: ``AxiamError/auth(_:)`` — client-side, no request sent — when this
    ///   client holds a login result that is not organization-level, or whose
    ///   `reachableTenantIDs` does not contain `tenantID`.
    public func actingTenant(_ tenantID: UUID?) throws {
        try ensureOpen()
        guard let tenantID else {
            actingTenant = nil
            return
        }
        if let sessionUser {
            // CONTRACT 1.52 N-5.4 (C-12): a gate refusal is §2's AuthzError — the 403 the
            // server would answer for the same header change — never AuthError. This
            // client refuses no differently than the server would; it should report no
            // differently either.
            guard sessionUser.organizationLevel else {
                throw AxiamError.authz(AuthzError(
                    "actingTenant(_:) is meaningful only for an organization-level principal "
                    + "(CONTRACT.md §5.2 rule 1); this session's principal is not one. "
                    + "No request was sent."))
            }
            if let reachable = sessionUser.reachableTenantIDs, !reachable.isEmpty,
               // CONTRACT 1.52 N-5.6 (C-12): tenant ids compare as UUIDs, never as
               // strings — case and formatting MUST NOT decide reach. `.uuidString` is
               // always upper-case; the server sends `reachable_tenant_ids` lower-case,
               // so a case-sensitive string comparison wrongly refused every real one.
               !reachable.contains(where: { UUID(uuidString: $0) == tenantID }) {
                throw AxiamError.authz(AuthzError(
                    "actingTenant(_:) named a tenant outside this principal's "
                    + "reachableTenantIDs (CONTRACT.md §5.2.3 rule 4). No request was sent."))
            }
        }
        // A client holding no login result (a service account, or an injected token) has
        // nothing to gate on: send the header as asked and let the server decide.
        actingTenant = tenantID.uuidString
    }

    /// Clear the acting tenant. Equivalent to `try? actingTenant(nil)`, spelled without
    /// the optional-`nil` call site and without `throws` — clearing can never be refused.
    public func clearActingTenant() {
        actingTenant = nil
    }

    /// `("X-Axiam-Tenant", value)` when an acting tenant is set, or `nil` — §5.2 rule 1:
    /// "the header is sent only when set". Every `/api/v1` request-building site adds
    /// this alongside `X-Tenant-ID` (§5 rule 2); this SDK ships no gRPC transport, so
    /// REST is the only transport §5.2 rule 1 has to reach.
    private var actingTenantHeader: (String, String)? {
        actingTenant.map { ("X-Axiam-Tenant", $0) }
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
            ? DecisionMemo.key(
                subjectID: subjectID, resource: resource, action: action, scope: scope,
                actingTenant: actingTenant)
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
            expectedAudience: config.expectedAudience,
            revocationFeed: revocationFeed,
            resourceMetadataUrl: config.resourceMetadataUrl
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

    // MARK: - OPAQUE, RFC 9807 (CONTRACT.md §23)

    /// `POST /api/v1/auth/opaque/login/start` then `/finish` — OPAQUE login, RFC 9807
    /// (CONTRACT.md §23).
    ///
    /// A sibling of ``login(email:password:)``, not a replacement. It takes the same arguments and
    /// returns the same ``LoginResult``, MFA branch included, so an application can switch a
    /// tenant to OPAQUE without touching its own code.
    ///
    /// ## What this does that `login` does not
    ///
    /// The password never leaves this process. What crosses the wire is a blinded group element
    /// and a MAC, neither useful without the account's registration record *and* the tenant's OPRF
    /// seed — so a TLS-terminating proxy, an accidentally verbose request log, or a heap dump on
    /// the server cannot capture a plaintext password, because the server never has one. It also
    /// means a stolen record database is not offline-crackable on its own, which is the
    /// pre-computation resistance SRP could not offer. It does **not** protect against a
    /// compromised AXIAM server.
    ///
    /// ## Swift no longer needs a `pbkdf2_sha256` tenant
    ///
    /// The SRP client this replaces refused an `argon2id` tenant outright — Swift has no Argon2
    /// that ships on every supported platform, and substituting PBKDF2 would have derived a
    /// different `x` and surfaced as "invalid password". AXIAM's *default* KDF was, for Swift,
    /// unreachable. The key stretching now happens inside `libaxiam_opaque_ffi`, so the only
    /// remaining condition is having that library, which ``opaqueAvailable()`` reports.
    ///
    /// ## One round trip, and no server-proof step
    ///
    /// SRP had to guess a group before the server named one and restart the exchange if it guessed
    /// wrong; `KE1` does not depend on the key-stretching function. And where the old §23.3 rule 6
    /// had to mandate an `M2` check in capitals — because skipping it kept only half the protocol
    /// — RFC 9807's AKE authenticates the server during the handshake, so opening `KE2` *is* the
    /// proof that it holds the record.
    ///
    /// ## Cost
    ///
    /// Runs the tenant's key-stretching function: Argon2id at 19 MiB and t=2 by default, tens to
    /// hundreds of milliseconds of CPU plus that memory. That cost is the point — it is what makes
    /// a stolen record expensive to attack even by someone holding the OPRF seed. It runs on the
    /// calling task rather than a shared executor.
    ///
    /// ## When `KE2` does not open, `mode` decides what happens next
    ///
    /// The `login/start` response carries the tenant's `opaque_mode`, and §23.4 rule 7 branches on
    /// it and on nothing else:
    ///
    /// - `optional` — this method **retries over ``login(email:password:)``** with the same
    ///   credentials and returns that call's outcome, before reporting any failure. `optional` is
    ///   the mid-migration state: every account has no OPAQUE record the moment an operator
    ///   enables it, and acquires one only when its password is next set, so treating the failed
    ///   exchange as final would lock out every user of the tenant.
    /// - `required`, **and a response with no `mode` field at all** (a server older than the
    ///   field), and any value this SDK does not recognise — ``AxiamError/auth(_:)``, the exchange
    ///   is over, and nothing is retried. Failing closed is the default.
    ///
    /// `mode` is **not** downgrade protection: a hostile server that wanted the plaintext could
    /// answer `404` and get a caller's fallback whatever it puts here. What closes that is
    /// `required` server-side, which refuses `/auth/login` for every principal before examining
    /// any credential.
    ///
    /// - Throws: ``AxiamError/network(_:)`` when the tenant has OPAQUE disabled (the endpoint
    ///   answers `404` — a property of the tenant, not of any user), when `libaxiam_opaque_ffi` is
    ///   not installed, and when the server names a key-stretching function this SDK cannot ask
    ///   for. Deliberately not ``AxiamError/auth(_:)``: reporting a configuration gap as a
    ///   credential failure would send a user off to reset a password that works, and would stop a
    ///   caller falling back to ``login(email:password:)``.
    /// - Throws: ``AxiamError/auth(_:)`` for a wrong password, an account that does not exist, an
    ///   account with no registration record, and a server that does not hold the record —
    ///   indistinguishable by design. **Nothing is sent to `login/finish` in that case**
    ///   (§23.4 rule 7). A caller must not retry it over ``login(email:password:)`` by hand: under
    ///   `optional` this method has already done so (see above), and under `required` the retry is
    ///   refused anyway and would put a plaintext password on the wire for nothing.
    ///
    public func loginOpaque(usernameOrEmail: String, password: String) async throws -> LoginResult {
        try ensureOpen()
        // §17.1 rule 9: cleared on the CALLER'S INTENT to change credentials.
        memo.clear()

        let exchange = try Opaque.startLogin(password: password)
        // A no-op once finish() has spent the handle; the point is the paths where
        // it has not -- a refused KSF, a malformed response, a non-200 start.
        defer { exchange.close() }

        let started = try await opaqueStart(
            path: "api/v1/auth/opaque/login/start",
            body: try encode(OpaqueLoginStartRequest(
                username_or_email: usernameOrEmail,
                ke1: exchange.ke1,
                tenant_id: config.tenantID,
                tenant_slug: config.tenantSlug,
                org_id: config.orgID,
                org_slug: config.orgSlug
            )),
            what: "login/start"
        )

        guard let ke2 = started.ke2 else {
            throw AxiamError.network(NetworkError("OPAQUE: login/start returned no `ke2`"))
        }

        let ke3: String
        do {
            ke3 = try exchange.finish(password: password, ke2: ke2, ksf: started.ksfParams)
        } catch let failure as AxiamError {
            // §23.4 rule 7 (contract 1.29). `KE2` failing to open ends the OPAQUE exchange either
            // way -- nothing is sent to login/finish -- and what happens next depends on `mode`
            // and on nothing else. A .network failure here is a refused key-stretching function
            // or a spent exchange, not a credential check, so it is never a fallback trigger.
            guard case .auth = failure, started.retriesOverPasswordLogin else { throw failure }

            // `optional` is the mid-migration state: every account has no registration record the
            // moment an operator enables OPAQUE and acquires one only when its password is next
            // set, so a failed exchange is the ORDINARY case rather than a wrong password.
            // Treating it as final would lock out every user of the tenant. Under `required` this
            // branch is not taken -- the server would answer 403 opaque_required anyway, and an
            // SDK that tried would put a plaintext password on the wire for nothing.
            //
            // The retry is login() itself rather than a second hand-rolled request, so the MFA
            // branches, the 403 disambiguation, the session adoption and the org-id recovery are
            // the ones a caller already gets, and this call's outcome IS the outcome: its success
            // on success, its error on failure.
            return try await login(email: usernameOrEmail, password: password)
        }

        let body = try encode(
            OpaqueLoginFinishRequest(opaque_session: started.opaque_session, ke3: ke3))
        let response = try await rawSend(
            method: .post, path: "api/v1/auth/opaque/login/finish", body: body)

        // Identical adoption to login(): the union is the same, so the session
        // state, the cached user, the org-id recovery and the 403 disambiguation
        // are too. An application must be able to keep one result handler when a
        // tenant moves to OPAQUE, which it cannot if a branch is missing here.
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
            // As in login(): a 403 here can be the login-flow "MFA enrolment
            // required" response rather than a genuine authorization denial --
            // disambiguate on the body shape.
            if let setup = try? JSONDecoder().decode(
                MfaSetupRequiredResponse.self, from: response.body),
               setup.mfa_setup_required, !setup.setup_token.isEmpty {
                return .mfaSetupRequired(setupToken: Sensitive(setup.setup_token))
            }
            throw mapError(response)
        default:
            throw mapError(response)
        }
    }

    /// Builds a registration record for `password`, to send with any request that sets one:
    /// `POST /api/v1/users`, `/auth/password/change`, `/auth/reset/confirm` and
    /// `/admin/bootstrap`.
    ///
    /// The server cannot build this — it never sees the plaintext — so it has to arrive with the
    /// request or not at all.
    ///
    /// Unlike the `srpEnrollment` it replaces this performs I/O: one `register/start` round trip.
    /// OPAQUE's envelope is sealed under the server's oblivious PRF, so there is no offline
    /// computation that produces a valid record.
    ///
    /// Note the parameters that are gone. There is no `identity`: the SRP version required the
    /// account's **username**, and an email there produced a verifier no login could ever satisfy,
    /// whereas a record binds to a credential identifier the server chooses. And there is no
    /// `group` or `params`, because those come from the `register/start` response — a caller
    /// cannot pick a cost the server will not honour.
    ///
    /// - Throws: ``AxiamError/network(_:)`` when the tenant has OPAQUE disabled, when
    ///   `libaxiam_opaque_ffi` is not installed, or when the server names a key-stretching
    ///   function this SDK cannot ask for.
    public func opaqueEnrollment(password: String) async throws -> OpaqueEnrollment {
        try await enroll(password: password, principalTenantID: nil)
    }

    /// Builds a registration record for the **caller's own** new password, sealed against the
    /// tenant the caller's account lives in.
    ///
    /// CONTRACT.md §5.2.2 rule 2. `POST /auth/password/change` and the record that accompanies
    /// it are about the *account*, not about whatever tenant the client is currently pointed
    /// at, and a record sealed against the acting tenant is refused with *"the OPAQUE session
    /// was issued for a different tenant"*.
    ///
    /// The distinction only bites for an organization-level principal that has selected another
    /// tenant to act on; for everyone else the two tenants are the same value and this behaves
    /// identically to ``opaqueEnrollment(password:)``. It is still the method to call for a
    /// self-service password change, because which principal is signed in is not something the
    /// call site usually knows.
    ///
    /// - Throws: ``AxiamError/network(_:)`` when no login has completed on this client yet —
    ///   the principal tenant is reported by the login response, so there is nothing to seal
    ///   against before then — and on the same terms as ``opaqueEnrollment(password:)``
    ///   otherwise.
    public func opaqueEnrollmentForSelf(password: String) async throws -> OpaqueEnrollment {
        guard let principal = sessionUser?.principalTenantID else {
            throw AxiamError.network(NetworkError(
                "OPAQUE: no principal tenant is known yet — sign in before building a "
                + "registration record for your own password"))
        }
        return try await enroll(password: password, principalTenantID: principal)
    }

    /// The shared body of the two enrolment methods; they differ only in the tenant the record
    /// is sealed against. `nil` is the ordinary case.
    private func enroll(
        password: String,
        principalTenantID: String?
    ) async throws -> OpaqueEnrollment {
        try ensureOpen()

        let exchange = try Opaque.startRegistration(password: password)
        defer { exchange.close() }

        // §5.2.2 rule 2: when a principal tenant is named, it is named BY ID and the slug is
        // dropped. A slug naming the acting tenant left beside the id would out-vote it
        // server-side, which is the exact confusion this override exists to avoid. The
        // organization fields still apply — they identify the organization, not the tenant.
        let started = try await opaqueStart(
            path: "api/v1/auth/opaque/register/start",
            body: try encode(OpaqueRegisterStartRequest(
                registration_request: exchange.request,
                tenant_id: principalTenantID ?? config.tenantID,
                tenant_slug: principalTenantID == nil ? config.tenantSlug : nil,
                org_id: config.orgID,
                org_slug: config.orgSlug
            )),
            what: "register/start"
        )

        guard let registrationResponse = started.registration_response else {
            throw AxiamError.network(NetworkError(
                "OPAQUE: register/start returned no `registration_response`"))
        }

        let record = try exchange.finish(
            password: password,
            registrationResponse: registrationResponse,
            ksf: started.ksfParams
        )

        return OpaqueEnrollment(
            opaque_session: started.opaque_session,
            registration_record: record
        )
    }

    /// Whether this installation can perform OPAQUE (§23.2).
    ///
    /// Genuinely able to answer `false`: the protocol comes from `libaxiam_opaque_ffi`, a
    /// per-platform release asset rather than a SwiftPM package, resolved with `dlopen` at run
    /// time so that a consumer who never uses OPAQUE is not made to link it.
    ///
    /// Unlike the `srpAvailable` it replaces, a `true` here **is** a promise that every tenant
    /// will work. `srpAvailable` was hard-coded `true` while an `argon2id` tenant still failed at
    /// login, because Swift had no Argon2 to offer; that gap is gone.
    public func opaqueAvailable() -> Bool { Opaque.available() }

    /// Sends one `/start` request and returns the decoded response.
    ///
    /// Shared by both OPAQUE paths so the meaning of a failure cannot drift between them. A `404`
    /// is a property of the tenant ("OPAQUE is off here"), not of the user and not of the
    /// credentials — so it is an ``AxiamError/network(_:)`` a caller can fall back on, never an
    /// ``AxiamError/auth(_:)`` that would be shown as "invalid password".
    private func opaqueStart(
        path: String,
        body: Data,
        what: String
    ) async throws -> OpaqueStartResponse {
        let response = try await rawSend(method: .post, path: path, body: body)

        if response.status == 404 {
            throw AxiamError.network(NetworkError(
                "OPAQUE: this tenant does not offer OPAQUE (opaque_mode is disabled); "
                + "use login(email:password:) instead"))
        }
        guard response.status == 200 else { throw mapError(response) }

        do {
            return try JSONDecoder().decode(OpaqueStartResponse.self, from: response.body)
        } catch {
            throw AxiamError.network(NetworkError(
                "OPAQUE: the \(what) response was not the shape §23 defines", cause: error))
        }
    }

    /// Decode the `org_id` claim out of the `axiam_access` cookie the login response set and
    /// cache it in `resolvedOrgID` (D-14). Best-effort and unverified: the value is used only to
    /// populate the refresh body, which the server re-derives and re-validates authoritatively,
    /// so this carries no trust weight (the real credential is the httpOnly cookie the server
    /// verifies). A malformed token or missing claim leaves `resolvedOrgID` unchanged.
    private func resolveOrgIDFromToken(_ explicitToken: String? = nil) {
        guard let token = explicitToken ?? cookieJar.value(named: "axiam_access") else { return }
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
        if response.status == 401, canRefresh {
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
            if response.status == 401, canRefresh {
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
        if let actingTenantHeader {
            headers.append(actingTenantHeader) // §5.2 rule 1: only when set
        }
        if body != nil {
            headers.append(("Content-Type", "application/json"))
        }
        headers.append(contentsOf: credentialHeaders(for: url, method: method))

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

    /// The §4/§6.1 credential headers for one request: this client's cookie jar (§4, the
    /// default, plus the §3 CSRF echo on state-changing methods), or — once
    /// `authenticateDevice()` has adopted one — the device bearer token with an EXPLICIT
    /// empty `Cookie` header, so a stale session cookie from an earlier login can never
    /// ride alongside it (§6.1 rule 6: the server reads `axiam_access` before
    /// `Authorization`). CSRF does not apply to the bearer path: §3 defends a
    /// cookie-based session, and the device token is not one.
    private func credentialHeaders(for url: URL, method: HTTPRequestMethod) -> [(String, String)] {
        if let deviceAccessToken {
            return [("Authorization", "Bearer \(deviceAccessToken.expose())"), ("Cookie", "")]
        }
        var out: [(String, String)] = []
        if let cookieHeader = cookieJar.cookieHeader(for: url) {
            out.append(("Cookie", cookieHeader))
        }
        if method.isStateChanging, let csrfToken {
            out.append(("X-CSRF-Token", csrfToken))
        }
        return out
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

// MARK: - Internal seams for the §24/§25/§26 extensions
//
// `rawSend`/`mapError`/`memo` are file-private, and the WebAuthn and account-lifecycle
// operations live in their own files to keep this one readable. These few internal
// accessors are what they reach through — deliberately a named surface rather than
// widening the private members, so what those extensions can touch stays enumerable.

extension AxiamClient {
    /// The §17 memo drop every credential change owes (§17.1 rule 9).
    func clearDecisionMemo() {
        memo.clear()
    }

    /// Whether a prior `login`/ceremony left this client holding a session.
    var hasActiveSession: Bool { hasSession }

    /// The challenge token a `login` that answered `.mfaRequired` retained (§1), so a
    /// second-factor WebAuthn ceremony can continue it without the caller re-supplying one.
    func currentChallengeToken() -> Sensitive<String>? { challengeToken }

    var configuredTenantID: String? { config.tenantID }
    var configuredTenantSlug: String? { config.tenantSlug }
    var configuredOrgID: String? { resolvedOrgID ?? config.orgID }
    var configuredOrgSlug: String? { config.orgSlug }

    /// Marks the client authenticated after a §24.3 / §25.2 rule 2 credential adoption. The
    /// session cookies arrived on the same response and were stored by `rawSend`; this is
    /// the in-memory half.
    ///
    /// `sessionUser` is always SET to `user` — including to `nil` when the completion's own
    /// response carries no `LoginUserInfo` (a plain WebAuthn authentication, an SSO/federation
    /// completion). This resets the §5.2 acting-tenant gate to "unknown" rather than leaving a
    /// PREVIOUS session's `organizationLevel`/`reachableTenantIDs` in place for a new principal
    /// this response never described — every completed session gets the SAFE reading, which
    /// sends the acting-tenant header as asked and lets the server's `403` answer, exactly as a
    /// client holding no login result at all already does (§5.2 rule 1). Leaving the old value
    /// in place here was a real defect: a caller who authenticated as principal A, switched to
    /// act on tenant X, then signed in again over WebAuthn as principal B would otherwise keep
    /// acting on X under A's now-stale `organizationLevel` gate.
    func adoptSessionAfterCeremony(user: AxiamUser? = nil) {
        hasSession = true
        challengeToken = nil
        sessionUser = user
        resolveOrgIDFromToken()
    }

    /// One JSON POST against this client's own base URL, carrying the §3/§4/§5 decoration
    /// every other REST call gets.
    func webauthnRawSend(path: String, body: Data?) async throws -> HTTPResponseData {
        try await rawSend(method: .post, path: path, body: body)
    }

    /// One JSON POST for the §24.1 `setup/register/*` pair (contract 1.45), which — unlike
    /// every other call `webauthnRawSend` carries — MUST NOT ride this client's own session
    /// credential, even when one is configured (§24.1, §24.8): the setup token in the body
    /// is the only credential these two accept, and attaching a second one invites a server
    /// that changes its mind about which to trust.
    ///
    /// Built like `rawSend` in every other respect. The §5 tenant header still goes out
    /// (rule 2 admits no exceptions), and a `Set-Cookie` / `X-CSRF-Token` on the RESPONSE is
    /// still captured into this client's jar — `setup/register/finish` completes a login,
    /// and its own §24.3 adoption depends on that landing exactly as it does for every other
    /// credential-adopting call. What is withheld is only what this client already holds
    /// coming IN: no `Cookie` header is sent, and no `X-CSRF-Token` is echoed, so a session
    /// already in the jar from an unrelated prior login can never ride alongside the setup
    /// token.
    func setupTokenRawSend(path: String, body: Data) async throws -> HTTPResponseData {
        let url = config.baseURL.appendingPathComponent(path)
        var headers: [(String, String)] = [
            ("X-Tenant-ID", config.tenantHeaderValue), // §5: on every request
            ("Accept", "application/json"),
            ("Content-Type", "application/json"),
        ]
        if let actingTenantHeader {
            headers.append(actingTenantHeader) // §5.2 rule 1: every /api/v1 REST call
        }
        let spec = HTTPRequestSpec(method: .post, url: url, headers: headers, body: body)
        let response = try await transport.execute(spec, timeout: config.requestTimeout)

        // §24.3 rule 2 / §24.8: a completed `finish` still adopts the session this response
        // sets, exactly as every other §24/§25 credential-adopting call does.
        let setCookies = response.allHeaders("set-cookie")
        if !setCookies.isEmpty {
            cookieJar.store(setCookieLines: setCookies, requestURL: url)
        }
        if let csrf = response.firstHeader("x-csrf-token") {
            csrfToken = csrf
        }
        return response
    }

    /// One JSON POST against this client's own base URL whose **response carries the session**.
    ///
    /// The two §12.1 federation completions (`sso_complete_oauth2`, `sso_complete_handoff`)
    /// answer `200` alongside `Set-Cookie`, and that cookie is the whole result — the body
    /// carries no token material (§12.1 note 6). Routed through `rawSend` rather than §12's
    /// own `oidcJSONPost` for exactly that reason: `rawSend` is what stores the §4 jar and
    /// captures the §3 CSRF token. Errors are not mapped here; §12 maps them itself.
    func federationSessionPost(path: String, body: Data) async throws -> HTTPResponseData {
        try await rawSend(method: .post, path: path, body: body)
    }

    /// One GET against this client's own base URL carrying a query string.
    ///
    /// Built through `URLComponents`, never by concatenation: `rawSend` joins its `path`
    /// with `appendingPathComponent`, which percent-escapes a `?` INTO the path — and a
    /// reset-context call that lands on the wrong path 404s in a way that reads exactly
    /// like an expired token.
    func rawGetWithQuery(
        path: String,
        query: [URLQueryItem],
        context: String
    ) async throws -> HTTPResponseData {
        let base = config.baseURL.appendingPathComponent(path)
        guard var components = URLComponents(url: base, resolvingAgainstBaseURL: false) else {
            throw AxiamError.network(NetworkError("\(context): could not build a request URL"))
        }
        components.queryItems = query
        guard let url = components.url else {
            throw AxiamError.network(NetworkError("\(context): could not build a request URL"))
        }

        var headers: [(String, String)] = [
            ("X-Tenant-ID", config.tenantHeaderValue),
            ("Accept", "application/json"),
        ]
        if let actingTenantHeader {
            headers.append(actingTenantHeader) // §5.2 rule 1: every /api/v1 REST call
        }
        headers.append(contentsOf: credentialHeaders(for: url, method: .get))
        let spec = HTTPRequestSpec(method: .get, url: url, headers: headers, body: nil)
        return try await transport.execute(spec, timeout: config.requestTimeout)
    }

    /// The §2 status mapping, applied to a response the caller already has in hand.
    func webauthnMapError(_ response: HTTPResponseData, _ context: String) -> AxiamError {
        let errBody = try? JSONDecoder().decode(ErrorBody.self, from: response.body)
        let message = errBody?.message ?? errBody?.error ?? context
        return ErrorMapper.map(
            status: response.status,
            message: context.hasSuffix(message) ? context : "\(context): \(message)",
            action: errBody?.action,
            resourceID: errBody?.resource_id
        )
    }
}

// MARK: - Internal seams for the §27 management surface
//
// §27.8 is explicit that the generated layer "MUST sit on the SDK's existing request path"
// and "MUST NOT open its own connection, build its own client, or re-implement any of §3
// (CSRF), §4 (cookie jar), §5 (tenant/org headers), §6 (TLS), §9 (single-flight refresh),
// §16 (retry) or §19 (telemetry)". These three seams are how it reaches that path — the
// same named-surface approach the §24/§25/§26 seams above take, rather than widening the
// private members, so what the management layer can touch stays enumerable.

extension AxiamClient {
    /// One request on this client's own request path, with a query string.
    ///
    /// `rawSend` joins its path with `appendingPathComponent`, which percent-escapes a `?`
    /// INTO the path; the management surface has 20 paginated routes and several filtered
    /// ones, so it needs the `URLComponents` form. Everything else is `rawSend`'s: the §5
    /// tenant header, the §4 cookie jar in both directions, and the §3 CSRF token on
    /// state-changing methods.
    func managementRawSend(
        method: HTTPRequestMethod,
        path: String,
        query: [(String, String)],
        body: Data?
    ) async throws -> HTTPResponseData {
        let base = config.baseURL.appendingPathComponent(path)
        guard var components = URLComponents(url: base, resolvingAgainstBaseURL: false) else {
            throw AxiamError.network(NetworkError("could not build a request URL for \(path)"))
        }
        if !query.isEmpty {
            components.queryItems = query.map { URLQueryItem(name: $0.0, value: $0.1) }
        }
        guard let url = components.url else {
            throw AxiamError.network(NetworkError("could not build a request URL for \(path)"))
        }

        var headers: [(String, String)] = [
            ("X-Tenant-ID", config.tenantHeaderValue),
            ("Accept", "application/json"),
        ]
        if let actingTenantHeader {
            headers.append(actingTenantHeader) // §5.2 rule 1: every management call
        }
        if body != nil {
            headers.append(("Content-Type", "application/json"))
        }
        headers.append(contentsOf: credentialHeaders(for: url, method: method))

        let spec = HTTPRequestSpec(method: method, url: url, headers: headers, body: body)
        let response = try await transport.execute(spec, timeout: config.requestTimeout)

        let setCookies = response.allHeaders("set-cookie")
        if !setCookies.isEmpty {
            cookieJar.store(setCookieLines: setCookies, requestURL: url)
        }
        if let csrf = response.firstHeader("x-csrf-token") {
            csrfToken = csrf
        }
        return response
    }

    /// Whether this client holds a session — §27.4 rule 1's precondition, and the guard on
    /// the §9 refresh-then-retry-once path.
    func managementHasSession() -> Bool { hasSession }

    /// Whether a `401` on a management call should attempt the §9 refresh (§6.1 rule 6:
    /// `false` for a device-authenticated client — there is no refresh token for it).
    func managementCanRefresh() -> Bool { canRefresh }

    /// The §9 single-flight refresh. Reached rather than reimplemented: a management layer
    /// with its own refresh would put 147 endpoints outside this client's one guard.
    func managementRefreshOnce() async throws { try await refreshOnce() }
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

// Internal rather than fileprivate: `AxiamClient+Account.swift` builds the same
// user from the same §25.2 login-success shape after an MFA-setup ceremony.
extension LoginSuccessResponse {
    func toUser() -> AxiamUser {
        AxiamUser(
            userID: user.id,
            tenantID: user.tenant_id,
            roles: [],
            username: user.username,
            email: user.email,
            // §5.2: absent means false, which is what a server older than contract 1.31
            // answers and the safe direction in both cases.
            organizationLevel: user.organization_level ?? false,
            // §5.2.2 rule 1: absent means *equal* to the acting tenant, not unknown. A
            // server older than contract 1.34 omits the field and cannot switch the acting
            // tenant either, so `tenant_id` is not a guess here — it is the only value the
            // field could have had. Applied at this seam rather than left to the caller,
            // because it is the whole point of the field and is easy to lose.
            principalTenantID: user.principal_tenant_id ?? user.tenant_id,
            principalTenantSlug: user.principal_tenant_slug,
            orgID: user.org_id,
            // §5.2.3: a present-but-empty list stays `nil`. It would read as "reaches
            // nothing", the exact opposite of what an omitted field means here.
            reachableTenantIDs: user.reachable_tenant_ids.flatMap { $0.isEmpty ? nil : $0 }
        )
    }
}
