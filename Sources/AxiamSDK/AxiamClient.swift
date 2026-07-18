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
    let config: AxiamConfig
    private let transport: HTTPTransport
    let jwks: JwksVerifier

    // Session state (actor-isolated).
    private var cookieJar = CookieJar()
    private var csrfToken: String?
    private var challengeToken: Sensitive<String>?
    private var sessionUser: AxiamUser?
    private var hasSession = false
    private var refreshTask: Task<Void, Error>?

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
    }

    /// Release the underlying HTTP client. Call when the client is no longer needed.
    public func shutdown() async throws {
        try await transport.shutdown()
    }

    // MARK: - §1 Authentication

    /// Authenticate with email/username + password (§1 `login`).
    ///
    /// On success the session cookies are stored in this client's jar (§4). If the account
    /// needs MFA, the returned result is `.mfaRequired` and the challenge token is retained
    /// internally (as ``Sensitive``) for the subsequent ``verifyMfa(_:)`` call.
    public func login(email: String, password: String) async throws -> LoginResult {
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
        challengeToken = nil
    }

    /// Force a token refresh (§1 `refresh`). Routed through the single-flight guard (§9) so a
    /// manual refresh coalesces with any auto-refresh already in flight.
    public func refresh() async throws {
        try await refreshOnce()
    }

    /// End the session (§1 `logout`). Local session state is always cleared.
    public func logout() async throws {
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
        let bodies = checks.map {
            CheckAccessBody(action: $0.action, resource_id: $0.resource, scope: $0.scope, subject_id: $0.subjectID)
        }
        let body = try encode(BatchCheckAccessBody(checks: bodies))
        let response = try await authorizedPOST(path: "api/v1/authz/check/batch", body: body)
        let decoded = try decode(BatchCheckAccessResponse.self, response.body)
        return decoded.results.map { AccessResult(allowed: $0.allowed, reason: $0.reason) }
    }

    /// Subject-aware access check used by the §11 guards (`subject_id` = authenticated end user).
    func checkAccessInternal(action: String, resource: String, scope: String?, subjectID: String?) async throws -> AccessResult {
        let body = try encode(CheckAccessBody(action: action, resource_id: resource, scope: scope, subject_id: subjectID))
        let response = try await authorizedPOST(path: "api/v1/authz/check", body: body)
        let decoded = try decode(CheckAccessResponse.self, response.body)
        return AccessResult(allowed: decoded.allowed, reason: decoded.reason)
    }

    // MARK: - §10/§11 integration factories

    /// A framework-agnostic request authenticator (§10) verifying inbound sessions against the
    /// org JWKS and producing an ``AxiamUser``.
    public nonisolated func makeAuthenticator() -> AxiamRequestAuthenticator {
        AxiamRequestAuthenticator(jwks: jwks, tenantID: config.tenantHeaderValue)
    }

    /// Declarative authorization guard factories (§11): `requireAuth` / `requireAccess` /
    /// `requireRole`, built strictly on top of the §10 authenticator.
    public nonisolated func makeGuards() -> AxiamGuards {
        AxiamGuards(authenticator: makeAuthenticator(), client: self)
    }

    // MARK: - §9 single-flight refresh

    private func refreshOnce() async throws {
        // NOTE: the nil-check + task creation + assignment below run with no `await` between
        // them, so within the actor they are atomic — exactly one refresh Task is ever created.
        if let existing = refreshTask {
            try await existing.value
            return
        }
        let task = Task<Void, Error> { [self] in
            try await self.doRefresh()
        }
        refreshTask = task
        do {
            try await task.value
            refreshTask = nil
        } catch {
            refreshTask = nil
            throw error // §9: no retry loop on refresh failure — surface AuthError to the caller.
        }
    }

    private func doRefresh() async throws {
        let tenantID = sessionUser?.tenantID ?? config.tenantID ?? config.tenantSlug ?? ""
        let orgID = config.orgID ?? config.orgSlug ?? ""
        let body = try encode(RefreshRequest(tenant_id: tenantID, org_id: orgID))
        let response = try await rawSend(method: .post, path: "api/v1/auth/refresh", body: body)
        guard (200..<300).contains(response.status) else {
            if response.status == 401 { hasSession = false } // must re-authenticate (§9.3)
            throw mapError(response)
        }
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
