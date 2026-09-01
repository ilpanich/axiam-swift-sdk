import Foundation

// CONTRACT.md §12 — the OIDC/SSO relying-party helpers.
//
// Thirteen operations — the original nine, plus the four login-provider operations that joined
// them at contract 1.37 — built on this SDK's existing machinery and forking none of it: the §6/§6.1
// transport, the §7 `Sensitive` wrapper, and the same JWKS verifier the §10 guard uses. §12
// adds no second HTTP path and no second key-fetching path.
//
// The section was deferred in this SDK through contract 1.10 and ported in 1.11 (§12.6). The
// reasoning that lifted the deferral is worth keeping in view while reading this file: the
// browser-redirect argument covered `oidcBegin` and `oidcExchange` and nothing else, and by
// contract 1.10 this SDK was already speaking OAuth2 at `/oauth2/token` for §20's ticket grant
// — with its own discovery document and none of the ID-token validation below.

extension AxiamClient {

    // MARK: - Constants

    static let oidcDiscoveryPath = ".well-known/openid-configuration"
    static let federationProvidersPath = "api/v1/auth/federation/providers"
    static let federationOAuth2StartPath = "api/v1/auth/federation/oauth2/start"
    static let federationOAuth2CallbackPath = "api/v1/auth/federation/oauth2/callback"
    static let federationHandoffPath = "api/v1/auth/federation/handoff"
    static let refreshGrantType = "refresh_token"
    static let clientCredentialsGrantType = "client_credentials"
    static let authorizationCodeGrantType = "authorization_code"

    // MARK: - §12.1 oidc_discover

    /// `GET /.well-known/openid-configuration` (§12.1).
    ///
    /// Cached per client for ``AxiamConfig/oidcDiscoveryTTL`` (five minutes minimum, §12.3
    /// rule 6). The cache is per **client instance**, which satisfies the origin-keying rule by
    /// construction: this client is bound to one base URL for its lifetime, so a document
    /// fetched from one origin can never be served for another.
    ///
    /// The document's `issuer` is authoritative for §12.4 rule 3 even when it differs from the
    /// base URL — behind a proxy it legitimately does, and §12.3 rule 6 forbids rejecting the
    /// document over that.
    public func oidcDiscover() async throws -> OidcConfiguration {
        try ensureOpen()
        if let cached = oidcConfigurationCache, cached.expiresAt > Date() {
            return cached.document
        }
        let url = config.baseURL.appendingPathComponent(Self.oidcDiscoveryPath)
        let response = try await umaSendAbsolute(
            method: .get, url: url, headers: [("Accept", "application/json")], body: nil)
        guard (200..<300).contains(response.status) else { throw oidcMapError(response) }
        let document = try oidcDecode(OidcConfiguration.self, response.body, "oidc discovery")
        oidcConfigurationCache = (document, Date().addingTimeInterval(config.oidcDiscoveryTTL))
        return document
    }

    // MARK: - §12.1 oidc_begin

    /// Build the authorization-code + PKCE redirect (§12.1) — **pure local computation, no
    /// network I/O** beyond the discovery fetch this client would cache anyway.
    ///
    /// **The caller owns the returned `state`, `nonce` and `codeVerifier`** (§12.3 rule 1). This
    /// SDK stores none of them: not on the client, not in a global, not in an implicit cache.
    /// Persist them in your own session and pass the last two back into
    /// ``oidcExchange(code:redirectURI:codeVerifier:nonce:tenantID:configuration:)``.
    ///
    /// - Parameters:
    ///   - redirectURI: must be replayed byte-identically to `oidcExchange`; the server compares
    ///     them exactly.
    ///   - scope: defaults to `openid profile email`. The `openid` scope is what makes the
    ///     server issue an ID token, and §12.4 rule 6 relies on it.
    public func oidcBegin(
        redirectURI: String,
        scope: String = "openid profile email",
        configuration: OidcConfiguration
    ) throws -> AuthorizationRequest {
        let clientID = try requireOidcClientID()
        let state = OidcPkce.makeCorrelationValue()
        let nonce = OidcPkce.makeCorrelationValue()
        let verifier = OidcPkce.makeVerifier()

        guard var components = URLComponents(string: configuration.authorizationEndpoint) else {
            throw AxiamError.network(NetworkError("invalid authorization_endpoint in the discovery document"))
        }
        var query = components.queryItems ?? []
        query.append(contentsOf: [
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "client_id", value: clientID),
            URLQueryItem(name: "redirect_uri", value: redirectURI),
            URLQueryItem(name: "scope", value: scope),
            URLQueryItem(name: "state", value: state),
            URLQueryItem(name: "nonce", value: nonce),
            URLQueryItem(name: "code_challenge", value: OidcPkce.challenge(for: verifier)),
            URLQueryItem(name: "code_challenge_method", value: OidcPkce.method),
        ])
        components.queryItems = query
        guard let url = components.url else {
            throw AxiamError.network(NetworkError("could not build the authorization URL"))
        }
        return AuthorizationRequest(
            url: url.absoluteString, state: state, nonce: nonce, codeVerifier: Sensitive(verifier))
    }

    /// ``oidcBegin(redirectURI:scope:configuration:)`` fetching the discovery document itself.
    ///
    /// Still performs no authorization-request I/O of its own — the one call it makes is the
    /// cached discovery fetch §12.1's "no network I/O" note explicitly permits.
    public func oidcBegin(
        redirectURI: String,
        scope: String = "openid profile email"
    ) async throws -> AuthorizationRequest {
        try oidcBegin(
            redirectURI: redirectURI, scope: scope, configuration: try await oidcDiscover())
    }

    // MARK: - §12.1 oidc_exchange

    /// `POST /oauth2/token` with `grant_type=authorization_code` (§12.1).
    ///
    /// **Stateless** (§12.3 rule 1): `codeVerifier` and `nonce` come from the caller, and
    /// nothing about this exchange is retained. The `redirectURI` must be the one
    /// ``oidcBegin(redirectURI:scope:configuration:)`` was given, byte-identically.
    ///
    /// Every §12.4 rule is enforced on the returned `id_token` before this returns, and rule 7
    /// makes that all-or-nothing: on any validation failure the whole token set is discarded —
    /// the access and refresh tokens from the same response are never handed back.
    public func oidcExchange(
        code: String,
        redirectURI: String,
        codeVerifier: Sensitive<String>,
        nonce: String,
        tenantID: String? = nil,
        configuration: OidcConfiguration? = nil
    ) async throws -> OidcTokenSet {
        let document = try await oidcConfiguration(configuration)
        var form = [
            "grant_type": Self.authorizationCodeGrantType,
            "code": code,
            "redirect_uri": redirectURI,
            "code_verifier": codeVerifier.wrapped,
            "client_id": try requireOidcClientID(),
        ]
        if let secret = config.oidcClientSecret { form["client_secret"] = secret.wrapped }

        let wire = try await oidcTokenGrant(form, document: document, tenantID: tenantID)
        // §12.4 rule 6: the nonce is mandatory here — this helper always requests `openid`, so
        // the server always issues one.
        return try await oidcTokenSet(wire, document: document, expectedNonce: nonce)
    }

    // MARK: - §12.1 oidc_refresh

    /// `POST /oauth2/token` with `grant_type=refresh_token` (§12.1).
    ///
    /// §12.4 rules 1–5 and 7 apply to any `id_token` in the response; rule 6 (nonce) is skipped,
    /// because OIDC Core §12.2 does not require a nonce in a refresh-issued ID token.
    public func oidcRefresh(
        refreshToken: Sensitive<String>,
        tenantID: String? = nil,
        configuration: OidcConfiguration? = nil
    ) async throws -> OidcTokenSet {
        let document = try await oidcConfiguration(configuration)
        var form = [
            "grant_type": Self.refreshGrantType,
            "refresh_token": refreshToken.wrapped,
            "client_id": try requireOidcClientID(),
        ]
        if let secret = config.oidcClientSecret { form["client_secret"] = secret.wrapped }

        let wire = try await oidcTokenGrant(form, document: document, tenantID: tenantID)
        return try await oidcTokenSet(wire, document: document, expectedNonce: nil)
    }

    // MARK: - §12.1 login_client_credentials

    /// `POST /oauth2/token` with `grant_type=client_credentials` (§12.1) — service-account
    /// login, and the operation §12.6 itself named as the one an embedded consumer wants.
    ///
    /// Requests no `openid` scope, so the response carries no ID token.
    ///
    /// **The result is not adopted as this client's credential.** Adoption is a §12.1 MAY, and
    /// this SDK takes the same posture everywhere: a token is returned to the caller, never
    /// silently installed. §20's PAT works the same way and for the same reason.
    public func loginClientCredentials(
        scope: String? = nil,
        tenantID: String? = nil,
        configuration: OidcConfiguration? = nil
    ) async throws -> OidcTokenSet {
        let document = try await oidcConfiguration(configuration)
        var form = [
            "grant_type": Self.clientCredentialsGrantType,
            "client_id": try requireOidcClientID(),
            "client_secret": try requireOidcClientSecret("loginClientCredentials").wrapped,
        ]
        if let scope, !scope.isEmpty { form["scope"] = scope }

        let wire = try await oidcTokenGrant(form, document: document, tenantID: tenantID)
        return try await oidcTokenSet(wire, document: document, expectedNonce: nil)
    }

    // MARK: - §12.1 introspect

    /// `POST /oauth2/introspect` (RFC 7662, §12.1). Requires confidential-client credentials
    /// (§12.1 note 4) — a public client cannot call it.
    public func introspect(
        token: Sensitive<String>,
        tokenTypeHint: String? = nil,
        tenantID: String? = nil,
        configuration: OidcConfiguration? = nil
    ) async throws -> IntrospectionResult {
        let document = try await oidcConfiguration(configuration)
        guard let endpoint = document.introspectionEndpoint else {
            throw AxiamError.network(NetworkError(
                "the discovery document advertises no introspection_endpoint"))
        }
        var form = [
            "token": token.wrapped,
            "client_id": try requireOidcClientID(),
            "client_secret": try requireOidcClientSecret("introspect").wrapped,
        ]
        if let tokenTypeHint { form["token_type_hint"] = tokenTypeHint }

        let response = try await oidcFormPost(endpoint, form: form, tenantID: tenantID)
        guard (200..<300).contains(response.status) else { throw oidcMapGrantError(response) }
        let wire = try oidcDecode(IntrospectionWire.self, response.body, "introspection")
        return IntrospectionResult(
            active: wire.active, scope: wire.scope, clientID: wire.client_id,
            username: wire.username, tokenType: wire.token_type, expiresAt: wire.exp,
            issuedAt: wire.iat, subject: wire.sub, audience: wire.aud, issuer: wire.iss,
            jwtID: wire.jti)
    }

    // MARK: - §12.1 revoke

    /// `POST /oauth2/revoke` (RFC 7009, §12.1). Returns nothing, and a `200` is success —
    /// **including for a token this client never issued**. Idempotence is the point of RFC 7009,
    /// and §12.1 note 5 requires a test for exactly that case.
    ///
    /// A `5xx` is still a `NetworkError`: returning void does not make a server failure a
    /// success.
    public func revoke(
        token: Sensitive<String>,
        tokenTypeHint: String? = nil,
        tenantID: String? = nil,
        configuration: OidcConfiguration? = nil
    ) async throws {
        let document = try await oidcConfiguration(configuration)
        guard let endpoint = document.revocationEndpoint else {
            throw AxiamError.network(NetworkError(
                "the discovery document advertises no revocation_endpoint"))
        }
        var form = [
            "token": token.wrapped,
            "client_id": try requireOidcClientID(),
            "client_secret": try requireOidcClientSecret("revoke").wrapped,
        ]
        if let tokenTypeHint { form["token_type_hint"] = tokenTypeHint }

        let response = try await oidcFormPost(endpoint, form: form, tenantID: tenantID)
        guard (200..<300).contains(response.status) else { throw oidcMapGrantError(response) }
    }

    // MARK: - §12.1 sso_start / sso_complete

    /// `POST /api/v1/auth/federation/oidc/start` (§12.1) — begin an upstream-IdP login.
    ///
    /// JSON, not form-encoded: this is an AXIAM REST endpoint rather than an OAuth2 one, and it
    /// carries org/tenant context in the body per §5.1 instead of a `tenant_id` query parameter.
    /// There is no nonce to store — the server keeps the federation nonce (§12.1 note 7).
    public func ssoStart(
        federationConfigID: String,
        redirectURI: String
    ) async throws -> SsoStartResult {
        try ensureOpen()
        var body: [String: String] = [
            "federation_config_id": federationConfigID,
            "redirect_uri": redirectURI,
        ]
        // §5.1: one tenant form and one org form, whichever this client was constructed with.
        if let tenantID = config.tenantID { body["tenant_id"] = tenantID }
        else if let slug = config.tenantSlug { body["tenant_slug"] = slug }
        if let orgID = config.orgID { body["org_id"] = orgID }
        else if let orgSlug = config.orgSlug { body["org_slug"] = orgSlug }

        let wire: SsoStartWire = try await oidcJSONPost(
            "api/v1/auth/federation/oidc/start", body: body, context: "sso start")
        return SsoStartResult(
            authorizeURL: wire.authorize_url, state: wire.state,
            expiresInSecs: wire.expires_in_secs)
    }

    /// `POST /api/v1/auth/federation/oidc/callback` (§12.1) — finish an upstream-IdP login.
    ///
    /// The session arrives as `Set-Cookie` and lands in this client's §4 cookie jar; the
    /// returned value carries **no token material** (§12.1 note 6). The server recovers the full
    /// context from the single-use `state`, so no tenant or org argument is needed here.
    public func ssoComplete(code: String, state: String) async throws -> SsoCompleteResult {
        try ensureOpen()
        let wire: SsoCompleteWire = try await oidcJSONPost(
            "api/v1/auth/federation/oidc/callback",
            body: ["code": code, "state": state],
            context: "sso complete")
        return SsoCompleteResult(
            userID: wire.user_id, sessionID: wire.session_id, expiresIn: wire.expires_in,
            redirectURI: wire.redirect_uri)
    }

    // MARK: - §12.1 sso_providers / sso_start_oauth2 / sso_complete_oauth2 / sso_complete_handoff

    /// `GET /api/v1/auth/federation/providers` (§12.1) — which "Sign in with X" buttons to
    /// render for a workspace.
    ///
    /// The workspace travels as **query parameters**, not a body: this is the one §12
    /// operation that is a `GET`. Arguments override what this client was constructed with;
    /// anything neither given nor configured is simply omitted.
    ///
    /// **An empty array is a success, and the only success there is** (§12.1 note 9). An
    /// unknown organization, a known one with no providers, and a request naming no workspace
    /// at all all answer `200` with `providers: []`. This method therefore never synthesises a
    /// not-found error, never refuses client-side for missing context, and offers no way to
    /// tell the three apart — the endpoint is shaped so it cannot be used to enumerate org or
    /// tenant slugs, and an SDK that restored the distinction would restore the oracle. A
    /// caller learns it named the workspace wrongly at the start operations, where every
    /// failure is a uniform `401`.
    ///
    /// Dispatch on each provider's ``FederationProvider/protocol`` to pick the start operation
    /// (§12.1 note 10) — never on ``FederationProvider/providerKind``.
    public func ssoProviders(
        orgID: String? = nil,
        orgSlug: String? = nil,
        tenantID: String? = nil,
        tenantSlug: String? = nil
    ) async throws -> [FederationProvider] {
        try ensureOpen()
        // §5.1: one form per workspace level, UUID winning over slug, exactly as the body-
        // carrying start operations resolve it. Nothing is required — see note 9 above.
        var query: [URLQueryItem] = []
        if let value = orgID ?? config.orgID {
            query.append(URLQueryItem(name: "org_id", value: value))
        } else if let value = orgSlug ?? config.orgSlug {
            query.append(URLQueryItem(name: "org_slug", value: value))
        }
        if let value = tenantID ?? config.tenantID {
            query.append(URLQueryItem(name: "tenant_id", value: value))
        } else if let value = tenantSlug ?? config.tenantSlug {
            query.append(URLQueryItem(name: "tenant_slug", value: value))
        }

        let response = try await rawGetWithQuery(
            path: Self.federationProvidersPath, query: query, context: "sso providers")
        guard (200..<300).contains(response.status) else { throw oidcMapError(response) }
        let wire: PublicFederationProvidersWire = try oidcDecode(
            PublicFederationProvidersWire.self, response.body, "sso providers")
        return wire.providers.map {
            FederationProvider(
                id: $0.id,
                providerKind: $0.provider_kind,
                displayName: $0.display_name,
                protocol: $0.`protocol`,
                hasBundledMark: $0.has_bundled_mark,
                buttonIcon: $0.button_icon,
                inherited: $0.inherited)
        }
    }

    /// `POST /api/v1/auth/federation/oauth2/start` (§12.1) — begin a login through a
    /// **plain-OAuth2** upstream (GitHub, Facebook, any configured `generic_oauth2`).
    ///
    /// Call this, and not ``ssoStart(federationConfigID:redirectURI:)``, exactly when the
    /// provider's ``FederationProvider/protocol`` is
    /// ``FederationProvider/protocolOAuth2`` (§12.1 note 10). The server refuses a mismatch
    /// with `400` rather than accepting it silently.
    ///
    /// PKCE is mandatory on this path and is generated and stored **server-side** (§12.1
    /// note 11): no verifier and no challenge appears in this request or its response, and
    /// this SDK computes neither. The OAuth2 variant also carries reduced assurance — there is
    /// no ID token, so no signature, no `nonce` and no `aud`; the server authenticates by
    /// calling the provider's userinfo endpoint.
    ///
    /// A `400` can also mean the deployment does not accept `redirectURI`'s origin (§12.1
    /// rule 12a). §2 maps `400` to ``NetworkError`` — this taxonomy's configuration/programming
    /// error, as distinct from the ``AuthError`` a `401` gets — and it is never retried. Never
    /// build `redirectURI` from a value the identity provider supplied.
    public func ssoStartOauth2(
        federationConfigID: String,
        redirectURI: String
    ) async throws -> SsoStartResult {
        try ensureOpen()
        var body: [String: String] = [
            "federation_config_id": federationConfigID,
            "redirect_uri": redirectURI,
        ]
        // §5.1, identical to `ssoStart` — and with no PKCE field anywhere, by note 11.
        if let tenantID = config.tenantID { body["tenant_id"] = tenantID }
        else if let slug = config.tenantSlug { body["tenant_slug"] = slug }
        if let orgID = config.orgID { body["org_id"] = orgID }
        else if let orgSlug = config.orgSlug { body["org_slug"] = orgSlug }

        let wire: SsoStartWire = try await oidcJSONPost(
            Self.federationOAuth2StartPath, body: body, context: "sso start oauth2")
        return SsoStartResult(
            authorizeURL: wire.authorize_url, state: wire.state,
            expiresInSecs: wire.expires_in_secs)
    }

    /// `POST /api/v1/auth/federation/oauth2/callback` (§12.1) — finish a plain-OAuth2 login.
    ///
    /// The SPA calls this same-origin, so the session arrives directly as `Set-Cookie` and
    /// lands in this client's §4 cookie jar; the returned value carries **no token material**
    /// (§12.1 note 6). The server recovers the whole context from the single-use `state`, so
    /// no tenant or org argument is needed.
    public func ssoCompleteOauth2(code: String, state: String) async throws -> SsoCompleteResult {
        try ensureOpen()
        return try await completeFederationSession(
            path: Self.federationOAuth2CallbackPath,
            body: ["code": code, "state": state],
            context: "sso complete oauth2")
    }

    /// `POST /api/v1/auth/federation/handoff` (§12.1) — redeem a handoff code for a session.
    ///
    /// SAML and Apple's `response_mode=form_post` return cross-site, so the server cannot set
    /// `SameSite=Strict` cookies on that response. It redirects the browser to the SPA callback
    /// with the code in the ``FederationHandoff/queryParameter`` query parameter; *this*
    /// same-origin POST is the one that carries `Set-Cookie` (§12.1 note 12).
    ///
    /// The code is single-use and lives ``FederationHandoff/codeTTLSeconds`` seconds. Unknown,
    /// expired and already-redeemed all answer the same `401`, deliberately — so a `401` here
    /// is **terminal**: the code is gone either way and a failed redemption must never be
    /// retried. Redeem from the same origin the code was delivered to.
    public func ssoCompleteHandoff(code: String) async throws -> SsoCompleteResult {
        try ensureOpen()
        return try await completeFederationSession(
            path: Self.federationHandoffPath,
            body: ["code": code],
            context: "sso complete handoff")
    }

    /// The shared body of the two session-establishing federation POSTs.
    ///
    /// One wire call through the same §6 transport the rest of §12 uses, the §2 status mapping
    /// on anything but success, and — because these two responses are the ones that carry the
    /// session — the `Set-Cookie` lines stored into the §4 jar and any rotated CSRF token kept.
    private func completeFederationSession(
        path: String,
        body: [String: String],
        context: String
    ) async throws -> SsoCompleteResult {
        let payload = try JSONSerialization.data(withJSONObject: body)
        // §12.1 note 8: these endpoints are unauthenticated, so on a first call no `axiam_csrf`
        // cookie exists yet and no `X-CSRF-Token` header is sent. §3 step 3 governs, and
        // `federationSessionPost` follows it — it never invents a value.
        let response = try await federationSessionPost(path: path, body: payload)
        guard (200..<300).contains(response.status) else { throw oidcMapError(response) }
        let wire: SsoCompleteWire = try oidcDecode(SsoCompleteWire.self, response.body, context)
        return SsoCompleteResult(
            userID: wire.user_id, sessionID: wire.session_id, expiresIn: wire.expires_in,
            redirectURI: wire.redirect_uri)
    }
}
