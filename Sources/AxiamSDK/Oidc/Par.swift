import Foundation

// CONTRACT.md §26 — Pushed Authorization Requests (RFC 9126).
extension AxiamClient {

    /// `POST /oauth2/par` (CONTRACT.md §26.1) — push the authorization request over the
    /// back channel and get an opaque handle to redirect with.
    ///
    /// PAR moves the authorization request off the browser. Instead of putting `scope`,
    /// `redirect_uri`, `state` and the PKCE challenge into a URL the user agent carries,
    /// the client POSTs them straight to AXIAM over an authenticated channel and puts an
    /// opaque `request_uri` in the redirect. What travels through the browser is then a
    /// random string that cannot be edited into meaning something else.
    ///
    /// **Required for a FAPI 2.0 client**: `profile: "fapi2"` refuses a registration that
    /// does not set `require_par`, so such a client cannot authorize any other way (§21.1).
    ///
    /// Not retried on a `5xx` or a transport failure — it is a POST that creates server
    /// state, so it falls outside §16.2's read-only eligibility exactly as `oidcExchange`
    /// does. The safe recovery is a fresh push, which costs one round trip and cannot
    /// double-consume anything (§26.2 rule 4).
    ///
    /// - Parameters:
    ///   - request: what ``oidcBegin(redirectURI:scope:configuration:)`` returned. Its
    ///     `state`, `nonce` and PKCE verifier are pushed as-is — §26.2 rule 1 forbids a
    ///     second generator.
    ///   - redirectURI: the same redirect URI that will be sent at exchange time.
    ///   - scope: the requested scope. Must match what was pushed at `oidcBegin`.
    ///   - dpopJkt: RFC 9449 §10.1 — the JWK SHA-256 thumbprint of the key the client will
    ///     prove possession of at the token endpoint, binding the authorization code to that
    ///     key from the moment it is issued rather than from first use. Sent **only when
    ///     given**; omitting it is the unbound behaviour every release before contract 1.42
    ///     had. **Caller-supplied, and it has to be**: CONTRACT.md §21.9 records this SDK as
    ///     verifying DPoP proofs but not generating them, so it holds no client key and has
    ///     no thumbprint of its own to offer. An application doing DPoP computes the
    ///     thumbprint over its own key (RFC 7638) and passes it here.
    ///   - tenantID: a tenant override for the `?tenant_id=` query parameter.
    ///   - configuration: the discovery document, or `nil` to discover.
    /// - Throws: ``AxiamError/auth(_:)`` client-side, with **no wire call**, when the
    ///   discovery document advertises no PAR endpoint — §12.7.2 rule 1's discipline: never
    ///   synthesise the URL from the issuer.
    public func oidcPar(
        request: AuthorizationRequest,
        redirectURI: String,
        scope: String = "openid profile email",
        dpopJkt: String? = nil,
        tenantID: String? = nil,
        configuration: OidcConfiguration? = nil
    ) async throws -> PushedAuthorizationRequest {
        try ensureOpen()
        let document = try await oidcConfiguration(configuration)
        let clientID = try requireOidcClientID()

        guard
            let endpoint = preferredEndpoint(
                document,
                { $0.pushedAuthorizationRequestEndpoint },
                document.pushedAuthorizationRequestEndpoint
            ),
            !endpoint.isEmpty
        else {
            throw AxiamError.auth(AuthError(
                "the authorization server's discovery document advertises no "
                    + "pushed_authorization_request_endpoint: this server does not support "
                    + "RFC 9126 (CONTRACT.md §26.1)."
            ))
        }

        // §26.2 rule 1: everything below was computed by oidcBegin. There is no second
        // generator here, and there must not be — two sources for state or the PKCE pair
        // are two things that can disagree.
        var form = [
            "client_id": clientID,
            "response_type": "code",
            "redirect_uri": redirectURI,
            "scope": scope,
            "state": request.state,
            "nonce": request.nonce,
            "code_challenge": OidcPkce.challenge(for: request.codeVerifier.wrapped),
            "code_challenge_method": "S256",
        ]
        if let secret = config.oidcClientSecret { form["client_secret"] = secret.wrapped }
        // RFC 9449 §10.1: present only when the caller supplied one. An empty or absent
        // `dpop_jkt` is not the same as one bound to no key — the server reads the parameter's
        // presence as "this code may only be redeemed with a proof of that key", and sending
        // it speculatively would make every push demand a proof this SDK cannot produce
        // (§21.9: verifies, does not generate).
        if let dpopJkt { form["dpop_jkt"] = dpopJkt }

        // `request_uri` is deliberately NOT a parameter of this method, although contract 1.42
        // adds one to the `PushedAuthorizationRequest` wire schema. RFC 9126 §2.1 makes it the
        // one authorization parameter a client MUST NOT push; the server models it so it can
        // REFUSE it. A client able to send it is a client able to chain one pushed request into
        // another, which is the confusion §26.2 rule 2 exists to stop — so the capability is
        // not offered here at all.

        // 201, not 200. RFC 9126 §2.2 specifies Created, and this is the one thing an
        // implementation of this section gets wrong: a success predicate written == 200
        // treats every successful push as a failure while passing every other assertion.
        // The 2xx range admits both.
        let response = try await oidcFormPost(endpoint, form: form, tenantID: tenantID)
        guard (200..<300).contains(response.status) else { throw oidcMapGrantError(response) }

        let wire = try oidcDecode(
            PushedAuthorizationResponseWire.self,
            response.body,
            "pushed authorization response"
        )
        guard !wire.request_uri.isEmpty else {
            throw AxiamError.network(
                NetworkError("pushed authorization response carried no request_uri")
            )
        }

        // §26.2 rule 2: the two authorization parameters, and no others. The server REFUSES a
        // request carrying both a request_uri and any inline authorization parameter rather
        // than merging them: an attacker supplies the inline value they want and lets the
        // pushed copy satisfy whichever check reads the other one. Re-adding them "for
        // compatibility" restores the attack — which is why any query the discovered endpoint
        // already carried is dropped here rather than merged.
        //
        // `tenant_id` is the single exception, and it is not an authorization parameter.
        // AXIAM's discovery document publishes `authorization_endpoint` already scoped as
        // `…/oauth2/authorize?tenant_id=<uuid>` (axiam-oauth2 `tenant_scoped`) whenever the
        // discovery request named a tenant, or the deployment sets `oauth2_default_tenant_id`.
        // It is routing — it picks the tenant whose session and client registry the request is
        // resolved against — and dropping it sends the browser to an endpoint with no tenant,
        // where a user agent carrying no session is answered `401` rather than a login page.
        // Carrying it does not widen what a request can say: there is no pushed `tenant_id` for
        // an inline one to disagree with, because the tenant travels on the PAR call's own
        // query string rather than in its form body.
        //
        // The resolved tenant wins over whatever the advertised URL carried, for the reason it
        // does on the back channel too: the push that just minted this `request_uri` went to
        // that tenant, and a deterministic answer beats a silent mismatch. It is resolvable
        // here because `oidcFormPost` above would have thrown, with no wire call, had it not
        // been a UUID (§12.3 rule 4).
        guard var components = URLComponents(string: document.authorizationEndpoint) else {
            throw AxiamError.network(
                NetworkError("invalid authorization_endpoint in the discovery document")
            )
        }
        var items = [
            URLQueryItem(name: "client_id", value: clientID),
            URLQueryItem(name: "request_uri", value: wire.request_uri),
        ]
        if let tenant = tenantID ?? config.tenantID {
            items.append(URLQueryItem(name: "tenant_id", value: tenant))
        }
        components.queryItems = items
        guard let url = components.url?.absoluteString else {
            throw AxiamError.network(
                NetworkError("could not build the pushed authorization redirect URL")
            )
        }

        return PushedAuthorizationRequest(
            url: url,
            requestURI: Sensitive(wire.request_uri),
            expiresIn: wire.expires_in,
            state: request.state,
            nonce: request.nonce,
            codeVerifier: request.codeVerifier
        )
    }
}
