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
    ///   - tenantID: a tenant override for the `?tenant_id=` query parameter.
    ///   - configuration: the discovery document, or `nil` to discover.
    /// - Throws: ``AxiamError/auth(_:)`` client-side, with **no wire call**, when the
    ///   discovery document advertises no PAR endpoint — §12.7.2 rule 1's discipline: never
    ///   synthesise the URL from the issuer.
    public func oidcPar(
        request: AuthorizationRequest,
        redirectURI: String,
        scope: String = "openid profile email",
        tenantID: String? = nil,
        configuration: OidcConfiguration? = nil
    ) async throws -> PushedAuthorizationRequest {
        try ensureOpen()
        let document = try await oidcConfiguration(configuration)
        let clientID = try requireOidcClientID()

        guard
            let endpoint = document.pushedAuthorizationRequestEndpoint,
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

        // §26.2 rule 2: exactly two query parameters. The server REFUSES a request carrying
        // both a request_uri and any inline authorization parameter rather than merging
        // them: an attacker supplies the inline value they want and lets the pushed copy
        // satisfy whichever check reads the other one. Re-adding them "for compatibility"
        // restores the attack — which is why any query the discovered endpoint already
        // carried is dropped here rather than merged.
        guard var components = URLComponents(string: document.authorizationEndpoint) else {
            throw AxiamError.network(
                NetworkError("invalid authorization_endpoint in the discovery document")
            )
        }
        components.queryItems = [
            URLQueryItem(name: "client_id", value: clientID),
            URLQueryItem(name: "request_uri", value: wire.request_uri),
        ]
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
