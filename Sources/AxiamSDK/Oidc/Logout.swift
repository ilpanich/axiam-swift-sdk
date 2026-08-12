import Foundation

// CONTRACT.md §12.7 — the RP side of RP-Initiated Logout 1.0 and Back-Channel Logout 1.0.
//
// Two operations on opposite sides of the flow: one builds a URL for the browser, the other
// verifies something the *server* pushed to this relying party. Neither performs network I/O of
// its own — `logoutURL` beyond the discovery fetch this client would cache anyway, and
// `verifyLogoutToken` against the JWKS the §12.4 verifier already holds.

extension AxiamClient {

    /// The `event` key that distinguishes a logout token from an ID token (§12.7.3 rule 3).
    static let backchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

    /// Build the `end_session_endpoint` URL to redirect the user agent to (§12.7.1).
    ///
    /// - Parameters:
    ///   - idToken: passed whole, as `id_token_hint`. **There is no hint-less mode** and this
    ///     SDK will not invent one (§12.7.1): no such parameter exists on the wire, and naming
    ///     the user some other way would encourage exactly the request the server refuses to act
    ///     on.
    ///   - postLogoutRedirectURI: passed through unvalidated. The allow-list lives in the
    ///     client's server-side registration; a local copy would drift and would reject a URI an
    ///     operator had just registered (§12.7.2 rule 3).
    ///   - state: **the caller's to generate and the caller's to check.** This SDK never invents
    ///     one, because the value only means something to the application that receives it back
    ///     (§12.7.2 rule 2).
    ///
    /// Performs no network I/O and does **not** clear this client's own session (§12.7.2
    /// rule 4): a backend holding a service-account session must not lose it because a *user*
    /// logged out.
    public func logoutURL(
        idToken: Sensitive<String>,
        postLogoutRedirectURI: String? = nil,
        state: String? = nil,
        configuration: OidcConfiguration
    ) throws -> String {
        // §12.7.2 rule 1: the endpoint comes from discovery. Concatenating `{issuer}/oauth2/…`
        // works against AXIAM and breaks against any other OP the same code is pointed at.
        guard let endpoint = configuration.endSessionEndpoint else {
            throw AxiamError.network(NetworkError(
                "the discovery document advertises no end_session_endpoint"))
        }
        guard var components = URLComponents(string: endpoint) else {
            throw AxiamError.network(NetworkError("invalid end_session_endpoint in the discovery document"))
        }
        var query = components.queryItems ?? []
        query.append(URLQueryItem(name: "id_token_hint", value: idToken.wrapped))
        if let postLogoutRedirectURI {
            query.append(URLQueryItem(name: "post_logout_redirect_uri", value: postLogoutRedirectURI))
        }
        if let state {
            query.append(URLQueryItem(name: "state", value: state))
        }
        components.queryItems = query
        guard let url = components.url else {
            throw AxiamError.network(NetworkError("could not build the logout URL"))
        }
        return url.absoluteString
    }

    /// ``logoutURL(idToken:postLogoutRedirectURI:state:configuration:)`` fetching the discovery
    /// document itself.
    public func logoutURL(
        idToken: Sensitive<String>,
        postLogoutRedirectURI: String? = nil,
        state: String? = nil
    ) async throws -> String {
        try logoutURL(
            idToken: idToken, postLogoutRedirectURI: postLogoutRedirectURI, state: state,
            configuration: try await oidcDiscover())
    }

    /// Verify a back-channel logout token the OP POSTed to this relying party's own endpoint
    /// (§12.7.3).
    ///
    /// This is the half that carries security weight: the input arrives unsolicited, from the
    /// network, and instructs the RP to terminate a session. Every check below is required, and
    /// each exists because skipping it has a name:
    ///
    /// 1. Signature against the OP's JWKS, through the same §12.4 verifier — no second
    ///    key-fetching path.
    /// 2. `iss` matches the discovery issuer; `aud` contains this client's `client_id`. A token
    ///    minted for another RP is not accepted here.
    /// 3. `events` contains the back-channel logout key with an object value. This is what
    ///    distinguishes a logout token from an ID token; skipping it accepts a replayed ID token
    ///    as a logout instruction.
    /// 4. `nonce` is **absent**. Back-Channel Logout 1.0 §2.4 forbids it, and its presence is
    ///    the documented signature of an ID token being replayed — rejected, not ignored.
    /// 5. At least one of `sid` and `sub` is present. A token naming neither identifies nothing.
    /// 6. `exp` is in the future and `iat` recent.
    ///
    /// **When ``VerifiedLogoutToken/sid`` is present, end that session only.** Falling back to
    /// "every session for `sub`" when a `sid` was supplied is the same over-reach the server
    /// refuses to make.
    ///
    /// ``VerifiedLogoutToken/jwtID`` is surfaced so the caller can deduplicate; this SDK does
    /// not dedup internally (§12.7.3 rule 7) — delivery is at-least-once, and a library with no
    /// durable store would silently drop a real second logout after a restart.
    public func verifyLogoutToken(
        _ token: String,
        configuration: OidcConfiguration
    ) async throws -> VerifiedLogoutToken {
        try ensureOpen()

        // Rule 1.
        do {
            _ = try await jwks.verifySignatureOnlyUnchecked(token: token)
        } catch {
            throw AxiamError.auth(AuthError(
                "logout token signature verification failed", oauthError: "invalid_signature"))
        }

        let segments = token.split(separator: ".", omittingEmptySubsequences: false)
        guard segments.count == 3, let payload = Base64URL.decode(String(segments[1])),
              let wire = try? JSONDecoder().decode(LogoutTokenWire.self, from: payload) else {
            throw AxiamError.auth(AuthError("logout token is not a well-formed JWT"))
        }

        // Rule 2.
        guard wire.iss == configuration.issuer else {
            throw AxiamError.auth(AuthError(
                "logout token `iss` does not match the discovery document's issuer",
                oauthError: "invalid_issuer"))
        }
        let clientID = try requireOidcClientID()
        guard (wire.aud?.values ?? []).contains(clientID) else {
            throw AxiamError.auth(AuthError(
                "logout token `aud` does not contain this client_id", oauthError: "invalid_audience"))
        }

        // Rule 3 — the key must be present AND its value must be an object.
        guard let events = wire.events, events[Self.backchannelLogoutEvent] != nil else {
            throw AxiamError.auth(AuthError(
                "logout token carries no backchannel-logout event: this is what distinguishes it "
                + "from an ID token"))
        }

        // Rule 4 — reject, do not ignore.
        guard wire.nonce == nil else {
            throw AxiamError.auth(AuthError(
                "logout token carries a `nonce`, which Back-Channel Logout 1.0 §2.4 forbids: "
                + "this is the documented signature of an ID token being replayed"))
        }

        // Rule 5.
        guard wire.sid != nil || wire.sub != nil else {
            throw AxiamError.auth(AuthError("logout token names neither `sid` nor `sub`"))
        }

        // Rule 6 — the same freshness tolerance §13 applies.
        let now = Date()
        let skew = config.oidcClockSkew
        guard let iat = wire.iat else {
            throw AxiamError.auth(AuthError("logout token carries no `iat`", oauthError: "token_expired"))
        }
        if let exp = wire.exp, Date(timeIntervalSince1970: exp) <= now.addingTimeInterval(-skew) {
            throw AxiamError.auth(AuthError("logout token has expired", oauthError: "token_expired"))
        }
        let issuedAt = Date(timeIntervalSince1970: iat)
        guard issuedAt <= now.addingTimeInterval(skew) else {
            throw AxiamError.auth(AuthError("logout token `iat` is in the future", oauthError: "token_expired"))
        }

        return VerifiedLogoutToken(
            sid: wire.sid, subject: wire.sub, jwtID: wire.jti, issuer: wire.iss, issuedAt: issuedAt)
    }

    /// ``verifyLogoutToken(_:configuration:)`` fetching the discovery document itself.
    public func verifyLogoutToken(_ token: String) async throws -> VerifiedLogoutToken {
        try await verifyLogoutToken(token, configuration: try await oidcDiscover())
    }
}

/// A logout token's claims. `events` is decoded as a map of *objects* rather than a bare set of
/// keys, because §12.7.3 rule 3 requires the value to be an object.
struct LogoutTokenWire: Decodable {
    let iss: String
    let aud: JwtAudience?
    let sid: String?
    let sub: String?
    let jti: String?
    let iat: Double?
    let exp: Double?
    let nonce: String?
    let events: [String: [String: String]]?
}
