import Foundation

// CONTRACT.md §15 — RFC 8693 token exchange. A backend holding a user's access token trades it
// for a *narrower* one before calling the next service.
//
// The rule this file must not paper over: an exchange only ever narrows. The server enforces
// that; this SDK's job is to not hide the refusals, because every one of them is the server
// telling the caller their assumption about their own privileges was wrong.

extension AxiamClient {

    static let tokenExchangeGrantType = "urn:ietf:params:oauth:grant-type:token-exchange"

    /// The RFC 8693 token type this SDK sends and expects. Both `subject_token_type` and
    /// `actor_token_type` are access tokens against AXIAM.
    static let accessTokenType = "urn:ietf:params:oauth:token-type:access_token"

    /// `POST /oauth2/token` with the RFC 8693 grant (§15.1).
    ///
    /// - Parameters:
    ///   - subjectToken: the token being exchanged — positional and first, because four
    ///     optional strings in positional order is a bug waiting to be written.
    ///   - actorToken: **its presence selects delegation; its absence selects impersonation.**
    ///     Two different operations with different risk, and §15.2 rule 1 forbids papering over
    ///     the difference: this SDK supplies no default actor token and never substitutes its
    ///     own session for one. Passing nothing here asks for impersonation, and the server
    ///     refuses unless this client holds that grant.
    ///   - scopes: omit to inherit the subject's, bounded by this client's registration. The
    ///     response's ``ExchangedToken/scope`` is what was actually granted, which may be
    ///     narrower than what was asked for even on success (§15.2 rule 7) — read it.
    ///
    /// What this deliberately does **not** do:
    ///
    /// - **No retry, downgrade or rewrite on `unauthorized_client`** (§15.2 rule 2). It means
    ///   either "this client may not exchange at all" or "this client may not impersonate";
    ///   both are registration facts an operator must fix, and reworking the request into a
    ///   delegation would send one the caller did not write.
    /// - **No auto-narrowing on `invalid_scope`** (§15.2 rule 3). The server refuses rather than
    ///   silently narrowing precisely so the caller finds out here.
    /// - **No refresh token, ever** (§15.2 rule 4). `TokenExchangeResponse` has no such field,
    ///   ``ExchangedToken`` has nowhere to put one, and this result never enters the §9
    ///   single-flight refresh guard. Re-run the exchange to get a fresh token.
    /// - **No adoption** (§15.2 rule 5). The exchanged token is not this client's session — not
    ///   even behind an opt-in flag, which is a MUST NOT here where adoption elsewhere is a MAY.
    ///   It is a token to hand onward in one outbound call; adopting it would silently
    ///   re-privilege every subsequent call this client makes.
    ///
    /// A cross-tenant subject token answers `invalid_grant`, and this SDK does not try to
    /// distinguish "wrong tenant" from "bad token" (§15.3): the server collapses them because
    /// telling them apart is a tenant-enumeration signal.
    public func tokenExchange(
        subjectToken: Sensitive<String>,
        actorToken: Sensitive<String>? = nil,
        scopes: [String]? = nil,
        audience: String? = nil,
        resource: String? = nil,
        tenantID: String? = nil,
        configuration: OidcConfiguration? = nil
    ) async throws -> ExchangedToken {
        let document = try await oidcConfiguration(configuration)

        // §15.1: the exchanging client authenticates — unlike §14's device, this is a
        // confidential service.
        var form = [
            "grant_type": Self.tokenExchangeGrantType,
            "subject_token": subjectToken.wrapped,
            "subject_token_type": Self.accessTokenType,
            "client_id": try requireOidcClientID(),
            "client_secret": try requireOidcClientSecret("tokenExchange").wrapped,
        ]
        if let actorToken {
            form["actor_token"] = actorToken.wrapped
            form["actor_token_type"] = Self.accessTokenType
        }
        if let scopes, !scopes.isEmpty { form["scope"] = scopes.joined(separator: " ") }
        if let audience { form["audience"] = audience }
        if let resource { form["resource"] = resource }

        let response = try await oidcFormPost(document.tokenEndpoint, form: form, tenantID: tenantID)
        guard (200..<300).contains(response.status) else {
            // Dispatches on the `error` field before the status mapping (§15.3), and surfaces it
            // verbatim: no retry, no rewriting, no guess about which of the six it "really" was.
            throw oidcMapGrantError(response)
        }
        let wire = try oidcDecode(TokenExchangeWire.self, response.body, "token exchange")
        return ExchangedToken(
            accessToken: Sensitive(wire.access_token),
            // §15.2 rule 6: surfaced, never dropped — a client that asked for one type and
            // received another has to be able to tell.
            issuedTokenType: wire.issued_token_type,
            tokenType: wire.token_type,
            expiresIn: wire.expires_in,
            scope: wire.scope)
    }
}
