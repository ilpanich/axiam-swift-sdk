import Foundation

// The §12 machinery: the token-endpoint plumbing every grant shares, and the §12.4 ID-token
// validation checklist all of them run their `id_token` through.

/// The seven §12.3 rule 3 reason codes. **A closed vocabulary** — no SDK may add an eighth, so
/// several distinct failures deliberately share one code and the sharing is normative rather
/// than incidental.
public enum OidcValidationCode: String, Sendable {
    /// Also covers a JOSE header that cannot be parsed at all: the algorithm cannot then be
    /// established, so there is nothing else to call it.
    case invalidAlg = "invalid_alg"
    /// Also covers "the header carries no `kid` at all", and a JWKS transport failure during the
    /// §12.4 rule 2 re-fetch.
    case unknownKid = "unknown_kid"
    /// The catch-all for any other verification failure, so nothing has to invent a code.
    case invalidSignature = "invalid_signature"
    case invalidIssuer = "invalid_issuer"
    case invalidAudience = "invalid_audience"
    /// **Every** rule-5 time failure: a past `exp`, an *absent* `exp`, an absent or future
    /// `iat`, and a future `nbf` all report this one code.
    case tokenExpired = "token_expired"
    case nonceMismatch = "nonce_mismatch"
}

extension AxiamClient {

    // MARK: - Client configuration

    func requireOidcClientID() throws -> String {
        guard let clientID = config.oidcClientID, !clientID.isEmpty else {
            throw AxiamError.auth(AuthError(
                "this operation requires an OIDC client_id: construct the client with "
                + "oidcClientID (CONTRACT.md §12.1 — client_id is client configuration, not a "
                + "per-call argument)."))
        }
        return clientID
    }

    func requireOidcClientSecret(_ operation: String) throws -> Sensitive<String> {
        guard let secret = config.oidcClientSecret, !secret.wrapped.isEmpty else {
            throw AxiamError.auth(AuthError(
                "\(operation) requires confidential-client credentials: construct the client "
                + "with oidcClientSecret (CONTRACT.md §12.1 note 4)."))
        }
        return secret
    }

    /// The caller's pre-fetched document, or a (cached) discovery fetch.
    ///
    /// A plain `??` cannot express this: its right-hand side is an autoclosure, which cannot be
    /// `async`. Every operation below takes an optional document so a caller driving several
    /// calls in a row can fetch once.
    func oidcConfiguration(_ provided: OidcConfiguration?) async throws -> OidcConfiguration {
        if let provided { return provided }
        return try await oidcDiscover()
    }

    // MARK: - The token endpoint

    /// One form-encoded POST to an absolute `/oauth2/*` endpoint, carrying the mandatory
    /// `?tenant_id=<uuid>` query parameter (§12.1 note 2).
    ///
    /// No cookie and no CSRF token ride along: these endpoints authenticate the **client**
    /// through the form body, and attaching this client's user session would put a second,
    /// unasked-for identity on the request.
    func oidcFormPost(
        _ endpoint: String,
        form: [String: String],
        tenantID: String?
    ) async throws -> HTTPResponseData {
        try ensureOpen()
        let url = try oidcTenantScopedURL(endpoint, tenantID: tenantID)
        return try await umaSendAbsolute(
            method: .post,
            url: url,
            headers: [
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("Accept", "application/json"),
            ],
            body: Data(Self.oidcFormEncode(form).utf8))
    }

    /// A token-endpoint grant: POST the form, map an `OAuth2ErrorResponse` body, decode.
    func oidcTokenGrant(
        _ form: [String: String],
        document: OidcConfiguration,
        tenantID: String?
    ) async throws -> TokenResponseWire {
        let response = try await oidcFormPost(document.tokenEndpoint, form: form, tenantID: tenantID)
        guard (200..<300).contains(response.status) else { throw oidcMapGrantError(response) }
        return try oidcDecode(TokenResponseWire.self, response.body, "token response")
    }

    /// The `/oauth2/*` URL plus `?tenant_id=<uuid>`.
    ///
    /// §12.3 rule 4: the parameter takes a **UUID**, and a tenant slug is never a substitute.
    /// A slug-only client that passes no explicit `tenantID` therefore fails **client-side,
    /// with no wire call** — the request could not have succeeded, and sending it would leak a
    /// slug into a field the server reads as a UUID.
    func oidcTenantScopedURL(_ endpoint: String, tenantID: String?) throws -> URL {
        let candidate = tenantID ?? config.tenantID
        guard let candidate, UUID(uuidString: candidate) != nil else {
            throw AxiamError.auth(AuthError(
                "this operation requires a tenant_id UUID for the /oauth2 query parameter: pass "
                + "tenantID explicitly, or construct the client with a tenantID (UUID). A tenant "
                + "slug is not a substitute (CONTRACT.md §12.3 rule 4)."))
        }
        guard var components = URLComponents(string: endpoint) else {
            throw AxiamError.network(NetworkError("invalid endpoint in the discovery document"))
        }
        var query = components.queryItems ?? []
        query.removeAll { $0.name == "tenant_id" }
        query.append(URLQueryItem(name: "tenant_id", value: candidate))
        components.queryItems = query
        guard let url = components.url else {
            throw AxiamError.network(NetworkError("invalid endpoint in the discovery document"))
        }
        return url
    }

    /// A JSON POST against a path on this client's own base URL — the two federation
    /// operations, which are AXIAM REST endpoints rather than OAuth2 ones.
    func oidcJSONPost<T: Decodable>(
        _ path: String,
        body: [String: String],
        context: String
    ) async throws -> T {
        let url = config.baseURL.appendingPathComponent(path)
        let payload = try JSONSerialization.data(withJSONObject: body)
        let response = try await umaSendAbsolute(
            method: .post,
            url: url,
            headers: [("Content-Type", "application/json"), ("Accept", "application/json")],
            body: payload)
        guard (200..<300).contains(response.status) else { throw oidcMapError(response) }
        return try oidcDecode(T.self, response.body, context)
    }

    // MARK: - §12.4 ID-token validation

    /// Build the token set, validating any `id_token` first.
    ///
    /// §12.4 rule 7 is why validation happens before the set is assembled: on failure the whole
    /// response is discarded, so the access and refresh tokens never reach the caller.
    func oidcTokenSet(
        _ wire: TokenResponseWire,
        document: OidcConfiguration,
        expectedNonce: String?
    ) async throws -> OidcTokenSet {
        var claims: IdTokenClaims?
        if let idToken = wire.id_token, !idToken.isEmpty {
            claims = try await validateIdToken(idToken, document: document, expectedNonce: expectedNonce)
        }
        return OidcTokenSet(
            accessToken: Sensitive(wire.access_token),
            tokenType: wire.token_type,
            expiresIn: wire.expires_in,
            scope: wire.scope,
            refreshToken: wire.refresh_token.map(Sensitive.init),
            idToken: wire.id_token.map(Sensitive.init),
            idClaims: claims)
    }

    /// The §12.4 checklist, in order, against the same JWKS verifier the §10 guard uses.
    ///
    /// Rules 1 and 2 (algorithm pinned before key lookup, Ed25519 signature by `kid`, one
    /// re-fetch per cooldown window on an unknown `kid`) are enforced inside that verifier —
    /// extended, never forked, exactly as §12.4 requires. Rules 3–6 are here.
    func validateIdToken(
        _ idToken: String,
        document: OidcConfiguration,
        expectedNonce: String?
    ) async throws -> IdTokenClaims {
        let verified: VerifiedToken
        do {
            verified = try await jwks.verifySignatureOnlyUnchecked(token: idToken)
        } catch {
            // The verifier's failures are already the rule 1/2 set; it distinguishes them in its
            // message. Mapping them here would need a second classification of the same failure.
            throw oidcValidationError(.invalidSignature, "id_token signature verification failed")
        }

        let claims = try oidcIdTokenClaims(idToken)

        // Rule 3 — exact string comparison. No normalization, no trailing-slash tolerance.
        guard claims.issuer == document.issuer else {
            throw oidcValidationError(.invalidIssuer, "id_token `iss` does not match the discovery document's issuer")
        }

        // Rule 4 — `aud` contains our client_id; with more than one audience, `azp` must be it.
        let clientID = try requireOidcClientID()
        guard claims.audience.contains(clientID) else {
            throw oidcValidationError(.invalidAudience, "id_token `aud` does not contain this client_id")
        }
        if claims.audience.count > 1 {
            guard claims.authorizedParty == clientID else {
                throw oidcValidationError(
                    .invalidAudience,
                    "id_token carries multiple audiences without an `azp` naming this client_id")
            }
        }

        // Rule 5 — every time failure reports token_expired, including an absent exp or iat.
        let now = Date()
        let skew = config.oidcClockSkew
        guard claims.expiresAt > now.addingTimeInterval(-skew) else {
            throw oidcValidationError(.tokenExpired, "id_token has expired")
        }
        guard claims.issuedAt <= now.addingTimeInterval(skew) else {
            throw oidcValidationError(.tokenExpired, "id_token `iat` is in the future")
        }
        if let notBefore = claims.notBefore, notBefore > now.addingTimeInterval(skew) {
            throw oidcValidationError(.tokenExpired, "id_token is not yet valid")
        }

        // Rule 6 — mandatory for oidc_exchange, skipped for refresh/client-credentials.
        if let expectedNonce {
            guard let actual = claims.nonce else {
                throw oidcValidationError(.nonceMismatch, "id_token carries no `nonce`")
            }
            guard ConstantTime.equals(Array(actual.utf8), Array(expectedNonce.utf8)) else {
                throw oidcValidationError(.nonceMismatch, "id_token `nonce` does not match the one from oidcBegin")
            }
        }

        return IdTokenClaims(
            subject: claims.subject, issuer: claims.issuer, audience: claims.audience,
            expiresAt: claims.expiresAt, issuedAt: claims.issuedAt, nonce: claims.nonce,
            authorizedParty: claims.authorizedParty, email: claims.email,
            preferredUsername: claims.preferredUsername, tenantID: claims.tenantID,
            roles: claims.roles)
    }

    /// Decode the payload segment. Rule 5 treats `exp` and `iat` as **required**, so an absent
    /// one is a `token_expired` failure rather than a decode error with a different code.
    func oidcIdTokenClaims(_ idToken: String) throws -> IdTokenPayload {
        let segments = idToken.split(separator: ".", omittingEmptySubsequences: false)
        guard segments.count == 3, let payload = Base64URL.decode(String(segments[1])) else {
            throw oidcValidationError(.invalidAlg, "id_token is not a well-formed JWT")
        }
        guard let wire = try? JSONDecoder().decode(IdTokenPayloadWire.self, from: payload) else {
            throw oidcValidationError(.invalidSignature, "id_token claims are not decodable")
        }
        guard let exp = wire.exp else {
            throw oidcValidationError(.tokenExpired, "id_token carries no `exp`")
        }
        guard let iat = wire.iat else {
            throw oidcValidationError(.tokenExpired, "id_token carries no `iat`")
        }
        return IdTokenPayload(
            subject: wire.sub ?? "",
            issuer: wire.iss ?? "",
            audience: wire.aud?.values ?? [],
            expiresAt: Date(timeIntervalSince1970: exp),
            issuedAt: Date(timeIntervalSince1970: iat),
            notBefore: wire.nbf.map { Date(timeIntervalSince1970: $0) },
            nonce: wire.nonce,
            authorizedParty: wire.azp,
            email: wire.email,
            preferredUsername: wire.preferred_username,
            tenantID: wire.tenant_id,
            roles: wire.roles ?? [])
    }

    /// An `AuthError` carrying the §12.3 rule 3 reason code. The message never embeds the token.
    func oidcValidationError(_ code: OidcValidationCode, _ message: String) -> AxiamError {
        .auth(AuthError("\(code.rawValue): \(message)", oauthError: code.rawValue))
    }

    // MARK: - Errors and codecs

    /// Map a non-2xx from an `/oauth2/*` endpoint, dispatching on the `error` field first.
    ///
    /// §12.3 rule 3: a `400` from the token endpoint and a `401` from introspect/revoke carry an
    /// `OAuth2ErrorResponse` and MUST NOT surface as the generic `NetworkError` the §2 status
    /// rows would otherwise give. A body that is not one still gets the ordinary mapping, so a
    /// proxy's HTML `502` does not become an authentication error with an empty code.
    func oidcMapGrantError(_ response: HTTPResponseData) -> AxiamError {
        if let wire = try? JSONDecoder().decode(OidcOAuth2ErrorWire.self, from: response.body),
           !wire.error.isEmpty {
            return .auth(AuthError(
                "\(wire.error): \(wire.error_description ?? "")",
                oauthError: wire.error,
                oauthErrorDescription: wire.error_description))
        }
        return oidcMapError(response)
    }

    func oidcMapError(_ response: HTTPResponseData) -> AxiamError {
        let errBody = try? JSONDecoder().decode(ErrorBody.self, from: response.body)
        return ErrorMapper.map(
            status: response.status,
            message: errBody?.message ?? errBody?.error ?? "HTTP \(response.status)",
            action: errBody?.action,
            resourceID: errBody?.resource_id)
    }

    func oidcDecode<T: Decodable>(_ type: T.Type, _ data: Data, _ context: String) throws -> T {
        do {
            return try JSONDecoder().decode(type, from: data)
        } catch {
            throw AxiamError.network(NetworkError("Failed to decode \(context)", cause: error))
        }
    }

    static func oidcFormEncode(_ form: [String: String]) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        return form
            .sorted { $0.key < $1.key }
            .map { key, value in
                let k = key.addingPercentEncoding(withAllowedCharacters: allowed) ?? key
                let v = value.addingPercentEncoding(withAllowedCharacters: allowed) ?? value
                return "\(k)=\(v)"
            }
            .joined(separator: "&")
    }
}

/// The decoded ID-token payload, before §12.4's rules run against it.
struct IdTokenPayload: Sendable {
    let subject: String
    let issuer: String
    let audience: [String]
    let expiresAt: Date
    let issuedAt: Date
    let notBefore: Date?
    let nonce: String?
    let authorizedParty: String?
    let email: String?
    let preferredUsername: String?
    let tenantID: String?
    let roles: [String]
}

struct IdTokenPayloadWire: Decodable {
    let sub: String?
    let iss: String?
    let aud: JwtAudience?
    let exp: Double?
    let iat: Double?
    let nbf: Double?
    let nonce: String?
    let azp: String?
    let email: String?
    let preferred_username: String?
    let tenant_id: String?
    let roles: [String]?
}

struct OidcOAuth2ErrorWire: Decodable {
    let error: String
    let error_description: String?
}
