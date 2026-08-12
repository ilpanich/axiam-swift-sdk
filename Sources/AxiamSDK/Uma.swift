import Foundation

// UMA 2.0 — Protection API and ticket grant (CONTRACT.md §20).
//
// The resource-server side of User-Managed Access: a service that guards resources on someone
// else's behalf registers them, asks the authorization server what a caller would need, and
// exchanges the resulting ticket for a Requesting Party Token.
//
// **Why this ships while §12 does not.** The README records §12.7, §14 and §15 as blocked on §12,
// because each is a token-endpoint operation that reaches for §12's discovery cache and ID-token
// validation — implementing them alone would mean a second, parallel OIDC stack. §20 does not have
// that dependency: UMA carries its **own** discovery document (`/.well-known/uma2-configuration`,
// §20.1's named wire reference), the Protection API is ordinary bearer-authenticated REST, and the
// ticket grant returns an opaque RPT with no `id_token` to validate. One GET and one POST, with no
// PKCE, no state store, no JWKS interaction and no §9 refresh coupling. So §20 stands on its own,
// and this file is the whole of it.

// MARK: - §20.1 types

/// A UMA resource set — an AXIAM resource seen through the Protection API (§20.1).
///
/// `id` is **the AXIAM resource id**, not a parallel identifier: the same UUID is directly usable
/// as ``UmaRequestedPermission/resourceID``, and as the resource id anywhere else in this SDK.
public struct UmaResourceSet: Sendable, Equatable {
    /// Assigned by the server on registration; `nil` on the way in.
    public let id: String?
    /// Human-readable name, shown in the admin UI.
    public let name: String
    /// Free-form resource type. Omitted from the payload when `nil`, so the server applies its own
    /// `uma_resource` default rather than storing an empty string that sorts oddly next to
    /// hand-made resources.
    public let type: String?
    /// The scope names a resource server may ask for on this resource.
    ///
    /// **Replaced wholesale by an update, never merged** (§20.2 rule 8) — this SDK does not read
    /// the current scopes and fold them into an update payload as a convenience, because that
    /// would make removing a scope impossible through it.
    public let resourceScopes: [String]

    public init(id: String? = nil, name: String, type: String? = nil, resourceScopes: [String] = []) {
        self.id = id
        self.name = name
        self.type = type
        self.resourceScopes = resourceScopes
    }
}

/// One `(resource, scopes)` pair a resource server requires (§20.1).
public struct UmaRequestedPermission: Sendable, Equatable {
    /// The AXIAM resource id — the same UUID the Protection API returned as `_id`.
    public let resourceID: String
    /// Scope names, each of which the resource must already declare. Matched exactly: no prefix or
    /// wildcard semantics in either direction.
    public let resourceScopes: [String]

    public init(resourceID: String, resourceScopes: [String]) {
        self.resourceID = resourceID
        self.resourceScopes = resourceScopes
    }
}

/// One entry of an RPT's `permissions` claim (§20.1).
///
/// **A record of a decision already made, not a live authorization answer** (§20.2 rule 7). These
/// are the pairs the engine allowed when the RPT was minted; a grant revoked afterwards does not
/// empty a live RPT. Do not cache them beyond the token's own expiry — which is why that expiry is
/// short.
public struct UmaRptPermission: Sendable, Equatable {
    public let resourceID: String
    public let resourceScopes: [String]
    /// Absolute expiry, seconds since the epoch.
    public let exp: Int

    public init(resourceID: String, resourceScopes: [String], exp: Int) {
        self.resourceID = resourceID
        self.resourceScopes = resourceScopes
        self.exp = exp
    }
}

/// The result of the UMA ticket grant (§20.1).
///
/// **There is no `refreshToken` property, and that is deliberate** (§20.2 rule 5). The grant issues
/// none, so an RPT cannot outlive the ticket that authorised it; an application that wants a fresh
/// one re-runs the grant. This result never enters the §9 single-flight refresh guard — there is
/// nothing to refresh.
public struct RequestingPartyToken: Sendable {
    /// The RPT itself (§20.6 secret).
    public let accessToken: Sensitive<String>
    /// Always `Bearer`.
    public let tokenType: String
    /// `min(claim token remaining, server ceiling, 300 s)`.
    public let expiresIn: Int
}

/// A parsed `WWW-Authenticate: UMA` challenge (UMA 2.0 §3.2, §20.3).
public struct UmaChallenge: Sendable {
    /// The protection realm the resource server named.
    public let realm: String?
    /// The authorization server the resource server nominates. **Not automatically trusted** — see
    /// ``AxiamClient/umaParseChallenge(_:)``.
    public let asURI: String?
    /// The ticket to exchange — a bearer credential for its 60-second life (§20.6).
    public let ticket: Sensitive<String>?
}

/// The confidential-client credentials the ticket grant authenticates with (§20.1).
///
/// Passed per call rather than held on ``AxiamConfig``: this SDK implements no other
/// token-endpoint operation, and a client identity on the config would imply an OIDC client
/// identity it does not otherwise have.
public struct UmaClientCredentials: Sendable {
    public let clientID: String
    public let clientSecret: Sensitive<String>

    public init(clientID: String, clientSecret: Sensitive<String>) {
        self.clientID = clientID
        self.clientSecret = clientSecret
    }
}

/// The UMA 2.0 discovery document (§20.1), read from `/.well-known/uma2-configuration`.
///
/// Endpoints are read from this document and never hardcoded, for the same reason §12.3 rule 6
/// gives for the OIDC one: a deployment is free to move them.
public struct Uma2Configuration: Sendable, Decodable, Equatable {
    public let issuer: String
    public let tokenEndpoint: String
    public let permissionEndpoint: String
    public let resourceRegistrationEndpoint: String
    /// The ticket TTL the server advertises, so a resource server can size its own timing against
    /// it rather than discovering it by having a ticket expire.
    public let permissionTicketLifetime: Int?

    enum CodingKeys: String, CodingKey {
        case issuer
        case tokenEndpoint = "token_endpoint"
        case permissionEndpoint = "permission_endpoint"
        case resourceRegistrationEndpoint = "resource_registration_endpoint"
        case permissionTicketLifetime = "permission_ticket_lifetime"
    }
}

// MARK: - Wire shapes

private struct ResourceSetWire: Codable {
    let _id: String?
    let name: String
    let type: String?
    let resource_scopes: [String]?
}

private struct RequestedPermissionWire: Encodable {
    let resource_id: String
    let resource_scopes: [String]
}

private struct PermissionTicketWire: Decodable {
    let ticket: String
}

private struct RequestingPartyTokenWire: Decodable {
    let access_token: String
    let token_type: String
    let expires_in: Int
}

private struct OAuth2ErrorWire: Decodable {
    let error: String
    let error_description: String?
}

// MARK: - §20 operations

extension AxiamClient {

    /// The scope a PAT must carry (§20.2 rule 1) — for callers minting one.
    public static let umaProtectionScope = "uma_protection"

    /// `grant_type` of the UMA 2.0 ticket grant (§20.1).
    static let umaTicketGrantType = "urn:ietf:params:oauth:grant-type:uma-ticket"

    /// The only `claim_token_format` AXIAM implements. §20.2 rule 2 makes the `claim_token` itself
    /// required rather than defaulted; the *format* has one value, so the SDK supplies it.
    static let umaClaimTokenFormat = "urn:ietf:params:oauth:token-type:access_token"

    static let umaDiscoveryPath = ".well-known/uma2-configuration"

    /// `GET /.well-known/uma2-configuration` (§20.1) — fetch the UMA discovery document.
    ///
    /// Cached for five minutes, the same floor §12.3 rule 6 sets for the OIDC document: an
    /// endpoint map is not a credential and re-fetching it on every guarded request is a
    /// self-inflicted round trip.
    public func umaDiscover() async throws -> Uma2Configuration {
        try ensureOpen()
        if let cached = umaConfigurationCache, cached.expiresAt > Date() {
            return cached.document
        }
        let url = config.baseURL.appendingPathComponent(Self.umaDiscoveryPath)
        let response = try await umaSendAbsolute(
            method: .get, url: url, headers: [("Accept", "application/json")], body: nil)
        guard (200..<300).contains(response.status) else { throw umaMapError(response) }
        let document = try decodeUma(Uma2Configuration.self, response.body, "uma discovery")
        umaConfigurationCache = (document, Date().addingTimeInterval(300))
        return document
    }

    /// `POST /uma2/rreg/resource_set` (§20.1) — register a resource set.
    ///
    /// The returned ``UmaResourceSet/id`` is **the AXIAM resource id**, directly usable as a
    /// ``UmaRequestedPermission``'s `resourceID`.
    ///
    /// - Parameter pat: a Protection API Token — a *client-credentials* token carrying
    ///   `uma_protection` (§20.2 rule 1). This SDK never substitutes its own session for it.
    @discardableResult
    public func umaRegisterResource(
        pat: Sensitive<String>,
        name: String,
        type: String? = nil,
        resourceScopes: [String] = []
    ) async throws -> UmaResourceSet {
        let configuration = try await umaDiscover()
        let body = try encodeUma(resourceSetWire(name: name, type: type, resourceScopes: resourceScopes))
        let response = try await umaProtectionRequest(
            method: .post, absoluteURL: configuration.resourceRegistrationEndpoint, pat: pat, body: body)
        return try umaResourceSet(from: response)
    }

    /// `GET /uma2/rreg/resource_set/{id}` (§20.1) — read a registered resource set.
    public func umaReadResource(pat: Sensitive<String>, id: String) async throws -> UmaResourceSet {
        let configuration = try await umaDiscover()
        let response = try await umaProtectionRequest(
            method: .get, absoluteURL: umaResourceURL(configuration, id), pat: pat, body: nil)
        return try umaResourceSet(from: response)
    }

    /// `PUT /uma2/rreg/resource_set/{id}` (§20.1) — replace a resource set's state.
    ///
    /// **`resourceScopes` replaces the declared list; it does not merge with it** (§20.2 rule 8).
    /// This method deliberately performs no read-modify-write: folding the current scopes into the
    /// payload as a convenience would make removing a scope impossible through this SDK.
    @discardableResult
    public func umaUpdateResource(
        pat: Sensitive<String>,
        id: String,
        name: String,
        type: String? = nil,
        resourceScopes: [String] = []
    ) async throws -> UmaResourceSet {
        let configuration = try await umaDiscover()
        let body = try encodeUma(resourceSetWire(name: name, type: type, resourceScopes: resourceScopes))
        let response = try await umaProtectionRequest(
            method: .put, absoluteURL: umaResourceURL(configuration, id), pat: pat, body: body)
        return try umaResourceSet(from: response)
    }

    /// `DELETE /uma2/rreg/resource_set/{id}` (§20.1) — deregister a resource set.
    public func umaDeleteResource(pat: Sensitive<String>, id: String) async throws {
        let configuration = try await umaDiscover()
        _ = try await umaProtectionRequest(
            method: .delete, absoluteURL: umaResourceURL(configuration, id), pat: pat, body: nil)
    }

    /// `GET /uma2/rreg/resource_set` (§20.1) — the ids **this client** registered.
    ///
    /// Not the tenant's resource tree: the server scopes the listing to the registering client, so
    /// a PAT is not an enumeration handle.
    public func umaListResources(pat: Sensitive<String>) async throws -> [String] {
        let configuration = try await umaDiscover()
        let response = try await umaProtectionRequest(
            method: .get, absoluteURL: configuration.resourceRegistrationEndpoint, pat: pat, body: nil)
        return try decodeUma([String].self, response.body, "uma list resources")
    }

    /// `POST /uma2/perm` (§20.1) — mint a permission ticket for the pairs a caller lacks.
    ///
    /// The ticket comes back wrapped: for its 60-second life it is the credential that converts
    /// into an RPT, and a short lifetime is not the same as a harmless one (§20.6).
    public func umaRequestTicket(
        pat: Sensitive<String>,
        permissions: [UmaRequestedPermission]
    ) async throws -> Sensitive<String> {
        let configuration = try await umaDiscover()
        let wire = permissions.map {
            RequestedPermissionWire(resource_id: $0.resourceID, resource_scopes: $0.resourceScopes)
        }
        let response = try await umaProtectionRequest(
            method: .post, absoluteURL: configuration.permissionEndpoint, pat: pat, body: try encodeUma(wire))
        let ticket = try decodeUma(PermissionTicketWire.self, response.body, "uma request ticket")
        return Sensitive(ticket.ticket)
    }

    /// `POST /oauth2/token` with the UMA ticket grant (§20.1) — redeem a permission ticket for a
    /// Requesting Party Token.
    ///
    /// Unlike the Protection API above, this is a token-endpoint grant: the *client* authenticates
    /// through the form body (`client_secret_post`), so `credentials` is required.
    ///
    /// What this method deliberately does **not** do:
    ///
    /// - **No retry, ever** (§20.2 rule 6) — not on `5xx`, not on a timeout, not on
    ///   `invalid_grant`. This is the one documented exception to §16, and a security rule rather
    ///   than a performance one: the ticket is consumed *before* the request is evaluated, so a
    ///   failed exchange has already spent it, and a retry is a second redemption — exactly the
    ///   concurrent redemption whose measured residual `ilpanich/axiam#302` records. The property
    ///   holds structurally here: this call goes through ``AxiamClient/rawSend(method:path:body:)``'s
    ///   absolute-URL sibling and never enters ``retryingPOST(operation:path:body:)``'s budget.
    /// - **No defaulted `claimToken`** (rule 2). It is the only channel that names the requesting
    ///   party; defaulting it to the resource server's own PAT would mint an RPT for the resource
    ///   server rather than for the user. An empty one is refused client-side, with no wire call,
    ///   so a request that could not have succeeded never spends a ticket.
    /// - **No auto-narrowing on `access_denied`** (rule 3). A partial grant is refused whole, and
    ///   whether two-of-three permissions is useful is the calling application's judgement.
    /// - **No adoption** (rule 4). The RPT is the *requesting party's* token; adopting it would
    ///   re-privilege every later call this resource server makes as that user. This client has no
    ///   bearer-credential slot to adopt into at all — its session lives in `httpOnly` cookies —
    ///   so the rule holds by construction.
    /// - **No refresh token** (rule 5) — the grant issues none, and ``RequestingPartyToken`` has
    ///   nowhere to put one.
    ///
    /// The four ticket refusals — unknown, expired, already used, minted by another client — all
    /// arrive as one `invalid_grant`, and this SDK does not guess which (§20.4): the server
    /// collapses them because telling them apart lets a caller probe for live ticket handles.
    public func umaExchangeTicket(
        ticket: Sensitive<String>,
        claimToken: Sensitive<String>,
        credentials: UmaClientCredentials,
        tenantID: String? = nil
    ) async throws -> RequestingPartyToken {
        try ensureOpen()
        guard !ticket.wrapped.isEmpty else {
            throw AxiamError.auth(AuthError("umaExchangeTicket requires a ticket (CONTRACT.md §20.1)."))
        }
        guard !claimToken.wrapped.isEmpty else {
            throw AxiamError.auth(AuthError(
                "umaExchangeTicket requires a claim_token naming the requesting party; it is never "
                + "defaulted (CONTRACT.md §20.2 rule 2)."))
        }
        let configuration = try await umaDiscover()
        let endpoint = try umaTokenURL(configuration, tenantID: tenantID)

        let form = [
            "grant_type": Self.umaTicketGrantType,
            "ticket": ticket.wrapped,
            "claim_token": claimToken.wrapped,
            "claim_token_format": Self.umaClaimTokenFormat,
            "client_id": credentials.clientID,
            "client_secret": credentials.clientSecret.wrapped,
        ]

        // One request. No retry wrapper, on any status — see the rule 6 note above. Cookies are
        // deliberately not attached: the token endpoint authenticates the CLIENT through the form
        // body, and sending the user's session alongside would be a second, unasked-for identity
        // on the same request.
        let response = try await umaSendAbsolute(
            method: .post,
            url: endpoint,
            headers: [("Content-Type", "application/x-www-form-urlencoded")],
            body: Data(Self.umaFormEncode(form).utf8))

        guard (200..<300).contains(response.status) else { throw umaMapGrantError(response) }
        let wire = try decodeUma(RequestingPartyTokenWire.self, response.body, "uma ticket exchange")
        return RequestingPartyToken(
            accessToken: Sensitive(wire.access_token),
            tokenType: wire.token_type,
            expiresIn: wire.expires_in)
    }

    // MARK: - §20.3 the challenge helpers

    /// Parse a `WWW-Authenticate: UMA …` header value (§20.3) into its three fields, returning
    /// `nil` when the header names a different scheme.
    ///
    /// **Pure local computation — it performs no exchange of the ticket it finds**, and that is
    /// the point. Parsing a challenge and acting on it are separate decisions: the `as_uri` names
    /// an authorization server the client has not necessarily chosen to trust, and auto-exchanging
    /// would send the requesting party's `claim_token` to whatever host answered the `401`. Return
    /// the parsed challenge and let the caller decide.
    public nonisolated static func umaParseChallenge(_ header: String) -> UmaChallenge? {
        let trimmed = header.trimmingCharacters(in: .whitespaces)
        guard trimmed.hasPrefix("UMA") else { return nil }
        let rest = String(trimmed.dropFirst(3))
        // "UMA" alone is a valid, if useless, challenge; anything else must be separated by
        // whitespace so `UMAX realm="…"` is not read as UMA.
        if let first = rest.first, !first.isWhitespace { return nil }

        var realm: String?
        var asURI: String?
        var ticket: Sensitive<String>?
        for part in rest.split(separator: ",") {
            guard let equals = part.firstIndex(of: "=") else { continue }
            let key = part[part.startIndex..<equals].trimmingCharacters(in: .whitespaces)
            let raw = part[part.index(after: equals)...].trimmingCharacters(in: .whitespaces)
            let value = raw.hasPrefix("\"") && raw.hasSuffix("\"") && raw.count >= 2
                ? String(raw.dropFirst().dropLast())
                : raw
            switch key {
            case "realm": realm = value
            case "as_uri": asURI = value
            case "ticket": ticket = Sensitive(value)
            default:
                // Unknown parameters are ignored rather than rejected: UMA 2.0 permits a server to
                // add its own, and refusing the whole challenge over one would lose the ticket
                // with it.
                break
            }
        }
        return UmaChallenge(realm: realm, asURI: asURI, ticket: ticket)
    }

    /// Format a `WWW-Authenticate: UMA` header value (§20.3, emit half) — for a resource server
    /// that has just minted a ticket and wants to tell the caller where to redeem it.
    public nonisolated static func umaChallengeHeader(
        realm: String,
        asURI: String,
        ticket: Sensitive<String>
    ) -> String {
        "UMA realm=\"\(realm)\", as_uri=\"\(asURI)\", ticket=\"\(ticket.wrapped)\""
    }

    // MARK: - Internals

    /// One Protection API call, PAT-authenticated (§20.2 rule 1).
    ///
    /// The PAT is an explicit `Authorization` header on a request that carries no session cookie:
    /// a minted ticket is bound to the `client_id` that minted it, so the credential here must be
    /// the caller's PAT and never a silent fallback to this client's own session. An empty PAT is
    /// refused client-side rather than sent as an absent header the server would answer `401` to.
    private func umaProtectionRequest(
        method: HTTPRequestMethod,
        absoluteURL: String,
        pat: Sensitive<String>,
        body: Data?
    ) async throws -> HTTPResponseData {
        try ensureOpen()
        guard !pat.wrapped.isEmpty else {
            throw AxiamError.auth(AuthError(
                "the UMA Protection API requires a PAT — a client-credentials token carrying the "
                + "uma_protection scope; this SDK does not fall back to its own session "
                + "(CONTRACT.md §20.2 rule 1)."))
        }
        guard let url = URL(string: absoluteURL) else {
            throw AxiamError.network(NetworkError("invalid endpoint URL from the UMA discovery document"))
        }

        var headers: [(String, String)] = [
            ("Authorization", "Bearer \(pat.wrapped)"),
            ("Accept", "application/json"),
        ]
        if body != nil { headers.append(("Content-Type", "application/json")) }

        let response = try await umaSendAbsolute(method: method, url: url, headers: headers, body: body)
        guard (200..<300).contains(response.status) else {
            // §20.4 maps the Protection API by status (401 / 403 / 400), not through the OAuth2
            // `error` rows — those belong to the token endpoint.
            throw umaMapError(response)
        }
        return response
    }

    /// Map a non-2xx from the ticket grant, dispatching on the `error` field at **any** status
    /// before falling back to the §2 status mapping (§20.4).
    ///
    /// `access_denied` answers HTTP 403 here where RFC 8628's answers 400, and §20.4 requires
    /// dispatching on the field rather than the status so this stays correct if either moves. The
    /// result is an ``AuthError`` carrying the protocol code in ``AuthError/oauthError`` — Swift
    /// structs cannot be subclassed, so an `AuthError` that carries the code is this SDK's
    /// rendering of the contract's `OAuthProtocolError`-as-an-`AuthError`-subtype.
    ///
    /// A body that is not an `OAuth2ErrorResponse` still gets the ordinary mapping, so a proxy's
    /// HTML `502` does not become an authentication error with an empty code.
    private func umaMapGrantError(_ response: HTTPResponseData) -> AxiamError {
        if let wire = try? JSONDecoder().decode(OAuth2ErrorWire.self, from: response.body), !wire.error.isEmpty {
            return .auth(AuthError(
                "\(wire.error): \(wire.error_description ?? "")",
                oauthError: wire.error,
                oauthErrorDescription: wire.error_description))
        }
        return umaMapError(response)
    }

    private func umaMapError(_ response: HTTPResponseData) -> AxiamError {
        let errBody = try? JSONDecoder().decode(ErrorBody.self, from: response.body)
        return ErrorMapper.map(
            status: response.status,
            message: errBody?.message ?? errBody?.error ?? "HTTP \(response.status)",
            action: errBody?.action,
            resourceID: errBody?.resource_id)
    }

    private func resourceSetWire(name: String, type: String?, resourceScopes: [String]) -> ResourceSetWire {
        // §12.1's absent-optional rule: `type` is omitted rather than sent empty, so the server
        // applies its own `uma_resource` default.
        ResourceSetWire(
            _id: nil,
            name: name,
            type: (type?.isEmpty ?? true) ? nil : type,
            resource_scopes: resourceScopes)
    }

    private func umaResourceSet(from response: HTTPResponseData) throws -> UmaResourceSet {
        let wire = try decodeUma(ResourceSetWire.self, response.body, "uma resource set")
        return UmaResourceSet(
            id: wire._id,
            name: wire.name,
            type: wire.type,
            resourceScopes: wire.resource_scopes ?? [])
    }

    private func umaResourceURL(_ configuration: Uma2Configuration, _ id: String) -> String {
        let escaped = id.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? id
        return configuration.resourceRegistrationEndpoint + "/" + escaped
    }

    /// The token endpoint plus the mandatory `?tenant_id=<uuid>` query parameter (§12.1 note 2,
    /// which §20.1 applies to the ticket grant unchanged).
    ///
    /// A tenant *slug* cannot be substituted, so a client configured with only a slug and given no
    /// explicit `tenantID` fails here client-side, with no wire call — the same discipline the
    /// sibling SDKs apply, and for the same reason: the request could not have succeeded, and a
    /// ticket must not be spent on one that could not.
    private func umaTokenURL(_ configuration: Uma2Configuration, tenantID: String?) throws -> URL {
        let candidate = tenantID ?? config.tenantID
        guard let candidate, UUID(uuidString: candidate) != nil else {
            throw AxiamError.auth(AuthError(
                "the UMA ticket grant requires a tenant_id UUID for the /oauth2 query parameter: "
                + "pass tenantID explicitly, or construct the client with a tenantID (UUID) "
                + "(CONTRACT.md §12.3 rule 4)."))
        }
        guard var components = URLComponents(string: configuration.tokenEndpoint) else {
            throw AxiamError.network(NetworkError("invalid token endpoint in the UMA discovery document"))
        }
        var query = components.queryItems ?? []
        query.removeAll { $0.name == "tenant_id" }
        query.append(URLQueryItem(name: "tenant_id", value: candidate))
        components.queryItems = query
        guard let url = components.url else {
            throw AxiamError.network(NetworkError("invalid token endpoint in the UMA discovery document"))
        }
        return url
    }

    private static func umaFormEncode(_ form: [String: String]) -> String {
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

    private func encodeUma<T: Encodable>(_ value: T) throws -> Data {
        do {
            return try JSONEncoder().encode(value)
        } catch {
            throw AxiamError.network(NetworkError("Failed to encode request body", cause: error))
        }
    }

    private func decodeUma<T: Decodable>(_ type: T.Type, _ data: Data, _ context: String) throws -> T {
        do {
            return try JSONDecoder().decode(type, from: data)
        } catch {
            throw AxiamError.network(NetworkError("\(context): malformed response body", cause: error))
        }
    }
}
