import Foundation

// CONTRACT.md §28.12 — RFC 7592 client configuration (contract 1.53).
//
// A client that registered itself through `POST /oauth2/register` (RFC 7591) receives, once, a
// `registration_client_uri` and a `registration_access_token`. With those two it can read,
// replace and delete ITS OWN registration — three methods on `AxiamClient`:
// `readClientRegistration`, `updateClientRegistration` and `deleteClientRegistration`.
//
// Four rules shape all three (§28.12.2):
//
// 1. The URI is used verbatim, and only at the configured AXIAM. A URI whose scheme, host or
//    port differs from the client's base URL — or an `http` URI when the base URL is not `http`
//    on a loopback host — is refused locally, before any request: the token is a bearer, and a
//    helper that followed a URI to another origin would hand it to whoever wrote the URI.
// 2. The token travels in `Authorization: Bearer` only — never in the query, never in a body.
// 3. It is not the SDK's session. These requests go out on the bare path (`bareSend`): no
//    cookie jar, no CSRF token, no device bearer, no redirect following — and a `401` from
//    them never reaches the §9 refresh guard.
// 4. Neither write is retried. An update that reached the server and lost its response has
//    already rotated the token; a delete whose `204` was lost would read `401` on a retry.
//    Only the read follows §16.

/// An RFC 7591 §3.2.1 / RFC 7592 §3 client information response (CONTRACT.md §28.12.1).
///
/// ``registrationAccessToken`` and ``clientSecret`` are ``Sensitive`` (§28.12.4), and this type
/// is deliberately not `Encodable`: its ``description`` names neither, and nothing can serialise
/// it whole.
///
/// **Every member the server sent that this type does not name is kept in ``extra``** — RFC 7591
/// §3.2.1 lets a server add members (the CIBA `backchannel_*` members are an example), and
/// because an update is a **full replacement**, a member a read returned and an update left out
/// is a member the server deletes. Passing a read's result straight to
/// ``AxiamClient/updateClientRegistration(registrationClientURI:registrationAccessToken:metadata:)``
/// therefore sends it back intact, `jwks` / `jwks_uri` included.
public struct ClientRegistration: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    /// The client's `client_id`.
    public var clientID: String
    /// When the client id was issued (seconds since the epoch). Never sent on an update.
    public var clientIDIssuedAt: Int?
    /// The registered display name.
    public var clientName: String?
    /// The registered redirect URIs.
    public var redirectURIs: [String]
    /// The registered grant types.
    public var grantTypes: [String]
    /// The registered response types.
    public var responseTypes: [String]
    /// How the client authenticates at the token endpoint. The server refuses an update that
    /// changes it.
    public var tokenEndpointAuthMethod: String?
    /// The registered scope, space-separated.
    public var scope: String?
    /// Where this registration is read, replaced and deleted. Never sent on an update.
    public var registrationClientURI: String?
    /// When the client secret expires (`0` = never). Never sent on an update.
    public var clientSecretExpiresAt: Int?
    /// The client's JWK Set, for a `private_key_jwt` client.
    public var jwks: ManagementJSON?
    /// Where the client's JWK Set is published.
    public var jwksURI: String?
    /// The client secret — present only on the registration response itself, never on a read
    /// or an update. Never sent back.
    public var clientSecret: Sensitive<String>?
    /// The registration access token — present on the registration response and, **rotated**,
    /// on every update response; absent on a read. Never sent in a body.
    public var registrationAccessToken: Sensitive<String>?
    /// Every other member of the response, verbatim.
    public var extra: [String: ManagementJSON]

    /// The members ``AxiamClient/updateClientRegistration(registrationClientURI:registrationAccessToken:metadata:)``
    /// never sends (§28.12.2 rule 4). The first four the server refuses with
    /// `400 invalid_request`; `client_secret` it never accepts back.
    static let serverStatedMembers: [String] = [
        "registration_access_token",
        "registration_client_uri",
        "client_secret_expires_at",
        "client_id_issued_at",
        "client_secret",
    ]

    public init(
        clientID: String,
        clientIDIssuedAt: Int? = nil,
        clientName: String? = nil,
        redirectURIs: [String] = [],
        grantTypes: [String] = [],
        responseTypes: [String] = [],
        tokenEndpointAuthMethod: String? = nil,
        scope: String? = nil,
        registrationClientURI: String? = nil,
        clientSecretExpiresAt: Int? = nil,
        jwks: ManagementJSON? = nil,
        jwksURI: String? = nil,
        clientSecret: Sensitive<String>? = nil,
        registrationAccessToken: Sensitive<String>? = nil,
        extra: [String: ManagementJSON] = [:]
    ) {
        self.clientID = clientID
        self.clientIDIssuedAt = clientIDIssuedAt
        self.clientName = clientName
        self.redirectURIs = redirectURIs
        self.grantTypes = grantTypes
        self.responseTypes = responseTypes
        self.tokenEndpointAuthMethod = tokenEndpointAuthMethod
        self.scope = scope
        self.registrationClientURI = registrationClientURI
        self.clientSecretExpiresAt = clientSecretExpiresAt
        self.jwks = jwks
        self.jwksURI = jwksURI
        self.clientSecret = clientSecret
        self.registrationAccessToken = registrationAccessToken
        self.extra = extra
    }

    /// Decode a client information response, tolerating unknown members (RFC 7591 §3.2.1).
    ///
    /// A member of an unexpected type is kept in ``extra`` rather than dropped: a replacement
    /// must not lose what the server holds.
    ///
    /// - Throws: ``AxiamError/network(_:)`` when `json` is not a JSON object, or carries no
    ///   string `client_id`.
    public init(json: Data) throws {
        guard let decoded = try? JSONDecoder().decode(ManagementJSON.self, from: json),
              case .object(let object) = decoded
        else {
            throw AxiamError.network(NetworkError(
                "client registration response is not a JSON object"))
        }
        var members = object

        func takeString(_ key: String) -> String? {
            guard let value = members.removeValue(forKey: key) else { return nil }
            switch value {
            case .string(let text): return text
            case .null: return nil
            default:
                members[key] = value
                return nil
            }
        }
        func takeInt(_ key: String) -> Int? {
            guard let value = members.removeValue(forKey: key) else { return nil }
            switch value {
            case .int(let number): return number
            case .null: return nil
            default:
                members[key] = value
                return nil
            }
        }
        func takeList(_ key: String) -> [String] {
            guard let value = members.removeValue(forKey: key) else { return [] }
            guard case .array(let items) = value else { return [] }
            return items.compactMap { $0.stringValue }
        }

        guard let clientID = takeString("client_id") else {
            throw AxiamError.network(NetworkError(
                "client registration response carries no client_id"))
        }
        var jwks: ManagementJSON?
        if let value = members.removeValue(forKey: "jwks"), value != .null {
            jwks = value
        }
        let clientIDIssuedAt = takeInt("client_id_issued_at")
        let clientName = takeString("client_name")
        let redirectURIs = takeList("redirect_uris")
        let grantTypes = takeList("grant_types")
        let responseTypes = takeList("response_types")
        let tokenEndpointAuthMethod = takeString("token_endpoint_auth_method")
        let scope = takeString("scope")
        let registrationClientURI = takeString("registration_client_uri")
        let clientSecretExpiresAt = takeInt("client_secret_expires_at")
        let jwksURI = takeString("jwks_uri")
        let clientSecret = takeString("client_secret").map { Sensitive($0) }
        let registrationAccessToken = takeString("registration_access_token").map { Sensitive($0) }

        self.init(
            clientID: clientID,
            clientIDIssuedAt: clientIDIssuedAt,
            clientName: clientName,
            redirectURIs: redirectURIs,
            grantTypes: grantTypes,
            responseTypes: responseTypes,
            tokenEndpointAuthMethod: tokenEndpointAuthMethod,
            scope: scope,
            registrationClientURI: registrationClientURI,
            clientSecretExpiresAt: clientSecretExpiresAt,
            jwks: jwks,
            jwksURI: jwksURI,
            clientSecret: clientSecret,
            registrationAccessToken: registrationAccessToken,
            extra: members)
    }

    /// The RFC 7592 §2.2 replacement body: every member but the five the server states
    /// (§28.12.2 rule 4), with `client_id` set to this registration's own.
    func updateBody() -> [String: ManagementJSON] {
        var body = extra
        for key in Self.serverStatedMembers {
            body.removeValue(forKey: key)
        }
        body["client_id"] = .string(clientID)
        if let clientName { body["client_name"] = .string(clientName) }
        body["redirect_uris"] = .array(redirectURIs.map { ManagementJSON.string($0) })
        body["grant_types"] = .array(grantTypes.map { ManagementJSON.string($0) })
        body["response_types"] = .array(responseTypes.map { ManagementJSON.string($0) })
        if let tokenEndpointAuthMethod {
            body["token_endpoint_auth_method"] = .string(tokenEndpointAuthMethod)
        }
        if let scope { body["scope"] = .string(scope) }
        if let jwks { body["jwks"] = jwks }
        if let jwksURI { body["jwks_uri"] = .string(jwksURI) }
        return body
    }

    /// Names the registration and which credentials it holds — never their values.
    public var description: String {
        let extraKeys = extra.keys.sorted().joined(separator: ", ")
        return "ClientRegistration(clientID: \(clientID), clientName: \(clientName ?? "nil"), "
            + "redirectURIs: \(redirectURIs), grantTypes: \(grantTypes), "
            + "tokenEndpointAuthMethod: \(tokenEndpointAuthMethod ?? "nil"), "
            + "clientSecret: \(clientSecret == nil ? "nil" : "[SENSITIVE]"), "
            + "registrationAccessToken: \(registrationAccessToken == nil ? "nil" : "[SENSITIVE]"), "
            + "extra: [\(extraKeys)])"
    }

    public var debugDescription: String { description }
}

extension AxiamClient {

    /// `GET registration_client_uri` (RFC 7592 §2.1, CONTRACT.md §28.12) — read this client's
    /// registration.
    ///
    /// The result carries neither the token nor the client secret: the server never returns
    /// them on a read. It does carry every member an update needs, so the usual update is
    /// "read, change a field, update".
    ///
    /// Retried per §16 on a transport failure, `408`, `429` or `5xx` (a read is safe to
    /// repeat), never on another `4xx`. A `401 invalid_token` — an unknown client, a wrong or
    /// rotated-away token, another tenant's client, a client with no token: the server never
    /// says which — is an ``AuthError`` carrying ``AuthError/oauthError``, and never refreshes
    /// this client's session (§28.12.2 rule 3).
    ///
    /// - Parameters:
    ///   - registrationClientURI: the URI the registration response returned, used verbatim
    ///     (query included). It must be at this client's configured origin.
    ///   - registrationAccessToken: the registration's bearer — the latest one an update
    ///     returned.
    /// - Throws: a local ``NetworkError`` with ``NetworkError/isValidation`` set, before any
    ///   request, when the URI is not at the configured origin (§28.12.2 rule 1).
    public func readClientRegistration(
        registrationClientURI: String,
        registrationAccessToken: Sensitive<String>
    ) async throws -> ClientRegistration {
        try ensureOpen()
        let url = try checkRegistrationURI(registrationClientURI, "readClientRegistration")
        let response = try await bareSend(
            operation: "read_client_registration",
            pathTemplate: "{registration_client_uri}",
            method: .get,
            url: url,
            headers: [
                ("Authorization", "Bearer \(registrationAccessToken.expose())"),
                ("Accept", "application/json"),
            ],
            body: nil,
            retry: .section16)
        return try decodeRegistration(response, "readClientRegistration")
    }

    /// `PUT registration_client_uri` (RFC 7592 §2.2, CONTRACT.md §28.12) — **replace** this
    /// client's registration, and receive a **rotated** token.
    ///
    /// `metadata` is the **whole** registration: a member it omits is a member the server
    /// deletes. Start from ``readClientRegistration(registrationClientURI:registrationAccessToken:)``'s
    /// result, which carries every member (`jwks` / `jwks_uri` and anything this SDK does not
    /// name, in ``ClientRegistration/extra``), and change what you mean to change. The SDK sets
    /// `client_id` to `metadata.clientID` and never sends `registration_access_token`,
    /// `registration_client_uri`, `client_secret_expires_at`, `client_id_issued_at` or
    /// `client_secret`.
    ///
    /// **Persist the returned ``ClientRegistration/registrationAccessToken`` before doing
    /// anything else.** From the moment the server answers, it is the only valid token: the one
    /// you presented is dead for every operation (§28.12.2 rule 5).
    ///
    /// **Never retried** — not on a transport error, not on a `5xx`. An update that reached the
    /// server and lost its response has already rotated the token; repeating it with the old
    /// one is a `401` that locks you out of your own registration. On a lost answer, read the
    /// registration with the token you hold: a `401` means the update landed.
    public func updateClientRegistration(
        registrationClientURI: String,
        registrationAccessToken: Sensitive<String>,
        metadata: ClientRegistration
    ) async throws -> ClientRegistration {
        try ensureOpen()
        let url = try checkRegistrationURI(registrationClientURI, "updateClientRegistration")
        let payload: Data
        do {
            payload = try JSONEncoder().encode(ManagementJSON.object(metadata.updateBody()))
        } catch {
            throw AxiamError.network(NetworkError(
                "updateClientRegistration: failed to encode the registration", cause: error))
        }
        let response = try await bareSend(
            operation: "update_client_registration",
            pathTemplate: "{registration_client_uri}",
            method: .put,
            url: url,
            headers: [
                ("Authorization", "Bearer \(registrationAccessToken.expose())"),
                ("Accept", "application/json"),
                ("Content-Type", "application/json"),
            ],
            body: payload,
            retry: .never)
        return try decodeRegistration(response, "updateClientRegistration")
    }

    /// `DELETE registration_client_uri` (RFC 7592 §2.3, CONTRACT.md §28.12) — delete this
    /// client's registration. A `204` returns normally.
    ///
    /// **Never retried**: a retry after a lost `204` would read `401` and report a successful
    /// deletion as a failure.
    public func deleteClientRegistration(
        registrationClientURI: String,
        registrationAccessToken: Sensitive<String>
    ) async throws {
        try ensureOpen()
        let url = try checkRegistrationURI(registrationClientURI, "deleteClientRegistration")
        let response = try await bareSend(
            operation: "delete_client_registration",
            pathTemplate: "{registration_client_uri}",
            method: .delete,
            url: url,
            headers: [("Authorization", "Bearer \(registrationAccessToken.expose())")],
            body: nil,
            retry: .never)
        guard (200..<300).contains(response.status) else {
            throw oidcMapGrantError(response)
        }
    }

    // MARK: - Internals

    /// §28.12.2 rule 1: accept `uri` only at the configured AXIAM origin.
    ///
    /// The refusal names no part of the URI: it is caller input, and an error message is the
    /// one most often logged.
    func checkRegistrationURI(_ uri: String, _ operation: String) throws -> URL {
        func refuse(_ why: String) -> AxiamError {
            .network(NetworkError(
                "\(operation): registration_client_uri \(why) (CONTRACT.md §28.12.2 rule 1)",
                statusCode: 400,
                isValidation: true))
        }
        guard let url = URL(string: uri),
              let scheme = url.scheme?.lowercased(),
              let host = url.host?.lowercased(), !host.isEmpty
        else {
            throw refuse("is not an absolute URL")
        }
        guard scheme == "https" || scheme == "http" else {
            throw refuse("must be an https URL")
        }
        let base = config.baseURL
        let baseScheme = base.scheme?.lowercased() ?? ""
        let baseHost = base.host?.lowercased() ?? ""
        guard scheme == baseScheme,
              host == baseHost,
              Self.effectivePort(url) == Self.effectivePort(base)
        else {
            throw refuse(
                "is not at the configured AXIAM origin (scheme, host and port must match the "
                    + "client's base URL)")
        }
        if scheme == "http", !Self.isLoopbackHost(baseHost) {
            throw refuse("must be https unless the base URL is http on a loopback host")
        }
        return url
    }

    /// The port a URL addresses, its scheme's default when it names none.
    static func effectivePort(_ url: URL) -> Int? {
        if let port = url.port { return port }
        switch url.scheme?.lowercased() {
        case "https": return 443
        case "http": return 80
        default: return nil
        }
    }

    /// `localhost`, `127.0.0.1` or `::1` — the hosts on which plain `http` is a development
    /// deployment rather than a downgrade.
    static func isLoopbackHost(_ host: String) -> Bool {
        let bare = host.trimmingCharacters(in: CharacterSet(charactersIn: "[]")).lowercased()
        return bare == "localhost" || bare == "127.0.0.1" || bare == "::1"
    }

    private func decodeRegistration(
        _ response: HTTPResponseData,
        _ operation: String
    ) throws -> ClientRegistration {
        guard (200..<300).contains(response.status) else {
            // §28.12.3: a body with a non-empty `error` is an OAuthProtocolError at ANY status,
            // a 401 included; anything else maps by status (§2).
            throw oidcMapGrantError(response)
        }
        do {
            return try ClientRegistration(json: response.body)
        } catch let error as AxiamError {
            throw error
        } catch {
            throw AxiamError.network(NetworkError(
                "\(operation): failed to parse the response", cause: error))
        }
    }
}
