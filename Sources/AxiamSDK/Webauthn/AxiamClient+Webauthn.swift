import Foundation

// CONTRACT.md §24 — the WebAuthn relying-party layer.
//
// The six wire operations plus §24.6a's JSON bridge. These are available on every build,
// including Linux: §24.6b's ceremony helper is what needs `AuthenticationServices`, and
// rule 1 forbids making it the only way to reach these.
extension AxiamClient {

    private enum WebauthnPath {
        static let registerStart = "api/v1/auth/webauthn/register/start"
        static let registerFinish = "api/v1/auth/webauthn/register/finish"
        static let authenticateStart = "api/v1/auth/webauthn/authenticate/start"
        static let authenticateFinish = "api/v1/auth/webauthn/authenticate/finish"
        static let discoverableStart = "api/v1/auth/webauthn/authenticate/discoverable/start"
        static let discoverableFinish = "api/v1/auth/webauthn/authenticate/discoverable/finish"
    }

    /// `POST /api/v1/auth/webauthn/register/start` (CONTRACT.md §24.1) — begin enrolling a
    /// passkey for the signed-in user.
    ///
    /// Requires a session, and refuses **client-side with no wire call** when there is none
    /// — the shape §1.1 rule 3 requires of `getUserInfo`.
    ///
    /// The returned options are the server's, untouched (§24.0). A `503` here means the
    /// tenant's attestation policy needs FIDO metadata the server cannot reach: a
    /// configuration state, not a transient one, and §24.4 rule 2 deliberately does not
    /// retry it.
    public func webauthnRegisterStart() async throws -> WebauthnChallenge {
        try ensureOpen()
        try requireWebauthnSession("webauthnRegisterStart")
        return try await webauthnStart(path: WebauthnPath.registerStart, body: Data("{}".utf8))
    }

    /// `POST /api/v1/auth/webauthn/register/finish` (CONTRACT.md §24.1) — hand the
    /// authenticator's answer back and store the credential.
    ///
    /// - Parameters:
    ///   - stateToken: the token from ``webauthnRegisterStart()``.
    ///   - credentialName: the label to store the credential under.
    ///   - response: the platform's own response JSON, **verbatim** (§24.6a rule 2). It
    ///     reaches the wire byte for byte, because re-encoding a signed buffer is three
    ///     chances to corrupt it in service of nothing.
    @discardableResult
    public func webauthnRegisterFinish(
        stateToken: Sensitive<String>,
        credentialName: String,
        response: String
    ) async throws -> WebauthnCredential {
        try ensureOpen()
        try requireWebauthnSession("webauthnRegisterFinish")

        let body = try Self.webauthnFinishBody(
            stateToken: stateToken,
            response: response,
            operation: "webauthnRegisterFinish",
            extraFields: ["credential_name": credentialName]
        )
        let http = try await webauthnRawSend(path: WebauthnPath.registerFinish, body: body)
        guard http.status == 200 || http.status == 201 else {
            throw webauthnRegisterFinishError(http)
        }

        let wire = try webauthnDecode(WebauthnCredentialResponse.self, http)
        return WebauthnCredential(
            id: wire.id,
            credentialID: wire.credential_id,
            name: wire.name,
            credentialType: wire.credential_type,
            createdAt: wire.created_at,
            lastUsedAt: wire.last_used_at
        )
    }

    /// `POST /api/v1/auth/webauthn/authenticate/start` (CONTRACT.md §24.1) — begin the
    /// **second-factor** ceremony.
    ///
    /// Continues a ``login(email:password:)`` that answered `.mfaRequired` with
    /// `"webauthn"` among its available methods. Pass `nil` to use the challenge token that
    /// login retained internally, exactly as ``verifyMfa(_:)`` does.
    ///
    /// A different flow from ``webauthnDiscoverableStart(workspace:)``, not the same one
    /// with a flag (§24.2) — which is why a challenge token is required here and rejected
    /// there.
    public func webauthnAuthenticateStart(
        challengeToken: Sensitive<String>? = nil
    ) async throws -> WebauthnChallenge {
        try ensureOpen()
        guard let token = challengeToken ?? currentChallengeToken() else {
            throw AxiamError.auth(AuthError(
                "webauthnAuthenticateStart needs the challenge token from a login that "
                    + "answered mfaRequired (CONTRACT.md §24.2)."
            ))
        }
        let body = try Self.webauthnJSONObject(["challenge_token": token.expose()])
        return try await webauthnStart(path: WebauthnPath.authenticateStart, body: body)
    }

    /// `POST /api/v1/auth/webauthn/authenticate/finish` (CONTRACT.md §24.1).
    ///
    /// On success the client is signed in: the server sets the same cookie triple
    /// `POST /api/v1/auth/login` sets, and the §17 decision memo is cleared because the
    /// subject changed (§24.3).
    @discardableResult
    public func webauthnAuthenticateFinish(
        stateToken: Sensitive<String>,
        response: String
    ) async throws -> WebauthnLoginResult {
        try await webauthnFinish(
            path: WebauthnPath.authenticateFinish,
            stateToken: stateToken,
            response: response,
            operation: "webauthnAuthenticateFinish"
        )
    }

    /// `POST /api/v1/auth/webauthn/authenticate/discoverable/start` (CONTRACT.md §24.1) —
    /// begin the usernameless ceremony.
    ///
    /// A **primary factor**: nothing precedes it, `allowCredentials` comes back empty, and
    /// the assertion itself identifies the user. Pass `nil` for `workspace` to have it
    /// filled from this client's own configured identity.
    ///
    /// Unlike `authenticate/finish`, `discoverable/finish` fires the `login.post_auth`
    /// reactor hook (§22.5) — the former continues a login already gated at its password
    /// step, and this one has no such step.
    public func webauthnDiscoverableStart(
        workspace: WebauthnWorkspace? = nil
    ) async throws -> WebauthnChallenge {
        try ensureOpen()
        let body = try webauthnWorkspaceBody(workspace)
        return try await webauthnStart(path: WebauthnPath.discoverableStart, body: body)
    }

    /// `POST /api/v1/auth/webauthn/authenticate/discoverable/finish` (CONTRACT.md §24.1).
    /// Adopts credentials exactly as ``webauthnAuthenticateFinish(stateToken:response:)``
    /// does.
    @discardableResult
    public func webauthnDiscoverableFinish(
        stateToken: Sensitive<String>,
        response: String
    ) async throws -> WebauthnLoginResult {
        try await webauthnFinish(
            path: WebauthnPath.discoverableFinish,
            stateToken: stateToken,
            response: response,
            operation: "webauthnDiscoverableFinish"
        )
    }

    // MARK: - Shared mechanics

    /// Runs either `*_start` call and returns the options untouched.
    private func webauthnStart(path: String, body: Data) async throws -> WebauthnChallenge {
        let http = try await webauthnRawSend(path: path, body: body)
        guard http.status == 200 else { throw webauthnMapError(http, "webauthn start failed") }

        guard
            let root = try? JSONSerialization.jsonObject(with: http.body) as? [String: Any],
            let stateToken = root["state_token"] as? String
        else {
            throw AxiamError.network(NetworkError("webauthn start: malformed response body"))
        }

        // The options are re-serialized from the parsed object rather than sliced out of
        // the response bytes. That is a semantic round trip, not a reinterpretation: every
        // value in a WebAuthn options object is a string, number, bool, array or object,
        // and the platform parses it again on the other side. The direction that must be
        // byte-exact is the RESPONSE — a signed buffer — and that one never round-trips.
        let optionsObject = root["challenge"] ?? [String: Any]()
        let challengeData = (try? JSONSerialization.data(withJSONObject: optionsObject))
            ?? Data("{}".utf8)

        return WebauthnChallenge(challengeData: challengeData, stateToken: Sensitive(stateToken))
    }

    /// The shared tail of both authentication ceremonies.
    private func webauthnFinish(
        path: String,
        stateToken: Sensitive<String>,
        response: String,
        operation: String
    ) async throws -> WebauthnLoginResult {
        try ensureOpen()
        // §17.1 rule 9 / §24.3 rule 4: memo entries are keyed by subject, and this call
        // changes the subject.
        clearDecisionMemo()

        let body = try Self.webauthnFinishBody(
            stateToken: stateToken,
            response: response,
            operation: operation
        )
        let http = try await webauthnRawSend(path: path, body: body)
        guard http.status == 200 else { throw webauthnMapError(http, "\(operation) failed") }

        let wire = try webauthnDecode(WebauthnLoginResponse.self, http)
        adoptSessionAfterCeremony()
        return WebauthnLoginResult(
            accessToken: Sensitive(wire.access_token),
            refreshToken: Sensitive(wire.refresh_token),
            sessionID: wire.session_id,
            expiresIn: wire.expires_in
        )
    }

    /// Builds a `*_finish` body **as bytes**, splicing the caller's response JSON in
    /// verbatim (§24.0, §24.6a rule 2).
    ///
    /// Decoding the string and re-encoding it would reorder keys unpredictably, round every
    /// number through a `Double`, and generally hand the server a byte sequence the
    /// authenticator never signed. The one thing this does check is that the string IS a
    /// JSON object — the SDK will not POST a body it already knows the server cannot
    /// verify.
    static func webauthnFinishBody(
        stateToken: Sensitive<String>,
        response: String,
        operation: String,
        extraFields: [String: String] = [:]
    ) throws -> Data {
        let trimmed = response.trimmingCharacters(in: .whitespacesAndNewlines)
        guard
            let parsed = try? JSONSerialization.jsonObject(
                with: Data(trimmed.utf8),
                options: [.fragmentsAllowed]
            )
        else {
            throw AxiamError.auth(AuthError(
                "\(operation): the authenticator response string is not valid JSON. Pass "
                    + "the platform's response JSON verbatim (CONTRACT.md §24.6a)."
            ))
        }
        guard parsed is [String: Any] else {
            throw AxiamError.auth(AuthError(
                "\(operation): the authenticator response must be a JSON object "
                    + "(CONTRACT.md §24.6a)."
            ))
        }

        var fields: [(String, String)] = [("state_token", stateToken.expose())]
        for key in extraFields.keys.sorted() {
            fields.append((key, extraFields[key]!))
        }

        var body = Data("{".utf8)
        for (key, value) in fields {
            body.append(try Self.jsonString(key))
            body.append(Data(":".utf8))
            body.append(try Self.jsonString(value))
            body.append(Data(",".utf8))
        }
        body.append(Data("\"response\":".utf8))
        body.append(Data(trimmed.utf8))
        body.append(Data("}".utf8))
        return body
    }

    /// Encodes one string as a JSON string literal, escaping included.
    private static func jsonString(_ value: String) throws -> Data {
        // Encoded through a single-element array and unwrapped, because
        // JSONSerialization refuses a bare string on older platforms.
        let wrapped = try JSONSerialization.data(withJSONObject: [value])
        return wrapped.dropFirst().dropLast()
    }

    private static func webauthnJSONObject(_ object: [String: String]) throws -> Data {
        do {
            return try JSONSerialization.data(withJSONObject: object)
        } catch {
            throw AxiamError.network(NetworkError("Failed to encode request body", cause: error))
        }
    }

    /// §24.1: `register/…` needs a session, and the refusal is raised client-side with
    /// **no wire call**.
    private func requireWebauthnSession(_ operation: String) throws {
        guard hasActiveSession else {
            throw AxiamError.auth(AuthError(
                "\(operation) requires an authenticated session: enrol a passkey while "
                    + "signed in (CONTRACT.md §24.1)."
            ))
        }
    }

    /// §24.4 rule 1: the `403` from `register/finish` is the one whose *body* matters.
    ///
    /// The generic §2 mapping would raise an ``AuthzError`` reading
    /// "webauthnRegisterFinish failed", which tells the person holding the key nothing they
    /// can act on. The tenant's attestation policy rejected *this* authenticator, and the
    /// server's message is the only place that says which one would be accepted.
    private func webauthnRegisterFinishError(_ http: HTTPResponseData) -> AxiamError {
        var context = "webauthnRegisterFinish failed"
        if http.status == 403,
           let root = try? JSONSerialization.jsonObject(with: http.body) as? [String: Any],
           let message = root["message"] as? String,
           !message.isEmpty {
            context += ": \(message)"
        }
        return webauthnMapError(http, context)
    }

    /// Fills the discoverable ceremony's workspace from this client's own configuration
    /// when the caller passed none.
    ///
    /// Only fields that actually have a value are emitted: the server takes either form at
    /// either level, and sending `null` for the ones it does not have is indistinguishable
    /// from asking it to resolve nothing.
    private func webauthnWorkspaceBody(_ workspace: WebauthnWorkspace?) throws -> Data {
        var body: [String: String] = [:]

        var orgID = workspace?.orgID
        var orgSlug = workspace?.orgSlug
        if orgID == nil && orgSlug == nil {
            orgID = configuredOrgID
            orgSlug = configuredOrgSlug
        }
        if let orgID {
            body["org_id"] = orgID
        } else if let orgSlug {
            body["org_slug"] = orgSlug
        } else {
            throw AxiamError.auth(AuthError(
                "webauthnDiscoverableStart needs an organization: construct the client "
                    + "with one, or pass it in the workspace argument (CONTRACT.md §24.1)."
            ))
        }

        if let tenantID = workspace?.tenantID {
            body["tenant_id"] = tenantID
        } else if let tenantSlug = workspace?.tenantSlug {
            body["tenant_slug"] = tenantSlug
        } else if let ownTenantID = configuredTenantID {
            body["tenant_id"] = ownTenantID
        } else if let ownTenantSlug = configuredTenantSlug {
            body["tenant_slug"] = ownTenantSlug
        } else {
            throw AxiamError.auth(AuthError(
                "webauthnDiscoverableStart needs a tenant: construct the client with one, "
                    + "or pass it in the workspace argument (CONTRACT.md §24.1)."
            ))
        }

        return try Self.webauthnJSONObject(body)
    }

    private func webauthnDecode<T: Decodable>(_ type: T.Type, _ http: HTTPResponseData) throws -> T {
        do {
            return try JSONDecoder().decode(type, from: http.body)
        } catch {
            throw AxiamError.network(NetworkError("Failed to decode response body", cause: error))
        }
    }
}

// MARK: - Wire types

struct WebauthnCredentialResponse: Decodable {
    let id: String
    let credential_id: String
    let name: String
    let credential_type: String
    let created_at: String
    let last_used_at: String?
}

struct WebauthnLoginResponse: Decodable {
    let access_token: String
    let refresh_token: String
    let session_id: String
    let expires_in: Int
}
