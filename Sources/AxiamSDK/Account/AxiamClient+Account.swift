import Foundation

// CONTRACT.md §25 — account lifecycle and MFA enrolment: the calls a user makes about
// their own account, none of which is administration.
extension AxiamClient {

    private enum AccountPath {
        static let mfaEnroll = "api/v1/auth/mfa/enroll"
        static let mfaConfirm = "api/v1/auth/mfa/confirm"
        static let mfaSetupEnroll = "api/v1/auth/mfa/setup/enroll"
        static let mfaSetupConfirm = "api/v1/auth/mfa/setup/confirm"
        static let verifyEmail = "api/v1/auth/verify-email"
        static let resendVerification = "api/v1/auth/resend-verification"
        static let resendOwnVerification = "api/v1/users/me/resend-verification"
        static let reset = "api/v1/auth/reset"
        static let resetContext = "api/v1/auth/reset/context"
        static let resetConfirm = "api/v1/auth/reset/confirm"
    }

    /// `POST /api/v1/auth/mfa/enroll` (CONTRACT.md §25.1) — start voluntary TOTP enrolment
    /// for the signed-in user.
    ///
    /// Changes nothing about the current session. In particular it does **not** clear the
    /// §17 decision memo: the subject has not changed, and discarding a warm memo on an
    /// unrelated profile action costs a round trip on every check that follows
    /// (§25.2 rule 3).
    ///
    /// Enrolment is two calls and this is only the first: the factor is not active until
    /// ``mfaConfirm(_:)`` accepts a code derived from the returned secret. §25.2 rule 4
    /// forbids a composed one-call helper here, because the human step in the middle —
    /// scanning the URI, reading a code — is not something a helper can wait for.
    public func mfaEnroll() async throws -> MfaEnrollment {
        try ensureOpen()
        let http = try await webauthnRawSend(path: AccountPath.mfaEnroll, body: Data("{}".utf8))
        return try readMfaEnrollment(http, "mfaEnroll")
    }

    /// `POST /api/v1/auth/mfa/confirm` (CONTRACT.md §25.1) — activate the factor
    /// ``mfaEnroll()`` offered. Returns whether MFA is now enabled.
    @discardableResult
    public func mfaConfirm(_ totpCode: String) async throws -> Bool {
        try ensureOpen()
        let body = try accountEncode(MfaConfirmRequestBody(totp_code: totpCode))
        let http = try await webauthnRawSend(path: AccountPath.mfaConfirm, body: body)
        guard http.status == 200 else { throw webauthnMapError(http, "mfaConfirm failed") }
        return (try? JSONDecoder().decode(MfaConfirmResponseBody.self, from: http.body))?
            .mfa_enabled ?? false
    }

    /// `POST /api/v1/auth/mfa/setup/enroll` (CONTRACT.md §25.1) — start the enrolment a
    /// ``login(email:password:)`` demanded.
    ///
    /// Reached when `login` returns `.mfaSetupRequired`: the tenant requires MFA and this
    /// account has none. There is no session yet — the setup token *is* the credential.
    public func mfaSetupEnroll(setupToken: Sensitive<String>) async throws -> MfaEnrollment {
        try ensureOpen()
        let body = try accountEncode(MfaSetupEnrollRequestBody(setup_token: setupToken.expose()))
        let http = try await webauthnRawSend(path: AccountPath.mfaSetupEnroll, body: body)
        return try readMfaEnrollment(http, "mfaSetupEnroll")
    }

    /// `POST /api/v1/auth/mfa/setup/confirm` (CONTRACT.md §25.1) — finish forced enrolment
    /// and, with it, the login that was interrupted.
    ///
    /// Adopts credentials exactly as ``login(email:password:)`` does, because it *is* the
    /// completion of a login (§25.2 rule 2) — including clearing the §17 decision memo.
    @discardableResult
    public func mfaSetupConfirm(
        setupToken: Sensitive<String>,
        totpCode: String
    ) async throws -> AxiamUser {
        try ensureOpen()
        clearDecisionMemo() // §25.2 rule 2 → §24.3 rule 4
        let body = try accountEncode(MfaSetupConfirmRequestBody(
            setup_token: setupToken.expose(),
            totp_code: totpCode
        ))
        let http = try await webauthnRawSend(path: AccountPath.mfaSetupConfirm, body: body)
        guard http.status == 200 else { throw webauthnMapError(http, "mfaSetupConfirm failed") }

        let success = try accountDecode(LoginSuccessResponse.self, http)
        let user = success.toUser()
        adoptSessionAfterCeremony(user: user)
        return user
    }

    /// `POST /api/v1/auth/verify-email` (CONTRACT.md §25.1).
    ///
    /// Unauthenticated: a user whose address is unverified may have no session at all.
    /// `tenantID` is a **body** field here — this is not an `/oauth2` endpoint, so §12.1
    /// rule 2's query-parameter convention does not reach it.
    public func verifyEmail(token: Sensitive<String>, tenantID: String) async throws {
        try ensureOpen()
        let body = try accountEncode(VerifyEmailRequestBody(
            token: token.expose(),
            tenant_id: tenantID
        ))
        try await postExpectingNoContent(AccountPath.verifyEmail, body, "verifyEmail")
    }

    /// `POST /api/v1/auth/resend-verification` (CONTRACT.md §25.1) — the
    /// **unauthenticated** resend, for a caller with no session.
    ///
    /// **Returns normally whatever the outcome.** The address may not exist, may already be
    /// verified, or may be over the daily limit, and the server answers identically in every
    /// case because it takes an address from an anonymous caller: anything else is an oracle
    /// for which addresses have accounts (§25.4).
    ///
    /// A caller that *is* signed in wants ``resendOwnVerification()``, which says what
    /// happened. §25.7 rule 2 forbids routing either of these to the other, and this SDK
    /// does not.
    public func resendVerification(email: String, tenantID: String) async throws {
        try ensureOpen()
        let body = try accountEncode(ResendVerificationRequestBody(
            email: email,
            tenant_id: tenantID
        ))
        try await postExpectingNoContent(
            AccountPath.resendVerification,
            body,
            "resendVerification"
        )
    }

    /// `POST /api/v1/users/me/resend-verification` (CONTRACT.md §25.1, §25.7) — resend the
    /// **signed-in caller's own** verification mail, and say what happened.
    ///
    /// Takes no address. The server reads it off the caller's own record, and this signature
    /// deliberately offers no way to name a different one: a parameter here would let an
    /// authenticated session mail an arbitrary address.
    ///
    /// Unlike ``resendVerification(email:tenantID:)`` this reports the outcome, because the
    /// caller is signed in to the account it is asking about and none of the outcomes tells
    /// it anything it did not already bring with it:
    ///
    /// - returns — a token was minted and the mail **enqueued**. Delivery is asynchronous
    ///   and can still fail at the provider; a queue that accepts everything in front of a
    ///   provider that rejects it looks exactly like this succeeding (§25.7 rule 3).
    /// - `AxiamError.authz` (from `409`) — already verified, or an account state that must
    ///   not be sent a live token.
    /// - `AxiamError.network` (from `429`) — the daily resend limit.
    ///
    /// §25.7 rule 2 forbids falling back to the unauthenticated endpoint on either failure,
    /// and this SDK does not: that fallback turns both back into a silent success and
    /// restores the bug this operation exists to fix, with an extra round trip.
    ///
    /// Refused client-side with **no wire call** when there is no session.
    public func resendOwnVerification() async throws {
        try ensureOpen()
        guard hasActiveSession else {
            throw AxiamError.auth(AuthError(
                "resendOwnVerification requires an authenticated session: it resends the "
                    + "mail for the account you are signed in to, and names no address "
                    + "(CONTRACT.md §25.7). Use resendVerification(email:tenantID:) when "
                    + "there is no session."
            ))
        }
        // The empty object, exactly as `mfaEnroll` sends: the server takes the address off
        // the caller's own record, and §25.6 asks for a request carrying NO address field.
        try await postExpectingNoContent(
            AccountPath.resendOwnVerification,
            Data("{}".utf8),
            "resendOwnVerification"
        )
    }

    /// `POST /api/v1/auth/reset` (CONTRACT.md §25.1) — ask for a reset mail.
    ///
    /// **Returns normally whether or not the address exists**, and this SDK exposes no way
    /// to tell the two apart. That is not an omission to improve on: a client that surfaced
    /// a "no such user" state — even one inferred from timing — would turn the endpoint
    /// into the account-enumeration oracle its uniform response exists to prevent (§25.4).
    public func requestPasswordReset(_ request: PasswordResetRequest) async throws {
        try ensureOpen()
        var body: [String: String] = ["email": request.email]
        if let orgSlug = request.orgSlug ?? configuredOrgSlug {
            body["org_slug"] = orgSlug
        } else if let orgID = configuredOrgID {
            body["org_id"] = orgID
        }
        if let tenantID = request.tenantID {
            body["tenant_id"] = tenantID
        } else if let tenantSlug = request.tenantSlug {
            body["tenant_slug"] = tenantSlug
        } else if let ownTenantID = configuredTenantID {
            body["tenant_id"] = ownTenantID
        } else if let ownTenantSlug = configuredTenantSlug {
            body["tenant_slug"] = ownTenantSlug
        }

        let encoded = try accountEncode(body)
        try await postExpectingNoContent(AccountPath.reset, encoded, "requestPasswordReset")
    }

    /// `GET /api/v1/auth/reset/context` (CONTRACT.md §25.1) — the OPAQUE policy for the
    /// account a reset token belongs to.
    ///
    /// Call this before ``confirmPasswordReset(_:)`` on any tenant that might have §23
    /// enabled: the client has to build a registration record, and building one needs
    /// parameters it cannot know before it has a token to ask with. Sending a plaintext
    /// password to a tenant in `opaque_mode: required` is refused, and refused late
    /// (§25.4 rule 1).
    ///
    /// A `404` means unknown, expired **or** already-consumed, deliberately without
    /// distinguishing them; this SDK does not distinguish them either (§25.4 rule 3).
    public func passwordResetContext(token: Sensitive<String>) async throws -> PasswordResetContext {
        try ensureOpen()
        let http = try await rawGetWithQuery(
            path: AccountPath.resetContext,
            query: [URLQueryItem(name: "token", value: token.expose())],
            context: "passwordResetContext"
        )
        guard http.status == 200 else {
            throw webauthnMapError(http, "passwordResetContext failed")
        }

        guard let root = try? JSONSerialization.jsonObject(with: http.body) as? [String: Any] else {
            throw AxiamError.network(
                NetworkError("passwordResetContext: response body is not a JSON object")
            )
        }
        guard
            let opaque = root["opaque"],
            !(opaque is NSNull),
            let opaqueData = try? JSONSerialization.data(withJSONObject: opaque)
        else {
            return PasswordResetContext(opaqueData: nil)
        }
        return PasswordResetContext(opaqueData: opaqueData)
    }

    /// `POST /api/v1/auth/reset/confirm` (CONTRACT.md §25.1) — set the new password.
    public func confirmPasswordReset(_ confirmation: PasswordResetConfirmation) async throws {
        try ensureOpen()

        // Built as bytes so the §23 registration record — which this SDK does not model —
        // is spliced in exactly as the §23 helpers produced it.
        var body = Data("{".utf8)
        body.append(try Self.accountField("token", confirmation.token.expose()))
        body.append(Data(",".utf8))
        body.append(try Self.accountField("new_password", confirmation.newPassword.expose()))
        body.append(Data(",".utf8))
        body.append(try Self.accountField("tenant_id", confirmation.tenantID))
        if let opaqueData = confirmation.opaqueData {
            body.append(Data(",\"opaque\":".utf8))
            body.append(opaqueData)
        }
        body.append(Data("}".utf8))

        try await postExpectingNoContent(AccountPath.resetConfirm, body, "confirmPasswordReset")
    }

    // MARK: - Shared mechanics

    private func readMfaEnrollment(
        _ http: HTTPResponseData,
        _ operation: String
    ) throws -> MfaEnrollment {
        guard http.status == 200 else { throw webauthnMapError(http, "\(operation) failed") }
        let wire = try accountDecode(MfaEnrollResponseBody.self, http)
        return MfaEnrollment(
            secretBase32: Sensitive(wire.secret_base32),
            totpURI: Sensitive(wire.totp_uri)
        )
    }

    private func postExpectingNoContent(
        _ path: String,
        _ body: Data,
        _ operation: String
    ) async throws {
        let http = try await webauthnRawSend(path: path, body: body)
        guard http.status == 200 || http.status == 202 || http.status == 204 else {
            throw webauthnMapError(http, "\(operation) failed")
        }
    }

    private static func accountField(_ key: String, _ value: String) throws -> Data {
        let pair = try JSONSerialization.data(withJSONObject: [key: value])
        return pair.dropFirst().dropLast()
    }

    private func accountEncode<T: Encodable>(_ value: T) throws -> Data {
        do {
            return try JSONEncoder().encode(value)
        } catch {
            throw AxiamError.network(NetworkError("Failed to encode request body", cause: error))
        }
    }

    private func accountEncode(_ object: [String: String]) throws -> Data {
        do {
            return try JSONSerialization.data(withJSONObject: object)
        } catch {
            throw AxiamError.network(NetworkError("Failed to encode request body", cause: error))
        }
    }

    private func accountDecode<T: Decodable>(_ type: T.Type, _ http: HTTPResponseData) throws -> T {
        do {
            return try JSONDecoder().decode(type, from: http.body)
        } catch {
            throw AxiamError.network(NetworkError("Failed to decode response body", cause: error))
        }
    }
}

// MARK: - Wire types

struct MfaEnrollResponseBody: Decodable {
    let secret_base32: String
    let totp_uri: String
}

struct MfaConfirmRequestBody: Encodable {
    let totp_code: String
}

struct MfaConfirmResponseBody: Decodable {
    let mfa_enabled: Bool
}

struct MfaSetupEnrollRequestBody: Encodable {
    let setup_token: String
}

struct MfaSetupConfirmRequestBody: Encodable {
    let setup_token: String
    let totp_code: String
}

struct VerifyEmailRequestBody: Encodable {
    let token: String
    let tenant_id: String
}

struct ResendVerificationRequestBody: Encodable {
    let email: String
    let tenant_id: String
}
