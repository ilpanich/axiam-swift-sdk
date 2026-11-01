import Crypto
import Foundation

// CONTRACT.md §37 — native sign-in with a provider ID token (contract 1.65).
//
// A mobile or desktop app that used Google, Apple or Facebook's *native* SDK holds an ID token
// the provider signed for that app and no authorization code. This file is the one POST that
// turns that token into the client's ordinary AXIAM token set, and the helper that makes the
// nonce pair the grant needs.
//
// What this file is built around, because each is a way to get §37 wrong without a test failing:
//
//   - The `nonce` on the wire is the RAW one. The provider's SDK was given SHA-256(raw) as hex;
//     the server hashes what it is sent and compares. Sending the hash, or the token's own
//     `nonce` claim, is the same generic `invalid_grant` as every other refusal.
//   - The provider's token is single-use across the deployment, so the call is NEVER retried
//     (`BareRetry.never`), and `invalid_grant` is never refined or told apart.
//   - `openid` is NOT added to the scopes: an omitted `scope` means the empty set, and so no ID
//     token — the opposite of `oidcBegin` rule 4.
//   - Neither the provider ID token nor the raw nonce is logged, put in an error, or kept.

/// The pair a native sign-in needs (CONTRACT.md §37.4): the **raw** nonce AXIAM is sent, and its
/// SHA-256 as hexadecimal, which the provider's SDK is given.
///
/// `raw` is secret — with the provider's token it lets its holder sign in as the user — so it is
/// a ``Sensitive`` value (§37.6) and renders as `[SENSITIVE]` everywhere. `hashed` travels to
/// the provider and into the token it signs, and is not secret.
public struct ProviderNonce: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    /// The raw nonce: 32 random bytes, base64url without padding. Pass it to
    /// ``AxiamClient/loginWithProviderIdToken(provider:idToken:nonce:scopes:resource:tenantID:configuration:)``
    /// and hold it only for the length of the attempt.
    public let raw: Sensitive<String>
    /// `SHA-256(raw)` as 64 lower-case hexadecimal characters — the nonce to give the
    /// provider's SDK.
    public let hashed: String

    public init(raw: Sensitive<String>, hashed: String) {
        self.raw = raw
        self.hashed = hashed
    }

    public var description: String { "ProviderNonce(raw: [SENSITIVE], hashed: \(hashed))" }
    public var debugDescription: String { description }
}

extension AxiamClient {

    /// The grant URN of §37 — `urn:axiam:params:oauth:grant-type:provider-id-token`.
    static let providerIdTokenGrantType = "urn:axiam:params:oauth:grant-type:provider-id-token"

    // MARK: - §37.4 native_nonce

    /// A fresh ``ProviderNonce`` (CONTRACT.md §37.4) — **pure local computation, no network I/O**,
    /// and synchronous.
    ///
    /// Give ``ProviderNonce/hashed`` to the provider's SDK as *its* nonce, then give
    /// ``ProviderNonce/raw`` to
    /// ``loginWithProviderIdToken(provider:idToken:nonce:scopes:resource:tenantID:configuration:)``
    /// along with the ID token the provider returned. Giving the provider the raw value, or a
    /// hash in another encoding, comes back as the same generic `invalid_grant` as every other
    /// refusal — which is why this exists.
    ///
    /// Each call returns a different pair. Nothing is stored: not on the client, not in a cache.
    public nonisolated func nativeNonce() -> ProviderNonce {
        var bytes = [UInt8](repeating: 0, count: 32)
        for index in bytes.indices { bytes[index] = UInt8.random(in: 0...255) }
        let raw = Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return ProviderNonce(raw: Sensitive(raw), hashed: Self.nativeNonceHash(of: raw))
    }

    /// `SHA-256` of the UTF-8 (= ASCII) bytes of `raw`, as lower-case hexadecimal (§37.4 rule 2).
    nonisolated static func nativeNonceHash(of raw: String) -> String {
        SHA256.hash(data: Data(raw.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - §37.1 login_with_provider_id_token

    /// `POST /oauth2/token` with
    /// `grant_type=urn:axiam:params:oauth:grant-type:provider-id-token` (CONTRACT.md §37) —
    /// sign in with the ID token a Google, Apple or Facebook native SDK produced.
    ///
    /// The form carries exactly `grant_type`, `client_id`, `provider`, `id_token`, `nonce`, plus
    /// `scope` and `resource` when you pass them, plus the client's credential when it has one
    /// (`client_secret` in the body — never an `Authorization` header). A public client — the
    /// usual mobile app — sends `client_id` alone and is not refused for lacking a secret.
    /// `tenant_id` is the query parameter, as for every `/oauth2` call; a slug-only client is
    /// refused here with no request (§12.3 rule 4).
    ///
    /// - Parameters:
    ///   - provider: the provider's UUID or its `provider_slug`, sent exactly as given. **Not**
    ///     a kind name: `google` works only if the operator also chose it as the slug. This SDK
    ///     does not trim, fold, resolve or look it up.
    ///   - idToken: the provider's ID token. Single-use across the deployment. Never logged or
    ///     kept by this SDK.
    ///   - nonce: the **raw** nonce — what ``nativeNonce()`` returned in ``ProviderNonce/raw``,
    ///     whose SHA-256 you gave the provider's SDK. Sent byte for byte: not hashed, not
    ///     replaced by the token's `nonce` claim, and this call never generates one of its own.
    ///   - scopes: sent space-joined **only** when you pass some. This SDK adds none — no
    ///     `openid` — and an omitted `scope` means the empty set, so no ID token comes back.
    ///     Pass `["openid"]` to receive one.
    ///   - resource: an RFC 8707 resource indicator, sent only when given.
    ///   - tenantID: a tenant UUID overriding the client's own.
    ///   - configuration: the discovery document, or `nil` to discover. Needed only to find the
    ///     token endpoint; no support check is made against it (§37.8).
    /// - Returns: the ordinary ``OidcTokenSet``. Its ``OidcTokenSet/tokenType`` is read from the
    ///   response, not assumed; ``OidcTokenSet/refreshToken`` is present only when the client
    ///   also holds `refresh_token`; an `id_token` only when `openid` was granted, and then it is
    ///   validated under §12.4 with the **raw** `nonce` as the expected nonce. It is **not**
    ///   adopted as this client's credential — the posture of ``loginClientCredentials(scope:tenantID:configuration:)``
    ///   and ``deviceLogin(scope:tenantID:configuration:onAuthorization:)``.
    /// - Throws:
    ///   - a validation ``NetworkError`` (``NetworkError/isValidation``) for an empty `provider`,
    ///     `idToken` or `nonce` — no request sent;
    ///   - ``AxiamError/auth(_:)`` with ``AuthError/oauthError`` set for every OAuth2 refusal
    ///     (`invalid_grant`, `unauthorized_client`, `invalid_client`, `invalid_scope`,
    ///     `invalid_target`, `consent_required`, `rate_limit_exceeded`, a `5xx` that carries an
    ///     `error`), dispatched on the body at any status;
    ///   - ``NetworkError`` for a transport failure and a `5xx` with no OAuth body.
    ///
    /// **Never retried, not by this SDK and not by a wrapper it ships**: the provider's token is
    /// spent once the server has checked it. `invalid_grant` is the server's one answer to every
    /// refusal of that token (wrong audience, bad signature, stale or replayed token, nonce
    /// mismatch, provider off, account barred, a reactor veto) and is deliberately not
    /// refinable — this SDK does not try to tell the causes apart. Recover with a **fresh**
    /// provider ID token and a **fresh** nonce. A transport failure after the request left is
    /// indeterminate for the same reason and gets the same recovery. `429
    /// rate_limit_exceeded` spends nothing, so you may try the same pair again after
    /// `Retry-After`; this SDK does not do it for you. `consent_required` has spent the token and
    /// is not turned into a browser flow.
    ///
    /// Hold the raw nonce only for the length of the attempt: with the token it is a credential.
    public func loginWithProviderIdToken(
        provider: String,
        idToken: Sensitive<String>,
        nonce: Sensitive<String>,
        scopes: [String]? = nil,
        resource: String? = nil,
        tenantID: String? = nil,
        configuration: OidcConfiguration? = nil
    ) async throws -> OidcTokenSet {
        try ensureOpen()
        let operation = "loginWithProviderIdToken"

        // §37.2 rule 4: empty inputs are refused locally, before any wire call — and nothing
        // else about the three values is judged here. The messages name the argument only.
        if provider.isEmpty {
            throw ManagementChecks.refusal(operation, "provider must not be empty (CONTRACT.md §37.2 rule 4)")
        }
        if idToken.wrapped.isEmpty {
            throw ManagementChecks.refusal(operation, "idToken must not be empty (CONTRACT.md §37.2 rule 4)")
        }
        if nonce.wrapped.isEmpty {
            throw ManagementChecks.refusal(operation, "nonce must not be empty (CONTRACT.md §37.2 rule 4)")
        }
        // Before discovery, so a client that cannot make this call spends no request at all.
        let clientID = try requireOidcClientID()
        let tenant = try requireOidcTenantUUID(tenantID)

        let document = try await oidcConfiguration(configuration)
        var form = [
            "grant_type": Self.providerIdTokenGrantType,
            "client_id": clientID,
            "provider": provider,
            "id_token": idToken.wrapped,
            "nonce": nonce.wrapped,
        ]
        // §37.2 rule 5: the client's credential only when its caller configured one, in the
        // body, never `Authorization: Basic`. A public client sends none and is not refused.
        if let secret = config.oidcClientSecret { form["client_secret"] = secret.wrapped }
        // §37.2 rule 7: `scope` only when named, and never `openid` unless the caller passed it.
        if let scopes, !scopes.isEmpty { form["scope"] = scopes.joined(separator: " ") }
        if let resource, !resource.isEmpty { form["resource"] = resource }

        let endpoint = try preferredEndpoint(document, { $0.tokenEndpoint }, required: document.tokenEndpoint)
        // §37.2 rule 10: exactly one attempt, whatever happens. The bare path attaches no
        // session cookie and no CSRF token (rule 1) and reports only the operation name and the
        // path template to §19 telemetry — never the body.
        let response = try await bareSend(
            operation: "login_with_provider_id_token",
            pathTemplate: "/oauth2/token",
            method: .post,
            url: try oidcTenantScopedURL(endpoint, tenantID: tenant),
            headers: [
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("Accept", "application/json"),
            ],
            body: Data(Self.oidcFormEncode(form).utf8),
            retry: .never)
        // §37.3: dispatched on the body's `error` at any status; built from the response alone,
        // so the request (and the secrets in it) cannot reach the error.
        guard (200..<300).contains(response.status) else { throw oidcMapGrantError(response) }
        let wire = try oidcDecode(TokenResponseWire.self, response.body, "token response")
        // §37.2 rule 8: any `id_token` is AXIAM's own, validated under §12.4 — with the RAW
        // nonce as the expected one, since AXIAM's token carries the request's nonce as sent.
        return try await oidcTokenSet(wire, document: document, expectedNonce: nonce.wrapped)
    }
}
