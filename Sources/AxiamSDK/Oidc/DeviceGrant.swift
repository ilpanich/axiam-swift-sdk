import Foundation

// CONTRACT.md §14 — the RFC 8628 device authorization grant: signing in a device that cannot
// show a browser. A TV, a CLI, a headless commissioning tool.
//
// §14.2 is where implementations go wrong, so it is worth stating the four rules this file is
// built around before the code:
//
//   - `slow_down` increases the interval PERMANENTLY, by 5 s, and never resets it. An SDK that
//     backs off for one round and returns to the original interval will be told to slow down
//     again, forever.
//   - The initial interval comes from the RESPONSE, not from a constant; 5 s when the server
//     omits it. No faster floor may be hard-coded.
//   - `access_denied` and `expired_token` are DISTINCT. One means a human said no; the other
//     means nobody answered. Collapsing them loses the only thing the device can act on.
//   - Polling stops at `expires_in`, whether or not the server has said `expired_token` yet.
//   - A `5xx` on a poll is a transport failure whatever its body (rule 6, contract 1.64 amended).
//   - A `429` on a poll is waited out (contract 1.64, rule 9; the status decides): the loop waits
//     `Retry-After` as a minimum, capped at the deadline, counts that wait as one interval, does
//     NOT raise the interval for it, and polls again. Only the `400 slow_down` raises it.

/// A poll answered `rate_limit_exceeded` (§14.2 rule 9), with the `Retry-After` it carried.
///
/// Internal on purpose: ``AxiamClient/devicePoll(deviceCode:tenantID:configuration:)`` still
/// throws the plain ``AuthError`` (`oauthError == "rate_limit_exceeded"`) the rule requires of
/// the single call; this wrapper only lets
/// ``AxiamClient/deviceLogin(scope:tenantID:configuration:onAuthorization:)`` read the header
/// without widening ``AuthError``.
struct DevicePollRateLimited: Error {
    let error: AxiamError
    let retryAfter: TimeInterval?
}

extension AxiamClient {

    static let deviceCodeGrantType = "urn:ietf:params:oauth:grant-type:device_code"

    /// The RFC 8628 §3.2 default when the authorization response omits `interval`.
    static let deviceDefaultIntervalSeconds = 5

    /// The §14.2 rule 1 increment, added to the *current* interval on every `slow_down`.
    static let deviceSlowDownIncrementSeconds = 5

    /// `POST /oauth2/device_authorization` (§14.1) — start the grant.
    ///
    /// **Authenticates the client by what it was configured with** (§14.1 rule 2, contract 1.62):
    ///
    /// - A **public** client — the usual device, which cannot hold a secret — is constructed
    ///   without `oidcClientSecret` and without a client certificate. Only `client_id` goes out,
    ///   and this call is never refused client-side for lacking a credential (§14.1 rule 1).
    /// - A client with ``AxiamConfig/oidcClientSecret`` sends it as `client_secret` **in the
    ///   form body**, exactly as at `/oauth2/token`, whichever of `client_secret_post` and
    ///   `client_secret_basic` it is registered for. **No `Authorization: Basic` header is ever
    ///   sent** (§12.1 rule 3 stands for this route; the server accepts either form).
    /// - A client with a §6.1 client certificate presents it on the connection, and the request
    ///   goes to the `mtls_endpoint_aliases` entry when the document publishes one (§21.3 rule 2).
    ///
    /// A credential goes out only when the caller configured one: this never borrows a secret
    /// from another configuration and never invents one. A `401` `invalid_client` — an unknown
    /// client, a failed or missing credential, a credential sent by a public client — throws an
    /// ``AuthError`` whose ``AuthError/oauthError`` is `invalid_client`, after exactly one
    /// request, and never enters the §9 refresh guard (§14.2 rule 5). This SDK does not
    /// generate `private_key_jwt` assertions (§21.8), so there is no assertion form to send.
    public func deviceAuthorize(
        scope: String? = nil,
        tenantID: String? = nil,
        configuration: OidcConfiguration? = nil
    ) async throws -> DeviceAuthorization {
        let document = try await oidcConfiguration(configuration)
        // §21.3 rule 2: prefer the mTLS alias when this call presents a client certificate.
        // `nil` at BOTH levels still means "unsupported" — never a cue to build the URL by
        // concatenation (§14.1).
        guard let endpoint = try preferredEndpoint(
            document, { $0.deviceAuthorizationEndpoint }, document.deviceAuthorizationEndpoint
        ) else {
            throw AxiamError.network(NetworkError(
                "the discovery document advertises no device_authorization_endpoint"))
        }
        var form = ["client_id": try requireOidcClientID()]
        // §14.1 rule 2: a client configured with a secret authenticates here as it does at
        // `/oauth2/token` — in the body, never as `Authorization: Basic`. A public client
        // configures none and sends none.
        if let secret = config.oidcClientSecret { form["client_secret"] = secret.wrapped }
        if let scope, !scope.isEmpty { form["scope"] = scope }

        let response = try await oidcFormPost(endpoint, form: form, tenantID: tenantID)
        guard (200..<300).contains(response.status) else { throw oidcMapGrantError(response) }
        let wire = try oidcDecode(DeviceAuthorizationWire.self, response.body, "device authorization")
        return DeviceAuthorization(
            deviceCode: Sensitive(wire.device_code),
            userCode: wire.user_code,
            verificationURI: wire.verification_uri,
            // Surfaced when present, never synthesised by concatenation when absent (§14.3):
            // its format is the server's to choose.
            verificationURIComplete: wire.verification_uri_complete,
            expiresIn: wire.expires_in,
            interval: wire.interval ?? Self.deviceDefaultIntervalSeconds)
    }

    /// One `POST /oauth2/token` with the device-code grant (§14.1) — a single poll.
    ///
    /// Returns the token set when the user has approved. The five RFC 8628 §3.5 answers all
    /// arrive as `400` with an `OAuth2ErrorResponse`, and §14.2 rule 5 requires dispatching on
    /// the `error` field rather than the status: this throws an ``AuthError`` whose
    /// ``AuthError/oauthError`` carries that field, so a caller driving its own loop can tell
    /// `authorization_pending` and `slow_down` (keep going) from `access_denied`,
    /// `expired_token` and `invalid_grant` (stop). The sixth, `401` `invalid_client` (contract
    /// 1.62), is dispatched the same way and is terminal: a failed client authentication is not
    /// an expired session, so it is not retried and does not enter the §9 refresh guard.
    /// A `5xx` is a transport failure whatever its body (§14.2 rule 6, contract 1.64 amended): it
    /// throws the §2 ``NetworkError`` and the loop keeps polling. A `429` is rule 9's wait
    /// whatever its body names; this call throws it as `rate_limit_exceeded` when the body is an
    /// OAuth error, and as the §2 ``NetworkError`` when it is not.
    ///
    /// **Client authentication (§14.1 rules 2 and 3).** Every poll sends `client_id`. A client
    /// configured with ``AxiamConfig/oidcClientSecret`` also sends it as `client_secret` in the
    /// form body — never as `Authorization: Basic`, whatever the client is registered for — and a
    /// client with a §6.1 certificate presents it on the connection; a public client sends
    /// neither. This SDK verifies DPoP proofs but does not generate them (§21.9), so a client
    /// registered for DPoP cannot be driven from here: its poll is refused `401 invalid_client`
    /// and surfaces as above. A response whose `token_type` is `DPoP` is surfaced as the server
    /// said it (``OidcTokenSet/tokenType``), never assumed to be `Bearer`.
    ///
    /// ``deviceLogin(scope:tenantID:configuration:onAuthorization:)`` is the loop most callers
    /// want; this exists for one that needs its own.
    public func devicePoll(
        deviceCode: Sensitive<String>,
        tenantID: String? = nil,
        configuration: OidcConfiguration? = nil
    ) async throws -> OidcTokenSet {
        let document = try await oidcConfiguration(configuration)
        do {
            return try await devicePollOnce(
                deviceCode: deviceCode, tenantID: tenantID, document: document)
        } catch let limited as DevicePollRateLimited {
            // The single call raises the §2 `OAuthProtocolError` of rule 9; only the loop waits.
            throw limited.error
        }
    }

    /// One poll, keeping the `Retry-After` of a `429 rate_limit_exceeded` for the loop.
    func devicePollOnce(
        deviceCode: Sensitive<String>,
        tenantID: String?,
        document: OidcConfiguration
    ) async throws -> OidcTokenSet {
        var form = [
            "grant_type": Self.deviceCodeGrantType,
            "device_code": deviceCode.wrapped,
            "client_id": try requireOidcClientID(),
        ]
        // §14.1 rule 2: the same credential as `deviceAuthorize` and as every other token
        // request — a secret in the body when one is configured, none for a public client, the
        // certificate on the connection for an mTLS one. Never `Authorization: Basic`.
        if let secret = config.oidcClientSecret { form["client_secret"] = secret.wrapped }

        let endpoint = try preferredEndpoint(document, { $0.tokenEndpoint }, required: document.tokenEndpoint)
        let response = try await oidcFormPost(endpoint, form: form, tenantID: tenantID)
        guard (200..<300).contains(response.status) else {
            // §14.2 rule 6 (contract 1.64, amended): a `5xx` is a transport failure whatever its
            // body. The status is read BEFORE the body — AXIAM answers an internal failure
            // `500 {"error":"server_error"}`, which rule 5's dispatch on `error` would otherwise
            // turn into a terminal `AuthError` and lose a grant the user already approved.
            if response.status >= 500 { throw oidcMapError(response) }

            var error = oidcMapGrantError(response)
            // §14.2 rule 9 (contract 1.64, amended): the STATUS decides. Any `429` on a poll is
            // the rate-limit wait, whatever its body names — a `429 slow_down` (a server before
            // 1.1.2, or an intermediary) must not raise the interval, and a bodiless `429` (a
            // proxy's) still carries a `Retry-After` floor. Rule 5's dispatch on `error` applies
            // to the `400`.
            if response.status == 429 {
                if case let .auth(authError) = error, authError.oauthError != "rate_limit_exceeded" {
                    error = .auth(AuthError(
                        "rate_limit_exceeded: \(authError.oauthErrorDescription ?? "")",
                        oauthError: "rate_limit_exceeded",
                        oauthErrorDescription: authError.oauthErrorDescription))
                }
                throw DevicePollRateLimited(
                    error: error,
                    retryAfter: Retry.retryAfter(response.firstHeader("retry-after")))
            }
            throw error
        }
        let wire = try oidcDecode(TokenResponseWire.self, response.body, "token response")
        // §12.4 rules 1–5 and 7 apply to any id_token; rule 6 is skipped — there was no
        // authorization request in this flow to carry a nonce.
        return try await oidcTokenSet(wire, document: document, expectedNonce: nil)
    }

    /// The composed helper (§14.3): authorize, hand the caller the codes, poll to completion.
    ///
    /// `onAuthorization` is called **before polling begins** and is the only place the user code
    /// and verification URI are surfaced. §14.3 rule 2 is explicit that an SDK must not print
    /// them to stdout on the caller's behalf — a device shows them however it can: a screen, a
    /// QR code, an e-ink panel.
    ///
    /// The returned token set is **not adopted** as this client's credential. Adoption is the
    /// same MAY as `loginClientCredentials` (§14.3 rule 4), and this SDK takes one posture
    /// everywhere: return the tokens, install nothing.
    ///
    /// Polling follows §14.2 exactly: the interval starts at the server's, `slow_down` adds 5 s
    /// permanently, and the loop stops at `expires_in` even if the server has not yet said so.
    /// A `429 rate_limit_exceeded` (contract 1.64, rule 9) is not terminal and is not a
    /// `slow_down`: the next wait is the longer of the interval and `Retry-After`, it stands in
    /// for that one interval, the interval itself is unchanged, and when the wait would pass the
    /// deadline the loop raises `expired_token` at once and sends nothing after it.
    public func deviceLogin(
        scope: String? = nil,
        tenantID: String? = nil,
        configuration: OidcConfiguration? = nil,
        onAuthorization: @Sendable (DeviceAuthorization) -> Void
    ) async throws -> OidcTokenSet {
        let document = try await oidcConfiguration(configuration)
        let authorization = try await deviceAuthorize(
            scope: scope, tenantID: tenantID, configuration: document)

        // Rule 2: the caller gets the codes before the first poll, always.
        onAuthorization(authorization)

        var interval = authorization.interval
        // A `Retry-After` from a `429` poll, a minimum for the next wait only (rule 9).
        var retryAfter: TimeInterval = 0
        let deadline = Date().addingTimeInterval(TimeInterval(authorization.expiresIn))

        while true {
            // Rule 4: the deadline is authoritative, and it is the *next attempt* that must fall
            // inside it — not the current moment. Checking `now < deadline` before sleeping
            // looks equivalent and is not: after a `slow_down` takes the interval past the time
            // remaining, that check passes, the loop sleeps through the deadline, and polls
            // anyway. That request is exactly the "pure load" this rule exists to prevent.
            // Rule 9: after a `429` the wait is the interval or `Retry-After`, whichever is longer
            // — one interval slot, not two, and `interval` itself is untouched.
            let wait = max(TimeInterval(interval), retryAfter)
            retryAfter = 0
            let nextAttempt = Date().addingTimeInterval(wait)
            guard nextAttempt < deadline else {
                throw AxiamError.auth(AuthError(
                    "expired_token: the device grant expired before the user approved it",
                    oauthError: "expired_token"))
            }
            try await _sleep(wait)

            do {
                return try await devicePollOnce(
                    deviceCode: authorization.deviceCode, tenantID: tenantID, document: document)
            } catch let limited as DevicePollRateLimited {
                // Rule 9 (contract 1.64): not terminal, and never the polling signal.
                retryAfter = limited.retryAfter ?? 0
                continue
            } catch let error as AxiamError {
                guard case let .auth(authError) = error, let code = authError.oauthError else {
                    // §14.2 rule 6: a 5xx (whatever its body) or a transport failure is not
                    // terminal. The poll itself is a single request on the bare path, so the
                    // loop's next interval is the retry; a server restart mid-flow must not lose
                    // a grant the user already approved.
                    continue
                }
                switch code {
                case "authorization_pending":
                    continue
                case "slow_down":
                    // Rule 1: permanent, cumulative, never reset.
                    interval += Self.deviceSlowDownIncrementSeconds
                    continue
                default:
                    // access_denied, expired_token, invalid_grant — and anything else the server
                    // names. All terminal, and each surfaces with its own code intact (rule 3).
                    throw error
                }
            }
        }
    }
}
