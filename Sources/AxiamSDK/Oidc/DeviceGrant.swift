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

extension AxiamClient {

    static let deviceCodeGrantType = "urn:ietf:params:oauth:grant-type:device_code"

    /// The RFC 8628 §3.2 default when the authorization response omits `interval`.
    static let deviceDefaultIntervalSeconds = 5

    /// The §14.2 rule 1 increment, added to the *current* interval on every `slow_down`.
    static let deviceSlowDownIncrementSeconds = 5

    /// `POST /oauth2/device_authorization` (§14.1) — start the grant.
    ///
    /// **Unauthenticated**: a device that cannot show a browser also cannot hold a client
    /// secret, so §14.1 forbids sending one here and forbids refusing to call this from a client
    /// constructed without one. Only `client_id` goes out.
    public func deviceAuthorize(
        scope: String? = nil,
        tenantID: String? = nil,
        configuration: OidcConfiguration? = nil
    ) async throws -> DeviceAuthorization {
        let document = try await oidcConfiguration(configuration)
        guard let endpoint = document.deviceAuthorizationEndpoint else {
            throw AxiamError.network(NetworkError(
                "the discovery document advertises no device_authorization_endpoint"))
        }
        var form = ["client_id": try requireOidcClientID()]
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
    /// `expired_token` and `invalid_grant` (stop).
    ///
    /// ``deviceLogin(scope:tenantID:configuration:onAuthorization:)`` is the loop most callers
    /// want; this exists for one that needs its own.
    public func devicePoll(
        deviceCode: Sensitive<String>,
        tenantID: String? = nil,
        configuration: OidcConfiguration? = nil
    ) async throws -> OidcTokenSet {
        let document = try await oidcConfiguration(configuration)
        var form = [
            "grant_type": Self.deviceCodeGrantType,
            "device_code": deviceCode.wrapped,
            "client_id": try requireOidcClientID(),
        ]
        // A device client is public by definition (see deviceAuthorize), but a confidential one
        // driving the same grant must still authenticate — send the secret only when configured.
        if let secret = config.oidcClientSecret { form["client_secret"] = secret.wrapped }

        let wire = try await oidcTokenGrant(form, document: document, tenantID: tenantID)
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
        let deadline = Date().addingTimeInterval(TimeInterval(authorization.expiresIn))

        while true {
            // Rule 4: the deadline is authoritative, and it is the *next attempt* that must fall
            // inside it — not the current moment. Checking `now < deadline` before sleeping
            // looks equivalent and is not: after a `slow_down` takes the interval past the time
            // remaining, that check passes, the loop sleeps through the deadline, and polls
            // anyway. That request is exactly the "pure load" this rule exists to prevent.
            let nextAttempt = Date().addingTimeInterval(TimeInterval(interval))
            guard nextAttempt < deadline else {
                throw AxiamError.auth(AuthError(
                    "expired_token: the device grant expired before the user approved it",
                    oauthError: "expired_token"))
            }
            try await Task.sleep(nanoseconds: UInt64(interval) * 1_000_000_000)

            do {
                return try await devicePoll(
                    deviceCode: authorization.deviceCode, tenantID: tenantID, configuration: document)
            } catch let error as AxiamError {
                guard case let .auth(authError) = error, let code = authError.oauthError else {
                    // §14.2 rule 6: a 5xx or transport failure is not terminal — it already went
                    // through the §16 bounded retry inside the poll, and a server restart
                    // mid-flow must not lose a grant the user already approved.
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
