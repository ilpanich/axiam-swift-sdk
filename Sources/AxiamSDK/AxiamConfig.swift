import Foundation
import NIOSSL

/// A client-identity certificate for mutual TLS (§6.1 of CONTRACT.md).
///
/// The mandatory baseline is a PEM certificate chain plus a PEM private key (PKCS#8 or
/// PKCS#1). The private key is held behind ``Sensitive`` so it never appears in any
/// debug/log output (§7). A non-PEM value fails at construction time (§6.1 rule 1).
public enum ClientCertificate: Sendable {
    /// PEM certificate chain + PEM private key.
    case pem(certificate: Data, privateKey: Sensitive<Data>)

    /// Convenience initializer taking raw PEM bytes; wraps the key in ``Sensitive``.
    public static func pem(certificate: Data, privateKey: Data) -> ClientCertificate {
        .pem(certificate: certificate, privateKey: Sensitive(privateKey))
    }
}

/// Immutable configuration for an ``AxiamClient``.
///
/// Enforces the §5 tenant rule (a tenant identifier is mandatory) and the §6 "PEM only" TLS
/// rule at construction time. There is deliberately **no** insecure/skip-verify surface (§6).
public struct AxiamConfig: Sendable {
    public let baseURL: URL
    public let tenantID: String?
    public let tenantSlug: String?
    public let orgID: String?
    public let orgSlug: String?
    public let customCA: Data?
    public let clientCertificate: ClientCertificate?
    public let requestTimeout: TimeInterval

    /// The `iss` the §10 guard requires an inbound access token to carry (CONTRACT.md §10.1
    /// rule 5).
    ///
    /// Optional and `nil` by default: leaving it unset means the issuer is not checked. When set,
    /// ``AxiamRequestAuthenticator`` rejects a token whose `iss` is absent or different.
    public let expectedIssuer: String?

    /// An audience the §10 guard requires an inbound access token's `aud` to contain
    /// (CONTRACT.md §10.1 rule 6).
    ///
    /// Optional and `nil` by default: leaving it unset means the audience is not checked. A
    /// resource server guarding a user-facing API SHOULD set `axiam:user`.
    public let expectedAudience: String?

    /// Whether the §16 bounded read-only retry policy is active. **`true` by default.**
    ///
    /// There is deliberately no property for the attempt cap, the base delay or the delay cap:
    /// §16.1 permits *lowering* the budget or disabling it, never raising it, and a caller who can
    /// raise them turns one client into the herd a backoff exists to prevent. Set `false` for
    /// exactly one attempt — the right choice for a caller who owns their own retry layer and
    /// knows their own deadline.
    public let retryEnabled: Bool

    /// The §17 decision-memo TTL. **`nil` by default, which means disabled** — not "cache for zero
    /// seconds".
    ///
    /// A value above 5 s is **clamped** to 5 s rather than rejected (§17.1 rule 2), and the clamp
    /// is announced through the §19 ``TelemetryEvent/configClamped(setting:requested:effective:contractReference:)``
    /// event rather than applied in silence.
    ///
    /// > Important: **Read-your-own-writes is not guaranteed.** The staleness bound is the TTL in
    /// > both directions: a grant revoked on the server can still read as allowed for up to the
    /// > TTL, and a grant just *added* can still read as denied for up to the TTL. An admin UI that
    /// > grants a role and immediately re-checks is the case that breaks, and it breaks silently.
    /// > Switch this on having read that, not because it looks like an easy win.
    public let decisionMemoTtl: TimeInterval?

    /// An optional §19 telemetry sink.
    ///
    /// Invoked on the calling task from inside the client actor, so it must not block: §19.2 rule
    /// 4 makes buffering the caller's job so they can pick the policy. With none installed the
    /// cost is one optional check per request.
    public let telemetryHook: TelemetryHook?

    /// The relying party's OAuth2 `client_id` (§12.1).
    ///
    /// Client **configuration**, not a per-call argument: §12.3 keeps it here so the nine
    /// operations cannot disagree about which client they are. Required before `oidcBegin`,
    /// `oidcExchange`, `oidcRefresh`, `loginClientCredentials`, `introspect`, `revoke`,
    /// `deviceAuthorize`/`devicePoll`, `tokenExchange` and `logoutURL` can be used.
    public let oidcClientID: String?

    /// The confidential client's secret (§12.1 note 3: `client_secret_post`).
    ///
    /// Omit for a public client — the authorization-code + PKCE flow does not need one.
    /// `introspect` and `revoke` do (§12.1 note 4), and say so when it is absent.
    public let oidcClientSecret: Sensitive<String>?

    /// Discovery-document cache TTL (§12.3 rule 6). Values below the five-minute floor are
    /// raised to it; a shorter one would be a self-inflicted round trip on a per-origin
    /// protocol artifact that is not a credential.
    public let oidcDiscoveryTTL: TimeInterval

    /// Clock skew allowed on the §12.4 rule 5 time checks, in seconds.
    ///
    /// Clamped **down** to 60 s — the rule permits at most that in either direction and requires
    /// a larger configured value to be clamped rather than rejected. A negative value clamps to
    /// zero.
    public let oidcClockSkew: TimeInterval

    /// Designated initializer.
    ///
    /// - Throws: ``AuthError`` if neither `tenantID` nor `tenantSlug` is supplied (§5), or if
    ///   both `orgID` and `orgSlug` are supplied (they are mutually exclusive);
    ///   ``NetworkError`` if `baseURL` is not `https` and its host is not loopback (§6).
    public init(
        baseURL: URL,
        tenantID: String? = nil,
        tenantSlug: String? = nil,
        orgID: String? = nil,
        orgSlug: String? = nil,
        customCA: Data? = nil,
        clientCertificate: ClientCertificate? = nil,
        requestTimeout: TimeInterval = 30,
        expectedIssuer: String? = nil,
        expectedAudience: String? = nil,
        retryEnabled: Bool = true,
        decisionMemoTtl: TimeInterval? = nil,
        telemetryHook: TelemetryHook? = nil,
        oidcClientID: String? = nil,
        oidcClientSecret: Sensitive<String>? = nil,
        oidcDiscoveryTTL: TimeInterval = 300,
        oidcClockSkew: TimeInterval = 60
    ) throws {
        // §5: a tenant identifier is non-optional and cannot be deferred.
        let hasTenant = (tenantID?.isBlank == false) || (tenantSlug?.isBlank == false)
        guard hasTenant else {
            throw AuthError(
                "AxiamConfig requires either tenantID or tenantSlug (§5: no default tenant). "
                + "To sign in an organization-level principal, name the organization's reserved "
                + #"tenant, whose slug is "organization" (§5.2.1)."#
            )
        }
        // §5.2.1 rule 2: an SDK MUST NOT send an empty-string slug. The check
        // above is an *aggregate* — a blank `tenantSlug` beside a real
        // `tenantID` satisfies it, and the blank one is then stored and
        // serialized into every login body.
        //
        // Nothing can carry a blank slug, so the server resolves nothing — and
        // on /auth/opaque/login/start it fails on the workspace *before* the
        // tenant's OPAQUE mode is read, so the 404 that means "OPAQUE is not
        // offered here" never arrives, this SDK has no fallback to take, and
        // sign-in fails even against a tenant with OPAQUE disabled.
        //
        // `nil` stays fine: that is what "not named" looks like, and the server
        // reads an unnamed tenant as the organization's own scope.
        if tenantSlug?.isBlank == true {
            throw AuthError("AxiamConfig: tenantSlug must not be blank — leave it nil or name a tenant (§5, §5.2.1).")
        }
        if tenantID?.isBlank == true {
            throw AuthError("AxiamConfig: tenantID must not be blank — leave it nil or name a tenant (§5, §5.2.1).")
        }
        if orgSlug?.isBlank == true {
            throw AuthError("AxiamConfig: orgSlug must not be blank — leave it nil or name the organization (§5.1, §5.2.1).")
        }
        if orgID?.isBlank == true {
            throw AuthError("AxiamConfig: orgID must not be blank — leave it nil or name the organization (§5.1, §5.2.1).")
        }
        // org identifiers are optional but mutually exclusive.
        if (orgID?.isEmpty == false) && (orgSlug?.isEmpty == false) {
            throw AuthError("AxiamConfig accepts at most one of orgID or orgSlug, not both.")
        }
        // §6: a plaintext base URL is refused up front (SEC-073).
        try Self.validateSecureBaseURL(baseURL)

        self.baseURL = baseURL
        self.tenantID = tenantID
        self.tenantSlug = tenantSlug
        self.orgID = orgID
        self.orgSlug = orgSlug
        self.customCA = customCA
        self.clientCertificate = clientCertificate
        self.requestTimeout = requestTimeout
        self.expectedIssuer = expectedIssuer
        self.expectedAudience = expectedAudience
        self.retryEnabled = retryEnabled
        // Stored UNCLAMPED. The clamp happens when the memo is built, so the §19 `configClamped`
        // event can report what the caller actually asked for rather than the value it was
        // quietly turned into.
        self.decisionMemoTtl = decisionMemoTtl
        self.telemetryHook = telemetryHook
        self.oidcClientID = oidcClientID
        self.oidcClientSecret = oidcClientSecret
        // Both clamps are applied here rather than at use: unlike the §17 memo TTL, neither is
        // reported through a §19 event, so there is nothing to preserve the original value for.
        self.oidcDiscoveryTTL = max(oidcDiscoveryTTL, 300)
        self.oidcClockSkew = min(max(oidcClockSkew, 0), 60)
    }

    // MARK: - §6 transport-scheme guard

    /// `true` when `host` is a loopback literal — the sole exception to the `https`-only rule.
    ///
    /// `URL.host` reports an IPv6 literal without its brackets, but the bracketed form is
    /// accepted too in case a raw authority string is passed in.
    static func isLoopbackHost(_ host: String) -> Bool {
        switch host.lowercased() {
        case "localhost", "127.0.0.1", "::1", "[::1]":
            return true
        default:
            return false
        }
    }

    /// Reject a plaintext (non-TLS) base URL at construction time (§6, SEC-073).
    ///
    /// Every AXIAM transport must run over TLS: the client forwards the tenant identifier, the
    /// CSRF token and the session cookies on every request, and `login` carries the user's
    /// password — none of which may traverse a cleartext link. TLS is already strict *when*
    /// `https` is used (see ``makeTLSConfiguration()``), so the remaining hole is a misconfigured
    /// `http://` base that silently downgrades the whole session; it is refused rather than
    /// accepted.
    ///
    /// The single, deliberate exception is a loopback host (`localhost`, `127.0.0.1`, `::1`) so
    /// local development and integration tests against a non-TLS dev server still work. There is
    /// no flag that disables the check for a routable host.
    ///
    /// - Throws: ``NetworkError`` naming both schemes; the message contains no secret.
    static func validateSecureBaseURL(_ url: URL) throws {
        let scheme = url.scheme?.lowercased() ?? ""
        if scheme == "https" { return }
        if let host = url.host, isLoopbackHost(host) { return }
        throw NetworkError(
            "AxiamConfig baseURL must use the encrypted `https://` scheme "
                + "(got `\(scheme.isEmpty ? "<none>" : scheme)://`); plaintext transport is refused "
                + "because it would expose credentials, session cookies, CSRF and tenant headers. "
                + "The only exception is a loopback host (localhost/127.0.0.1/::1) for local "
                + "development (§6)."
        )
    }

    /// The value injected as the `X-Tenant-ID` header on every request (§5). Prefers the UUID
    /// form when both are present.
    var tenantHeaderValue: String {
        if let tenantID, !tenantID.isEmpty { return tenantID }
        return tenantSlug ?? ""
    }

    /// Build the NIOSSL `TLSConfiguration` for this config (§6 + §6.1).
    ///
    /// Strict server verification (`.fullVerification`) is **always** on. A `customCA` adds a
    /// trust root for development self-signed servers; a `clientCertificate` installs the mTLS
    /// client identity. There is no code path that weakens verification.
    ///
    /// - Throws: ``NetworkError`` if any PEM material fails to parse (§6/§6.1: PEM-only, clear
    ///   error at construction time).
    func makeTLSConfiguration() throws -> TLSConfiguration {
        var tls = TLSConfiguration.makeClientConfiguration()
        // Strict verification is mandatory and immutable (§6). Set explicitly for clarity.
        tls.certificateVerification = .fullVerification

        if let customCA {
            do {
                let caCerts = try NIOSSLCertificate.fromPEMBytes(Array(customCA))
                guard !caCerts.isEmpty else {
                    throw NetworkError("customCA did not contain any PEM certificate.")
                }
                tls.trustRoots = .certificates(caCerts)
            } catch let error as NetworkError {
                throw error
            } catch {
                throw NetworkError("customCA is not valid PEM (§6: PEM-only).", cause: error)
            }
        }

        if let clientCertificate {
            try Self.applyClientCertificate(clientCertificate, to: &tls)
        }

        return tls
    }

    /// Isolated so the client-cert path stays separate from server-verification code (§6.1 rule 2).
    static func applyClientCertificate(_ cert: ClientCertificate, to tls: inout TLSConfiguration) throws {
        switch cert {
        case let .pem(certificate, privateKey):
            do {
                let chain = try NIOSSLCertificate.fromPEMBytes(Array(certificate))
                    .map { NIOSSLCertificateSource.certificate($0) }
                guard !chain.isEmpty else {
                    throw NetworkError("clientCertificate chain contained no PEM certificate.")
                }
                let key = try NIOSSLPrivateKey(bytes: Array(privateKey.wrapped), format: .pem)
                tls.certificateChain = chain
                tls.privateKey = .privateKey(key)
            } catch let error as NetworkError {
                throw error
            } catch {
                throw NetworkError("clientCertificate is not valid PEM (§6.1: PEM cert + PEM key).", cause: error)
            }
        }
    }
}

/// A string of only whitespace is not an identifier (§5.2.1 rule 2).
///
/// Kept `internal` and separate from `isEmpty` on purpose: the two read alike
/// and mean different things here, and it is `isEmpty` — used in an aggregate
/// check — that let a blank slug through beside a valid id.
extension String {
    var isBlank: Bool { trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
}
