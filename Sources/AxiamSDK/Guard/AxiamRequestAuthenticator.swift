import Foundation

/// A minimal, framework-agnostic view of an inbound request: its headers and cookies.
///
/// Header lookup is case-insensitive. Adapters for concrete frameworks (Vapor, etc.) build one
/// of these from their own request type — see the README for a Vapor `AsyncMiddleware` example.
public struct AxiamRequestContext: Sendable {
    public let headers: [String: String]
    public let cookies: [String: String]

    public init(headers: [String: String] = [:], cookies: [String: String] = [:]) {
        self.headers = headers
        self.cookies = cookies
    }

    public func header(_ name: String) -> String? {
        let lower = name.lowercased()
        return headers.first(where: { $0.key.lowercased() == lower })?.value
    }
}

/// Framework-agnostic resource-server guard (§10 of CONTRACT.md).
///
/// Extracts the session from an inbound request (either `Authorization: Bearer <jwt>` or the
/// `axiam_access` cookie) and applies the **§10.1 minimum local-verification set** in full before
/// returning the authenticated ``AxiamUser``:
///
/// 1. signature against the org JWKS, `alg` pinned to EdDSA *before* key lookup;
/// 2. `exp` — **required**; absent or non-numeric rejects;
/// 3. `nbf` — honoured when present; a future `nbf` rejects;
/// 4. `tenant_id` — **required** and asserted against the configured tenant;
/// 5. `iss` — checked when ``AxiamConfig/expectedIssuer`` is configured;
/// 6. `aud` — checked when ``AxiamConfig/expectedAudience`` is configured;
/// 7. a single named, bounded leeway (``clockSkewTolerance``) on rules 2 and 3.
///
/// Every rule fails **closed**: a required claim that is absent, unparseable, or of the wrong
/// JSON type rejects the token. "The claim was missing so there was nothing to check" is never a
/// success path here. On any failure it throws ``AuthError`` (which a framework adapter surfaces
/// as HTTP 401).
public struct AxiamRequestAuthenticator: Sendable {
    let jwks: JwksVerifier
    /// The configured tenant identifiers a verified session must belong to (§5/§10).
    ///
    /// The client may be configured with a tenant UUID, a tenant slug, or both, so the assertion
    /// accepts a match against any of the configured values. AXIAM access tokens carry the tenant
    /// **UUID** in `tenant_id`, so a resource server that guards requests with this type should
    /// configure ``AxiamConfig/tenantID``; a slug-only configuration cannot bind a session and
    /// will (by design, fail-closed) reject every token.
    let configuredTenants: [String]

    /// The `iss` an inbound token must carry, or `nil` to skip the check (§10.1 rule 5).
    let expectedIssuer: String?

    /// An audience an inbound token's `aud` must contain, or `nil` to skip the check (§10.1
    /// rule 6).
    let expectedAudience: String?

    /// §10.1 rule 7 — the ONE named leeway applied to the `exp` and `nbf` comparisons.
    ///
    /// A constant, not an inline literal, and deliberately not settable: the contract forbids an
    /// operator raising the tolerance to an unbounded value.
    public static let clockSkewTolerance: TimeInterval = 60

    init(
        jwks: JwksVerifier,
        tenantID: String,
        tenantSlug: String? = nil,
        expectedIssuer: String? = nil,
        expectedAudience: String? = nil
    ) {
        self.jwks = jwks
        var tenants: [String] = []
        if !tenantID.isEmpty { tenants.append(tenantID) }
        if let tenantSlug, !tenantSlug.isEmpty, !tenants.contains(tenantSlug) { tenants.append(tenantSlug) }
        self.configuredTenants = tenants
        self.expectedIssuer = expectedIssuer
        self.expectedAudience = expectedAudience
    }

    /// The primary configured tenant identifier (the UUID form when one was configured).
    var tenantID: String { configuredTenants.first ?? "" }

    /// Names of the access-token cookie and bearer scheme.
    static let accessCookieName = "axiam_access"

    /// Authenticate an inbound request, returning the verified identity.
    ///
    /// Applies the §10.1 minimum local-verification set listed on the type. A raw signature check
    /// (``JwksVerifier/verifySignatureOnlyUnchecked(token:)``) is deliberately *not* a substitute
    /// for this method.
    ///
    /// - Throws: ``AuthError`` when no credential is present, the JWT is malformed, the
    ///   algorithm is not EdDSA, the signature is invalid, `exp` is absent/non-numeric/past,
    ///   `nbf` is in the future, the token does not belong to the configured tenant, the tenant
    ///   does not match the request's `X-Tenant-ID`, or a configured issuer/audience does not
    ///   match.
    public func authenticate(_ context: AxiamRequestContext) async throws -> AxiamUser {
        guard let token = Self.extractToken(from: context) else {
            throw AuthError("No AXIAM session: missing Authorization bearer token or axiam_access cookie.")
        }

        // §10.1 rule 1. The primitive checks the signature only — every claim rule below is this
        // guard's job. A non-numeric `exp`/`nbf` or a wrong-typed `aud` already fails there, in
        // the strict claim decode.
        let verified = try await jwks.verifySignatureOnlyUnchecked(token: token)
        let claims = verified.claims
        let now = Date().timeIntervalSince1970

        // §10.1 rule 2 (SEC-080): `exp` is REQUIRED. A token with no `exp` is a permanent
        // credential and must fail closed rather than be read as "no expiry constraint". The JWKS
        // trust anchor is organization-wide, so the guard must not lean on the AXIAM server's own
        // invariant that it always mints `exp`.
        guard let exp = claims.exp else {
            throw AuthError("AXIAM token has no exp claim; refusing to accept an unbounded session.")
        }
        if exp + Self.clockSkewTolerance < now {
            throw AuthError("AXIAM session token is expired.")
        }

        // §10.1 rule 3: `nbf` is optional, but binding when present.
        if let nbf = claims.nbf, nbf - Self.clockSkewTolerance > now {
            throw AuthError("AXIAM session token is not yet valid (nbf is in the future).")
        }

        guard let subject = claims.sub, !subject.isEmpty else {
            throw AuthError("AXIAM token has no subject (sub) claim.")
        }

        // §10.1 rule 4 (SEC-072): bind the session to the *configured* tenant on EVERY verified
        // token. The JWKS is organization-wide, so a valid signature alone does not imply the
        // token was issued for this client's tenant. This runs unconditionally — it is not
        // contingent on the request carrying an X-Tenant-ID header.
        try Self.assertTenant(tokenTenant: claims.tenant_id, configured: configuredTenants)

        // §10.1 rules 5 and 6: conditional on this SDK having been configured with an expected
        // value. Unset means "not checked"; set means a mismatch — or an absent claim — rejects.
        try Self.assertIssuer(claims.iss, expected: expectedIssuer)
        try Self.assertAudience(claims.aud, expected: expectedAudience)

        // Defense in depth: if the request also carries an explicit X-Tenant-ID and the token
        // names a different tenant, reject (catches a proxy/router routing the request as one
        // tenant while presenting another tenant's token).
        if let requestTenant = context.header("X-Tenant-ID"),
           let tokenTenant = claims.tenant_id,
           !requestTenant.isEmpty,
           requestTenant != tokenTenant {
            throw AuthError("Token tenant does not match request X-Tenant-ID.")
        }

        return AxiamUser(
            userID: subject,
            tenantID: claims.tenant_id ?? tenantID,
            roles: claims.roles ?? [],
            username: claims.preferred_username,
            email: claims.email
        )
    }

    /// Cross-tenant carry-forward control (SEC-072).
    ///
    /// The JWKS endpoint is organization-wide, so a signature-valid token may have been issued
    /// for a *different* tenant of the same organization. Every verified session is therefore
    /// asserted against the configured tenant; a token with no (or an empty) `tenant_id` claim
    /// fails closed rather than being carried forward with the configured value substituted in.
    ///
    /// - Throws: ``AuthError`` when the claim is absent/empty, no tenant is configured, or the
    ///   claim names a tenant this client is not configured for. The message never echoes the
    ///   token or the claim value.
    static func assertTenant(tokenTenant: String?, configured: [String]) throws {
        guard let tokenTenant, !tokenTenant.isEmpty else {
            throw AuthError("AXIAM token has no tenant_id claim; refusing to bind it to the configured tenant.")
        }
        guard !configured.isEmpty else {
            throw AuthError("AxiamRequestAuthenticator has no configured tenant to bind the session to.")
        }
        guard configured.contains(tokenTenant) else {
            throw AuthError("Token tenant_id does not match the configured tenant.")
        }
    }

    /// §10.1 rule 5. `expected == nil` means the SDK was not configured with an issuer, so there
    /// is nothing to check. Once configured, an absent `iss` fails closed like a mismatched one.
    static func assertIssuer(_ tokenIssuer: String?, expected: String?) throws {
        guard let expected else { return }
        guard let tokenIssuer, !tokenIssuer.isEmpty else {
            throw AuthError("AXIAM token has no iss claim but an expected issuer is configured.")
        }
        guard tokenIssuer == expected else {
            throw AuthError("Token iss does not match the configured expected issuer.")
        }
    }

    /// §10.1 rule 6. `expected == nil` means the SDK was not configured with an audience. Once
    /// configured, the token's `aud` (string or array form) must contain it; an absent `aud`
    /// fails closed.
    static func assertAudience(_ tokenAudience: JwtAudience?, expected: String?) throws {
        guard let expected else { return }
        guard let tokenAudience else {
            throw AuthError("AXIAM token has no aud claim but an expected audience is configured.")
        }
        guard tokenAudience.values.contains(expected) else {
            throw AuthError("Token aud does not contain the configured expected audience.")
        }
    }

    static func extractToken(from context: AxiamRequestContext) -> String? {
        if let auth = context.header("Authorization") {
            let parts = auth.split(separator: " ", maxSplits: 1)
            if parts.count == 2, parts[0].lowercased() == "bearer" {
                let token = parts[1].trimmingCharacters(in: .whitespaces)
                if !token.isEmpty { return token }
            }
        }
        if let cookie = context.cookies[accessCookieName], !cookie.isEmpty {
            return cookie
        }
        return nil
    }
}
