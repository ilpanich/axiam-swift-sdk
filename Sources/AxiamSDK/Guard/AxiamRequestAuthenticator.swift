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
/// `axiam_access` cookie), verifies its signature against the org JWKS (EdDSA/Ed25519 only,
/// §JWKS), enforces expiry and tenant scoping, and returns the authenticated ``AxiamUser``.
/// On any failure it throws ``AuthError`` (which a framework adapter surfaces as HTTP 401).
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

    init(jwks: JwksVerifier, tenantID: String, tenantSlug: String? = nil) {
        self.jwks = jwks
        var tenants: [String] = []
        if !tenantID.isEmpty { tenants.append(tenantID) }
        if let tenantSlug, !tenantSlug.isEmpty, !tenants.contains(tenantSlug) { tenants.append(tenantSlug) }
        self.configuredTenants = tenants
    }

    /// The primary configured tenant identifier (the UUID form when one was configured).
    var tenantID: String { configuredTenants.first ?? "" }

    /// Names of the access-token cookie and bearer scheme.
    static let accessCookieName = "axiam_access"

    /// Authenticate an inbound request, returning the verified identity.
    ///
    /// - Throws: ``AuthError`` when no credential is present, the JWT is malformed, the
    ///   algorithm is not EdDSA, the signature is invalid, the token is expired, the token does
    ///   not belong to the configured tenant, or the tenant does not match the request's
    ///   `X-Tenant-ID`.
    public func authenticate(_ context: AxiamRequestContext) async throws -> AxiamUser {
        guard let token = Self.extractToken(from: context) else {
            throw AuthError("No AXIAM session: missing Authorization bearer token or axiam_access cookie.")
        }

        let verified = try await jwks.verify(token: token)
        let claims = verified.claims

        // Expiry is enforced here (the JWKS verifier intentionally checks signature only).
        if let exp = claims.exp, exp < Date().timeIntervalSince1970 {
            throw AuthError("AXIAM session token is expired.")
        }

        guard let subject = claims.sub, !subject.isEmpty else {
            throw AuthError("AXIAM token has no subject (sub) claim.")
        }

        // §10 (SEC-072): bind the session to the *configured* tenant on EVERY verified token.
        // The JWKS is organization-wide, so a valid signature alone does not imply the token was
        // issued for this client's tenant. This runs unconditionally — it is not contingent on the
        // request carrying an X-Tenant-ID header.
        try Self.assertTenant(tokenTenant: claims.tenant_id, configured: configuredTenants)

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
