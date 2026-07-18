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
    let tenantID: String

    init(jwks: JwksVerifier, tenantID: String) {
        self.jwks = jwks
        self.tenantID = tenantID
    }

    /// Names of the access-token cookie and bearer scheme.
    static let accessCookieName = "axiam_access"

    /// Authenticate an inbound request, returning the verified identity.
    ///
    /// - Throws: ``AuthError`` when no credential is present, the JWT is malformed, the
    ///   algorithm is not EdDSA, the signature is invalid, the token is expired, or the tenant
    ///   does not match the request's `X-Tenant-ID`.
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

        // §10: scope verification to the request's tenant. If the request carries an explicit
        // X-Tenant-ID and the token names a different tenant, reject.
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
