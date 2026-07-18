import Foundation

/// A guard handler: given an inbound request context, return the authenticated user or throw.
///
/// - ``AuthError`` → the framework adapter should respond 401 `authentication_failed`.
/// - ``AuthzError`` → 403 `authorization_denied`.
/// - ``NetworkError`` → **fail closed** with 503 `authz_unavailable` (§11.2 rule 5); never allow
///   on transport failure.
public typealias AxiamGuardHandler = @Sendable (AxiamRequestContext) async throws -> AxiamUser

/// Declarative authorization helper factories (§11 of CONTRACT.md).
///
/// These compose strictly on top of the §10 ``AxiamRequestAuthenticator``: each returned
/// handler authenticates first, then applies its additional check. They never re-implement the
/// verification path. `requireAuth` and `requireAccess` are SHOULD-level; `requireRole` is the
/// MAY-level local check.
public struct AxiamGuards: Sendable {
    let authenticator: AxiamRequestAuthenticator
    let client: AxiamClient

    init(authenticator: AxiamRequestAuthenticator, client: AxiamClient) {
        self.authenticator = authenticator
        self.client = client
    }

    /// `require_auth` (§11): the endpoint requires any authenticated AXIAM identity.
    public func requireAuth() -> AxiamGuardHandler {
        let authenticator = self.authenticator
        return { context in
            try await authenticator.authenticate(context)
        }
    }

    /// `require_access(action, resource[, scope])` (§11): the **authenticated caller** must pass
    /// an AXIAM authorization check. `subject_id` is the end user's id (§11.2 rule 2), not the
    /// application's service-account session.
    public func requireAccess(_ action: String, resource: String, scope: String? = nil) -> AxiamGuardHandler {
        let authenticator = self.authenticator
        let client = self.client
        return { context in
            let user = try await authenticator.authenticate(context)
            let result = try await client.checkAccessInternal(
                action: action,
                resource: resource,
                scope: scope,
                subjectID: user.userID
            )
            guard result.allowed else {
                throw AuthzError(
                    "Access denied for '\(action)'.",
                    action: action,
                    resourceID: resource
                )
            }
            return user
        }
    }

    /// `require_role(role...)` (§11, MAY): a local check that the verified token's roles contain
    /// at least one of `roles`. No server round-trip; coarser than ``requireAccess(_:resource:scope:)``,
    /// which remains the authoritative check.
    public func requireRole(_ roles: String...) -> AxiamGuardHandler {
        let authenticator = self.authenticator
        let required = Set(roles)
        return { context in
            let user = try await authenticator.authenticate(context)
            guard !required.isDisjoint(with: Set(user.roles)) else {
                throw AuthzError("Caller lacks any of the required roles: \(roles.joined(separator: ", ")).")
            }
            return user
        }
    }
}
