import Foundation

/// The three error types every AXIAM SDK exposes (§2 of CONTRACT.md).
///
/// Additional context is carried as associated data, but the taxonomy is fixed to exactly
/// these three cases. Token strings never appear in any of these values (§2, §7).
public enum AxiamError: Error, Sendable {
    /// Authentication failure: wrong credentials, expired session, MFA failure,
    /// or a 401 on the refresh call itself.
    case auth(AuthError)
    /// Authorization failure: the caller is authenticated but lacks permission.
    case authz(AuthzError)
    /// Transport-level failure: connection refused, timeout, TLS error, DNS failure,
    /// malformed request, server (5xx) error.
    case network(NetworkError)
}

/// Authentication failure (§2). Carries a human-readable `message`.
public struct AuthError: Error, Sendable, CustomStringConvertible {
    public let message: String

    public init(_ message: String) {
        self.message = message
    }

    public var description: String { "AuthError: \(message)" }
}

/// Authorization failure (§2). Carries a `message` and, when the server provided them,
/// the denied `action` and `resourceID`.
public struct AuthzError: Error, Sendable, CustomStringConvertible {
    public let message: String
    public let action: String?
    public let resourceID: String?

    public init(_ message: String, action: String? = nil, resourceID: String? = nil) {
        self.message = message
        self.action = action
        self.resourceID = resourceID
    }

    public var description: String { "AuthzError: \(message)" }
}

/// Transport-level failure (§2). Carries the underlying transport error as `cause`
/// where one exists (connection refused, timeout, TLS handshake failure, DNS).
///
/// `@unchecked Sendable`: the only non-`Sendable`-typed field is `cause` (`any Error`), which is
/// set once at construction and never mutated; the struct is otherwise immutable.
public struct NetworkError: Error, @unchecked Sendable, CustomStringConvertible {
    public let message: String
    /// The underlying OS/transport error, when the failure originated below the HTTP layer.
    public let cause: (any Error)?
    /// The HTTP status code, when the failure was an HTTP error response.
    public let statusCode: Int?

    public init(_ message: String, cause: (any Error)? = nil, statusCode: Int? = nil) {
        self.message = message
        self.cause = cause
        self.statusCode = statusCode
    }

    public var description: String { "NetworkError: \(message)" }
}

// MARK: - HTTP status → error mapping (§2)

enum ErrorMapper {
    /// Maps an HTTP status code to the contract's error taxonomy (§2). Only called for
    /// non-2xx statuses. `body` is the (already-read) response body used to enrich
    /// `AuthzError` with `action`/`resource_id` when available.
    static func map(status: Int, message: String, action: String? = nil, resourceID: String? = nil) -> AxiamError {
        switch status {
        case 401:
            return .auth(AuthError(message))
        case 403, 409:
            return .authz(AuthzError(message, action: action, resourceID: resourceID))
        case 400, 408, 429:
            return .network(NetworkError(message, statusCode: status))
        default:
            // 5xx and any other unexpected status are transport-level per §2.
            return .network(NetworkError(message, statusCode: status))
        }
    }
}
