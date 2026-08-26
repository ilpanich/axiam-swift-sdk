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
///
/// When the failure came from an OAuth2 endpoint that answered an `OAuth2ErrorResponse` body —
/// currently only the §20 UMA ticket grant — ``oauthError`` carries the machine-readable code and
/// ``oauthErrorDescription`` the server's text. The contract models that as an `OAuthProtocolError`
/// *sub-type of* `AuthError`; Swift structs cannot be subclassed, so an `AuthError` that carries
/// the code is this SDK's rendering of it, and the §2 taxonomy stays at exactly three cases.
///
/// Both are `nil` for every other authentication failure, so a caller that ignores them sees the
/// same `AuthError` it always did.
public struct AuthError: Error, Sendable, CustomStringConvertible {
    public let message: String
    /// The `error` field of an `OAuth2ErrorResponse` — e.g. `invalid_grant`, `access_denied`.
    ///
    /// Dispatch on this rather than on the HTTP status: §20.4 puts `access_denied` on a `403`
    /// where RFC 8628's is a `400`, and the code is what stays correct if either moves.
    public let oauthError: String?
    /// The `error_description` field, when the server sent one.
    public let oauthErrorDescription: String?

    public init(_ message: String, oauthError: String? = nil, oauthErrorDescription: String? = nil) {
        self.message = message
        self.oauthError = oauthError
        self.oauthErrorDescription = oauthErrorDescription
    }

    public var description: String { "AuthError: \(message)" }
}

/// Authorization failure (§2). Carries a `message` and, when the server provided them,
/// the denied `action` and `resourceID`.
public struct AuthzError: Error, Sendable, CustomStringConvertible {
    public let message: String
    public let action: String?
    public let resourceID: String?
    /// A formatted `WWW-Authenticate: UMA` value (§20.3), present only when the guard was
    /// configured with a ``UmaChallenger`` and minting succeeded. A framework adapter should copy
    /// it onto the 403 it already returns; one that ignores it emits exactly the 403 it always did.
    ///
    /// Deliberately NOT part of ``description``: the value carries a live permission ticket, and a
    /// credential in a log line is a credential in a log line, 60-second life or not (§20.6).
    public let challenge: String?
    /// Which §27.4 rule 7 sub-type this is, on the management surface only.
    ///
    /// Rule 7 describes `NotFoundError` (404) and `ConflictError` (409) as sub-types OF
    /// `AuthzError`. Swift's §2 taxonomy is an enum over three structs and a struct cannot be
    /// subclassed, so the sub-type is carried here — the same accommodation this file already
    /// makes for `OAuthProtocolError` on ``AuthError``.
    ///
    /// The property rule 7 asks for survives it: a `catch AxiamError.authz` written before §27
    /// existed still catches both, which is precisely why 404 belongs under authorization at
    /// all. `nil` for every failure that is not one of those two.
    public let managementFailure: ManagementFailure?

    public init(
        _ message: String,
        action: String? = nil,
        resourceID: String? = nil,
        challenge: String? = nil,
        managementFailure: ManagementFailure? = nil
    ) {
        self.message = message
        self.action = action
        self.resourceID = resourceID
        self.challenge = challenge
        self.managementFailure = managementFailure
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
    /// `true` when this is §27.4 rule 7's `ValidationError` — a `400` or `422` from the
    /// management surface.
    ///
    /// Rule 7 puts that sub-type under `NetworkError`, inherited from §2's own `400` row, and
    /// that placement has one consequence worth naming: §16 retries `NetworkError`. So the
    /// management request path checks this flag and does not retry — a body the server has
    /// already rejected must not be sent three times.
    public let isValidation: Bool

    public init(
        _ message: String,
        cause: (any Error)? = nil,
        statusCode: Int? = nil,
        isValidation: Bool = false
    ) {
        self.message = message
        self.cause = cause
        self.statusCode = statusCode
        self.isValidation = isValidation
    }

    public var description: String { "NetworkError: \(message)" }
}

// MARK: - HTTP status → error mapping (§2)

enum ErrorMapper {
    /// The §27.4 rule 7 mapping, which REFINES `map(status:...)` rather than replacing it.
    ///
    /// Every status keeps the case §2 already gave it — 404 and 409 stay `.authz`, 400 and 422
    /// stay `.network` — and gains a discriminator saying which sub-type it is. An SDK that
    /// moved a status to a different case here would break `catch` blocks written against §2.
    ///
    /// 404 is the one worth reading twice. §2 has no row for it; rule 7 puts it under
    /// authorization because AXIAM answers 404 for an object in another tenant precisely so a
    /// probing caller cannot distinguish "does not exist" from "exists, not yours".
    static func mapManagement(
        status: Int,
        message: String,
        action: String? = nil,
        resourceID: String? = nil
    ) -> AxiamError {
        switch status {
        case 404:
            return .authz(AuthzError(
                message, action: action, resourceID: resourceID, managementFailure: .notFound))
        case 409:
            return .authz(AuthzError(
                message, action: action, resourceID: resourceID, managementFailure: .conflict))
        case 400, 422:
            return .network(NetworkError(message, statusCode: status, isValidation: true))
        default:
            return map(status: status, message: message, action: action, resourceID: resourceID)
        }
    }

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
