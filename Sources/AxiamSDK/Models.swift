import Foundation

// MARK: - Public result types

/// An authenticated AXIAM identity.
///
/// Produced both by a successful `login`/`verifyMfa` (from the login response) and by the
/// resource-server guard (from verified JWT claims). `roles` is populated from token claims
/// in the guard path and is empty on the login path (the login response does not carry roles).
public struct AxiamUser: Sendable, Equatable {
    public let userID: String
    public let tenantID: String
    public let roles: [String]
    public let username: String?
    public let email: String?

    public init(
        userID: String,
        tenantID: String,
        roles: [String] = [],
        username: String? = nil,
        email: String? = nil
    ) {
        self.userID = userID
        self.tenantID = tenantID
        self.roles = roles
        self.username = username
        self.email = email
    }
}

/// Outcome of `login` (§1). Tokens are delivered out-of-band via `httpOnly` cookies, so no
/// token material appears here.
public enum LoginResult: Sendable, Equatable {
    /// Login succeeded with no MFA step required. The session cookies are now set.
    case authenticated(AxiamUser)
    /// The account requires a second factor. Call `verifyMfa(_:)` with the TOTP code.
    /// `availableMethods` lists the offered factors (e.g. `["totp"]`). The challenge token
    /// is retained internally (as `Sensitive`) and never surfaced here.
    case mfaRequired(availableMethods: [String])
    /// The account must complete MFA enrolment before it can authenticate.
    case mfaSetupRequired
}

/// Outcome of a single authorization check (§1: `checkAccess`, `batchCheck`).
public struct AccessResult: Sendable, Equatable {
    public let allowed: Bool
    public let reason: String?

    public init(allowed: Bool, reason: String? = nil) {
        self.allowed = allowed
        self.reason = reason
    }
}

/// A single entry in a `batchCheck` request (§1).
public struct AccessCheck: Sendable, Equatable {
    public let action: String
    public let resource: String
    public let scope: String?
    public let subjectID: String?

    public init(action: String, resource: String, scope: String? = nil, subjectID: String? = nil) {
        self.action = action
        self.resource = resource
        self.scope = scope
        self.subjectID = subjectID
    }
}

// MARK: - Wire DTOs (internal)

struct LoginRequest: Encodable {
    let username_or_email: String
    let password: String
    let tenant_id: String?
    let tenant_slug: String?
    let org_id: String?
    let org_slug: String?
}

struct LoginUserInfo: Decodable {
    let id: String
    let username: String
    let email: String
    let tenant_id: String
    let tenant_slug: String?
    let org_slug: String?
}

struct LoginSuccessResponse: Decodable {
    let session_id: String
    let expires_in: Int
    let user: LoginUserInfo
}

struct MfaRequiredResponse: Decodable {
    let mfa_required: Bool
    let challenge_token: String
    let available_methods: [String]
}

struct MfaSetupRequiredResponse: Decodable {
    let mfa_setup_required: Bool
    let setup_token: String
}

struct MfaVerifyRequest: Encodable {
    let challenge_token: String
    let totp_code: String
}

struct RefreshRequest: Encodable {
    let tenant_id: String
    let org_id: String
}

struct CheckAccessBody: Encodable {
    let action: String
    let resource_id: String
    let scope: String?
    let subject_id: String?
}

struct CheckAccessResponse: Decodable {
    let allowed: Bool
    let reason: String?
}

struct BatchCheckAccessBody: Encodable {
    let checks: [CheckAccessBody]
}

struct BatchCheckAccessResponse: Decodable {
    let results: [CheckAccessResponse]
}

/// Shape of AXIAM's standardized JSON error body: `{ "error": ..., "message": ... }`.
struct ErrorBody: Decodable {
    let error: String?
    let message: String?
    let action: String?
    let resource_id: String?
}
