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
    /// Whether this is an **organization-level** principal (CONTRACT.md §5.2).
    ///
    /// Such a principal's record lives in its organization's reserved tenant, so its global
    /// grants apply in every tenant of that organization, and it can act on a different one
    /// by sending a different `X-Tenant-ID` on the next request — no re-login, because it
    /// already is a principal of every tenant there.
    ///
    /// An ordinary tenant principal is a principal of exactly one tenant; the same header
    /// change produces a `403` for it. This flag is therefore what an application checks
    /// *before* offering a tenant switch, rather than discovering the answer from a failed
    /// request.
    ///
    /// **Derived, never asserted** (§5.2 rule 2): resolved server-side from the caller's own
    /// tenant record, and never sent by this SDK. `false` when the login response omits it —
    /// which is what a server older than contract 1.31 answers — and `false` on the guard
    /// path, where this value is built from token claims that do not carry it. Both are the
    /// safe direction: the application then offers no cross-tenant action.
    public let organizationLevel: Bool

    public init(
        userID: String,
        tenantID: String,
        roles: [String] = [],
        username: String? = nil,
        email: String? = nil,
        organizationLevel: Bool = false
    ) {
        self.userID = userID
        self.tenantID = tenantID
        self.roles = roles
        self.username = username
        self.email = email
        self.organizationLevel = organizationLevel
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
    /// The tenant requires MFA and this account has no factor yet (CONTRACT.md §25.2
    /// rule 1). **Not a failure**: the server handed back a token to finish enrolment with,
    /// and there is no session until `mfaSetupConfirm` completes the login this interrupted.
    ///
    /// Pass `setupToken` to ``AxiamClient/mfaSetupEnroll(setupToken:)`` and then to
    /// ``AxiamClient/mfaSetupConfirm(setupToken:totpCode:)``. It is ``Sensitive`` because it
    /// is a bearer credential that completes a login (§25.3).
    ///
    /// > Important: this case gained its associated value in contract 1.28. A caller that
    /// > matched it exhaustively needs one line changed — the alternative was an SDK that
    /// > tells you enrolment is required and withholds the only thing that can complete it.
    case mfaSetupRequired(setupToken: Sensitive<String>)
}

/// Outcome of a single authorization check (§1: `checkAccess`, `batchCheck`).
public struct AccessResult: Sendable, Equatable {
    /// Whether the checked action is permitted.
    ///
    /// **This property alone carries the outcome.** ``reasonCode`` explains it and never
    /// contradicts it.
    public let allowed: Bool

    /// The server's human-readable explanation, when it sent one.
    public let reason: String?

    /// Machine-readable decision reason (CONTRACT.md §11 rule 9, B1 deny-override):
    /// ``ReasonCode/allowed``, ``ReasonCode/noGrant`` or ``ReasonCode/deniedByRule``.
    ///
    /// **The two refusals mean opposite things to the person on the other end.**
    /// `no_grant` says *ask an admin for access*; `denied_by_rule` says *an admin has
    /// already decided*. An application that cannot tell them apart sends users to raise
    /// tickets that will be refused — which is why the contract forbids collapsing them
    /// into a bare `false`.
    ///
    /// `nil` when the server omits the field: a newer SDK against an older server treats
    /// it as absent, never as an error. An unrecognised value is surfaced verbatim and
    /// never changes ``allowed`` — which is why this is a `String` rather than an enum, so
    /// a code this SDK has never heard of still reaches the caller intact.
    public let reasonCode: String?

    public init(allowed: Bool, reason: String? = nil, reasonCode: String? = nil) {
        self.allowed = allowed
        self.reason = reason
        self.reasonCode = reasonCode
    }
}

/// The three `reason_code` values CONTRACT.md §11 rule 9 defines.
///
/// A caseless enum of constants rather than a `String`-backed `enum` with cases, so an
/// unrecognised server value is still a valid ``AccessResult/reasonCode`` and reaches the
/// caller — a backed enum's failable init would force the SDK to drop what it cannot name.
public enum ReasonCode {
    /// An allow grant matched and no deny did.
    public static let allowed = "allowed"

    /// Nothing matched — default deny. *Ask an admin for access.*
    public static let noGrant = "no_grant"

    /// An explicit deny rule matched and overrode any allow. *An admin has already decided.*
    public static let deniedByRule = "denied_by_rule"
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
    // §5.2. Optional here rather than defaulted at the decoder, so "absent" and "false"
    // stay distinguishable at this layer; `toUser()` collapses them, in that direction.
    let organization_level: Bool?
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
    /// B1 deny-override decision reason (CONTRACT.md §11 rule 9). Optional so an older
    /// server that omits it still decodes.
    let reason_code: String?
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
