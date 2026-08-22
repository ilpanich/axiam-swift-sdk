import Foundation

// CONTRACT.md §25 — account lifecycle and MFA enrolment.

/// A TOTP factor offered but not yet active (CONTRACT.md §25.1).
///
/// **Both halves are ``Sensitive``, and the second one is why.** The `otpauth://` URI
/// *contains* the secret: wrapping the bare secret and then logging the URI leaks exactly
/// the same bytes (§25.3).
public struct MfaEnrollment: Sendable {
    /// The shared TOTP secret. Anyone holding it can generate valid codes for this account
    /// indefinitely.
    public let secretBase32: Sensitive<String>
    /// `otpauth://totp/…?secret=<secretBase32>` — the string an authenticator app scans
    /// out of a QR code.
    public let totpURI: Sensitive<String>
}

/// The OPAQUE policy for the account a reset token belongs to (CONTRACT.md §25.1).
public struct PasswordResetContext: Sendable {
    /// The tenant's §23 parameters when it has OPAQUE enabled, and `nil` when it does not
    /// — in which case the plaintext path is allowed.
    ///
    /// Held as raw JSON: the block is forwarded to the §23 helpers untouched, and this SDK
    /// does not model, validate or re-encode it. Use ``opaqueObject()`` to read a field.
    public let opaqueData: Data?

    init(opaqueData: Data?) {
        self.opaqueData = opaqueData
    }

    /// Whether the tenant this token belongs to has OPAQUE enabled.
    public var hasOpaquePolicy: Bool { opaqueData != nil }

    /// The policy decoded into a dictionary, for a caller that needs to read a field.
    public func opaqueObject() -> [String: Any]? {
        guard let opaqueData else { return nil }
        return try? JSONSerialization.jsonObject(with: opaqueData) as? [String: Any]
    }
}

/// Arguments to ``AxiamClient/requestPasswordReset(_:)`` (CONTRACT.md §25.1).
///
/// The workspace fields are all optional: unset, they are filled from the client's own
/// configured identity, which is what almost every caller wants.
public struct PasswordResetRequest: Sendable, Equatable {
    /// The address to send the reset mail to.
    public var email: String
    /// An organization override, in slug form.
    public var orgSlug: String?
    /// A tenant override, in UUID form.
    public var tenantID: String?
    /// A tenant override, in slug form.
    public var tenantSlug: String?

    public init(
        email: String,
        orgSlug: String? = nil,
        tenantID: String? = nil,
        tenantSlug: String? = nil
    ) {
        self.email = email
        self.orgSlug = orgSlug
        self.tenantID = tenantID
        self.tenantSlug = tenantSlug
    }
}

/// Arguments to ``AxiamClient/confirmPasswordReset(_:)`` (CONTRACT.md §25.1).
public struct PasswordResetConfirmation: Sendable {
    /// The single-use token from the reset mail.
    public var token: Sensitive<String>
    /// The replacement password.
    public var newPassword: Sensitive<String>
    /// The tenant the account belongs to.
    ///
    /// A **body** field: this is not an `/oauth2` endpoint, so §12.1 rule 2's
    /// query-parameter convention does not reach it.
    public var tenantID: String
    /// The §23 registration record, as raw JSON, for a tenant whose
    /// ``AxiamClient/passwordResetContext(token:)`` reported an OPAQUE policy. `nil` on
    /// the plaintext path.
    public var opaqueData: Data?

    public init(
        token: Sensitive<String>,
        newPassword: Sensitive<String>,
        tenantID: String,
        opaqueData: Data? = nil
    ) {
        self.token = token
        self.newPassword = newPassword
        self.tenantID = tenantID
        self.opaqueData = opaqueData
    }

    /// Convenience for the common case: the token and password arrive as plain strings out
    /// of a mail link and a form field, and wrapping them is the caller's first act.
    public init(
        token: String,
        newPassword: String,
        tenantID: String,
        opaqueData: Data? = nil
    ) {
        self.init(
            token: Sensitive(token),
            newPassword: Sensitive(newPassword),
            tenantID: tenantID,
            opaqueData: opaqueData
        )
    }
}
