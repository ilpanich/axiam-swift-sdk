import Foundation

// CONTRACT.md §24 — WebAuthn / passkeys.
//
// The relying-party layer and §24.6a's JSON bridge live here; §24.6b's linked-API
// ceremony helper lives in `WebauthnCeremony.swift`, compiled only where
// `AuthenticationServices` exists. Both halves are public: §24.6b rule 1 forbids making a
// composed helper the only way to reach the six wire operations, because a caller running
// a virtual authenticator in a test, or holding a response produced on another device,
// needs the pieces.

/// A started ceremony: the server's options plus the token binding a response to them
/// (CONTRACT.md §24.1).
public struct WebauthnChallenge: Sendable {
    /// The server's options, exactly as they arrived — a `{"publicKey": {…}}` object
    /// carrying base64url buffers.
    ///
    /// Held as the **raw JSON bytes** rather than a decoded model: §24.0 requires the SDK
    /// to hand these onward unchanged, and a decode/re-encode round trip through
    /// `JSONSerialization` is exactly the transformation that rule forbids. Use
    /// ``requestJson`` for the string a platform API takes, or ``challengeObject()`` when
    /// you genuinely need to inspect a field.
    public let challengeData: Data

    /// Binds the authenticator's answer to this challenge.
    ///
    /// A bearer credential for the length of the ceremony — one that leaks inside that
    /// window is a ceremony an attacker can try to complete — so it is ``Sensitive``
    /// (§24.5). It is **opaque**: this SDK never decodes it, and neither should a caller.
    public let stateToken: Sensitive<String>

    init(challengeData: Data, stateToken: Sensitive<String>) {
        self.challengeData = challengeData
        self.stateToken = stateToken
    }

    /// The challenge in the JSON form every platform authenticator API takes
    /// (§24.6a rule 1).
    ///
    /// This is the string a browser passes to
    /// `PublicKeyCredential.parseCreationOptionsFromJSON()` and an Android app passes to
    /// `CreatePublicKeyCredentialRequest`. It is the inner options object: the `publicKey`
    /// wrapper belongs to the DOM's `CredentialCreationOptions`, and the platform JSON
    /// APIs do not want it.
    ///
    /// Pure local computation, no I/O. Nothing is defaulted, dropped or reordered on the
    /// way through (§24.0).
    public var requestJson: String {
        guard
            let root = try? JSONSerialization.jsonObject(with: challengeData) as? [String: Any],
            let options = root["publicKey"],
            let inner = try? JSONSerialization.data(withJSONObject: options)
        else {
            return String(decoding: challengeData, as: UTF8.self)
        }
        return String(decoding: inner, as: UTF8.self)
    }

    /// The options decoded into a dictionary, for a caller that needs to read a field.
    ///
    /// Reading is fine; **sending the result back through a re-encode is not** (§24.0).
    /// Returns `nil` when the body is not a JSON object.
    public func challengeObject() -> [String: Any]? {
        try? JSONSerialization.jsonObject(with: challengeData) as? [String: Any]
    }
}

/// A credential the user just enrolled — the `201` body of `register/finish`
/// (CONTRACT.md §24.1).
public struct WebauthnCredential: Sendable, Equatable {
    /// This credential's AXIAM id, for a later delete.
    public let id: String
    /// The authenticator's own base64url credential id.
    public let credentialID: String
    /// The label it was stored under.
    public let name: String
    /// `passkey` or `security_key`, as the server classified it.
    public let credentialType: String
    /// RFC 3339 timestamp.
    public let createdAt: String
    /// RFC 3339 timestamp, or `nil` for a credential never used.
    public let lastUsedAt: String?
}

/// A completed authentication ceremony (CONTRACT.md §24.3).
///
/// The tokens are also adopted by the client that produced this value — the server sets
/// the `axiam_access` / `axiam_refresh` / `axiam_csrf` cookie triple alongside them — so a
/// caller who only wants to be signed in can ignore every property here.
public struct WebauthnLoginResult: Sendable {
    /// The new access token (§24.5).
    public let accessToken: Sensitive<String>
    /// The new refresh token (§24.5).
    public let refreshToken: Sensitive<String>
    /// The session this ceremony established.
    public let sessionID: String
    /// The access token's lifetime in seconds.
    public let expiresIn: Int
}

/// The workspace a usernameless ceremony runs in (CONTRACT.md §24.1).
///
/// `discoverable/start` is the one WebAuthn endpoint that carries the workspace
/// explicitly, because a usernameless ceremony has no prior step to have minted a token
/// that names it. Unlike the five `/oauth2` operations of §12.1 rule 2 it **accepts
/// slugs**, so a slug-only client can run it.
///
/// Pass `nil` to ``AxiamClient/webauthnDiscoverableStart(workspace:)`` to have it filled
/// from the client's own configured identity, which is what almost every caller wants.
public struct WebauthnWorkspace: Sendable, Equatable {
    /// An organization override, in UUID form.
    public var orgID: String?
    /// An organization override, in slug form.
    public var orgSlug: String?
    /// A tenant override, in UUID form.
    public var tenantID: String?
    /// A tenant override, in slug form.
    public var tenantSlug: String?

    public init(
        orgID: String? = nil,
        orgSlug: String? = nil,
        tenantID: String? = nil,
        tenantSlug: String? = nil
    ) {
        self.orgID = orgID
        self.orgSlug = orgSlug
        self.tenantID = tenantID
        self.tenantSlug = tenantSlug
    }
}

/// Which authenticator the user is reaching for (CONTRACT.md §24.6b rule 4).
///
/// **The one permitted addition to the server's options** (§24.0), and only from an
/// explicit caller argument: it is a hint, and without it a user who asked for a security
/// key is prompted for the platform's built-in biometric instead. The SDK never infers it
/// and never defaults it.
public enum WebauthnAttachment: String, Sendable, Equatable {
    /// The device's own authenticator — Touch ID, Face ID, a Secure Enclave passkey.
    case platform
    /// A roaming authenticator — a USB/NFC security key.
    case crossPlatform = "cross-platform"
}

/// A ceremony failure a caller can say something useful about (CONTRACT.md §24.6b rule 5).
///
/// Every platform reports a ceremony failure as one opaque type whose only
/// machine-readable part is a name, and translating that once beats translating it in
/// every caller. This SDK exposes the classification on **every** build, including Linux
/// where no ceremony helper exists: an application relaying a browser's `DOMException`
/// name to a Swift service has the same five outcomes.
public enum WebauthnFailure: String, Sendable, Equatable {
    /// Covers **both** an explicit refusal and a silent timeout.
    ///
    /// The WebAuthn spec deliberately refuses to distinguish them, because telling a
    /// website which one happened leaks whether an authenticator was present. It must not
    /// be recovered by timing the call, and user-facing copy must not accuse the user of
    /// cancelling.
    case cancelled

    /// The authenticator already holds a credential for this account and refused to
    /// silently mint a second — the exclusion list working, not a failure. The only
    /// classification whose remedy is "use a different device".
    case alreadyRegistered = "already_registered"

    /// An explicitly aborted ceremony.
    case timeout

    /// This device or browser cannot run the ceremony.
    case unsupported

    /// Everything else.
    case unknown

    /// Map a platform ceremony error name to its canonical classification.
    ///
    /// Anything unrecognised is ``unknown`` rather than a throw — a classifier that can
    /// fail is one more thing for an error handler to handle.
    public static func classify(_ name: String?) -> WebauthnFailure {
        switch (name ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "notallowederror", "canceled", "cancelled": return .cancelled
        case "invalidstateerror": return .alreadyRegistered
        case "aborterror", "timeout": return .timeout
        case "notsupportederror", "securityerror": return .unsupported
        default: return .unknown
        }
    }

    /// Copy for this failure, safe to show a user.
    public var message: String {
        switch self {
        case .cancelled:
            return "The request was cancelled or timed out. You can try again."
        case .alreadyRegistered:
            return "This device is already registered on your account. "
                + "Try a different device, or remove the existing one first."
        case .timeout:
            return "The request timed out before it completed. Please try again."
        case .unsupported:
            return "This browser or device cannot be used for passkeys. "
                + "Try a different browser, or use another sign-in method."
        case .unknown:
            return "Something went wrong. Please try again."
        }
    }
}

/// A ceremony that did not complete (CONTRACT.md §24.6b rule 5).
///
/// Thrown only by the §24.6b linked-API helpers. The relying-party operations raise the
/// ordinary §2 taxonomy, because their failures come from the server rather than from the
/// authenticator.
public struct WebauthnCeremonyError: Error, Sendable, CustomStringConvertible {
    /// The canonical classification.
    public let failure: WebauthnFailure
    /// The platform's own error, when there was one.
    public let cause: Error?

    init(_ failure: WebauthnFailure, cause: Error? = nil) {
        self.failure = failure
        self.cause = cause
    }

    public var description: String { failure.message }
}
