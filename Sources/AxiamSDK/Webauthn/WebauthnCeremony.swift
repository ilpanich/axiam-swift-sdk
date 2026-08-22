#if canImport(AuthenticationServices)
import AuthenticationServices
import Foundation

// CONTRACT.md §24.6b — the linked-API ceremony helpers.
//
// ONE helper set for both of this SDK's Apple platforms, not an iOS one and a macOS one:
// `ASAuthorizationPlatformPublicKeyCredentialProvider` and
// `ASAuthorizationSecurityKeyPublicKeyCredentialProvider` exist on both, and the
// presentation anchor is the only genuinely per-platform part — which is why the caller
// supplies it. The Linux build keeps the relying-party layer and §24.6a, compiled without
// the framework, and `webauthnCeremonySupported` answers `false` there rather than
// throwing (§24.6b rule 6).
//
// No software authenticator anywhere in this file (rule 2). Every credential comes from
// the platform.

/// Where the system should present the passkey sheet.
///
/// The one genuinely per-platform part of an otherwise shared implementation: a `UIWindow`
/// on iOS, an `NSWindow` on macOS. The SDK cannot pick one — it does not know which of an
/// application's windows is frontmost — so the caller supplies it.
@available(iOS 16.0, macOS 13.0, *)
public protocol WebauthnPresentationAnchorProviding: AnyObject, Sendable {
    /// The window to present the system sheet over.
    @MainActor func webauthnPresentationAnchor() -> ASPresentationAnchor
}

@available(iOS 16.0, macOS 13.0, *)
extension AxiamClient {

    /// Whether this runtime can run a ceremony (CONTRACT.md §24.6b rule 6).
    ///
    /// A **query, not an exception**: a caller hides the "Sign in with a passkey" button
    /// rather than offering one that throws. Always `false` on a build without
    /// `AuthenticationServices` — the whole of this file is absent there, and the
    /// non-conditional declaration in `WebauthnTypes.swift` answers.
    public nonisolated var webauthnCeremonySupported: Bool { true }

    /// Whether conditional mediation — passkey autofill — is available here
    /// (CONTRACT.md §24.6b rule 3).
    ///
    /// The probe **never throws** on a platform that lacks it; it answers `false`.
    public nonisolated var webauthnConditionalMediationSupported: Bool {
        if #available(iOS 16.0, macOS 13.5, *) { return true }
        return false
    }

    /// `webauthn_register` (CONTRACT.md §24.1) — the register pair with the ceremony
    /// between them, in one call.
    ///
    /// **Additive** (§24.6b rule 1): ``webauthnRegisterStart()`` and
    /// ``webauthnRegisterFinish(stateToken:credentialName:response:)`` stay public, because
    /// a caller running a virtual authenticator in a test, or holding a response produced
    /// on another device, needs the pieces.
    ///
    /// - Parameters:
    ///   - credentialName: the label to store the credential under.
    ///   - anchor: where to present the system sheet.
    ///   - attachment: which authenticator the user is reaching for (§24.6b rule 4). The
    ///     **one permitted addition** to the server's options, and only from this explicit
    ///     argument — the SDK never infers it and never defaults it.
    /// - Throws: ``WebauthnCeremonyError`` when the ceremony itself fails, and the ordinary
    ///   §2 taxonomy when the server does.
    @discardableResult
    public func webauthnRegister(
        credentialName: String,
        anchor: WebauthnPresentationAnchorProviding,
        attachment: WebauthnAttachment? = nil
    ) async throws -> WebauthnCredential {
        let challenge = try await webauthnRegisterStart()
        let response = try await WebauthnCeremony.performRegistration(
            requestJson: challenge.requestJson,
            anchor: anchor,
            attachment: attachment
        )
        return try await webauthnRegisterFinish(
            stateToken: challenge.stateToken,
            credentialName: credentialName,
            response: response
        )
    }

    /// `webauthn_login` (CONTRACT.md §24.1) — the second-factor authenticate pair, composed.
    ///
    /// Continues a ``login(email:password:)`` that answered `.mfaRequired`; pass `nil` to
    /// use the challenge token that login retained.
    @discardableResult
    public func webauthnLogin(
        challengeToken: Sensitive<String>? = nil,
        anchor: WebauthnPresentationAnchorProviding,
        attachment: WebauthnAttachment? = nil
    ) async throws -> WebauthnLoginResult {
        let challenge = try await webauthnAuthenticateStart(challengeToken: challengeToken)
        let response = try await WebauthnCeremony.performAssertion(
            requestJson: challenge.requestJson,
            anchor: anchor,
            attachment: attachment,
            conditional: false
        )
        return try await webauthnAuthenticateFinish(
            stateToken: challenge.stateToken,
            response: response
        )
    }

    /// `webauthn_discoverable_login` (CONTRACT.md §24.1) — the usernameless pair, composed.
    ///
    /// - Parameter conditional: run in **conditional mediation** (passkey autofill) mode
    ///   where the platform supports it (§24.6b rule 3). Degrades to the explicit prompt
    ///   where it does not. A conditional ceremony may never settle — the user simply may
    ///   not pick a passkey — so cancel the enclosing `Task` to abandon it; an abandoned
    ///   conditional ceremony surfaces as ``WebauthnFailure/cancelled``, **not** as an
    ///   authentication failure.
    @discardableResult
    public func webauthnDiscoverableLogin(
        workspace: WebauthnWorkspace? = nil,
        anchor: WebauthnPresentationAnchorProviding,
        attachment: WebauthnAttachment? = nil,
        conditional: Bool = false
    ) async throws -> WebauthnLoginResult {
        let challenge = try await webauthnDiscoverableStart(workspace: workspace)
        let response = try await WebauthnCeremony.performAssertion(
            requestJson: challenge.requestJson,
            anchor: anchor,
            attachment: attachment,
            conditional: conditional && webauthnConditionalMediationSupported
        )
        return try await webauthnDiscoverableFinish(
            stateToken: challenge.stateToken,
            response: response
        )
    }
}

// MARK: - The ceremony itself

/// Drives `AuthenticationServices` and re-assembles its typed result back into the
/// WebAuthn JSON response form (CONTRACT.md §24.6a rule 2), which is what `*_finish` takes.
///
/// Apple's API is the one row in §24.6's table that is neither string-in nor string-out: it
/// takes decoded fields and hands back decoded fields. The decode side reads the server's
/// options; the encode side rebuilds the response object with the base64url spelling the
/// server verifies against. Every buffer is re-encoded exactly as it came out of the
/// authenticator — the bytes are never reinterpreted, only spelled.
@available(iOS 16.0, macOS 13.0, *)
enum WebauthnCeremony {

    static func performRegistration(
        requestJson: String,
        anchor: WebauthnPresentationAnchorProviding,
        attachment: WebauthnAttachment?
    ) async throws -> String {
        let options = try CreationOptions(json: requestJson)

        var requests: [ASAuthorizationRequest] = []
        if attachment != .crossPlatform {
            let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
                relyingPartyIdentifier: options.rpID
            )
            let request = provider.createCredentialRegistrationRequest(
                challenge: options.challenge,
                name: options.userName,
                userID: options.userID
            )
            if let verification = options.userVerification {
                request.userVerificationPreference = .init(rawValue: verification)
            }
            if let attestation = options.attestation {
                request.attestationPreference = .init(rawValue: attestation)
            }
            requests.append(request)
        }
        if attachment != .platform {
            let provider = ASAuthorizationSecurityKeyPublicKeyCredentialProvider(
                relyingPartyIdentifier: options.rpID
            )
            let request = provider.createCredentialRegistrationRequest(
                challenge: options.challenge,
                displayName: options.userDisplayName,
                name: options.userName,
                userID: options.userID
            )
            request.credentialParameters = options.algorithms.map {
                ASAuthorizationPublicKeyCredentialParameters(algorithm: .init(rawValue: $0))
            }
            if let verification = options.userVerification {
                request.userVerificationPreference = .init(rawValue: verification)
            }
            if let attestation = options.attestation {
                request.attestationPreference = .init(rawValue: attestation)
            }
            requests.append(request)
        }

        let credential = try await run(requests: requests, anchor: anchor, conditional: false)
        guard let registration = credential as? ASAuthorizationPublicKeyCredentialRegistration else {
            throw WebauthnCeremonyError(.unknown)
        }

        return try encodeJSON([
            "id": base64URL(registration.credentialID),
            "rawId": base64URL(registration.credentialID),
            "type": "public-key",
            "response": [
                "clientDataJSON": base64URL(registration.rawClientDataJSON),
                "attestationObject": base64URL(registration.rawAttestationObject ?? Data()),
            ],
            "clientExtensionResults": [String: String](),
        ])
    }

    static func performAssertion(
        requestJson: String,
        anchor: WebauthnPresentationAnchorProviding,
        attachment: WebauthnAttachment?,
        conditional: Bool
    ) async throws -> String {
        let options = try RequestOptions(json: requestJson)

        var requests: [ASAuthorizationRequest] = []
        if attachment != .crossPlatform {
            let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
                relyingPartyIdentifier: options.rpID
            )
            let request = provider.createCredentialAssertionRequest(challenge: options.challenge)
            request.allowedCredentials = options.allowCredentials.map {
                ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: $0)
            }
            if let verification = options.userVerification {
                request.userVerificationPreference = .init(rawValue: verification)
            }
            requests.append(request)
        }
        if attachment != .platform {
            let provider = ASAuthorizationSecurityKeyPublicKeyCredentialProvider(
                relyingPartyIdentifier: options.rpID
            )
            let request = provider.createCredentialAssertionRequest(challenge: options.challenge)
            request.allowedCredentials = options.allowCredentials.map {
                ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor(
                    credentialID: $0,
                    transports: ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.Transport.allSupported
                )
            }
            if let verification = options.userVerification {
                request.userVerificationPreference = .init(rawValue: verification)
            }
            requests.append(request)
        }

        let credential = try await run(requests: requests, anchor: anchor, conditional: conditional)
        guard let assertion = credential as? ASAuthorizationPublicKeyCredentialAssertion else {
            throw WebauthnCeremonyError(.unknown)
        }

        var response: [String: Any] = [
            "clientDataJSON": base64URL(assertion.rawClientDataJSON),
            "authenticatorData": base64URL(assertion.rawAuthenticatorData),
            "signature": base64URL(assertion.signature),
        ]
        if !assertion.userID.isEmpty {
            response["userHandle"] = base64URL(assertion.userID)
        }

        return try encodeJSON([
            "id": base64URL(assertion.credentialID),
            "rawId": base64URL(assertion.credentialID),
            "type": "public-key",
            "response": response,
            "clientExtensionResults": [String: String](),
        ])
    }

    @MainActor
    private static func run(
        requests: [ASAuthorizationRequest],
        anchor: WebauthnPresentationAnchorProviding,
        conditional: Bool
    ) async throws -> ASAuthorizationCredential {
        guard !requests.isEmpty else { throw WebauthnCeremonyError(.unsupported) }

        let controller = ASAuthorizationController(authorizationRequests: requests)
        let delegate = CeremonyDelegate(anchor: anchor)
        controller.delegate = delegate
        controller.presentationContextProvider = delegate

        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                delegate.continuation = continuation
                if conditional, #available(iOS 16.0, macOS 13.5, *) {
                    controller.performAutoFillAssistedRequests()
                } else {
                    controller.performRequests()
                }
            }
        } onCancel: {
            // §24.6b rule 3: a conditional ceremony may never settle, so the caller must be
            // able to abandon it — and abandoning it is a cancellation, not an
            // authentication failure.
            Task { @MainActor in controller.cancel() }
        }
    }

    /// Maps a platform error to its canonical classification (§24.6b rule 5).
    static func classify(_ error: Error) -> WebauthnFailure {
        guard let authError = error as? ASAuthorizationError else { return .unknown }
        switch authError.code {
        case .canceled: return .cancelled
        case .failed, .invalidResponse: return .unknown
        case .notHandled, .notInteractive: return .unsupported
        default: return .unknown
        }
    }

    // MARK: - Option decoding

    /// The subset of `PublicKeyCredentialCreationOptions` Apple's API needs as fields.
    ///
    /// Reading is not re-encoding: nothing decoded here goes back to the server. The
    /// options travel to the authenticator through `AuthenticationServices`' own typed
    /// parameters, and §24.0's byte-preservation obligation binds the RESPONSE direction,
    /// which this file rebuilds from the authenticator's own buffers.
    private struct CreationOptions {
        let rpID: String
        let challenge: Data
        let userID: Data
        let userName: String
        let userDisplayName: String
        let userVerification: String?
        let attestation: String?
        let algorithms: [Int]

        init(json: String) throws {
            guard
                let root = try? JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any],
                let rp = root["rp"] as? [String: Any],
                let user = root["user"] as? [String: Any],
                let challengeString = root["challenge"] as? String,
                let challenge = WebauthnCeremony.decodeBase64URL(challengeString),
                let userIDString = user["id"] as? String,
                let userID = WebauthnCeremony.decodeBase64URL(userIDString),
                let userName = user["name"] as? String
            else {
                throw WebauthnCeremonyError(.unsupported)
            }
            // `rp.id` is optional in the spec — the browser defaults it to the origin. The
            // platform API needs one, so its absence is a ceremony this runtime cannot run
            // rather than a value the SDK may invent (§24.0).
            guard let rpID = rp["id"] as? String else { throw WebauthnCeremonyError(.unsupported) }

            self.rpID = rpID
            self.challenge = challenge
            self.userID = userID
            self.userName = userName
            self.userDisplayName = (user["displayName"] as? String) ?? userName
            self.userVerification =
                (root["authenticatorSelection"] as? [String: Any])?["userVerification"] as? String
            self.attestation = root["attestation"] as? String
            self.algorithms = ((root["pubKeyCredParams"] as? [[String: Any]]) ?? [])
                .compactMap { $0["alg"] as? Int }
        }
    }

    /// The subset of `PublicKeyCredentialRequestOptions` Apple's API needs as fields.
    private struct RequestOptions {
        let rpID: String
        let challenge: Data
        let allowCredentials: [Data]
        let userVerification: String?

        init(json: String) throws {
            guard
                let root = try? JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any],
                let rpID = root["rpId"] as? String,
                let challengeString = root["challenge"] as? String,
                let challenge = WebauthnCeremony.decodeBase64URL(challengeString)
            else {
                throw WebauthnCeremonyError(.unsupported)
            }
            self.rpID = rpID
            self.challenge = challenge
            self.allowCredentials = ((root["allowCredentials"] as? [[String: Any]]) ?? [])
                .compactMap { $0["id"] as? String }
                .compactMap { WebauthnCeremony.decodeBase64URL($0) }
            self.userVerification = root["userVerification"] as? String
        }
    }

    // MARK: - base64url

    static func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    static func decodeBase64URL(_ value: String) -> Data? {
        var padded = value.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while padded.count % 4 != 0 { padded += "=" }
        return Data(base64Encoded: padded)
    }

    private static func encodeJSON(_ object: [String: Any]) throws -> String {
        guard let data = try? JSONSerialization.data(withJSONObject: object) else {
            throw WebauthnCeremonyError(.unknown)
        }
        return String(decoding: data, as: UTF8.self)
    }
}

/// Bridges `ASAuthorizationController`'s delegate callbacks into the async continuation.
@available(iOS 16.0, macOS 13.0, *)
private final class CeremonyDelegate: NSObject,
    ASAuthorizationControllerDelegate,
    ASAuthorizationControllerPresentationContextProviding {

    var continuation: CheckedContinuation<ASAuthorizationCredential, Error>?
    private let anchor: WebauthnPresentationAnchorProviding
    /// Retains the delegate for the length of the ceremony: `ASAuthorizationController`
    /// holds its delegate weakly, and a deallocated one produces a callback that never
    /// arrives — a hang rather than an error.
    private var selfRetain: CeremonyDelegate?

    init(anchor: WebauthnPresentationAnchorProviding) {
        self.anchor = anchor
        super.init()
        selfRetain = self
    }

    func authorizationController(
        controller: ASAuthorizationController,
        didCompleteWithAuthorization authorization: ASAuthorization
    ) {
        continuation?.resume(returning: authorization.credential)
        continuation = nil
        selfRetain = nil
    }

    func authorizationController(
        controller: ASAuthorizationController,
        didCompleteWithError error: Error
    ) {
        continuation?.resume(
            throwing: WebauthnCeremonyError(WebauthnCeremony.classify(error), cause: error)
        )
        continuation = nil
        selfRetain = nil
    }

    @MainActor
    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        anchor.webauthnPresentationAnchor()
    }
}

#else

// The Linux build, and any other platform without AuthenticationServices. The relying-party
// layer and §24.6a's JSON bridge are fully present; §24.6b's helper is not — and
// `webauthnCeremonySupported` says so rather than throwing (§24.6b rule 6).
extension AxiamClient {
    /// Whether this runtime can run a ceremony (CONTRACT.md §24.6b rule 6).
    ///
    /// `false` here, and a **query rather than an exception**: a caller hides the
    /// "Sign in with a passkey" button instead of offering one that throws. Use
    /// ``webauthnDiscoverableStart(workspace:)`` with a ceremony run elsewhere.
    public nonisolated var webauthnCeremonySupported: Bool { false }

    /// Whether conditional mediation — passkey autofill — is available here
    /// (CONTRACT.md §24.6b rule 3). `false`, and never a throw.
    public nonisolated var webauthnConditionalMediationSupported: Bool { false }
}

#endif
