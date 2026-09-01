import Foundation

// The §12 relying-party value types, plus the §12.7, §14 and §15 results that share them.
//
// §12.3 rule 2 decides which fields are wrapped: `access_token`, `refresh_token`, `id_token`,
// `client_secret` and `code_verifier` are `Sensitive`; `state` and `nonce` are not — they are
// correlation values a caller must be able to compare and store in its own session.

/// The OIDC discovery document (§12.1), read from `/.well-known/openid-configuration`.
///
/// `issuer` is the **authoritative** issuer for the §12.4 rule 3 check. The server derives it
/// from its own configuration, so behind a proxy it may legitimately differ from the base URL
/// the document was fetched from, and §12.3 rule 6 forbids rejecting a document over that
/// mismatch. Endpoints are likewise read from here rather than concatenated onto the issuer.
public struct OidcConfiguration: Sendable, Decodable, Equatable {
    public let issuer: String
    public let authorizationEndpoint: String
    public let tokenEndpoint: String
    public let jwksURI: String
    public let introspectionEndpoint: String?
    public let revocationEndpoint: String?
    public let endSessionEndpoint: String?
    public let deviceAuthorizationEndpoint: String?
    /// RFC 9126 pushed authorization request endpoint, used by `oidcPar` (§26.1).
    ///
    /// `nil` when the server does not implement PAR. Its absence is an error at call time,
    /// never a cue to build the URL by concatenation — and for a FAPI 2.0 client it is fatal
    /// rather than a fallback, since §21.1 refuses a `fapi2` registration that does not set
    /// `require_par`.
    public let pushedAuthorizationRequestEndpoint: String?
    public let scopesSupported: [String]?
    public let responseTypesSupported: [String]?
    public let idTokenSigningAlgValuesSupported: [String]?

    enum CodingKeys: String, CodingKey {
        case issuer
        case authorizationEndpoint = "authorization_endpoint"
        case tokenEndpoint = "token_endpoint"
        case jwksURI = "jwks_uri"
        case introspectionEndpoint = "introspection_endpoint"
        case revocationEndpoint = "revocation_endpoint"
        case endSessionEndpoint = "end_session_endpoint"
        case deviceAuthorizationEndpoint = "device_authorization_endpoint"
        case pushedAuthorizationRequestEndpoint = "pushed_authorization_request_endpoint"
        case scopesSupported = "scopes_supported"
        case responseTypesSupported = "response_types_supported"
        case idTokenSigningAlgValuesSupported = "id_token_signing_alg_values_supported"
    }
}

/// What `oidcBegin` returns (§12.1): everything the caller needs to start the redirect and,
/// later, to finish it.
///
/// **The caller owns all three correlation values** (§12.3 rule 1). This SDK stores none of
/// them — not in the client, not in a global, not in an implicit cache — so `state`, `nonce`
/// and `codeVerifier` must be persisted by the application (typically in its own HTTP session)
/// and handed back to `oidcExchange`.
public struct AuthorizationRequest: Sendable {
    /// The URL to redirect the user agent to.
    public let url: String
    /// CSRF correlation value. Not a secret (§12.3 rule 2) — the caller compares it on return.
    public let state: String
    /// Replay-protection value, checked into the ID token by the server and asserted by
    /// §12.4 rule 6. Not a secret, for the same reason.
    public let nonce: String
    /// The PKCE verifier whose challenge went out in the URL (§12.5 secret).
    public let codeVerifier: Sensitive<String>
}

/// The validated claims of an ID token (§12.4).
///
/// Present only when the response carried an `id_token`, and only after every rule in §12.4
/// passed — §12.4 rule 7 makes validation all-or-nothing, so a token set is either returned
/// whole and verified or not at all.
public struct IdTokenClaims: Sendable, Equatable {
    public let subject: String
    public let issuer: String
    public let audience: [String]
    public let expiresAt: Date
    public let issuedAt: Date
    public let nonce: String?
    public let authorizedParty: String?
    public let email: String?
    public let preferredUsername: String?
    public let tenantID: String?
    public let roles: [String]
}

/// The result of every §12 token-endpoint grant (§12.1).
public struct OidcTokenSet: Sendable {
    public let accessToken: Sensitive<String>
    public let tokenType: String
    public let expiresIn: Int
    public let scope: String?
    public let refreshToken: Sensitive<String>?
    public let idToken: Sensitive<String>?
    /// The validated claims of ``idToken``, when one was issued (§12.3 rule 5: a relying
    /// party's claims come from here, never from `/oauth2/userinfo`).
    public let idClaims: IdTokenClaims?
}

/// RFC 7662 introspection result (§12.1).
///
/// `active` is the only field guaranteed present: an inactive token answers `{"active":false}`
/// and nothing else, which is the point of the endpoint.
public struct IntrospectionResult: Sendable, Equatable {
    public let active: Bool
    public let scope: String?
    public let clientID: String?
    public let username: String?
    public let tokenType: String?
    public let expiresAt: Int?
    public let issuedAt: Int?
    public let subject: String?
    public let audience: String?
    public let issuer: String?
    public let jwtID: String?
}

/// `POST /api/v1/auth/federation/oidc/start` (§12.1) — where to send the user agent for
/// upstream-IdP federation, and the single-use `state` that ties the callback to it.
///
/// There is no `nonce` here, and that is the server's design: it keeps the federation nonce
/// server-side (§12.1 note 7), so an SDK has nothing to store and nothing to check.
public struct SsoStartResult: Sendable, Equatable {
    public let authorizeURL: String
    public let state: String
    public let expiresInSecs: Int
}

/// `POST /api/v1/auth/federation/oidc/callback` (§12.1) — the completed federation login.
///
/// Carries **no token material**: the session arrives as `Set-Cookie` and lands in the §4
/// cookie jar (§12.1 note 6). A client without a persistent cookie store silently loses it.
public struct SsoCompleteResult: Sendable, Equatable {
    public let userID: String
    public let sessionID: String
    public let expiresIn: Int
    public let redirectURI: String?
}

/// A verified back-channel logout token (§12.7.3).
///
/// **Never collapsed to a bare boolean**, per §12.7.3: the relying party has to know *which*
/// session to end. When ``sid`` is present the RP MUST end that session only — falling back to
/// "every session for `sub`" is an over-reach the server itself refuses to make.
///
/// ``jti`` is surfaced so the RP can deduplicate. This SDK deliberately does not dedup
/// internally: delivery is at-least-once, so a valid token legitimately arrives twice, and a
/// library with no durable store would silently drop a real second logout after a restart.
public struct VerifiedLogoutToken: Sendable, Equatable {
    public let sid: String?
    public let subject: String?
    public let jwtID: String?
    public let issuer: String
    public let issuedAt: Date
}

/// `POST /oauth2/device_authorization` (§14.1) — the codes a device shows its user.
///
/// ``verificationURIComplete`` embeds the user code so a device that can render a QR code does
/// not make the user type anything. It is surfaced when the server sends it and **never
/// synthesised by concatenation** when it does not (§14.3): its format is the server's to
/// choose.
public struct DeviceAuthorization: Sendable, Equatable {
    /// The device code — a bearer-shaped credential the device redeems (§14.5).
    public let deviceCode: Sensitive<String>
    /// The code the *user* types. Not a secret: it is meant to be displayed.
    public let userCode: String
    public let verificationURI: String
    public let verificationURIComplete: String?
    /// Seconds until the whole grant expires. Polling stops here (§14.2 rule 4).
    public let expiresIn: Int
    /// Seconds between polls, from the server (§14.2 rule 2). Absent means 5 s.
    public let interval: Int
}

/// `POST /oauth2/token` with the RFC 8693 grant (§15.1) — a *narrower* token.
///
/// There is no refresh token here, and §15.2 makes that structural rather than incidental: an
/// exchange only ever narrows, and a refresh token would let the holder re-widen later.
public struct ExchangedToken: Sendable {
    public let accessToken: Sensitive<String>
    public let issuedTokenType: String
    public let tokenType: String
    public let expiresIn: Int
    /// The scopes actually granted. Read it: §15.2 requires the server to answer with what the
    /// caller got, which may be narrower than what it asked for.
    public let scope: String?
}

// MARK: - Wire shapes (internal)

struct TokenResponseWire: Decodable {
    let access_token: String
    let token_type: String
    let expires_in: Int
    let scope: String?
    let refresh_token: String?
    let id_token: String?
}

struct IntrospectionWire: Decodable {
    let active: Bool
    let scope: String?
    let client_id: String?
    let username: String?
    let token_type: String?
    let exp: Int?
    let iat: Int?
    let sub: String?
    let aud: String?
    let iss: String?
    let jti: String?
}

struct SsoStartWire: Decodable {
    let authorize_url: String
    let state: String
    let expires_in_secs: Int
}

struct SsoCompleteWire: Decodable {
    let user_id: String
    let session_id: String
    let expires_in: Int
    let redirect_uri: String?
}

struct DeviceAuthorizationWire: Decodable {
    let device_code: String
    let user_code: String
    let verification_uri: String
    let verification_uri_complete: String?
    let expires_in: Int
    let interval: Int?
}

struct TokenExchangeWire: Decodable {
    let access_token: String
    let issued_token_type: String
    let token_type: String
    let expires_in: Int
    let scope: String?
}


/// The result of `oidcPar` (CONTRACT.md §26.1).
///
/// The server answered **201** — RFC 9126 §2.2 specifies Created, and a success predicate
/// written `== 200` would treat every successful push as a failure.
///
/// ``state``, ``nonce`` and ``codeVerifier`` are carried straight through from the
/// ``AuthorizationRequest`` that was pushed: §26.2 rule 1 forbids a second generator, and
/// rule 6 wants exactly one verifier so there is no second place for the two to disagree.
public struct PushedAuthorizationRequest: Sendable {
    /// Where to redirect the user agent.
    ///
    /// Carries **exactly** `client_id` and `request_uri` — the server refuses a request that
    /// mixes a `request_uri` with inline authorization parameters rather than merging them,
    /// because merging is where parameter confusion lives (§26.2 rule 2).
    public let url: String

    /// The opaque, single-use handle.
    ///
    /// ``Sensitive`` per §26.5: between the push and the redirect it is a bearer handle to a
    /// fully-formed authorization request, and a log line is the wrong place for it to sit
    /// for the length of that window.
    public let requestURI: Sensitive<String>

    /// The handle's lifetime in seconds; not advisory (§26.2 rule 3).
    public let expiresIn: Int

    /// The value to compare against the `state` the IdP returns.
    public let state: String

    /// The value that must equal the ID token's `nonce` claim.
    public let nonce: String

    /// The PKCE verifier to pass into `oidcExchange` — the same one `oidcBegin` produced.
    public let codeVerifier: Sensitive<String>
}

struct PushedAuthorizationResponseWire: Decodable {
    let request_uri: String
    let expires_in: Int
}

// MARK: - §12.1 login providers (contract 1.37; rule 12a added at 1.38)

/// One sign-in button, from `GET /api/v1/auth/federation/providers` (§12.1).
///
/// Carries exactly what a button needs and nothing more. There is no `client_id`, no
/// `metadata_url`, no endpoint URL and no secret in this shape — the server builds it as a
/// dedicated unauthenticated response rather than narrowing the admin one, so a field added
/// to the admin response cannot reach here by inheritance (§12.1 note 9).
public struct FederationProvider: Sendable, Equatable {
    /// Config id, echoed back to whichever start operation ``protocol`` selects.
    public let id: String

    /// Which provider this is, for the button's branding (`google`, `github`, `generic_oidc`, …).
    ///
    /// **Not** what selects the start operation — ``protocol`` is (§12.1 note 10). A
    /// `generic_oauth2` config and a `google` one can both speak plain OAuth2, and a `google`
    /// one need not.
    public let providerKind: String

    /// The operator's display name for the provider.
    public let displayName: String

    /// `OidcConnect`, `Saml` or `OAuth2` — selects which start operation to call
    /// (§12.1 note 10): ``AxiamClient/ssoStart(federationConfigID:redirectURI:)``,
    /// the SAML login endpoint, and
    /// ``AxiamClient/ssoStartOauth2(federationConfigID:redirectURI:)`` respectively.
    ///
    /// Deliberately a `String` and not an enum: the server may add a protocol, and a closed
    /// enum would fail to decode the whole list over one provider a client does not yet
    /// understand. Compare against ``protocolOidcConnect``, ``protocolOAuth2`` and
    /// ``protocolSaml``, and treat anything else as "cannot start this one here".
    public let `protocol`: String

    /// Whether AXIAM ships this provider's own sign-in mark.
    ///
    /// `true` for the branded kinds, whose buttons must use it; `false` for the generic kinds,
    /// whose buttons read "Sign in with *displayName*" and use ``buttonIcon`` when the
    /// operator uploaded one.
    public let hasBundledMark: Bool

    /// The operator's uploaded button icon as a bounded raster `data:` URL, or `nil`.
    ///
    /// Absent for most providers, and branding rather than configuration — which is why it is
    /// the one additional field this unauthenticated response carries.
    public let buttonIcon: String?

    /// `true` when the provider is inherited from the organization (§12.1 note 13).
    ///
    /// Not needed to sign in. Resolution is entirely server-side: an SDK passes the workspace
    /// and the ``id`` it was handed and never computes inheritance itself.
    public let inherited: Bool

    public init(
        id: String,
        providerKind: String,
        displayName: String,
        protocol federationProtocol: String,
        hasBundledMark: Bool,
        buttonIcon: String?,
        inherited: Bool
    ) {
        self.id = id
        self.providerKind = providerKind
        self.displayName = displayName
        self.`protocol` = federationProtocol
        self.hasBundledMark = hasBundledMark
        self.buttonIcon = buttonIcon
        self.inherited = inherited
    }
}

extension FederationProvider {
    /// ``protocol`` value selecting ``AxiamClient/ssoStart(federationConfigID:redirectURI:)``.
    public static let protocolOidcConnect = "OidcConnect"

    /// ``protocol`` value selecting ``AxiamClient/ssoStartOauth2(federationConfigID:redirectURI:)``.
    public static let protocolOAuth2 = "OAuth2"

    /// ``protocol`` value selecting the SAML login endpoint, which is **not** a §12 vocabulary
    /// operation and therefore has no method on this client.
    public static let protocolSaml = "Saml"
}

/// The handoff mechanism's two constants (§12.1 note 12).
///
/// SAML and Apple's `response_mode=form_post` return **cross-site**, so the server cannot set
/// `SameSite=Strict` cookies on that response. It redirects the browser to the SPA callback
/// with ``queryParameter`` carrying a 256-bit code, which
/// ``AxiamClient/ssoCompleteHandoff(code:)`` redeems from the same origin.
public enum FederationHandoff {
    /// The query parameter the code arrives in on the SPA's callback route.
    public static let queryParameter = "axiam_handoff"

    /// How long the code stays redeemable. Single-use: unknown, expired and already-redeemed
    /// all answer the same `401`, deliberately, and a failed redemption is never retried.
    public static let codeTTLSeconds = 60
}

struct PublicFederationProviderWire: Decodable {
    let id: String
    let provider_kind: String
    let display_name: String
    let `protocol`: String
    let has_bundled_mark: Bool
    let button_icon: String?
    let inherited: Bool
}

struct PublicFederationProvidersWire: Decodable {
    let providers: [PublicFederationProviderWire]
}
