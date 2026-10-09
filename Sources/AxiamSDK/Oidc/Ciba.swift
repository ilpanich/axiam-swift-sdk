import Foundation
import Crypto
import _CryptoExtras

// CONTRACT.md §33 — CIBA, client-initiated backchannel authentication (contract 1.58; CIBA
// Core 1.0, poll and ping modes).
//
// A client that already knows whom it wants to authenticate asks AXIAM to authenticate that
// user ON ANOTHER DEVICE; AXIAM notifies the user, who approves or refuses on the console. The
// client then collects the tokens at the token endpoint — by polling, or once after AXIAM
// pings it. Four operations on `AxiamClient`:
//
// | Operation          | What it does                                                         |
// |--------------------|----------------------------------------------------------------------|
// | `cibaInitiate`     | `POST /oauth2/bc-authorize`. NEVER retried.                          |
// | `cibaPoll`         | one token request with `grant_type=urn:openid:params:grant-type:ciba` |
// | `cibaAwait`        | polls to a terminal outcome, honouring `interval` and `slow_down`    |
// | `cibaHandlePing`   | checks a ping's bearer and returns its `auth_req_id`; no I/O         |
//
// Two things a caller must not read into a success:
//
// - A successful `cibaInitiate` proves nothing about the user (§33.3 rule 4). AXIAM answers a
//   hint that names nobody, a locked user and a real one identically, and the only signal
//   that a user did not answer is `expired_token`.
// - A ping says the request was DECIDED, never how (§33.2). Call `cibaPoll` after answering
//   the ping; the outcome — tokens, `access_denied` or `expired_token` — comes from the token
//   endpoint.
//
// The client always authenticates, by the credential this SDK already uses at
// `/oauth2/token`: `client_secret_post` (`AxiamConfig.oidcClientSecret`), or the §6.1 client
// certificate for a `tls_client_auth` client (then `client_id` only). A client with neither is
// refused locally. `auth_req_id`, `client_notification_token`, the signing key and the signed
// `request` are `Sensitive` (§33.5).

// MARK: - Request and response types

/// Whom to authenticate: **exactly one** hint (§33.2). A sum type, so sending both, or neither,
/// cannot be written. `login_hint_token` is deliberately not offered (§33.3 rule 3).
public enum CibaUserHint: Sendable, Equatable {
    /// A username, then an e-mail address, within the tenant. Personal data: never logged.
    case loginHint(String)
    /// An ID token this deployment issued to this client.
    case idTokenHint(String)
}

/// How the client receives the outcome, as it registered (`backchannel_token_delivery_mode`).
public enum CibaDelivery: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    /// The client polls the token endpoint (`cibaAwait`).
    case poll
    /// AXIAM pings the client's registered notification endpoint, presenting this token as a
    /// bearer; the client then polls once. Keep the token to check the ping with
    /// ``AxiamClient/cibaHandlePing(headers:body:expectedToken:)``. Required, and non-empty.
    case ping(clientNotificationToken: Sensitive<String>)

    public var description: String {
        switch self {
        case .poll: return "poll"
        case .ping: return "ping(clientNotificationToken: [SENSITIVE])"
        }
    }

    public var debugDescription: String { description }
}

/// The algorithms a signed CIBA request may use (§33.2) — the client's registered
/// `backchannel_authentication_request_signing_alg`.
public enum CibaSigningAlgorithm: String, Sendable, CaseIterable {
    /// RSASSA-PSS with SHA-256 (an RSA key of 2048 bits or more).
    case ps256 = "PS256"
    /// ECDSA on P-256 with SHA-256.
    case es256 = "ES256"
    /// Ed25519.
    case edDSA = "EdDSA"
}

/// The key and algorithm for the signed request form (§33.2, CIBA Core §7.1.1).
///
/// **Both are the caller's**: there is no default for either, and the SDK signs under exactly
/// the algorithm given — the one the client registered. A key that cannot sign under that
/// algorithm is refused at construction, before any request (the constructor probe-signs).
///
/// The key material is held ``Sensitive``; ``description`` names the algorithm and key id,
/// never the key.
public struct CibaRequestSigner: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    /// The algorithm every request is signed under.
    public let algorithm: CibaSigningAlgorithm
    /// The `kid` put in the JWS header, when the client's JWKS needs one to pick the key.
    public let keyID: String?
    /// The normalised private key: the Ed25519 seed, the P-256 scalar, or the RSA key's DER.
    private let keyMaterial: Sensitive<Data>

    /// A signer from a PEM private key and the algorithm it signs under.
    ///
    /// - Parameters:
    ///   - algorithm: the client's registered signing algorithm.
    ///   - privateKeyPEM: a PKCS#8 PEM private key — Ed25519 for `EdDSA`, P-256 (PKCS#8 or
    ///     SEC 1) for `ES256`, RSA (PKCS#1 or PKCS#8, 2048 bits or more) for `PS256`.
    ///   - keyID: the JWS `kid`, or `nil`.
    /// - Throws: a local ``NetworkError`` with ``NetworkError/isValidation`` set when the PEM
    ///   is not a private key, or not one that signs under `algorithm`. Nothing is sent.
    public init(
        algorithm: CibaSigningAlgorithm,
        privateKeyPEM: Sensitive<String>,
        keyID: String? = nil
    ) throws {
        let refusal = ManagementChecks.refusal(
            "cibaInitiate",
            "signing_key: the key is not a private key that signs under \(algorithm.rawValue) "
                + "(CONTRACT.md §33.2)")
        let pem = privateKeyPEM.wrapped
        let material: Data
        switch algorithm {
        case .edDSA:
            guard let seed = Self.ed25519Seed(fromPKCS8PEM: pem) else { throw refusal }
            material = seed
        case .es256:
            guard let key = try? P256.Signing.PrivateKey(pemRepresentation: pem) else {
                throw refusal
            }
            material = key.rawRepresentation
        case .ps256:
            guard let key = try? _RSA.Signing.PrivateKey(pemRepresentation: pem) else {
                throw refusal
            }
            material = key.derRepresentation
        }
        self.algorithm = algorithm
        self.keyID = keyID
        self.keyMaterial = Sensitive(material)
        // A key that parses is not yet a key for this algorithm: prove it signs.
        guard (try? sign(Data("axiam-ciba-probe".utf8))) != nil else { throw refusal }
    }

    /// The JWS signature over `input` (the ASCII `header.payload`), in the JOSE encoding:
    /// raw for Ed25519, `r || s` for ES256, the RSA signature for PS256.
    func sign(_ input: Data) throws -> Data {
        let material = keyMaterial.wrapped
        switch algorithm {
        case .edDSA:
            let key = try Curve25519.Signing.PrivateKey(rawRepresentation: material)
            return try key.signature(for: input)
        case .es256:
            let key = try P256.Signing.PrivateKey(rawRepresentation: material)
            return try key.signature(for: input).rawRepresentation
        case .ps256:
            let key = try _RSA.Signing.PrivateKey(derRepresentation: material)
            return try key.signature(for: input, padding: .PSS).rawRepresentation
        }
    }

    /// The 32-byte seed of a PKCS#8 Ed25519 private key (RFC 8410 §7): a fixed 16-byte
    /// prefix and the seed.
    static func ed25519Seed(fromPKCS8PEM pem: String) -> Data? {
        let body = pem
            .components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.hasPrefix("-----") }
            .joined()
        guard !body.isEmpty, let der = Data(base64Encoded: body) else { return nil }
        let prefix: [UInt8] = [
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
            0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
        ]
        let bytes = [UInt8](der)
        guard bytes.count == prefix.count + 32, Array(bytes.prefix(prefix.count)) == prefix else {
            return nil
        }
        return Data(bytes.suffix(32))
    }

    public var description: String {
        "CibaRequestSigner(algorithm: \(algorithm.rawValue), keyID: \(keyID ?? "nil"), "
            + "key: [SENSITIVE])"
    }

    public var debugDescription: String { description }
}

/// What ``AxiamClient/cibaInitiate(_:tenantID:configuration:)`` sends (§33.2
/// `CibaInitiateRequest`). Exactly the members set are sent.
///
/// `bindingMessage` and the login hint can be personal data: the SDK never logs them, and
/// ``description`` names neither. `user_code`, `login_hint_token` and `request_uri` are not
/// members — AXIAM refuses each (§33.3 rule 3).
public struct CibaInitiateRequest: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    /// Space-separated; must include `openid`.
    public var scope: String
    /// Whom to authenticate.
    public var hint: CibaUserHint
    /// Shown to the user on the approval page — what lets them tell the request they started
    /// from one an attacker did. Required for a `fapi2` client.
    public var bindingMessage: String?
    /// The requested lifetime in seconds, 30 – 600 (absent: 300). Sent as a string on the form
    /// and as a number inside a signed request. Not pre-validated (§33.3 rule 5).
    public var requestedExpiry: Int?
    /// Space-separated authentication context classes.
    public var acrValues: String?
    /// RFC 8707 resource indicator.
    public var resource: String?
    /// Poll or ping, as registered.
    public var delivery: CibaDelivery
    /// Set: the request is sent as one signed JWT (`request`) beside the client
    /// authentication and nothing else — required of a client that registered a signing
    /// algorithm, refused from one that did not.
    public var signer: CibaRequestSigner?

    public init(
        scope: String,
        hint: CibaUserHint,
        bindingMessage: String? = nil,
        requestedExpiry: Int? = nil,
        acrValues: String? = nil,
        resource: String? = nil,
        delivery: CibaDelivery = .poll,
        signer: CibaRequestSigner? = nil
    ) {
        self.scope = scope
        self.hint = hint
        self.bindingMessage = bindingMessage
        self.requestedExpiry = requestedExpiry
        self.acrValues = acrValues
        self.resource = resource
        self.delivery = delivery
        self.signer = signer
    }

    /// The authentication-request members, exactly those set, as form strings.
    func members() -> [String: String] {
        var out = ["scope": scope]
        switch hint {
        case .loginHint(let value): out["login_hint"] = value
        case .idTokenHint(let value): out["id_token_hint"] = value
        }
        if let bindingMessage { out["binding_message"] = bindingMessage }
        if let requestedExpiry { out["requested_expiry"] = String(requestedExpiry) }
        if let acrValues { out["acr_values"] = acrValues }
        if let resource { out["resource"] = resource }
        if case .ping(let token) = delivery { out["client_notification_token"] = token.wrapped }
        return out
    }

    public var description: String {
        let hintKind: String
        switch hint {
        case .loginHint: hintKind = "loginHint"
        case .idTokenHint: hintKind = "idTokenHint"
        }
        return "CibaInitiateRequest(scope: \(scope), hint: \(hintKind), delivery: \(delivery), "
            + "signed: \(signer.map { $0.algorithm.rawValue } ?? "no"))"
    }

    public var debugDescription: String { description }
}

/// `CibaInitiateResponse` (§33.2), plus the moment it was received.
public struct CibaInitiateResponse: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    /// The request's id at the token endpoint — a bearer credential for the grant (§33.5).
    /// Never parse or length-check it.
    public let authReqID: Sensitive<String>
    /// The request's lifetime in seconds — authoritative (§33.7 rule 4).
    public let expiresIn: Int
    /// The minimum seconds between token requests: the response's value, or 5 when it was
    /// absent or zero (§33.7 rule 2).
    public let interval: Int
    /// When the response was received; ``AxiamClient/cibaAwait(_:tenantID:configuration:clock:)``'s
    /// deadline is this plus ``expiresIn``.
    public let receivedAt: Date

    public init(authReqID: Sensitive<String>, expiresIn: Int, interval: Int, receivedAt: Date) {
        self.authReqID = authReqID
        self.expiresIn = expiresIn
        self.interval = interval
        self.receivedAt = receivedAt
    }

    public var description: String {
        "CibaInitiateResponse(authReqID: [SENSITIVE], expiresIn: \(expiresIn), "
            + "interval: \(interval))"
    }

    public var debugDescription: String { description }
}

/// The clock ``AxiamClient/cibaAwait(_:tenantID:configuration:clock:)`` waits on — injectable
/// so its schedule is testable without sleeping (§33.8 tests 6 and 7).
public protocol CibaClock: Sendable {
    /// The current instant.
    func now() -> Date
    /// Wait `seconds`.
    func sleep(seconds: Int) async throws
}

/// The real clock: `Date()` and `Task.sleep`.
public struct SystemCibaClock: CibaClock {
    public init() {}

    public func now() -> Date { Date() }

    public func sleep(seconds: Int) async throws {
        try await Task.sleep(nanoseconds: UInt64(max(seconds, 0)) * 1_000_000_000)
    }
}

struct CibaInitiateResponseWire: Decodable {
    let auth_req_id: String
    let expires_in: Int
    let interval: Int?
}

// MARK: - The four operations

extension AxiamClient {

    /// `grant_type` of the CIBA token request (CIBA Core §10.1).
    static let cibaGrantType = "urn:openid:params:grant-type:ciba"

    /// The interval used when the initiate response carries none (§33.7 rule 2).
    static let cibaDefaultIntervalSeconds = 5

    /// Seconds added to the interval per `slow_down`, permanently (§33.7 rule 3).
    static let cibaSlowDownIncrementSeconds = 5

    /// The lifetime of a signed request this SDK mints: five minutes, inside the server's
    /// sixty-minute bound on `exp − nbf` (§33.2).
    static let cibaSignedRequestLifetimeSeconds = 300

    /// `POST /oauth2/bc-authorize` (CIBA Core §7, CONTRACT.md §33.1) — ask AXIAM to
    /// authenticate a user on another device.
    ///
    /// `tenant_id` goes in the query, never the body; the client authenticates as it does at
    /// `/oauth2/token`. On an mTLS client the `mtls_endpoint_aliases` entry is preferred
    /// (§21.3 rule 2); a document that publishes no `backchannel_authentication_endpoint` means
    /// the server does not support CIBA, and the SDK never builds the URL itself.
    ///
    /// **Never retried** — not on a transport error, a `5xx` or a `429` (§33.7 rule 1): every
    /// accepted call stores a request and may notify a person. On a lost answer, let it expire
    /// and ask again deliberately.
    ///
    /// **A success proves nothing about the user** (§33.3 rule 4): AXIAM answers a hint naming
    /// nobody exactly like a real one, and the only signal that a user did not answer is
    /// `expired_token`.
    ///
    /// - Throws: a local ``AuthError`` when the client has no credential (no request sent); a
    ///   local ``NetworkError`` with ``NetworkError/isValidation`` set for a ping-mode request
    ///   without a `client_notification_token`; the server's refusals as an ``AuthError``
    ///   carrying ``AuthError/oauthError`` at any status — `invalid_binding_message` with its
    ///   ``AuthError/oauthErrorDescription``, and a `429`'s `rate_limit_exceeded` too.
    public func cibaInitiate(
        _ request: CibaInitiateRequest,
        tenantID: String? = nil,
        configuration: OidcConfiguration? = nil
    ) async throws -> CibaInitiateResponse {
        try ensureOpen()
        var form = try cibaClientAuthentication("cibaInitiate")
        if case .ping(let token) = request.delivery, token.wrapped.isEmpty {
            throw ManagementChecks.refusal(
                "cibaInitiate",
                "a ping-mode request needs a non-empty client_notification_token: without one "
                    + "AXIAM has nothing to ping with (CONTRACT.md §33.2)")
        }
        let document = try await oidcConfiguration(configuration)
        guard let endpoint = try preferredEndpoint(
            document, { $0.backchannelAuthenticationEndpoint },
            document.backchannelAuthenticationEndpoint)
        else {
            throw AxiamError.auth(AuthError(
                "the discovery document advertises no backchannel_authentication_endpoint: "
                    + "this server does not support CIBA (CONTRACT.md §33.1)"))
        }
        let url = try oidcTenantScopedURL(endpoint, tenantID: tenantID)

        if let signer = request.signer {
            // §33.2 signed form: the client authentication and `request`, nothing else.
            let signed = try Self.cibaSignedRequest(
                request, signer: signer, clientID: form["client_id"] ?? "",
                audience: document.issuer, now: Date())
            form["request"] = signed.wrapped
        } else {
            for (key, value) in request.members() { form[key] = value }
        }

        let response = try await bareSend(
            operation: "ciba_initiate",
            pathTemplate: "/oauth2/bc-authorize",
            method: .post,
            url: url,
            headers: [
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("Accept", "application/json"),
            ],
            body: Data(Self.oidcFormEncode(form).utf8),
            retry: .never)
        let receivedAt = Date()
        guard (200..<300).contains(response.status) else { throw oidcMapGrantError(response) }
        let wire = try oidcDecode(CibaInitiateResponseWire.self, response.body, "CIBA initiation")
        let interval: Int
        if let given = wire.interval, given > 0 {
            interval = given
        } else {
            interval = Self.cibaDefaultIntervalSeconds
        }
        return CibaInitiateResponse(
            authReqID: Sensitive(wire.auth_req_id),
            expiresIn: wire.expires_in,
            interval: interval,
            receivedAt: receivedAt)
    }

    /// `POST /oauth2/token` with `grant_type=urn:openid:params:grant-type:ciba` (CIBA Core
    /// §10.1, CONTRACT.md §33.1) — **one** token request.
    ///
    /// The answers of §33.3 rule 6 surface as an ``AuthError`` carrying
    /// ``AuthError/oauthError``: `authorization_pending` and `slow_down` (non-terminal),
    /// `access_denied` and `expired_token` (terminal and distinct —
    /// ``AxiamError/isAccessDenied``, ``AxiamError/isExpiredToken``), `invalid_grant`. None is
    /// retried. A transport failure, `5xx`, `408` or bodiless `429` is retried per §16 within
    /// the call; another `4xx` is not. Any `id_token` is validated per §12.4 (no nonce).
    ///
    /// **Store the returned tokens before anything else**: a request is redeemed once, and a
    /// second `cibaPoll` for it is `invalid_grant` (§33.7 rule 7).
    public func cibaPoll(
        authReqID: Sensitive<String>,
        tenantID: String? = nil,
        configuration: OidcConfiguration? = nil
    ) async throws -> OidcTokenSet {
        try ensureOpen()
        var form = try cibaClientAuthentication("cibaPoll")
        let document = try await oidcConfiguration(configuration)
        let endpoint = try preferredEndpoint(
            document, { $0.tokenEndpoint }, required: document.tokenEndpoint)
        let url = try oidcTenantScopedURL(endpoint, tenantID: tenantID)
        form["grant_type"] = Self.cibaGrantType
        form["auth_req_id"] = authReqID.wrapped

        let response = try await bareSend(
            operation: "ciba_poll",
            pathTemplate: "/oauth2/token",
            method: .post,
            url: url,
            headers: [
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("Accept", "application/json"),
            ],
            body: Data(Self.oidcFormEncode(form).utf8),
            retry: .section16UnlessOAuthError)
        guard (200..<300).contains(response.status) else { throw oidcMapGrantError(response) }
        // §33.7 rule 7: the 200 is consumed before anything else — and never re-requested: the
        // server may already have redeemed the request.
        let wire = try oidcDecode(TokenResponseWire.self, response.body, "CIBA token response")
        return try await oidcTokenSet(wire, document: document, expectedNonce: nil)
    }

    /// Poll for `initiated`'s outcome until it is decided or expires (§33.1, §33.7). Surfaces
    /// nothing to the user — AXIAM notified them.
    ///
    /// - The first poll waits one `interval`; polling earlier only earns `slow_down`.
    /// - `slow_down` adds 5 s to the interval, cumulatively and permanently;
    ///   `authorization_pending` never lowers it.
    /// - A transport failure, `5xx` or `429` that outlived §16 is not terminal: the loop waits
    ///   the interval and polls again.
    /// - Polling stops at `receivedAt + expiresIn`, even if the server has not said
    ///   `expired_token`; the same `expired_token` outcome is then raised locally.
    ///
    /// Returns the token set **without adopting it** as this client's credential — the
    /// posture of `deviceLogin` and `loginClientCredentials`.
    ///
    /// **Ping mode** does not loop: call ``cibaPoll(authReqID:tenantID:configuration:)`` once
    /// from the handler that received the ping (``cibaHandlePing(headers:body:expectedToken:)``),
    /// and fall back to this loop only once half of `expiresIn` has passed without a ping
    /// (§33.7 rule 6).
    public func cibaAwait(
        _ initiated: CibaInitiateResponse,
        tenantID: String? = nil,
        configuration: OidcConfiguration? = nil,
        clock: any CibaClock = SystemCibaClock()
    ) async throws -> OidcTokenSet {
        let document = try await oidcConfiguration(configuration)
        let deadline = initiated.receivedAt.addingTimeInterval(TimeInterval(initiated.expiresIn))
        var interval = initiated.interval > 0 ? initiated.interval : Self.cibaDefaultIntervalSeconds

        while true {
            // §33.7 rule 4: it is the NEXT attempt that must fall inside the deadline.
            if clock.now().addingTimeInterval(TimeInterval(interval)) >= deadline {
                throw AxiamError.auth(AuthError(
                    "expired_token: the CIBA request expired before it was decided (client-side "
                        + "deadline from expires_in; CONTRACT.md §33.7 rule 4)",
                    oauthError: "expired_token"))
            }
            try await clock.sleep(seconds: interval)
            do {
                return try await cibaPoll(
                    authReqID: initiated.authReqID, tenantID: tenantID, configuration: document)
            } catch let error as AxiamError {
                switch Self.cibaStep(error) {
                case .pending, .transient:
                    continue
                case .slowDown:
                    interval += Self.cibaSlowDownIncrementSeconds
                case .terminal:
                    throw error
                }
            }
        }
    }

    /// Check a ping AXIAM delivered to your notification endpoint and return the
    /// `auth_req_id` it names (CIBA Core §10.2, CONTRACT.md §33.1). **No I/O, synchronous.**
    ///
    /// 1. Exactly one `Authorization` header (name matched case-insensitively): the scheme
    ///    `Bearer` in any case, one space, and `expectedToken` — compared in constant time.
    ///    Anything else is an ``AuthError`` whose message names no value.
    /// 2. The body is a JSON object with a non-empty string `auth_req_id`; other members are
    ///    ignored. Anything else is a local ``NetworkError`` with
    ///    ``NetworkError/isValidation`` set.
    ///
    /// It neither answers the HTTP request nor calls the token endpoint: answer `204` as soon
    /// as this returns, **then** call ``cibaPoll(authReqID:tenantID:configuration:)`` — AXIAM
    /// retries a ping that is not answered quickly. Nor does it check that the `auth_req_id`
    /// is one you issued: the token endpoint answers `invalid_grant` for any other.
    ///
    /// - Parameters:
    ///   - headers: the request's headers as `(name, value)` pairs, duplicates kept.
    ///   - body: the request's raw body.
    ///   - expectedToken: the `client_notification_token` the initiating request carried.
    public nonisolated func cibaHandlePing(
        headers: [(String, String)],
        body: Data,
        expectedToken: Sensitive<String>
    ) throws -> Sensitive<String> {
        let refused = AxiamError.auth(AuthError(
            "CIBA ping refused: the Authorization header is not the expected bearer "
                + "(CONTRACT.md §33.1)"))
        let values = headers.filter { $0.0.lowercased() == "authorization" }.map { $0.1 }
        guard values.count == 1, let value = values.first,
              let space = value.firstIndex(of: " ")
        else {
            throw refused
        }
        let scheme = value[value.startIndex..<space]
        let token = value[value.index(after: space)...]
        guard scheme.lowercased() == "bearer", !token.isEmpty else { throw refused }
        let expected = expectedToken.wrapped
        guard !expected.isEmpty,
              ConstantTime.equals(Array(token.utf8), Array(expected.utf8))
        else {
            throw refused
        }

        guard let parsed = try? JSONDecoder().decode(ManagementJSON.self, from: body),
              case .object(let members) = parsed,
              case .some(.string(let authReqID)) = members["auth_req_id"],
              !authReqID.isEmpty
        else {
            throw ManagementChecks.refusal(
                "cibaHandlePing",
                "the ping body is not a JSON object carrying a non-empty auth_req_id string")
        }
        return Sensitive(authReqID)
    }

    // MARK: - Internals

    /// What one poll answer means for the ``cibaAwait(_:tenantID:configuration:clock:)`` loop
    /// (§33.3 rule 6, §33.7).
    enum CibaStep: Equatable {
        /// `authorization_pending` — keep polling at the current interval.
        case pending
        /// `slow_down` — add 5 s to the interval, for good.
        case slowDown
        /// A transport failure, `5xx`, `408` or `429` that outlived §16 — wait one interval.
        case transient
        /// Anything else is the answer.
        case terminal
    }

    static func cibaStep(_ error: AxiamError) -> CibaStep {
        switch error {
        case .auth(let auth):
            switch auth.oauthError {
            case "authorization_pending"?: return .pending
            case "slow_down"?: return .slowDown
            // §33.3 rule 13: a 429's `rate_limit_exceeded` is never terminal for a poll.
            case "rate_limit_exceeded"?: return .transient
            default: return .terminal
            }
        case .network(let network):
            guard let status = network.statusCode else { return .transient }
            return status >= 500 || status == 408 || status == 429 ? .transient : .terminal
        case .authz:
            return .terminal
        }
    }

    /// The client's credential for the CIBA calls: `client_secret_post`, or — for a
    /// `tls_client_auth` client — `client_id` alone, the certificate being the credential.
    /// A CIBA client is never public (§33.3 rule 1), so neither is a local ``AuthError``.
    func cibaClientAuthentication(_ operation: String) throws -> [String: String] {
        let clientID = try requireOidcClientID()
        if let secret = config.oidcClientSecret, !secret.wrapped.isEmpty {
            return ["client_id": clientID, "client_secret": secret.wrapped]
        }
        guard presentsClientCertificate else {
            throw AxiamError.auth(AuthError(
                "\(operation) requires client authentication: a CIBA client is never public — "
                    + "construct the client with oidcClientSecret or a §6.1 client certificate "
                    + "(CONTRACT.md §33.1). No request was sent."))
        }
        return ["client_id": clientID]
    }

    /// The CIBA Core §7.1.1 signed request: every member inside the JWT (`requested_expiry` as
    /// a NUMBER), plus `iss` = the client id, `aud` = the issuer, `iat` = `nbf` = now,
    /// `exp` = now + 300 and a fresh 128-bit `jti`.
    static func cibaSignedRequest(
        _ request: CibaInitiateRequest,
        signer: CibaRequestSigner,
        clientID: String,
        audience: String,
        now: Date
    ) throws -> Sensitive<String> {
        let issuedAt = Int(now.timeIntervalSince1970)
        var claims: [String: ManagementJSON] = [:]
        for (key, value) in request.members() { claims[key] = .string(value) }
        if let requestedExpiry = request.requestedExpiry {
            claims["requested_expiry"] = .int(requestedExpiry)
        }
        claims["iss"] = .string(clientID)
        claims["aud"] = .string(audience)
        claims["iat"] = .int(issuedAt)
        claims["nbf"] = .int(issuedAt)
        claims["exp"] = .int(issuedAt + cibaSignedRequestLifetimeSeconds)
        claims["jti"] = .string(randomJTI())

        var header: [String: ManagementJSON] = ["alg": .string(signer.algorithm.rawValue)]
        if let keyID = signer.keyID { header["kid"] = .string(keyID) }

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let input: String
        let signature: Data
        do {
            let headerPart = Base64URL.encode(try encoder.encode(ManagementJSON.object(header)))
            let payloadPart = Base64URL.encode(try encoder.encode(ManagementJSON.object(claims)))
            input = headerPart + "." + payloadPart
            signature = try signer.sign(Data(input.utf8))
        } catch {
            throw ManagementChecks.refusal(
                "cibaInitiate", "signing_key: the signed request could not be signed")
        }
        return Sensitive(input + "." + Base64URL.encode(signature))
    }

    /// 128 bits from the system CSPRNG, as 32 lower-case hex digits.
    static func randomJTI() -> String {
        let digits = Array("0123456789abcdef")
        var generator = SystemRandomNumberGenerator()
        var out = ""
        for _ in 0..<16 {
            let byte = UInt8.random(in: 0...255, using: &generator)
            out.append(digits[Int(byte >> 4)])
            out.append(digits[Int(byte & 0x0f)])
        }
        return out
    }
}
