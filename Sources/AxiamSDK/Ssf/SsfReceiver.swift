import Foundation
import Crypto

// CONTRACT.md §32.7 — the SSF receiver helper (contract 1.56).
//
// AXIAM is a Shared Signals Framework transmitter: it sends CAEP and RISC security events as
// Security Event Tokens (RFC 8417) to the relying parties a tenant administrator registered
// (the §27 `ssf` namespace, `client.ssf`). This file is for the RELYING PARTY that receives
// them — a different audience from that namespace:
//
// - `SsfReceiver.verifySet(_:)` verifies one compact SET — pushed to your endpoint (RFC 8935)
//   or returned by a poll — in the contract's fixed order, and refuses at the first failure
//   with an `AuthError` whose `setFailureReason` names the step;
// - `SsfReceiver.poll(streamID:options:)` calls the stream's RFC 8936 poll endpoint, verifies
//   every returned SET, and hands back the verified and the refused apart.
//
// Neither transmits, signs or registers anything, and neither trusts a key it did not fetch
// from the configured JWKS: no `jwk` or `x5c` header member is honoured (§32.9).

/// The six event types AXIAM transmits, plus the two SSF stream events (§32.6).
///
/// Event types are **open**: a SET whose type is not among these still verifies, and
/// ``SecurityEvent/eventType`` carries it verbatim. The six AXIAM ones are also the generated
/// `SsfEventType` enum's raw values, for the management namespace.
public enum SsfEventTypeURI {
    /// CAEP session revoked.
    public static let sessionRevoked =
        "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
    /// CAEP credential change.
    public static let credentialChange =
        "https://schemas.openid.net/secevent/caep/event-type/credential-change"
    /// CAEP assurance level change.
    public static let assuranceLevelChange =
        "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change"
    /// RISC account disabled.
    public static let accountDisabled =
        "https://schemas.openid.net/secevent/risc/event-type/account-disabled"
    /// RISC account enabled.
    public static let accountEnabled =
        "https://schemas.openid.net/secevent/risc/event-type/account-enabled"
    /// RISC account purged.
    public static let accountPurged =
        "https://schemas.openid.net/secevent/risc/event-type/account-purged"
    /// SSF verification.
    public static let verification =
        "https://schemas.openid.net/secevent/ssf/event-type/verification"
    /// SSF stream updated.
    public static let streamUpdated =
        "https://schemas.openid.net/secevent/ssf/event-type/stream-updated"
}

/// Why ``SsfReceiver`` refused a SET (§32.7) — the step of the fixed order that failed.
///
/// Read it from ``AuthError/setFailureReason`` (or ``AxiamError/setFailureReason``).
public enum SetFailureReason: String, Sendable, CaseIterable {
    /// Step 1: not three base64url parts, or a header or payload that is not a JSON object.
    case malformed
    /// Step 2: `typ` is not `secevent+jwt` / `application/secevent+jwt`.
    case invalidType = "invalid_type"
    /// Steps 3–5: `alg` is not `EdDSA`, the `kid` is not in the JWKS, or the signature fails.
    case invalidKey = "invalid_key"
    /// Step 6: `iss` is not the configured issuer.
    case invalidIssuer = "invalid_issuer"
    /// Step 7: `aud` does not name the configured audience.
    case invalidAudience = "invalid_audience"
    /// Step 8: `exp` or `sub` present, `jti` / `iat` / `sub_id` missing, or `events` not
    /// exactly one member.
    case invalidRequest = "invalid_request"
    /// Step 9: the `jti` was already accepted within the replay window.
    case replayed

    /// The RFC 8935 §2.4 `err` code to answer a push with (`400 {"err": …}`), and to put in a
    /// poll's `setErrs`.
    ///
    /// The reason itself for `invalid_key`, `invalid_issuer`, `invalid_audience` and
    /// `invalid_request`; **`invalid_request`** for `malformed`, `invalid_type` and `replayed`,
    /// which are not RFC 8935 codes.
    public var pushErrorCode: String {
        switch self {
        case .invalidKey, .invalidIssuer, .invalidAudience, .invalidRequest:
            return rawValue
        case .malformed, .invalidType, .replayed:
            return SetFailureReason.invalidRequest.rawValue
        }
    }
}

/// An RFC 8936 `setErrs` entry: `{ "err": …, "description"?: … }`.
public struct SetErr: Sendable, Equatable {
    /// The RFC 8935 §2.4 code.
    public let err: String
    /// Optional text. AXIAM never stores it (§32.6).
    public let errorDescription: String?

    public init(err: String, errorDescription: String? = nil) {
        self.err = err
        self.errorDescription = errorDescription
    }

    /// The entry for a refusal: its ``SetFailureReason/pushErrorCode``.
    public init(reason: SetFailureReason, errorDescription: String? = nil) {
        self.init(err: reason.pushErrorCode, errorDescription: errorDescription)
    }

    var json: ManagementJSON {
        var members: [String: ManagementJSON] = ["err": .string(err)]
        if let errorDescription { members["description"] = .string(errorDescription) }
        return .object(members)
    }
}

/// Where the transmitter's signing keys come from.
public enum SsfKeySource: Sendable, Equatable {
    /// The JWKS URL itself (AXIAM: `{issuer}/oauth2/jwks`).
    case jwksURI(String)
    /// The transmitter's SSF configuration document (`/.well-known/ssf-configuration…`): its
    /// `jwks_uri` is used, and its `issuer` must equal the configured issuer.
    case discoveryURL(String)
}

/// Remembers the `jti`s already accepted, for step 9.
///
/// Pluggable so a receiver running several instances can share one store (§32.7).
/// ``InMemorySsfReplayStore`` is the default.
public protocol SsfReplayStore: Sendable {
    /// Record `jti` for `window` seconds and return `true`, or return `false` without
    /// recording when it is already held. **Must be atomic**: two concurrent calls with one
    /// `jti` must not both see `true`.
    func checkAndRecord(jti: String, window: TimeInterval) async -> Bool
}

/// The in-memory ``SsfReplayStore``: one process, lost on restart. An actor, so
/// check-and-record is atomic by isolation.
public actor InMemorySsfReplayStore: SsfReplayStore {
    private var expiries: [String: Date] = [:]
    private let now: @Sendable () -> Date

    public init() {
        self.now = { Date() }
    }

    /// A store reading `now` instead of the wall clock — for tests of the expiry.
    init(now: @escaping @Sendable () -> Date) {
        self.now = now
    }

    public func checkAndRecord(jti: String, window: TimeInterval) -> Bool {
        let current = now()
        expiries = expiries.filter { $0.value > current }
        if expiries[jti] != nil { return false }
        expiries[jti] = current.addingTimeInterval(window)
        return true
    }
}

/// Supplies the bearer ``SsfReceiver/poll(streamID:options:)`` presents: a client-credentials
/// access token carrying `ssf.manage` — for example from
/// ``AxiamClient/loginClientCredentials(scope:tenantID:configuration:)``. Called once per poll.
public typealias SsfAccessTokenProvider = @Sendable () async throws -> Sensitive<String>

/// Configuration for an ``SsfReceiver`` (§32.7: `{ issuer, audience, jwks_uri | discovery_url,
/// access_token_provider }`).
public struct SsfReceiverConfiguration: Sendable {
    /// The transmitter's issuer — compared to `iss` exactly.
    public var issuer: String
    /// This receiver's audience — the stream's `audience`.
    public var audience: String
    /// Where the signing keys come from.
    public var keySource: SsfKeySource
    /// The bearer for ``SsfReceiver/poll(streamID:options:)``; `nil` for a push-only receiver.
    public var accessTokenProvider: SsfAccessTokenProvider?
    /// How long a `jti` is remembered, in seconds. At least
    /// ``SsfReceiver/minimumReplayWindow`` (seven days), which is also the default.
    public var replayWindow: TimeInterval
    /// Where accepted `jti`s are kept; `nil` uses an ``InMemorySsfReplayStore``.
    public var replayStore: (any SsfReplayStore)?

    public init(
        issuer: String,
        audience: String,
        keySource: SsfKeySource,
        accessTokenProvider: SsfAccessTokenProvider? = nil,
        replayWindow: TimeInterval = SsfReceiver.minimumReplayWindow,
        replayStore: (any SsfReplayStore)? = nil
    ) {
        self.issuer = issuer
        self.audience = audience
        self.keySource = keySource
        self.accessTokenProvider = accessTokenProvider
        self.replayWindow = replayWindow
        self.replayStore = replayStore
    }
}

/// A verified Security Event Token (§32.7's result).
public struct SecurityEvent: Sendable, Equatable {
    /// The SET's unique id.
    public let jti: String
    /// When it was issued, seconds since the epoch.
    public let iat: Int
    /// The issuer, equal to the configured one.
    public let iss: String
    /// The audience as sent: one string, or an array containing yours.
    public let aud: ManagementJSON
    /// The transaction id shared by every SET one operation produced.
    public let txn: String?
    /// The single `events` key — an event-type URI, see ``SsfEventTypeURI``.
    public let eventType: String
    /// That event's object, opaque to the helper.
    public let event: ManagementJSON
    /// The RFC 9493 subject identifier, opaque to the helper.
    public let subID: ManagementJSON
}

/// One SET a poll returned and the helper refused.
public struct RefusedSet: Sendable, Equatable {
    /// The key the transmitter returned the SET under.
    public let jti: String
    /// Why it was refused. Pass `SetErr(reason:)` of it in the next poll's `setErrs`.
    public let reason: SetFailureReason
}

/// Arguments to ``SsfReceiver/poll(streamID:options:)``. Every member is passed through as
/// given; an unset one is not sent.
public struct SsfPollOptions: Sendable {
    /// `maxEvents` — the server clamps it to 100; `0` acknowledges and returns nothing.
    public var maxEvents: Int?
    /// `returnImmediately` — without it the server long-polls up to 30 s.
    public var returnImmediately: Bool?
    /// `ack` — the `jti`s you **processed** since the last poll.
    public var ack: [String]?
    /// `setErrs` — the `jti`s you refuse, each with its code.
    public var setErrs: [String: SetErr]?

    public init(
        maxEvents: Int? = nil,
        returnImmediately: Bool? = nil,
        ack: [String]? = nil,
        setErrs: [String: SetErr]? = nil
    ) {
        self.maxEvents = maxEvents
        self.returnImmediately = returnImmediately
        self.ack = ack
        self.setErrs = setErrs
    }

    /// The RFC 8936 request body: only the members that were set.
    var body: ManagementJSON {
        var members: [String: ManagementJSON] = [:]
        if let maxEvents { members["maxEvents"] = .int(maxEvents) }
        if let returnImmediately { members["returnImmediately"] = .bool(returnImmediately) }
        if let ack { members["ack"] = .array(ack.map { ManagementJSON.string($0) }) }
        if let setErrs {
            var errs: [String: ManagementJSON] = [:]
            for (jti, entry) in setErrs { errs[jti] = entry.json }
            members["setErrs"] = .object(errs)
        }
        return .object(members)
    }
}

/// What ``SsfReceiver/poll(streamID:options:)`` returns.
public struct SsfPollResult: Sendable {
    /// The SETs that verified.
    public let events: [SecurityEvent]
    /// Whether the transmitter holds more.
    public let moreAvailable: Bool
    /// The SETs that did not verify.
    public let refused: [RefusedSet]
}

/// The SSF receiver helper (CONTRACT.md §32.7) — `verifySet` and `poll` over a receiver
/// configuration.
///
/// Built over an ``AxiamClient``, whose transport (§6's TLS policy, no redirect following)
/// fetches the JWKS and calls the poll endpoint, and whose base URL is the transmitter root.
/// Neither call carries the client's own session: the poll authenticates with the provider's
/// bearer and nothing else.
public actor SsfReceiver {
    /// The replay window's floor and default: seven days, the transmitter's buffer retention
    /// (§32.6). A shorter window would forget a `jti` the transmitter can still re-send.
    public static let minimumReplayWindow: TimeInterval = 7 * 24 * 60 * 60

    /// Forced JWKS refetches (on an unknown `kid`) happen at most once per this many seconds.
    public static let forcedRefetchInterval: TimeInterval = 60

    private let client: AxiamClient
    private let issuer: String
    private let audience: String
    private let keySource: SsfKeySource
    private let accessTokenProvider: SsfAccessTokenProvider?
    private let replayWindow: TimeInterval
    private let replayStore: any SsfReplayStore
    private let now: @Sendable () -> Date

    private var jwksURL: URL?
    private var keys: [Jwk]?
    private var lastForcedRefetch: Date?

    /// Build a receiver over `client`.
    ///
    /// - Throws: a local ``NetworkError`` with ``NetworkError/isValidation`` set when
    ///   `replayWindow` is below ``minimumReplayWindow``, or `issuer` / `audience` is empty.
    public init(client: AxiamClient, configuration: SsfReceiverConfiguration) throws {
        try self.init(client: client, configuration: configuration, now: { Date() })
    }

    /// The designated initializer, with an injectable clock for the refetch rate limit.
    init(
        client: AxiamClient,
        configuration: SsfReceiverConfiguration,
        now: @escaping @Sendable () -> Date
    ) throws {
        guard configuration.replayWindow >= Self.minimumReplayWindow else {
            throw ManagementChecks.refusal(
                "ssf.receiver",
                "replay_window must be at least seven days, the transmitter's buffer "
                    + "retention (CONTRACT.md §32.7)")
        }
        guard !configuration.issuer.isEmpty, !configuration.audience.isEmpty else {
            throw ManagementChecks.refusal(
                "ssf.receiver", "issuer and audience are required (CONTRACT.md §32.7)")
        }
        self.client = client
        self.issuer = configuration.issuer
        self.audience = configuration.audience
        self.keySource = configuration.keySource
        self.accessTokenProvider = configuration.accessTokenProvider
        self.replayWindow = configuration.replayWindow
        self.replayStore = configuration.replayStore ?? InMemorySsfReplayStore()
        self.now = now
    }

    // MARK: - verify_set

    /// Verify one compact SET (§32.7), in this order, refusing at the first failure with the
    /// ``SetFailureReason`` in brackets:
    ///
    /// 1. three base64url parts, a JSON-object header and payload [`malformed`];
    /// 2. `typ` `secevent+jwt` or `application/secevent+jwt`, any case [`invalid_type`];
    /// 3. `alg` exactly `EdDSA` [`invalid_key`];
    /// 4. the `kid` in the configured JWKS — on a miss, one refetch, at most once a minute
    ///    [`invalid_key`];
    /// 5. the Ed25519 signature [`invalid_key`];
    /// 6. `iss` equal to the configured issuer [`invalid_issuer`];
    /// 7. `aud` equal to, or an array containing, the audience [`invalid_audience`];
    /// 8. no `exp`, no `sub`; a non-empty string `jti`, a numeric `iat`, an object `sub_id`;
    ///    exactly one `events` member [`invalid_request`];
    /// 9. a `jti` not seen within the replay window [`replayed`] — recorded only once steps
    ///    1–8 passed.
    ///
    /// **A SET that verifies has been recorded**: verifying it again is `replayed`.
    /// Acknowledge a polled SET once you have processed it.
    ///
    /// - Throws: ``AuthError`` with ``AuthError/setFailureReason`` set; or ``NetworkError``
    ///   when the JWKS could not be fetched — which is not a verdict on the SET.
    public func verifySet(_ set: String) async throws -> SecurityEvent {
        try await verify(set, expectedJTI: nil)
    }

    private func verify(_ set: String, expectedJTI: String?) async throws -> SecurityEvent {
        // 1.
        let parts = set.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 3,
              let headerData = Base64URL.decode(parts[0]),
              let payloadData = Base64URL.decode(parts[1]),
              let signature = Base64URL.decode(parts[2])
        else {
            throw Self.refuse(.malformed, "not three base64url parts")
        }
        guard let header = Self.jsonObject(headerData), let claims = Self.jsonObject(payloadData)
        else {
            throw Self.refuse(.malformed, "the header or payload is not a JSON object")
        }

        // 2.
        let typ = (header["typ"]?.stringValue ?? "").lowercased()
        guard typ == "secevent+jwt" || typ == "application/secevent+jwt" else {
            throw Self.refuse(.invalidType, "typ is not secevent+jwt")
        }

        // 3. Pinned before any key is looked up: `none` and every `HS*` stop here.
        guard header["alg"]?.stringValue == "EdDSA" else {
            throw Self.refuse(.invalidKey, "alg is not EdDSA")
        }

        // 4. Only the configured JWKS: a `jwk` or `x5c` header member is never read.
        guard let kid = header["kid"]?.stringValue, !kid.isEmpty else {
            throw Self.refuse(.invalidKey, "the header names no kid")
        }
        guard let jwk = try await key(for: kid) else {
            throw Self.refuse(.invalidKey, "no key for the kid in the JWKS")
        }

        // 5.
        guard jwk.kty == "OKP", jwk.crv == "Ed25519",
              let x = jwk.x, let raw = Base64URL.decode(x),
              let publicKey = try? Curve25519.Signing.PublicKey(rawRepresentation: raw)
        else {
            throw Self.refuse(.invalidKey, "the JWKS key is not a usable Ed25519 key")
        }
        let signingInput = Data((parts[0] + "." + parts[1]).utf8)
        guard publicKey.isValidSignature(signature, for: signingInput) else {
            throw Self.refuse(.invalidKey, "the signature does not verify")
        }

        // 6.
        let iss = claims["iss"]?.stringValue ?? ""
        guard iss == issuer else {
            throw Self.refuse(.invalidIssuer, "iss is not the configured issuer")
        }

        // 7.
        let aud = claims["aud"] ?? .null
        let audienceMatches: Bool
        switch aud {
        case .string(let value):
            audienceMatches = value == audience
        case .array(let values):
            audienceMatches = values.contains(.string(audience))
        default:
            audienceMatches = false
        }
        guard audienceMatches else {
            throw Self.refuse(.invalidAudience, "aud does not name this receiver")
        }

        // 8.
        guard claims["exp"] == nil, claims["sub"] == nil else {
            throw Self.refuse(.invalidRequest, "a SET carries no exp and no sub")
        }
        guard let jti = claims["jti"]?.stringValue, !jti.isEmpty else {
            throw Self.refuse(.invalidRequest, "no jti")
        }
        let iat: Int
        switch claims["iat"] {
        case .some(.int(let value)):
            iat = value
        case .some(.number(let value)):
            iat = Int(value)
        default:
            throw Self.refuse(.invalidRequest, "no numeric iat")
        }
        guard let subID = claims["sub_id"], case .object = subID else {
            throw Self.refuse(.invalidRequest, "no sub_id object")
        }
        guard case .some(.object(let events)) = claims["events"], events.count == 1,
              let only = events.first
        else {
            throw Self.refuse(.invalidRequest, "events must have exactly one member")
        }
        if let expectedJTI, expectedJTI != jti {
            throw Self.refuse(.invalidRequest, "the poll key is not the SET's jti")
        }

        // 9. Recorded only now, once 1–8 passed.
        guard await replayStore.checkAndRecord(jti: jti, window: replayWindow) else {
            throw Self.refuse(.replayed, "the jti was already accepted")
        }

        return SecurityEvent(
            jti: jti,
            iat: iat,
            iss: iss,
            aud: aud,
            txn: claims["txn"]?.stringValue,
            eventType: only.key,
            event: only.value,
            subID: subID)
    }

    // MARK: - poll

    /// Poll the stream's RFC 8936 endpoint, `{base URL}/ssf/v1/poll/{stream_id}`, with a bearer
    /// from the configured ``SsfReceiverConfiguration/accessTokenProvider``.
    ///
    /// `ack` and `setErrs` are sent exactly as given. **Nothing is acknowledged on your
    /// behalf**: acknowledge, on the next call, the `jti`s you processed, and pass each refused
    /// one in `setErrs` (`SetErr(reason:)`). A SET you neither acknowledge nor refuse is
    /// re-offered — and, having been recorded when it verified, then reads as `replayed`.
    ///
    /// Retried per §16 on a transport failure, `408`, `429` or `5xx`; never on another `4xx`,
    /// which maps as the management surface maps it (`400` is a ``NetworkError`` with
    /// ``NetworkError/isValidation`` set, `404` an ``AuthzError``…). A JWKS fetch failure
    /// aborts the poll with that error rather than refusing SETs it could not judge.
    ///
    /// - Throws: a local ``AuthError`` when no access-token provider is configured.
    public func poll(
        streamID: String,
        options: SsfPollOptions = SsfPollOptions()
    ) async throws -> SsfPollResult {
        guard let provider = accessTokenProvider else {
            throw AxiamError.auth(AuthError(
                "ssf.poll needs an accessTokenProvider (a client-credentials token with "
                    + "ssf.manage); no request was sent (CONTRACT.md §32.7)"))
        }
        let url = try client.ssfPollURL(streamID: streamID)
        let payload: Data
        do {
            payload = try JSONEncoder().encode(options.body)
        } catch {
            throw AxiamError.network(NetworkError("ssf.poll: failed to encode the body", cause: error))
        }
        let token = try await provider()
        let response = try await client.bareSend(
            operation: "ssf.poll",
            pathTemplate: "/ssf/v1/poll/{stream_id}",
            method: .post,
            url: url,
            headers: [
                ("Authorization", "Bearer \(token.expose())"),
                ("Content-Type", "application/json"),
                ("Accept", "application/json"),
            ],
            body: payload,
            retry: .section16)
        guard (200..<300).contains(response.status) else {
            let errBody = try? JSONDecoder().decode(ErrorBody.self, from: response.body)
            let detail = errBody?.message ?? errBody?.error ?? "HTTP \(response.status)"
            throw ErrorMapper.mapManagement(status: response.status, message: "ssf.poll: \(detail)")
        }
        guard let reply = Self.jsonObject(response.body) else {
            throw AxiamError.network(NetworkError("ssf.poll: the response is not a JSON object"))
        }

        var moreAvailable = false
        if case .some(.bool(let more)) = reply["moreAvailable"] { moreAvailable = more }

        var events: [SecurityEvent] = []
        var refused: [RefusedSet] = []
        if case .some(.object(let sets)) = reply["sets"] {
            for jti in sets.keys.sorted() {
                guard case .some(.string(let set)) = sets[jti] else {
                    refused.append(RefusedSet(jti: jti, reason: .malformed))
                    continue
                }
                do {
                    let event = try await verify(set, expectedJTI: jti)
                    events.append(event)
                } catch let error as AxiamError {
                    guard let reason = error.setFailureReason else { throw error }
                    refused.append(RefusedSet(jti: jti, reason: reason))
                }
            }
        }
        return SsfPollResult(events: events, moreAvailable: moreAvailable, refused: refused)
    }

    // MARK: - Keys

    /// The JWKS key named `kid`: from the cache, or — on a miss — after ONE forced refetch,
    /// at most once per ``forcedRefetchInterval``.
    private func key(for kid: String) async throws -> Jwk? {
        if keys == nil {
            keys = try await fetchKeys()
        }
        if let found = keys?.first(where: { $0.kid == kid }) {
            return found
        }
        let current = now()
        if let last = lastForcedRefetch, current.timeIntervalSince(last) < Self.forcedRefetchInterval {
            return nil
        }
        lastForcedRefetch = current
        keys = try await fetchKeys()
        return keys?.first(where: { $0.kid == kid })
    }

    private func fetchKeys() async throws -> [Jwk] {
        let url = try await resolveJwksURL()
        let response = try await client.bareSend(
            operation: "ssf.jwks",
            pathTemplate: "{jwks_uri}",
            method: .get,
            url: url,
            headers: [("Accept", "application/json")],
            body: nil,
            retry: .section16)
        guard (200..<300).contains(response.status) else {
            throw AxiamError.network(NetworkError(
                "the SSF transmitter's JWKS fetch failed: HTTP \(response.status)",
                statusCode: response.status))
        }
        guard let document = try? JSONDecoder().decode(JwksDocument.self, from: response.body) else {
            throw AxiamError.network(NetworkError("the SSF transmitter's JWKS did not decode"))
        }
        return document.keys
    }

    private func resolveJwksURL() async throws -> URL {
        if let jwksURL { return jwksURL }
        let resolved: String
        switch keySource {
        case .jwksURI(let uri):
            resolved = uri
        case .discoveryURL(let raw):
            let url = try Self.secureURL(raw, label: "discovery_url")
            let response = try await client.bareSend(
                operation: "ssf.discovery",
                pathTemplate: "{discovery_url}",
                method: .get,
                url: url,
                headers: [("Accept", "application/json")],
                body: nil,
                retry: .section16)
            guard (200..<300).contains(response.status) else {
                throw AxiamError.network(NetworkError(
                    "the SSF configuration fetch failed: HTTP \(response.status)",
                    statusCode: response.status))
            }
            guard let document = Self.jsonObject(response.body) else {
                throw AxiamError.network(NetworkError("the SSF configuration did not decode"))
            }
            guard document["issuer"]?.stringValue == issuer else {
                throw AxiamError.network(NetworkError(
                    "the SSF configuration's issuer is not the configured issuer"))
            }
            guard let uri = document["jwks_uri"]?.stringValue else {
                throw AxiamError.network(NetworkError("the SSF configuration carries no jwks_uri"))
            }
            resolved = uri
        }
        let url = try Self.secureURL(resolved, label: "jwks_uri")
        jwksURL = url
        return url
    }

    // MARK: - Helpers

    static func refuse(_ reason: SetFailureReason, _ detail: String) -> AxiamError {
        .auth(AuthError(
            "SET refused (\(reason.rawValue)): \(detail) (CONTRACT.md §32.7)",
            setFailureReason: reason))
    }

    static func jsonObject(_ data: Data) -> [String: ManagementJSON]? {
        guard let value = try? JSONDecoder().decode(ManagementJSON.self, from: data),
              case .object(let members) = value
        else {
            return nil
        }
        return members
    }

    /// An absolute `https` URL — or `http` on a loopback host, a development deployment.
    static func secureURL(_ raw: String, label: String) throws -> URL {
        guard let url = URL(string: raw),
              let scheme = url.scheme?.lowercased(),
              let host = url.host, !host.isEmpty
        else {
            throw AxiamError.network(NetworkError("\(label) is not an absolute URL"))
        }
        guard scheme == "https" || (scheme == "http" && AxiamClient.isLoopbackHost(host)) else {
            throw AxiamError.network(NetworkError("\(label) must be an https URL"))
        }
        return url
    }
}

extension AxiamClient {
    /// `{base URL}/ssf/v1/poll/{stream_id}`, the stream id path-escaped as one segment.
    nonisolated func ssfPollURL(streamID: String) throws -> URL {
        var unreserved = CharacterSet.alphanumerics
        unreserved.insert(charactersIn: "-._~")
        guard let escaped = streamID.addingPercentEncoding(withAllowedCharacters: unreserved),
              !escaped.isEmpty
        else {
            throw ManagementChecks.refusal("ssf.poll", "stream_id is empty")
        }
        var root = config.baseURL.absoluteString
        while root.hasSuffix("/") { root.removeLast() }
        guard let url = URL(string: "\(root)/ssf/v1/poll/\(escaped)") else {
            throw AxiamError.network(NetworkError("ssf.poll: could not build the poll URL"))
        }
        return url
    }
}
