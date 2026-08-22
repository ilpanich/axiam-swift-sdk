import Foundation

// AXIAM Reactor — CONTRACT.md §22, the protocol core over a caller-supplied
// transport.
//
// WHAT THIS SHIPS, AND WHAT IT DOES NOT.
//
// §22.1–§22.8 and §22.14 in full: the §8 v2 verification set on the event, the
// canonical serialization and MAC in both directions, the §22.5 registry and its
// mutable-field allow-lists, §22.8's strictest-wins default, and the declarative
// builder. What it does NOT do is open a connection. §22.11 defers only the
// transport, because there is no maintained AMQP client for this target that
// this project is willing to vendor.
//
// That split is the newer one. Until contract 1.28 this SDK shipped nothing from
// §22 while the section still bound an integrator to §22.1–§22.8 — so the half
// deferred for want of a *dependency* was the transport, and the half left to
// hand-roll from prose was the **protocol**: v2 HMAC over a canonical
// serialization with a `null` signature placeholder, freshness in both
// directions, nonce and correlation binding, the allow-lists. That is the half
// with the sharp edges, none of them AMQP-shaped, and asking every integrator to
// reimplement it is how a signing bug ships.

// MARK: - §22.5 the event registry

/// Every hookable event (§22.5).
///
/// **WHAT IS ABSENT IS LOAD-BEARING.** §22.7 is a normative MUST NOT: the three
/// hot-path decision operations are not hookable, and no SDK may present them as
/// such. They are in no case here and in no comment here — §22.13 asserts on the
/// enum, not on a comment. A reactor round trip is milliseconds; the check path's
/// budget is microseconds. An application needing external input on an
/// authorization decision writes a **deny grant**, which the engine evaluates in
/// the hot path at hot-path cost.
public enum ReactorEventName: String, Sendable, CaseIterable, Codable {
    case tokenPreIssue = "token.pre_issue"
    case loginPostAuth = "login.post_auth"
    case userPreCreate = "user.pre_create"
    case userPreUpdate = "user.pre_update"
    case grantPreAssign = "grant.pre_assign"

    /// Whether a patch may set `field` on this event (§22.5).
    ///
    /// A registry entry ending in `.` names a NAMESPACE: `ext.` admits
    /// `ext.department` and `ext.a.b.c`, and refuses `ext.` itself, `ext`,
    /// `extra`, `external_id` (a prefix match on the string is not a match on the
    /// namespace) and `evil.ext.department`.
    ///
    /// A QUERY, not a filter. §22.4 rule 1 sends a patch unfiltered, and nothing
    /// in this SDK calls this to prune one.
    public func allowsPatchField(_ field: String) -> Bool {
        for allowed in mutableFields {
            if allowed.hasSuffix(".") {
                if field.count > allowed.count, field.hasPrefix(allowed) { return true }
                continue
            }
            if field == allowed { return true }
        }
        return false
    }

    /// The fields this event admits in a patch. Empty for the veto-only events.
    ///
    /// `ext.` is the COMPLETE allow-list for `token.pre_issue`: no standard claim
    /// begins with it, so `sub`, `aud`, `exp`, `scope` and the rest are
    /// unreachable. A hook that could rewrite `sub` is a hook that could mint a
    /// token for anyone, and a CORRECTLY SIGNED reply setting it is refused
    /// exactly as a forged one is.
    public var mutableFields: [String] {
        switch self {
        case .tokenPreIssue: return ["ext."]
        case .userPreCreate, .userPreUpdate: return ["username", "email", "metadata."]
        case .loginPostAuth, .grantPreAssign: return []
        }
    }

    /// This event's own default failure policy (§22.8).
    public var defaultFailurePolicy: ReactorFailurePolicy {
        switch self {
        case .tokenPreIssue: return .failOpen
        case .loginPostAuth, .userPreCreate, .userPreUpdate, .grantPreAssign: return .failClosed
        }
    }
}

/// What the server does when a reactor does not answer (§22.8).
public enum ReactorFailurePolicy: String, Sendable, Codable {
    case failOpen = "fail_open"
    case failClosed = "fail_closed"
}

extension ReactorFailurePolicy {
    /// §22.8's strictest-wins default, in either array order.
    ///
    /// A reactor registered for both `token.pre_issue` (open) and
    /// `login.post_auth` (closed) can veto a login, so it inherits `fail_closed`.
    /// Reducing this to "take the first event's default" would let the order of a
    /// JSON array decide whether an unreachable fraud check passes.
    ///
    /// An EMPTY registration is `failClosed`, not "nothing to fail at".
    public static func strictestDefault(for events: [ReactorEventName]) -> ReactorFailurePolicy {
        guard !events.isEmpty else { return .failClosed }
        return events.contains { $0.defaultFailurePolicy == .failClosed } ? .failClosed : .failOpen
    }
}

// MARK: - §22.1 topology

/// §22.1 topology names.
///
/// **RENDERING THESE IS NOT DECLARING THEM**: a reactor consumes the queue the
/// server declared and never declares or binds anything.
public enum ReactorTopology {
    public static func routingKey(tenantID: String, event: ReactorEventName) -> String {
        "\(tenantID).\(event.rawValue)"
    }

    public static func queueName(tenantID: String, reactorID: String) -> String {
        "axiam.reactor.q.\(tenantID).\(reactorID)"
    }
}

// MARK: - §22.3 the event

/// A delivery that passed every §22.3 check.
///
/// A handler never sees anything else: a runtime that hands unverified bytes to
/// user code has already lost, because the handler will act on them and "we
/// checked afterwards" is not a check.
public struct ReactorEvent: Sendable {
    public let tenantID: String
    public let event: ReactorEventName
    public let correlationID: String
    /// The server's payload as JSON TEXT. Not a decoded model: this SDK cannot
    /// know your payload's shape, and handing back the bytes leaves you free to
    /// decode them into whatever type your service already has.
    ///
    /// `_reactor_patch`, when present, is the patch accumulated by earlier
    /// reactors in the chain — READ-ONLY context. Echoing it back inside your own
    /// patch is not how a field is preserved; the server merges (§22.6).
    public let payloadJSON: String
    /// The window the server will wait. §22.10 rule 4: work whose window has
    /// closed is abandoned rather than answered late.
    public let timeoutMilliseconds: Int
    public let nonce: String

    /// Decode ``payloadJSON`` into a `Decodable` type of your own.
    public func decodePayload<T: Decodable>(_ type: T.Type) throws -> T {
        try JSONDecoder().decode(type, from: Data(payloadJSON.utf8))
    }
}

// MARK: - §22.4 the reply

/// One of the three answers, plus `requireMFA` as a flag on the allow answer.
///
/// There is deliberately no way to spell `allow` + `patch`: both allow cases take
/// none (§22.4 rule 2), and a patch travels only on ``mutate(_:)``.
public enum ReactorDecision: Sendable, Equatable {
    case allow
    /// `allow` + `require_mfa: true` on `login.post_auth` means "proceed only
    /// after step-up". It is NOT a fourth decision value.
    ///
    /// On the federated paths (SAML ACS, OIDC callback) there is no step-up
    /// branch, so it FAILS the sign-in rather than being quietly dropped — answer
    /// ``deny(_:)`` there and drive enrolment out of band (§22.5).
    case allowWithStepUp
    /// A deny with no reason still denies; the server substitutes "denied by
    /// reactor". An empty reason is OMITTED, not sent as `""` — the omission
    /// changes the canonical bytes and therefore the MAC.
    case deny(String)
    /// §22.4 rule 1: a patch is sent UNFILTERED. One forbidden key rejects the
    /// WHOLE patch server-side, including the fields that would have been fine —
    /// and dropping the offender to rescue the rest would leave the author
    /// believing a field was set when it was dropped, which is exactly the
    /// failure the server refuses to produce.
    case mutate([String: String])
}

/// A handler's answer, or ABSTENTION.
///
/// `nil` publishes no reply and lets the registration's `failure_policy` resolve
/// the event exactly as §22.8 resolves a timeout. It is what §22.14 rule 4
/// requires of an unbound event, and it is expressible by a plain handler too — a
/// handler that cannot decide must be able to say so rather than pick one of the
/// three answers on the operator's behalf.
public typealias ReactorAnswer = ReactorDecision?

/// One function from a verified event to one answer (§22.10).
public typealias ReactorHandler = @Sendable (ReactorEvent) async throws -> ReactorAnswer

// MARK: - §22.11 the transport seam

/// One inbound message, as the broker hands it over.
public struct ReactorDelivery: Sendable {
    /// The raw message body. Verified by the runtime, never by the transport.
    public let body: Data
    /// The `reply_to` basic property — where the reply is published.
    public let replyTo: String?
    /// The `correlation_id` basic property.
    public let correlationID: String?

    public init(body: Data, replyTo: String? = nil, correlationID: String? = nil) {
        self.body = body
        self.replyTo = replyTo
        self.correlationID = correlationID
    }
}

/// **EXACTLY TWO CAPABILITIES** (§22.11 rule 1). Deliberately not wider: a
/// protocol that also exposed declare, bind or queue-name derivation would hand
/// the integrator the tools §22.1 forbids using.
public protocol ReactorTransport: Sendable {
    /// The next delivery, or `nil` when the consumer is done — which is how
    /// ``reactorServe(config:transport:handler:)`` returns.
    func nextDelivery() async throws -> ReactorDelivery?
    /// Publish a signed reply. `destination` is the delivery's `replyTo`.
    func publishReply(destination: String, correlationID: String, body: Data) async throws
}

// MARK: - §22.3 verification outcomes

/// Why a delivery was refused. A CATEGORY, never the MAC, the key or the payload.
///
/// `Error` so the verification outcome can be a `Result`; a caller driving the
/// runtime never sees one thrown, because §22.10 rule 2 turns every refusal into
/// silence rather than into an error to handle.
public enum ReactorRefusal: String, Error, Sendable, Equatable {
    case malformed
    case keyVersionTooOld = "key_version_too_old"
    case badSignature = "bad_signature"
    case stale
    case replay
    case tenantMismatch = "tenant_mismatch"
    case unknownEvent = "unknown_event"
}

/// A reply this SDK refuses to build, because the server would refuse it and the
/// registration's failure policy should decide instead of a corrected reply.
public enum ReactorReplyError: Error, Sendable, Equatable {
    /// `require_mfa` is valid on `login.post_auth` only (§22.4 row 7).
    case requireMFAOnWrongEvent(ReactorEventName)
    /// A `mutate` answer with an empty patch.
    case emptyMutation
}

/// A binding this SDK refuses to record (§22.14).
public enum ReactorBindingError: Error, Sendable, Equatable {
    /// A name outside the §22.5 registry, refused AT BIND TIME.
    case unknownEvent(String)
    /// A second binding for an already-bound event (rule 3).
    case duplicateBinding(ReactorEventName)
}
