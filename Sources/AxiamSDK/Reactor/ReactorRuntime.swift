import Foundation

// MARK: - §22.10 the runtime

/// What ``reactorServe(config:transport:handler:)`` needs to run.
public struct ReactorConfig: Sendable {
    /// The tenant this reactor is registered for. An event naming another tenant
    /// is refused AFTER the MAC — identity is not cryptography, and spending it
    /// on unauthenticated bytes tells an unauthenticated party what this reactor
    /// accepts.
    public let tenantID: String
    public let reactorID: String
    /// The tenant's HKDF-derived AMQP subkey (§8.1) as RAW BYTES — the same key
    /// in both directions. §22.12 makes it a credential: it MUST NOT be logged at
    /// any level, and MUST NOT appear in a reconnect diagnostic.
    public let signingKey: Sensitive<Data>

    /// Test seams. §22.13's sign-direction vectors pin an exact `issued_at` and
    /// `nonce`, and a runtime whose values are unreachable can only be tested
    /// through a reimplementation of the thing under test. Both default to the
    /// real clock and a CSPRNG; neither is a knob anyone should reach for in
    /// production.
    public let clock: @Sendable () -> Date
    public let nonceSource: @Sendable () -> String

    public init(
        tenantID: String,
        reactorID: String,
        signingKey: Sensitive<Data>,
        clock: @escaping @Sendable () -> Date = { Date() },
        nonceSource: @escaping @Sendable () -> String = { UUID().uuidString.lowercased() }
    ) {
        self.tenantID = tenantID
        self.reactorID = reactorID
        self.signingKey = signingKey
        self.clock = clock
        self.nonceSource = nonceSource
    }
}

/// Consume, verify, dispatch, sign, publish — until the transport is done.
///
/// For each delivery, in this order (§22.3): refuse `key_version` below 2; verify
/// the MAC; check freshness in BOTH directions; check the nonce against a
/// seen-set held for this call's whole lifetime. Only then is the handler
/// invoked.
///
/// Four rules from §22.10, all of them observable:
///
/// 1. **It declares no topology** (§22.1). The transport is not even given the
///    vocabulary to.
/// 2. **It fails closed on its own errors.** A handler that throws, or a body the
///    runtime cannot verify, produces NO REPLY — letting the server's
///    `failure_policy` decide. A runtime that answered `allow` for a handler that
///    threw would have overridden the operator's `fail_closed` setting from
///    inside the library.
/// 3. **It does not filter a patch** (§22.4 rule 1).
/// 4. **It honours `timeout_ms`** by abandoning work whose window has closed
///    rather than replying late.
///
/// - Throws: only what the *transport* throws. A handler's failure is caught and
///   turned into an abstention, because that is what rule 2 requires; a
///   transport's is not, because a broker that has gone away is not something to
///   keep looping on.
public func reactorServe(
    config: ReactorConfig,
    transport: ReactorTransport,
    handler: ReactorHandler
) async throws {
    // ONE seen-set for this call's whole lifetime. A fresh one per delivery
    // defeats replay dedup entirely, which is the failure §22.3 names.
    var seenNonces: [String: Date] = [:]

    while let delivery = try await transport.nextDelivery() {
        let receivedAt = config.clock()
        let verified = ReactorProtocol.verifyEvent(
            signingKey: config.signingKey,
            body: delivery.body,
            expectedTenantID: config.tenantID,
            now: receivedAt,
            seenNonces: &seenNonces)

        guard case .success(let event) = verified else {
            // §22.10 rule 2: NO REPLY. A body this runtime could not verify is
            // not a body it may answer on the handler's behalf.
            continue
        }

        let answer: ReactorAnswer
        do {
            answer = try await handler(event)
        } catch {
            // Same rule, the other source.
            continue
        }
        guard let decision = answer else { continue }  // abstained (§22.14 rule 4)

        // §22.10 rule 4: work whose window has closed is abandoned rather than
        // answered late. The server has already resolved the event by its
        // failure_policy, and a reply arriving after that is at best ignored.
        if event.timeoutMilliseconds > 0 {
            let elapsed = config.clock().timeIntervalSince(receivedAt) * 1000
            if elapsed > Double(event.timeoutMilliseconds) { continue }
        }

        let reply: String
        do {
            reply = try ReactorProtocol.buildReply(
                signingKey: config.signingKey,
                correlationID: event.correlationID,
                tenantID: event.tenantID,
                event: event.event,
                decision: decision,
                nonce: config.nonceSource(),
                issuedAt: ReactorTime.format(config.clock()))
        } catch {
            // A refusal from the reply builder — `require_mfa` on the wrong
            // event, an empty mutate — is the runtime's own error, and rule 2
            // applies to it exactly as to a handler that threw.
            continue
        }

        try await transport.publishReply(
            destination: delivery.replyTo ?? "axiam.reactor.replies",
            correlationID: event.correlationID,
            body: Data(reply.utf8))
    }
}

// MARK: - §22.14 declarative handler binding

/// Bind one handler per event and let the SDK compose them into the single
/// handler ``reactorServe(config:transport:handler:)`` takes.
///
/// §22.10's handler is ONE function from an event to one answer, which is the
/// right shape for the wire and the wrong shape for the code. A reactor
/// registered for three events opens with a `switch` on `event.event`, and that
/// switch is where two defects live. The first is cheap: a misspelled event name
/// binds nothing and is discovered as an event that never fires. The second is
/// not — it is the `default:` arm that returns `.allow` on behalf of code that
/// never ran, which is §22.10 rule 2's defect relocated into user code where the
/// rule does not reach it.
///
/// **A BUILDER RATHER THAN AN ATTRIBUTE**, and §22.14 records why: a Swift
/// reactor handler is an `async` closure, and collecting `async` members by
/// reflection costs a runtime dependency an SDK should not add to hand out an
/// attribute. A builder type-checks the closure against
/// `(ReactorEvent) async throws -> ReactorAnswer` at compile time, which is
/// stricter than what the reflection would have bought. Kotlin made the same
/// trade for the same reason.
///
/// **PURE SUGAR.** It opens no connection, consumes no queue, verifies no event,
/// signs no reply and interprets no `timeout_ms`; its output is exactly the
/// handler the runtime accepts (rule 1).
public struct ReactorRouter: Sendable {
    private var bindings: [(ReactorEventName, ReactorHandler)] = []
    private var fallbackHandler: ReactorHandler?

    public init() {}

    /// Bind `handler` to `event`.
    ///
    /// - Throws: ``ReactorBindingError/duplicateBinding(_:)`` on a second binding
    ///   for an already-bound event (rule 3). Never a silent overwrite: which of
    ///   two handlers runs is not something the author of either can see from
    ///   their own file.
    public mutating func on(
        _ event: ReactorEventName,
        _ handler: @escaping ReactorHandler
    ) throws {
        guard !bindings.contains(where: { $0.0 == event }) else {
            throw ReactorBindingError.duplicateBinding(event)
        }
        bindings.append((event, handler))
    }

    /// Bind by NAME, for a reactor whose event list is configuration rather than
    /// source.
    ///
    /// - Throws: ``ReactorBindingError/unknownEvent(_:)`` when the name is not in
    ///   the §22.5 registry — AT BIND TIME, not at dispatch time (rule 2).
    ///   Failing when the binding is written is the entire point: a typo that
    ///   survives to production is discovered as silence, and silence on a
    ///   `fail_open` event is indistinguishable from a healthy reactor with
    ///   nothing to say.
    ///
    ///   This is also how §22.7's three hot-path operations are refused: they are
    ///   in no registry row, so they fail like any other unknown name. There is
    ///   deliberately no separate hot-path list to produce a more specific
    ///   message — that list would be a constant naming them, which §22.13's
    ///   hot-path assertion forbids.
    ///
    ///   The strongly-typed ``on(_:_:)`` above cannot reach this case at all,
    ///   which is the better default: the compiler refuses the typo.
    public mutating func on(
        eventNamed name: String,
        _ handler: @escaping ReactorHandler
    ) throws {
        guard let event = ReactorEventName(rawValue: name) else {
            throw ReactorBindingError.unknownEvent(name)
        }
        try on(event, handler)
    }

    /// An explicit fallback for unbound events.
    ///
    /// OPTIONAL, and it has no default (rule 4). Without one an unbound event
    /// ABSTAINS — no reply, and the registration's `failure_policy` resolves it.
    /// It is not answered `allow`, and not answered `deny` either: the binder does
    /// not know what the registration was for, and the operator's policy does.
    public mutating func fallback(_ handler: @escaping ReactorHandler) {
        fallbackHandler = handler
    }

    /// The bound event names, so a reactor author can compute §22.8's
    /// strictest-wins default from the code that actually handles the events
    /// rather than from a restatement of the registration.
    public var boundEvents: [ReactorEventName] { bindings.map(\.0) }

    /// The composed handler.
    ///
    /// A handler's own failure propagates UNCHANGED (rule 5): nothing here
    /// catches a thrown error or converts one into an answer, because §22.10 rule
    /// 2 puts the fail-closed obligation on the runtime and a binder that
    /// swallowed a failure first would satisfy the letter of that rule while
    /// defeating it.
    public func handler() -> ReactorHandler {
        let bindings = self.bindings
        let fallback = self.fallbackHandler
        return { event in
            for (name, bound) in bindings where name == event.event {
                return try await bound(event)
            }
            if let fallback { return try await fallback(event) }
            return nil
        }
    }
}
