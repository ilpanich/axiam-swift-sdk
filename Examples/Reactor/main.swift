import AxiamSDK
import Foundation

// CONTRACT.md §22 — an AXIAM Reactor on the SDK's protocol core, driven by a
// transport you supply.
//
// A REACTOR is an external service AXIAM consults synchronously at five points in
// its own flows: it may veto a login, enrich a token, or adjust a user before
// creation. §22.1–§22.8 and §22.14 are in the library — verification, canonical
// signing, the registry and its allow-lists, the runtime, the builder.
//
// WHAT THIS SDK DOES NOT SHIP IS A CONNECTION. §22.11 defers the transport, and
// only the transport: there is no maintained AMQP client for this target that this
// project is willing to vendor, which is the same reason §8 has never listed Swift
// among the SDKs that speak AMQP. Conform `ReactorTransport` over whichever client
// you already trust and nothing else moves.
//
// Run: swift run ReactorExample

func env(_ key: String, _ fallback: String) -> String {
    ProcessInfo.processInfo.environment[key].flatMap { $0.isEmpty ? nil : $0 } ?? fallback
}

// The transport seam — the part this project does not fill for you.
//
// Its obligations are §22.1's and §8b's, not the runtime's:
//
//   * connect over `amqps://` with the endpoint validated below;
//   * consume `ReactorTopology.queueName(...)`, the queue the SERVER declared,
//     with manual acknowledgement;
//   * DECLARE NOTHING. No exchange, no queue, no binding. §22.1 is a MUST NOT,
//     and note that this protocol gives you no method with which to;
//   * publish the reply to the delivery's `replyTo` through the default exchange,
//     echoing its `correlationID` property. What the server authenticates is the
//     `correlation_id` INSIDE the signed reply body — the runtime copies it from
//     the event for you.
//
// Everything above the transport — verify, dispatch, sign, publish-or-abstain —
// is `reactorServe`'s, including the rule that a failure of its own publishes
// NOTHING: a handler that throws, a body it cannot verify, or a window that has
// closed all produce no reply, and the registration's `failure_policy` decides.
actor DemoTransport: ReactorTransport {
    private var bodies: [Data]
    private(set) var published = 0

    init(bodies: [Data]) { self.bodies = bodies }

    func nextDelivery() async throws -> ReactorDelivery? {
        guard !bodies.isEmpty else { return nil }
        return ReactorDelivery(
            body: bodies.removeFirst(), replyTo: "amq.rabbitmq.reply-to.example")
    }

    func publishReply(destination: String, correlationID: String, body: Data) async throws {
        published += 1
        print("  → publish to \(destination) (correlation \(correlationID))")
        print("    \(String(data: body, encoding: .utf8) ?? "")")
    }
}

struct LoginPayload: Decodable {
    let sub: String?
    let ip: String?
}

let tenantID = env("AXIAM_TENANT_ID", "11111111-1111-1111-1111-111111111111")
let reactorID = env("AXIAM_REACTOR_ID", "99999999-9999-9999-9999-999999999999")

do {
    // -----------------------------------------------------------------------
    // §8b rules 1–5, BEFORE anything opens a socket.
    //
    // This is the constructor §8b rule 7's second clause names: where an SDK
    // takes a caller-supplied connection, it must still ship the guard, and that
    // guard is what its README and examples show. Documenting the requirement
    // instead is precisely the failure contract 1.23 was written to stop — three
    // SDKs asserting `amqps://` in a doc comment above a call that accepted
    // anything.
    // -----------------------------------------------------------------------
    print("§8b — the broker URL, checked before a socket exists")
    let endpoint = try amqpsEndpoint(
        env("AXIAM_AMQP_URL", "amqps://broker.internal:5671/prod"),
        caPEM: ProcessInfo.processInfo.environment["AXIAM_AMQP_CA_PEM"])
    print("  ok   \(endpoint.host):\(endpoint.port) vhost \(endpoint.virtualHost)")

    // There is NO loopback exception (§8b rule 8): §6's `http://localhost` dev
    // carve-out does not extend to the broker, and the server has no plaintext
    // listener for such an exception to reach.
    let plaintext = "amqp://localhost:5672"  // refused below — §8b rules 1 and 8
    do {
        _ = try amqpsEndpoint(plaintext)
        print("  FAIL plaintext localhost must be refused")
        exit(1)
    } catch {
        print("  ok   amqp://localhost is refused — no loopback exception")
    }

    // -----------------------------------------------------------------------
    // §22.14 — bind one handler per event.
    //
    // The alternative is a `switch` on `event.event` with a `default:` arm, and
    // that arm is where §22.14's second defect lives: it answers on behalf of
    // code that never ran, defeating an operator's `fail_closed` from a file they
    // never read. Here an unbound event ABSTAINS.
    //
    // This is a BUILDER rather than an attribute, and §22.14 records why: a Swift
    // reactor handler is an `async` closure, and collecting `async` members by
    // reflection costs a runtime dependency an SDK should not add to hand out an
    // attribute. The builder type-checks the closure at compile time instead.
    // -----------------------------------------------------------------------
    var router = ReactorRouter()
    try router.on(.loginPostAuth) { event in
        // The payload arrives as JSON TEXT — decode it into a type of your own.
        // Do NOT log it at info level by default (§22.12): it is tenant business
        // data, even though it is not a §7 secret.
        let payload = try event.decodePayload(LoginPayload.self)
        if payload.ip?.hasPrefix("203.0.113.") == true {
            // `allow` + require_mfa on login.post_auth means "proceed only after
            // step-up". It is not a fourth decision value, and on the federated
            // paths (SAML ACS, OIDC callback) there is no step-up branch — answer
            // `.deny` there and drive enrolment out of band (§22.5).
            return .allowWithStepUp
        }
        return .allow
    }
    try router.on(.tokenPreIssue) { _ in
        // `ext.` is the complete allow-list for this event: no standard claim
        // begins with it, so `sub`, `aud` and the rest are unreachable — a hook
        // that could rewrite `sub` is a hook that could mint a token for anyone.
        .mutate(["ext.department": "engineering"])
    }

    print("\n§22.8 — this reactor's strictest-wins default: "
        + ReactorFailurePolicy.strictestDefault(for: router.boundEvents).rawValue)
    print("§22.1 — the queue the SERVER declared and this reactor consumes: "
        + ReactorTopology.queueName(tenantID: tenantID, reactorID: reactorID))

    // -----------------------------------------------------------------------
    // §22.10 — the runtime, over the transport above.
    //
    // The signing key is the tenant's HKDF-derived AMQP subkey (§8.1) as RAW
    // BYTES. §22.12 makes it a credential: it must not appear at any log level,
    // nor in a reconnect diagnostic, which is why it is `Sensitive`.
    // -----------------------------------------------------------------------
    let signingKey = Sensitive(
        Data(env("AXIAM_REACTOR_SIGNING_KEY", "not-a-real-key").utf8))
    print("§22.12 — the signing key renders as \(signingKey)")

    let transport = DemoTransport(bodies: [Data(#"{"not":"a signed event"}"#.utf8)])
    let config = ReactorConfig(
        tenantID: tenantID, reactorID: reactorID, signingKey: signingKey)

    print("\n§22.3/§22.10 — verify, dispatch, sign, publish")
    try await reactorServe(config: config, transport: transport, handler: router.handler())

    // The delivery above is unsigned, so it is refused — and a refusal publishes
    // NOTHING rather than a synthesized allow (§22.10 rule 2). Point the
    // transport at a real broker and this is where replies start flowing.
    let published = await transport.published
    print("  \(published) replies published (an unsigned delivery is never answered)")
} catch {
    FileHandle.standardError.write(Data("axiam: \(error)\n".utf8))
    exit(1)
}
