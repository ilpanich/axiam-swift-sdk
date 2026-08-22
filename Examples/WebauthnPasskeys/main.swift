import AxiamSDK
import Foundation

#if canImport(AuthenticationServices)
import AuthenticationServices
#endif

// CONTRACT.md §24 — WebAuthn / passkeys, from Swift.
//
// This is the SDK where the two halves of §24.6 are both real. On iOS 16+ and macOS 13+
// the §24.6b linked-API helpers drive `AuthenticationServices` directly, so a passkey is
// three lines. On Linux — a supported target of this SDK — the framework does not exist,
// §24.6b's helpers are compiled out, and §24.6a's JSON bridge is what a caller uses
// instead. The relying-party layer is identical on both.
//
// Run: AXIAM_BASE_URL=… AXIAM_TENANT=… swift run WebauthnPasskeysExample

func env(_ key: String, _ fallback: String) -> String {
    ProcessInfo.processInfo.environment[key].flatMap { $0.isEmpty ? nil : $0 } ?? fallback
}

let config = try AxiamConfig(
    baseURL: URL(string: env("AXIAM_BASE_URL", "https://localhost:8443"))!,
    tenantSlug: env("AXIAM_TENANT", "acme"),
    orgSlug: env("AXIAM_ORG_SLUG", "acme")
)
let client = try AxiamClient(config: config)
defer { Task { try? await client.close() } }

// ---------------------------------------------------------------------------
// 0. Feature detection is a query, not an exception (§24.6b rule 6)
// ---------------------------------------------------------------------------

print("== can this runtime run a ceremony? ==")
print("  ceremony helper: \(client.webauthnCeremonySupported)")
print("  conditional mediation (passkey autofill): \(client.webauthnConditionalMediationSupported)")
// A caller hides the "Sign in with a passkey" button rather than offering one that throws.

// ---------------------------------------------------------------------------
// 1. Enrolment — requires a session (§24.1)
// ---------------------------------------------------------------------------

print("== enrolling a passkey ==")
do {
    _ = try await client.login(
        email: env("AXIAM_EMAIL", "alice@acme.test"),
        password: env("AXIAM_PASSWORD", "pw")
    )

    // The server chooses every option: the challenge, the RP id, the algorithms, the
    // attestation policy, whether a resident key is required. This SDK defaults nothing and
    // validates nothing (§24.0) — a client that "helpfully" filled in a missing field would
    // be overriding a policy decision it cannot see.
    let challenge = try await client.webauthnRegisterStart()

    // §24.6a rule 1: the wire JSON form, ready for whatever runs the ceremony. On Linux
    // this is what you send to the browser half; on Apple platforms the §24.6b helper
    // below consumes the same string internally.
    print("  options: \(challenge.requestJson)")

    let credential = try await client.webauthnRegisterFinish(
        stateToken: challenge.stateToken,
        credentialName: "Alice's laptop",
        response: authenticatorResponseFromSomewhere()
    )
    print("  enrolled: \(credential.name) (\(credential.credentialType)), id \(credential.id)")
} catch let AxiamError.authz(error) {
    // §24.4 rule 1: a 403 here is the tenant's ATTESTATION POLICY rejecting this particular
    // authenticator, and the server's message is the only place that says which one would
    // be accepted. Printing a generic "forbidden" strands the person holding the key.
    print("  policy refused this authenticator: \(error.message)")
} catch let AxiamError.auth(error) {
    print("  not signed in — passkey enrolment needs a session: \(error.message)")
} catch {
    // §24.4 rule 2: a 503 from register/start means the tenant's attestation policy needs
    // FIDO metadata the server cannot reach. That is a CONFIGURATION state, not a transient
    // one — the SDK does not retry it, and neither should this loop.
    print("  enrolment unavailable: \(error)")
}

// ---------------------------------------------------------------------------
// 2. Sign-in — the discoverable ceremony (§24.1)
// ---------------------------------------------------------------------------

print("== signing in with a passkey ==")
do {
    // No username. The authenticator already knows which accounts it holds for this relying
    // party, so the workspace — not the user — is what the server needs, and it comes from
    // the client's own configuration when the argument is nil.
    let challenge = try await client.webauthnDiscoverableStart()

    let result = try await client.webauthnDiscoverableFinish(
        stateToken: challenge.stateToken,
        response: assertionFromSomewhere()
    )

    // As of contract 1.28 the server sets the session cookie triple on this response as
    // well, so the client is signed in for every cookie-driven call that follows. Before
    // that fix a completed ceremony left the caller with no session at all.
    print("  signed in, session \(result.sessionID) valid for \(result.expiresIn)s")
} catch {
    print("  the ceremony did not complete: \(error)")
}

// ---------------------------------------------------------------------------
// 3. The §24.6b helper — one call, on the platforms that have an authenticator
// ---------------------------------------------------------------------------

#if canImport(AuthenticationServices)
if #available(iOS 16.0, macOS 13.0, *) {
    print("== §24.6b: the composed helpers ==")
    print("""
          // In an app, with a window to present over:
          final class Anchor: WebauthnPresentationAnchorProviding {
              @MainActor func webauthnPresentationAnchor() -> ASPresentationAnchor { window }
          }

          // Enrol. `attachment` is the ONE permitted addition to the server's options
          // (§24.6b rule 4), and only from this explicit argument — without it a user who
          // asked for a security key is prompted for Face ID instead.
          let credential = try await client.webauthnRegister(
              credentialName: "iPhone",
              anchor: anchor,
              attachment: .platform
          )

          // Sign in, with passkey autofill where the platform supports it. A conditional
          // ceremony may never settle — the user simply may not pick a passkey — so cancel
          // the enclosing Task to abandon it. That is a cancellation, not an
          // authentication failure (§24.6b rule 3).
          let session = try await client.webauthnDiscoverableLogin(
              anchor: anchor,
              conditional: client.webauthnConditionalMediationSupported
          )
          """)
}
#else
print("== §24.6b: absent on this platform, and §24.6a is the complete answer ==")
print("""
      No AuthenticationServices here, so no ceremony helper — §24.6b rule 2 forbids
      emulating an authenticator in software, and a "credential" held in process memory
      is not a second factor. Send `challenge.requestJson` to whatever does have one
      (a browser, an app) and pass its response JSON back into the matching *Finish.
      Nothing is destructured, nothing is re-encoded.
      """)
#endif

// ---------------------------------------------------------------------------
// 4. Saying something useful when the ceremony fails (§24.6b rule 5)
// ---------------------------------------------------------------------------

print("== classifying a ceremony failure ==")

// Every platform reports a ceremony failure as one opaque type whose only
// machine-readable part is a name. Translating that once beats translating it in every
// caller — and the classification is available on EVERY build, including Linux, where a
// browser front end still relays DOMException names.
let outcome = WebauthnFailure.classify("InvalidStateError")
print("  \(outcome.rawValue): \(outcome.message)")

// The distinction that matters: alreadyRegistered is the only one whose remedy is "use a
// different device" rather than "try again".
precondition(outcome == .alreadyRegistered)

// And the one that must never accuse the user. `cancelled` covers both an explicit refusal
// and a silent timeout, because the spec refuses to distinguish them — telling a website
// which happened would leak whether an authenticator was present.
print("  \(WebauthnFailure.classify("NotAllowedError").message)")

// ---------------------------------------------------------------------------

/// Stands in for whatever ran the ceremony — a browser, an app, a test authenticator.
func authenticatorResponseFromSomewhere() -> String {
    """
    {"id":"Y3JlZC1pZA","rawId":"Y3JlZC1pZA",
     "response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0",
                 "attestationObject":"o2NmbXRkbm9uZQ"},
     "type":"public-key","clientExtensionResults":{}}
    """
}

func assertionFromSomewhere() -> String {
    """
    {"id":"Y3JlZC1pZA","rawId":"Y3JlZC1pZA",
     "response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",
                 "authenticatorData":"YXV0aC1kYXRh","signature":"c2ln",
                 "userHandle":"dXNlci1oYW5kbGU"},
     "type":"public-key","clientExtensionResults":{}}
    """
}
