// TokenExchange — the §15 RFC 8693 exchange: a backend holding a user's access token trades it
// for a NARROWER one before calling the next service.
//
// The rule the whole section is built to protect: an exchange only ever narrows. The server
// enforces it, and this SDK's job is to not hide the refusals — every one of them is the server
// telling you your assumption about your own privileges was wrong.
//
// Build:  swift build --target TokenExchangeExample
// Run:    swift run TokenExchangeExample

import Foundation
import AxiamSDK

func env(_ key: String, default fallback: String) -> String {
    ProcessInfo.processInfo.environment[key] ?? fallback
}

let baseURLString = env("AXIAM_BASE_URL", default: "https://localhost:8443")
guard let baseURL = URL(string: baseURLString) else {
    fatalError("Invalid AXIAM_BASE_URL: \(baseURLString)")
}

// The exchanging client authenticates (§15.1): unlike §14's device, this is a confidential
// service.
let config = try AxiamConfig(
    baseURL: baseURL,
    tenantID: env("AXIAM_TENANT_ID", default: "00000000-0000-0000-0000-000000000000"),
    oidcClientID: env("AXIAM_OIDC_CLIENT_ID", default: "orders-service"),
    oidcClientSecret: Sensitive(env("AXIAM_OIDC_CLIENT_SECRET", default: "service-secret")))
let client = try AxiamClient(config: config)

let subjectToken = Sensitive(env("AXIAM_SUBJECT_TOKEN", default: "the-users-access-token"))

do {
    // Passing an actorToken selects DELEGATION — "this service, acting for that user". Omitting
    // it selects IMPERSONATION — "this service, as that user". They are different operations
    // with different risk, and §15.2 rule 1 forbids papering over the difference: this SDK
    // supplies no default actor token and never substitutes its own session for one.
    let exchanged = try await client.tokenExchange(
        subjectToken: subjectToken,
        actorToken: Sensitive(env("AXIAM_ACTOR_TOKEN", default: "the-services-own-token")),
        scopes: ["orders:read"],
        audience: env("AXIAM_AUDIENCE", default: "inventory-service"))

    // Read the granted scope rather than assuming you got what you asked for: §15.2 rule 7 says
    // it may be narrower even on success, when your registration bounds the subject's.
    print("granted: \(exchanged.scope ?? "(the subject's own, inherited)")")
    // §15.2 rule 6: the issued type is surfaced, never dropped, so a client that asked for one
    // type and received another can tell.
    print("issued token type: \(exchanged.issuedTokenType)")
    print("valid for \(exchanged.expiresIn)s")

    // There is no refresh token here and there never will be (§15.2 rule 4) — re-run the
    // exchange to get a fresh one. And this token is NOT now the client's session (rule 5):
    // hand it onward in one outbound call, and nothing else this client does changes.
} catch let error as AxiamError {
    if case let .auth(authError) = error {
        switch authError.oauthError {
        case "unauthorized_client":
            // Surfaced verbatim (§15.2 rule 2). Either this client may not exchange at all, or
            // it may not impersonate; both are registration facts an operator must fix, and
            // reworking the request into a delegation would send one you never wrote.
            print("this client is not registered for that exchange. Fix the registration.")
        case "invalid_scope":
            // NOT a hint to retry with fewer scopes (§15.2 rule 3): the server refuses rather
            // than silently narrowing precisely so you find out here.
            print("the subject does not hold those scopes. Ask for fewer, deliberately.")
        case "invalid_grant":
            // Covers a cross-tenant subject token too, and this SDK does not try to tell which
            // (§15.3): the server collapses them because the distinction is a tenant-
            // enumeration signal.
            print("the subject or actor token was not accepted.")
        default:
            print("exchange failed: \(authError.oauthError ?? "no code")")
        }
    } else {
        print("exchange failed: \(error)")
    }
}

try? await client.shutdown()
