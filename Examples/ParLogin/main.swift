import AxiamSDK
import Foundation

// CONTRACT.md §26 — Pushed Authorization Requests (RFC 9126).
//
// PAR moves the authorization request off the browser. Instead of putting `scope`,
// `redirect_uri`, `state` and the PKCE challenge into a URL the user agent carries, the
// client POSTs them straight to AXIAM over an authenticated back channel and puts an opaque
// `request_uri` in the redirect. What travels through the browser is then a random string
// that cannot be edited into meaning something else.
//
// A FAPI 2.0 client has no choice: `profile: "fapi2"` refuses a registration that does not
// set `require_par`, so such a client cannot authorize any other way (§21.1).
//
// Run: AXIAM_BASE_URL=… AXIAM_TENANT_ID=… AXIAM_CLIENT_ID=… swift run ParLoginExample

func env(_ key: String, _ fallback: String) -> String {
    ProcessInfo.processInfo.environment[key].flatMap { $0.isEmpty ? nil : $0 } ?? fallback
}

let redirectURI = env("AXIAM_REDIRECT_URI", "https://app.example.com/callback")

let config = try AxiamConfig(
    baseURL: URL(string: env("AXIAM_BASE_URL", "https://localhost:8443"))!,
    tenantID: env("AXIAM_TENANT_ID", "00000000-0000-0000-0000-000000000000"),
    oidcClientID: env("AXIAM_CLIENT_ID", "app"),
    oidcClientSecret: Sensitive(env("AXIAM_CLIENT_SECRET", "s3cret"))
)
let client = try AxiamClient(config: config)
defer { Task { try? await client.close() } }

do {
    let document = try await client.oidcDiscover()

    // §26 is optional, so a server may advertise no endpoint at all. The SDK refuses
    // client-side rather than concatenating a URL onto the issuer and POSTing a
    // fully-formed authorization request at a 404 (§12.7.2 rule 1).
    guard document.pushedAuthorizationRequestEndpoint != nil else {
        print("this server does not support RFC 9126 — fall back to the plain oidcBegin redirect")
        exit(0)
    }

    // oidcBegin still runs first, and still owns state/nonce/PKCE. §26.2 rule 1 forbids a
    // second generator: two sources for any of those are two things that can disagree.
    let begun = try client.oidcBegin(
        redirectURI: redirectURI,
        scope: "openid profile",
        configuration: document
    )

    let pushed = try await client.oidcPar(
        request: begun,
        redirectURI: redirectURI,
        scope: "openid profile",
        configuration: document
    )
    // Note there is no retry here, and there must not be. This is a POST that creates
    // server state, so it falls outside §16.2's read-only eligibility. The safe recovery is
    // a fresh push, which costs one round trip and cannot double-consume anything
    // (§26.2 rule 4).

    // The URL carries EXACTLY client_id and request_uri. The server refuses a request that
    // mixes a request_uri with inline authorization parameters rather than merging them —
    // an attacker supplies the inline value they want and lets the pushed copy satisfy
    // whichever check reads the other one. Re-adding scope "for compatibility" restores the
    // attack (§26.2 rule 2).
    print("redirect the browser to: \(pushed.url)")
    print("the handle expires in \(pushed.expiresIn)s")

    // Persist these three exactly as a non-PAR login would — the redirect being opaque
    // changes nothing about the callback's obligations. The SDK stores nothing (§12.3
    // rule 1).
    print("  stashed state/nonce/verifier for the callback")

    let returnedState = env("AXIAM_STATE", "the-state-from-the-redirect")
    guard pushed.state == returnedState else {
        // state is not a secret (§12.3 rule 2), but this comparison is the CSRF guard, so a
        // real application makes it constant-time.
        print("state mismatch — drop this callback on the floor")
        exit(0)
    }

    // The exchange is the ordinary §12 one. The request_uri is spent by now: it is
    // single-use, and a second redirect through it fails.
    let tokens = try await client.oidcExchange(
        code: env("AXIAM_AUTH_CODE", "the-code-from-the-redirect"),
        redirectURI: redirectURI,
        codeVerifier: pushed.codeVerifier,
        nonce: pushed.nonce,
        configuration: document
    )
    print("signed in, id token subject: \(tokens.idClaims?.subject ?? "(none)")")
} catch {
    print("no reachable server, or the push did not complete: \(error)")
}
