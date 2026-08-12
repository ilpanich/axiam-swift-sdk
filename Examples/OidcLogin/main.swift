// OidcLogin — the §12 relying-party flow, and the §12.7 logout that ends it.
//
// "Login with AXIAM", in the three steps §12 splits it into:
//
//   1. `oidcBegin` builds the authorization URL. Local computation — no network I/O of its
//      own — and it hands back `state`, `nonce` and `codeVerifier`.
//   2. YOUR APPLICATION stores those three. This SDK does not (§12.3 rule 1): not on the
//      client, not in a global, not in an implicit cache. A real web app puts them in its own
//      HTTP session, keyed by `state`, and this example just keeps them in a local.
//   3. `oidcExchange` trades the callback's `code` for tokens, replaying `codeVerifier` and
//      `nonce`. Every §12.4 rule runs on the returned ID token before it comes back, and rule 7
//      makes that all-or-nothing: a validation failure discards the access and refresh tokens
//      from the same response too.
//
// Build:  swift build --target OidcLoginExample
// Run:    swift run OidcLoginExample

import Foundation
import AxiamSDK

func env(_ key: String, default fallback: String) -> String {
    ProcessInfo.processInfo.environment[key] ?? fallback
}

let baseURLString = env("AXIAM_BASE_URL", default: "https://localhost:8443")
guard let baseURL = URL(string: baseURLString) else {
    fatalError("Invalid AXIAM_BASE_URL: \(baseURLString)")
}

let config = try AxiamConfig(
    baseURL: baseURL,
    // §12.3 rule 4: the five token-endpoint operations need a tenant UUID for the query
    // parameter. A slug-only client is refused client-side, with no wire call.
    tenantID: env("AXIAM_TENANT_ID", default: "00000000-0000-0000-0000-000000000000"),
    oidcClientID: env("AXIAM_OIDC_CLIENT_ID", default: "my-app"),
    // Omit for a public client: authorization-code + PKCE does not need a secret.
    oidcClientSecret: Sensitive(env("AXIAM_OIDC_CLIENT_SECRET", default: "client-secret")))
let client = try AxiamClient(config: config)

do {
    let configuration = try await client.oidcDiscover()
    // The document's own issuer is authoritative (§12.3 rule 6) even when it differs from the
    // base URL — behind a proxy it legitimately does.
    print("issuer: \(configuration.issuer)")

    // ---- 1. Begin ----
    // `await` because AxiamClient is an actor, not because this touches the network: §12.1
    // keeps oidcBegin free of I/O, and it is.
    let request = try await client.oidcBegin(
        redirectURI: env("AXIAM_OIDC_REDIRECT_URI", default: "https://app.example/callback"),
        configuration: configuration)

    // ---- 2. The application's storage, not the SDK's ----
    //
    // Neither `state` nor `nonce` is a secret (§12.3 rule 2) — they are correlation values the
    // caller must be able to compare — so printing them is fine. The `codeVerifier` is not, and
    // is not printed.
    let session = (state: request.state, nonce: request.nonce, verifier: request.codeVerifier)
    print("send the user to: \(request.url)")
    print("stored state=\(session.state) (compare it on the callback)")

    // ---- 3. Exchange ----
    //
    // In a real app `code` and the returned `state` arrive on the callback request; check the
    // state matches what you stored BEFORE exchanging.
    let code = env("AXIAM_OIDC_CODE", default: "")
    guard !code.isEmpty else {
        print("set AXIAM_OIDC_CODE to the callback's code to run the exchange.")
        try? await client.shutdown()
        exit(0)
    }

    let tokens = try await client.oidcExchange(
        code: code,
        // Byte-identical to the one oidcBegin was given: the server compares them exactly.
        redirectURI: env("AXIAM_OIDC_REDIRECT_URI", default: "https://app.example/callback"),
        codeVerifier: session.verifier,
        nonce: session.nonce,
        configuration: configuration)

    // The claims come from the validated ID token (§12.3 rule 5) — never from
    // /oauth2/userinfo, which §12 keeps out of the vocabulary entirely.
    if let claims = tokens.idClaims {
        print("signed in: \(claims.subject) (\(claims.email ?? "no email"))")
    }
    print("access token expires in \(tokens.expiresIn)s")

    // ---- §12.7: ending the session ----
    //
    // Building the URL clears nothing locally (§12.7.2 rule 4): a backend holding a
    // service-account session must not lose it because a *user* logged out.
    if let idToken = tokens.idToken {
        let url = try await client.logoutURL(
            idToken: idToken,
            postLogoutRedirectURI: env("AXIAM_POST_LOGOUT_URI", default: "https://app.example/"),
            // The state is the caller's to generate and the caller's to check — the SDK never
            // invents one, because the value only means something to the app that receives it.
            state: "logout-\(session.state)",
            configuration: configuration)
        print("to log out, send the user to: \(url)")
    }
} catch {
    print("failed: \(error)")
}

try? await client.shutdown()
