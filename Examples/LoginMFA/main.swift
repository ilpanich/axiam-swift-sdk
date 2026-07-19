// LoginMFA — the two-phase login / verifyMfa flow (CONTRACT.md §1, §5, §5.1).
//
// Demonstrates:
//   - Constructing an `AxiamConfig` with a non-optional `tenantSlug` (§5 — there is
//     no default tenant) AND an `orgSlug` (§5.1 — login/refresh require organization
//     context, since a tenant slug is only unique within an organization; the server
//     rejects a login with no org identifier: HTTP 400 "must provide org_id or org_slug").
//   - Calling `login`, branching on the `LoginResult` enum, and completing the MFA
//     challenge with `verifyMfa(_:)` when the server responds with `.mfaRequired`.
//
// This example is illustrative and self-contained: it reads connection details from
// environment variables (with defaults) and compiles without a live AXIAM server.
// Running it end-to-end requires a reachable AXIAM server matching the base URL.
//
// Build:  swift build --target LoginMFAExample
// Run:    swift run LoginMFAExample

import Foundation
import AxiamSDK

func env(_ key: String, default fallback: String) -> String {
    ProcessInfo.processInfo.environment[key] ?? fallback
}

let baseURLString = env("AXIAM_BASE_URL", default: "https://localhost:8443")
let tenantSlug = env("AXIAM_TENANT_SLUG", default: "acme")
let orgSlug = env("AXIAM_ORG_SLUG", default: "acme")
let email = env("AXIAM_EMAIL", default: "user@example.com")
let password = env("AXIAM_PASSWORD", default: "changeme")
let totpCode = env("AXIAM_TOTP_CODE", default: "000000")

guard let baseURL = URL(string: baseURLString) else {
    fatalError("Invalid AXIAM_BASE_URL: \(baseURLString)")
}

// §5: `tenantSlug` is mandatory (empty ⇒ AuthError, never a silent default).
// §5.1: `orgSlug` supplies the organization context login/refresh require.
let config = try AxiamConfig(baseURL: baseURL, tenantSlug: tenantSlug, orgSlug: orgSlug)
let client = try AxiamClient(config: config)

do {
    // POST /api/v1/auth/login (CONTRACT.md §1).
    switch try await client.login(email: email, password: password) {
    case .authenticated(let user):
        print("Login complete (no MFA) — user: \(user.userID)")

    case .mfaRequired(let methods):
        print("MFA required — available methods: \(methods)")
        // POST /api/v1/auth/mfa/verify — the challenge token from the preceding
        // login() call is retained internally (as Sensitive), so verifyMfa needs
        // only the user-supplied TOTP code (§1's exact `verifyMfa(code)` shape).
        try await client.verifyMfa(totpCode)
        print("MFA verified — session established")

    case .mfaSetupRequired:
        print("MFA enrolment required before this account can authenticate")
    }

    // Tokens are delivered via httpOnly cookies and never surfaced here (§4/§7).
    try await client.logout()
} catch AxiamError.auth(let error) {
    print("Authentication failed: \(error.message)")
} catch AxiamError.network(let error) {
    print("Transport failure: \(error.message)")
}

// Release the underlying HTTP client.
try await client.shutdown()
