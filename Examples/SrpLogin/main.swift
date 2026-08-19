// SrpLogin — the SRP-6a login path (CONTRACT.md §23).
//
// SRP proves the password to the server without the password — or anything from
// which it can be cheaply recovered — ever crossing the wire. What the server
// receives is `A` and a proof, neither of which is useful without the account's
// verifier, so a TLS-terminating proxy, an accidentally verbose request log or a
// heap dump cannot capture a plaintext password.
//
// It does NOT protect against a compromised AXIAM server. Nothing client-side can.
//
// Three things this example is built to show:
//
//   1. `loginSrp` returns the SAME `LoginResult` as `login`, MFA branch included,
//      so the result handling below is identical to Examples/LoginMFA.
//   2. A tenant with `srp_mode: disabled` answers the challenge endpoint with 404,
//      which reaches the caller as `.network` and NOT as a credential failure — so
//      falling back to `login` is correct and safe.
//   3. A tenant with `srp_mode: required` answers `/auth/login` with
//      `403 srp_required`, which is `.authz`. A user whose password is perfectly
//      good must never be told it is invalid.
//
// §23.8 makes SRP conditional here in one respect: Swift has no Argon2 that ships
// on every supported platform, so a tenant configured for `argon2id` is refused
// with a clear message rather than served a wrong derivation. Set the tenant's
// `srp_kdf` to `pbkdf2_sha256` for Swift clients.
//
// Illustrative and self-contained: it reads connection details from environment
// variables and compiles without a live AXIAM server.
//
// Build:  swift build --target SrpLoginExample
// Run:    swift run SrpLoginExample

import Foundation
import AxiamSDK

func env(_ key: String, default fallback: String) -> String {
    ProcessInfo.processInfo.environment[key] ?? fallback
}

let baseURLString = env("AXIAM_BASE_URL", default: "https://localhost:8443")
let tenantSlug = env("AXIAM_TENANT_SLUG", default: "acme")
let orgSlug = env("AXIAM_ORG_SLUG", default: "acme")
let username = env("AXIAM_USERNAME", default: "alice")
let password = env("AXIAM_PASSWORD", default: "changeme")
let totpCode = env("AXIAM_TOTP_CODE", default: "000000")

guard let baseURL = URL(string: baseURLString) else {
    FileHandle.standardError.write(Data("invalid AXIAM_BASE_URL\n".utf8))
    exit(1)
}

let config = try AxiamConfig(
    baseURL: baseURL,
    tenantSlug: tenantSlug,
    orgSlug: orgSlug
)
let client = try AxiamClient(config: config)

// §23.1 puts this probe in every SDK's vocabulary. On Swift it is `true`; the
// Argon2 probe is the one that says no.
let available = await client.srpAvailable
if !available {
    FileHandle.standardError.write(Data("this build cannot perform SRP\n".utf8))
    exit(1)
}
if !Srp.argon2Available {
    print("note: this SDK has no argon2id (§23.8); a tenant configured for it will be")
    print("      refused with a clear message rather than served a wrong derivation.")
}

do {
    let result: LoginResult
    do {
        result = try await client.loginSrp(usernameOrEmail: username, password: password)
    } catch AxiamError.network(let error) {
        // A tenant that has not enabled SRP, or a KDF this SDK cannot do, is not a
        // failed login. Fall back rather than reporting a credential problem the
        // user does not have.
        print("SRP unavailable here (\(error.message)) — falling back to password login")
        result = try await client.login(email: username, password: password)
    }

    switch result {
    case .authenticated(let user):
        print("authenticated as \(user.userID)")
    case .mfaRequired:
        // Identical to the non-SRP path — that is the point of §23.1's
        // same-result-type requirement. `verifyMfa` completes the session in
        // place rather than returning a second result.
        try await client.verifyMfa(totpCode)
        print("authenticated after MFA")
    case .mfaSetupRequired:
        print("this account must complete MFA enrolment first")
    }

    // Enrolment, for any request that SETS a password. The server cannot compute a
    // verifier — it never sees the plaintext — so it has to arrive with the request
    // or not at all. Read the tenant's parameters from GET /api/v1/auth/me (or the
    // reset context) rather than hard-coding them: the server dictates the costs
    // per exchange, and a verifier enrolled under different costs stays valid.
    if let newPassword = ProcessInfo.processInfo.environment["AXIAM_NEW_PASSWORD"],
       !newPassword.isEmpty {
        let enrolment = try await client.srpEnrollment(
            // The account's USERNAME, which is the canonical identity the challenge
            // endpoint hands back. An email here produces a verifier no login can
            // ever satisfy.
            identity: username,
            password: newPassword
        )
        // Encode this as the `srp` member of the change-password body. Never log the
        // salt or verifier: they are §23.3 rule 12 material, which is why only the
        // parameters are printed here.
        print("enrolment ready: group=\(enrolment.group) kdf=\(enrolment.kdf)")
    }
} catch AxiamError.authz(let error) {
    // srp_mode: required, reached through login(). The credentials were never
    // examined.
    FileHandle.standardError.write(Data("this tenant refuses password login: \(error.message)\n".utf8))
    try? await client.shutdown()
    exit(1)
} catch {
    // Illustrative: without a reachable server this is the expected path.
    FileHandle.standardError.write(Data("login failed: \(error)\n".utf8))
    try? await client.shutdown()
    exit(1)
}

try await client.shutdown()
