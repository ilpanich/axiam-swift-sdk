// OpaqueLogin — the OPAQUE login path, RFC 9807 (CONTRACT.md §23).
//
// OPAQUE proves the password to the server without the password — or anything
// from which it can be cheaply recovered — ever crossing the wire. What the
// server receives is a blinded group element and a MAC, neither of which is
// useful without the account's registration record AND the tenant's OPRF seed.
// So a TLS-terminating proxy, an accidentally verbose request log or a heap dump
// cannot capture a plaintext password: the server never has one.
//
// It also does something the SRP-6a this replaces could not: a stolen record
// database is not offline-crackable on its own. That is the pre-computation
// resistance, and it is the substantive reason for the migration.
//
// It does NOT protect against a compromised AXIAM server. Nothing client-side can.
//
// Four things this example is built to show:
//
//   1. `loginOpaque` returns the SAME `LoginResult` as `login`, MFA branch
//      included, so the result handling below is identical to Examples/LoginMFA.
//   2. A tenant with `opaque_mode: disabled` answers `*/start` with 404, which
//      reaches the caller as `.network` and NOT as a credential failure — so
//      falling back to `login` is correct and safe.
//   3. `.auth` means the envelope did not open. That is the whole credential
//      check, and it is NOT a case to retry over `login`: retrying would hand
//      the plaintext to an endpoint that has just failed to prove it holds the
//      record. RFC 9807's AKE authenticates the server during the handshake,
//      so opening `KE2` IS the server's proof — there is no separate `M2` step
//      the old SRP §23.3 rule 6 had to mandate in capitals.
//   4. A tenant with `opaque_mode: required` answers `/auth/login` with
//      `403 opaque_required`, which is `.authz`. A user whose password is
//      perfectly good must never be told it is invalid.
//
// What changed for Swift specifically: the SRP client was doubly conditional.
// Swift has no Argon2 that ships on every supported platform, so a tenant on
// AXIAM's DEFAULT `argon2id` was refused outright and had to be reconfigured to
// `pbkdf2_sha256` for Swift callers. The key stretching now happens inside
// `libaxiam_opaque_ffi`, so that condition is gone: the only remaining one is
// having the library, which `opaqueAvailable()` reports honestly.
//
// The library is a per-platform GitHub release asset of `ilpanich/axiam-opaque`,
// not a SwiftPM package — it is resolved with `dlopen` at run time so a consumer
// who never uses OPAQUE is not made to link it. Point `AXIAM_OPAQUE_LIBRARY` at
// it, or install it where the dynamic loader already looks.
//
// Illustrative and self-contained: it reads connection details from environment
// variables and compiles without a live AXIAM server.
//
// Build:  swift build --target OpaqueLoginExample
// Run:    swift run OpaqueLoginExample

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

// §23.2 puts this probe in every SDK's vocabulary, and on Swift it genuinely can
// say no — unlike `srpAvailable`, which was hard-coded `true` while an argon2id
// tenant still failed at login. Ask it BEFORE collecting a password: there is no
// point prompting for one this installation cannot use.
let opaqueReady = await client.opaqueAvailable()
if !opaqueReady {
    FileHandle.standardError.write(Data("""
        this installation cannot perform OPAQUE: libaxiam_opaque_ffi was not found.
        Install the release asset for this platform from ilpanich/axiam-opaque and
        set AXIAM_OPAQUE_LIBRARY to its path.

        """.utf8))
    try? await client.shutdown()
    exit(1)
}

do {
    let result: LoginResult
    do {
        result = try await client.loginOpaque(usernameOrEmail: username, password: password)
    } catch AxiamError.network(let error) {
        // The ONLY case that may fall back. A tenant that has not enabled OPAQUE,
        // a missing library, a key-stretching function this SDK cannot ask for,
        // and a malformed response are all configuration facts, not credential
        // facts — reporting them as a bad password would send a user off to reset
        // one that works.
        //
        // `.auth` is deliberately not caught here. See point 3 in the header.
        print("OPAQUE unavailable here (\(error.message)) — falling back to password login")
        result = try await client.login(email: username, password: password)
    }

    switch result {
    case .authenticated(let user):
        print("authenticated as \(user.userID)")
    case .mfaRequired:
        // Identical to the non-OPAQUE path — that is the point of §23.1's
        // same-result-type requirement. `verifyMfa` completes the session in
        // place rather than returning a second result.
        try await client.verifyMfa(totpCode)
        print("authenticated after MFA")
    case .mfaSetupRequired:
        print("this account must complete MFA enrolment first")
    }

    // Enrolment, for any request that SETS a password. The server cannot build a
    // registration record — it never sees the plaintext — so it has to arrive with
    // the request or not at all.
    //
    // Unlike the SRP enrolment this replaces, it performs I/O: one `register/start`
    // round trip, because OPAQUE's envelope is sealed under the server's oblivious
    // PRF and there is no offline computation that produces a valid record.
    //
    // Note the arguments that are GONE. There is no `identity`: SRP needed the
    // account's canonical username, and an email there produced a verifier no login
    // could ever satisfy — a record binds to a credential identifier the server
    // chooses, so renaming a user no longer invalidates their credential. There is
    // no `group` and no `kdf` either: the server names the key-stretching function
    // per exchange, so a caller cannot pick a cost the server will not honour.
    if let newPassword = ProcessInfo.processInfo.environment["AXIAM_NEW_PASSWORD"],
       !newPassword.isEmpty {
        let enrolment = try await client.opaqueEnrollment(password: newPassword)
        // Encode this as the `opaque` member of the change-password body. Never log
        // `registration_record`: it is the credential material, which is why only
        // the session handle's presence is reported here.
        print("enrolment ready: opaque_session=\(enrolment.opaque_session.isEmpty ? "<missing>" : "<issued>")")
    }
} catch AxiamError.auth {
    // The envelope did not open: a wrong password, an account that does not exist,
    // or a server that does not hold the record — indistinguishable by design.
    // Nothing was sent to `login/finish` (§23.4 rule 7), and this must NOT be
    // retried over `login`.
    FileHandle.standardError.write(Data("invalid credentials\n".utf8))
    try? await client.shutdown()
    exit(1)
} catch AxiamError.authz(let error) {
    // opaque_mode: required, reached through login(). The credentials were never
    // examined.
    FileHandle.standardError.write(
        Data("this tenant refuses password login: \(error.message)\n".utf8))
    try? await client.shutdown()
    exit(1)
} catch {
    // Illustrative: without a reachable server this is the expected path.
    FileHandle.standardError.write(Data("login failed: \(error)\n".utf8))
    try? await client.shutdown()
    exit(1)
}

try await client.shutdown()
