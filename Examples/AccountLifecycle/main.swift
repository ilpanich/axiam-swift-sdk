import AxiamSDK
import Foundation

// CONTRACT.md §25 — account lifecycle and MFA enrolment: the calls a user makes about
// their own account, none of which is administration.
//
// Five demonstrations:
//   1. Forced enrolment — the third `login` outcome. A tenant that requires MFA meets an
//      account that has none, and the login is neither a success nor a failure.
//   2. Voluntary enrolment — the same two calls from inside an existing session.
//   3. Email verification — unauthenticated, because a user whose address is unverified
//      may have no session at all.
//   4. The two resends (§25.7) — one for a caller with no session, one for a caller signed
//      in to the account it is asking about. They are not alternatives, and neither is
//      routed to the other.
//   5. Password reset — including the §23 detour a tenant with OPAQUE enabled forces, and
//      the enumeration guarantee that makes the first call return nothing useful on
//      purpose.
//
// Run: AXIAM_BASE_URL=… AXIAM_TENANT=… swift run AccountLifecycleExample

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

let tenantID = env("AXIAM_TENANT_ID", "00000000-0000-0000-0000-000000000000")

// ---------------------------------------------------------------------------
// 1. The third login outcome (§25.2 rule 1)
// ---------------------------------------------------------------------------

print("== login ==")
do {
    switch try await client.login(
        email: env("AXIAM_EMAIL", "alice@acme.test"),
        password: env("AXIAM_PASSWORD", "pw")
    ) {
    case let .mfaSetupRequired(setupToken):
        // Not a failure. The tenant requires MFA, this account has none, and the server
        // handed back a setup token to finish with. There is no session yet — the token IS
        // the credential for the next two calls.
        let enrollment = try await client.mfaSetupEnroll(setupToken: setupToken)
        print("  scan this: \(enrollment.totpURI.expose())")

        // mfaSetupConfirm completes the LOGIN, not just the enrolment: it adopts
        // credentials exactly as login does (§25.2 rule 2), so there is nothing left for
        // the caller to install.
        let user = try await client.mfaSetupConfirm(
            setupToken: setupToken,
            totpCode: env("AXIAM_TOTP_CODE", "123456")
        )
        print("  signed in as \(user.userID)")

    case .mfaRequired:
        // The account already HAS a factor — challenge it, don't enrol.
        try await client.verifyMfa(env("AXIAM_TOTP_CODE", "123456"))
        print("  signed in after an MFA challenge")

    case let .authenticated(user):
        print("  signed in as \(user.userID)")
    }
} catch {
    print("  login unavailable: \(error)")
}

// ---------------------------------------------------------------------------
// 2. Voluntary enrolment (§25.1)
// ---------------------------------------------------------------------------

print("== enrolling TOTP from inside a session ==")
do {
    let enrollment = try await client.mfaEnroll()

    // Both halves are Sensitive, and the second one matters: the otpauth URI CONTAINS the
    // secret (§25.3). Wrapping the bare secret and then printing the URI into a log leaks
    // exactly the same bytes.
    print("  secret (redacted when rendered): \(enrollment.secretBase32)")
    print("  [QR code for \(enrollment.totpURI.expose().prefix(20))...]")

    // Two calls, and the first is not enough: §25.2 rule 4 forbids a composed helper here,
    // because the human step in the middle — scanning the URI, reading a code — is not
    // something a helper can wait for.
    if try await client.mfaConfirm(env("AXIAM_TOTP_CODE", "123456")) {
        print("  MFA is live on this account")
    }

    // Note what did NOT happen: the §17 decision memo was not cleared. The subject has not
    // changed, and discarding a warm memo on an unrelated profile action costs a round trip
    // on every check that follows (§25.2 rule 3).
} catch {
    print("  enrolment unavailable: \(error)")
}

// ---------------------------------------------------------------------------
// 3. Email verification (§25.1) — no session required
// ---------------------------------------------------------------------------

print("== verifying an email address ==")
do {
    // The tenant is a BODY field here. §12.1 rule 2's ?tenant_id= convention is scoped to
    // the /oauth2 endpoints, and this is not one of those.
    try await client.verifyEmail(
        token: Sensitive(env("AXIAM_VERIFY_TOKEN", "paste-the-token-from-the-mail")),
        tenantID: tenantID
    )
    print("  verified")
} catch {
    print("  that link has expired — sending another")
    try? await client.resendVerification(email: "alice@acme.test", tenantID: tenantID)
}

// ---------------------------------------------------------------------------
// 4. The two resends (§25.7) — they look like one operation and are not
// ---------------------------------------------------------------------------

print("== resending a verification mail ==")

// (a) No session. A sign-up screen has an address and nothing else, so the server must
//     answer identically whether that address exists, is already verified, or is over the
//     daily limit: anything else is an oracle for which addresses have accounts (§25.4).
try? await client.resendVerification(email: "alice@acme.test", tenantID: tenantID)
print("  if that address needs verifying, a mail is on its way")

// (b) Signed in. A profile page's caller is already authenticated to the account it is
//     asking about, so none of the outcomes tells it anything it did not bring with it —
//     and this call therefore says which one happened. It names NO address: a parameter
//     here would let an authenticated session mail an arbitrary one.
do {
    try await client.resendOwnVerification()
    print("  enqueued — delivery is asynchronous and can still fail at the provider")
} catch AxiamError.authz {
    // 409: already verified, or an account state that must not be sent a live token.
    print("  nothing to send: that address is already verified")
} catch AxiamError.network {
    // 429: the daily resend limit. NOT retried against the unauthenticated endpoint —
    // §25.7 rule 2 forbids that fallback, which would turn this failure back into a silent
    // success and restore the bug this operation exists to fix.
    print("  the daily resend limit is reached; try again tomorrow")
} catch AxiamError.auth {
    // Including "no session at all", refused client-side with no wire call.
    print("  sign in first; the public resend is the one for an anonymous caller")
} catch {
    // `AxiamError` has exactly three cases, but the compiler sees `any Error` here, so a
    // top-level `do` still needs a catch-all to be exhaustive.
    print("  resend unavailable: \(error)")
}

// ---------------------------------------------------------------------------
// 5. Password reset (§25.4)
// ---------------------------------------------------------------------------

print("== resetting a password ==")
do {
    // Returns Void, whether or not the address exists, and this SDK exposes no way to tell
    // the two apart. That is not an omission to improve on: a client that surfaced a
    // "no such user" state — even one inferred from timing — would turn the endpoint into
    // the account-enumeration oracle its uniform response exists to prevent.
    try await client.requestPasswordReset(PasswordResetRequest(email: "alice@acme.test"))
    print("  if that address has an account, a mail is on its way")

    let token = Sensitive(env("AXIAM_RESET_TOKEN", "paste-the-token-from-the-mail"))

    // Ask the context BEFORE building anything. On a tenant with §23 enabled the client has
    // to construct an OPAQUE registration record, and building one needs parameters it
    // cannot know before it has a token to ask with. Sending a plaintext password to a
    // tenant in opaque_mode: required is refused, and refused late (§25.4 rule 1).
    let context = try await client.passwordResetContext(token: token)

    if context.hasOpaquePolicy {
        print("  this tenant uses OPAQUE: \(context.opaqueObject() ?? [:])")
        // Build the record with the SDK's §23 helpers, then pass it as
        // PasswordResetConfirmation.opaqueData.
    } else {
        try await client.confirmPasswordReset(PasswordResetConfirmation(
            token: token,
            newPassword: Sensitive("a new correct horse battery staple"),
            tenantID: tenantID
        ))
        print("  password changed")
    }
} catch {
    // A 404 means unknown, expired OR already-consumed, deliberately without
    // distinguishing them (§25.4 rule 3). Neither does this.
    print("  that reset link is no longer usable")
}
