# AXIAM Swift SDK

[![CI](https://github.com/ilpanich/axiam-swift-sdk/actions/workflows/sdk-ci-swift.yml/badge.svg?branch=main)](https://github.com/ilpanich/axiam-swift-sdk/actions/workflows/sdk-ci-swift.yml)
[![Coverage Status](https://coveralls.io/repos/github/ilpanich/axiam-swift-sdk/badge.svg?branch=main)](https://coveralls.io/github/ilpanich/axiam-swift-sdk?branch=main)
[![Swift](https://img.shields.io/badge/Swift-5.9%2B-orange.svg)](https://swift.org)
[![Platforms](https://img.shields.io/badge/platforms-macOS%20%7C%20iOS%20%7C%20Linux-lightgrey.svg)](https://swift.org)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![SPM](https://img.shields.io/badge/SwiftPM-compatible-brightgreen.svg)](https://swift.org/package-manager)
[![Docs](https://img.shields.io/badge/docs-DocC-blue.svg)](https://ilpanich.github.io/axiam-swift-sdk/)

The official Swift SDK for **AXIAM** (Access eXtended Identity and Authorization Management).

**Platform documentation:** <https://ilpanich.github.io/axiam/> — getting started, the authorization model, the OAuth2/OIDC surface, and the operations guides. This README covers the SDK; the site covers the server it talks to.

> **This SDK conforms to CONTRACT.md §1–§7, §9–§13, §14, §15, §17, §19, §20, §21, §22, §23,
> §24, §25 and §26 (including §6.1 mTLS, §12.7 logout, the §11 rule 9 decision reason codes, and
> the §23 OPAQUE login path — which needs `libaxiam_opaque_ffi` installed, see below).**
>
> §22 is §22.1–§22.8 and §22.14 over a **caller-supplied transport**: this SDK vendors no AMQP
> client, and you conform `ReactorTransport` over whichever one you already trust (§22.11).
> "Conforms to … §22" is the claim; "ships an AMQP client" is not.
>
> Sections are named individually rather than folded into ranges: widening a
> range silently turns a statement that was true when written into a different
> claim. **§16 and §18 are absent by that same rule, not by omission** — the
> contract makes retry policy and deterministic shutdown MUST-level and says
> they are not named, because an SDK is either conformant on them or it is not.
> This one is.

It is a REST client built on [`async-http-client`](https://github.com/swift-server/async-http-client)
+ [`swift-nio-ssl`](https://github.com/apple/swift-nio-ssl) (so custom-CA and client-certificate
mutual TLS work on **Linux** as well as Apple platforms) and
[`swift-crypto`](https://github.com/apple/swift-crypto) for EdDSA/Ed25519 JWKS verification.

> URLSession is deliberately **not** used: client-certificate mTLS (§6.1) via URLSession
> depends on Apple's Security.framework and does not work on Linux. AsyncHTTPClient + NIOSSL
> gives one code path across all platforms.

## Scope

| Area | Status |
|------|--------|
| §1 methods, §2 errors, §3 CSRF, §4 cookies, §5 tenant | ✅ implemented |
| §6 TLS + §6.1 mTLS, §7 `Sensitive`, §9 single-flight refresh | ✅ implemented |
| §10 route-guard, §11 declarative helpers, EdDSA JWKS | ✅ implemented |
| gRPC transport (incl. `getUserInfo`, CONTRACT §1.1) | ⏭️ deferred follow-up (no §-requirement for Swift; no REST substitution per §1.1) |
| §8 AMQP HMAC | ⏭️ deferred (contract lists AMQP for Rust/TS/Go/Python/Java/PHP, **not** Swift) |
| §22 reactors (`reactorServe`) | ✅ implemented (contract 1.28) — §22.1–§22.8 and §22.14 in full, over a **caller-supplied transport**. §22.11 now defers only the *connection*: this SDK vendors no AMQP client, and you conform `ReactorTransport` over whichever one you already trust. "Conforms to … §22" is the claim; **"ships an AMQP client" is not** |
| §11 rule 9 decision reason codes | ✅ implemented |
| §16 bounded read-only retry, §17 decision memo, §18 `close()`, §19 telemetry hooks | ✅ implemented |
| §12 OIDC/SSO relying-party helpers | ✅ implemented (contract 1.11) — the nine operations on `AxiamClient`, under the names §12.2 had reserved for Swift while the section was deferred |
| §12.7 logout, §14 device grant, §15 token exchange | ✅ implemented (contract 1.11) — all three build on §12's discovery cache, token endpoint and ID-token validation, which is exactly why they land together with it |
| §24 WebAuthn / passkeys | ✅ implemented (contract 1.28) — the six relying-party operations and §24.6a's JSON bridge on **every** target, plus §24.6b's linked-API ceremony helpers on iOS 16+ and macOS 13+. The Linux build keeps the RP layer and the bridge; `webauthnCeremonySupported` answers `false` there rather than throwing |
| §25 account lifecycle & MFA enrolment | ✅ implemented (contract 1.28) — voluntary and forced TOTP enrolment, email verification, and the password-reset triple |
| §26 Pushed Authorization Requests (RFC 9126) | ✅ implemented (contract 1.28) — required for a FAPI 2.0 client, which cannot authorize any other way (§21.1) |
| §20 UMA 2.0 Protection API + ticket grant | ✅ implemented, and it landed *before* §12 rather than waiting for it: UMA carries its own discovery document (`/.well-known/uma2-configuration`), the Protection API is ordinary bearer-authenticated REST, and the ticket grant returns an opaque RPT with no `id_token` to validate. That §20 could ship alone is part of what showed the §12 deferral was cutting across the wrong seam — see contract §12.6 |

## Installation

### Swift Package Manager

```swift
dependencies: [
    .package(url: "https://github.com/ilpanich/axiam-swift-sdk.git", from: "1.0.0-alpha40")
],
targets: [
    .target(name: "MyApp", dependencies: [
        .product(name: "AxiamSDK", package: "axiam-swift-sdk")
    ])
]
```

### CocoaPods

```ruby
pod 'AxiamSDK', '~> 1.0.0-alpha40'
```

## Quickstart

```swift
import AxiamSDK

let config = try AxiamConfig(
    baseURL: URL(string: "https://id.example.com")!,
    tenantSlug: "acme",           // §5: a tenant identifier is mandatory (no default tenant)
    orgSlug: "acme"               // §5.1: login/refresh also require organization context
)
let client = try AxiamClient(config: config)

switch try await client.login(email: "user@example.com", password: "correct horse") {
case .authenticated(let user):
    print("logged in as \(user.userID)")
case .mfaRequired(let methods):
    print("MFA needed: \(methods)")
    try await client.verifyMfa("123456")
case .mfaSetupRequired:
    print("enrol a second factor first")
}

// Authorization
let canEdit = try await client.can("edit", resource: "1f2e...-uuid")
let result  = try await client.checkAccess("delete", resource: "1f2e...-uuid", scope: "field:title")
let batch   = try await client.batchCheck([
    AccessCheck(action: "read",  resource: "res-a"),
    AccessCheck(action: "write", resource: "res-b"),
])

try await client.logout()
try await client.shutdown()   // release the underlying HTTP client
```

Tokens are delivered by the server via `httpOnly` cookies and managed by the client's
in-memory cookie jar (§4); your code never handles raw token strings.

## TLS & mutual TLS

Strict server verification is **always on**. There is no insecure/skip-verify option — by
design (§6). A plaintext `http://` base URL is **rejected at construction**, since the client
puts credentials, session cookies, the CSRF token and the tenant header on every request; the
only exception is a loopback host (`localhost`, `127.0.0.1`, `::1`) for local development.

```swift
_ = try AxiamConfig(baseURL: URL(string: "http://id.example.com")!, tenantSlug: "acme")
// throws NetworkError: baseURL must use the encrypted `https://` scheme …

_ = try AxiamConfig(baseURL: URL(string: "http://localhost:8080")!, tenantSlug: "acme")  // OK (dev)
```

```swift
// Development self-signed server: add a custom CA (PEM) as an extra trust root (§6).
let config = try AxiamConfig(
    baseURL: URL(string: "https://localhost:8443")!,
    tenantSlug: "acme",
    orgSlug: "acme",                                     // §5.1: org context for login/refresh
    customCA: try Data(contentsOf: caPemURL)
)

// IoT / service-account mutual TLS: present a client identity certificate (§6.1).
let mtls = try AxiamConfig(
    baseURL: URL(string: "https://id.example.com")!,
    tenantSlug: "acme",
    orgSlug: "acme",                                     // §5.1: org context for login/refresh
    clientCertificate: .pem(
        certificate: try Data(contentsOf: clientCertPemURL),  // PEM cert chain
        privateKey:  try Data(contentsOf: clientKeyPemURL)     // PEM PKCS#8 / PKCS#1 key
    )
)
```

The mTLS private key is held behind `Sensitive` and never appears in logs or debug output
(§7); presenting a client certificate never relaxes server verification (§6.1 rule 2).

## Sensitive values (§7)

Secret material (the MFA challenge token, the mTLS private key) is wrapped in `Sensitive<T>`,
whose textual representation is always `"[SENSITIVE]"`:

```swift
let s = Sensitive("super-secret")
print(s)                 // [SENSITIVE]
print("\(s)")            // [SENSITIVE]
```

There is no public getter for the wrapped value. Equality is **constant-time** over the wrapped
bytes (`Sensitive` is `Equatable` for `String`, `Data`, `[UInt8]`, and anything else you conform
to `ConstantTimeComparable`), so comparing a secret never leaks how long a prefix matched.
`Sensitive` is deliberately **not** `Hashable`: secrets should not become dictionary/`Set` keys,
where lookup is a hash-bucketed comparison that is not constant time.

## Resource-server integration (§10 / §11)

The SDK ships a **framework-agnostic** guard that operates on request headers/cookies and
returns an `AxiamUser`, plus declarative helper factories. This keeps the core dependency-light
(no Vapor in the core).

```swift
let authenticator = client.makeAuthenticator()          // §10
let guards        = client.makeGuards()                 // §11 factories

// A guard handler: (AxiamRequestContext) async throws -> AxiamUser
let requireAuth   = guards.requireAuth()
let requireEdit   = guards.requireAccess("edit", resource: "doc-uuid")
let requireAdmin  = guards.requireRole("admin")

let ctx  = AxiamRequestContext(
    headers: ["Authorization": "Bearer \(jwt)", "X-Tenant-ID": "acme"],
    cookies: ["axiam_access": cookieJwt]
)
let user = try await requireEdit(ctx)                   // throws AuthError/AuthzError/NetworkError
```

- `requireAuth` — authenticated identity required (401 on failure).
- `requireAccess(action, resource:)` — the **authenticated end user** (`subject_id`) must pass
  an AXIAM authorization check; 403 on deny. Argument order is `(action, resource)` (§1/§11).
- `requireRole(_:)` — local check against the verified token's roles (no server round-trip);
  documented as coarser than, and not a substitute for, `requireAccess`.

### What the guard checks (§10.1 minimum local-verification set)

`authenticate(_:)` applies **all seven** rules; a signature check alone is not a guard.

| # | Claim | Rule |
|---|---|---|
| 1 | signature | Against the org JWKS (`GET /oauth2/jwks`, cached 300s, fetched single-flight), with `alg` pinned to **EdDSA before key lookup** — `alg: none` and HS-family confusion never reach a key. |
| 2 | `exp` | **Required.** Absent or non-numeric ⇒ reject. An absent `exp` is a permanent credential, not "no expiry constraint". |
| 3 | `nbf` | Honoured when present; a future `nbf` rejects. Absent `nbf` is fine. |
| 4 | `tenant_id` | **Required** and matched against the configured tenant. |
| 5 | `iss` | Checked only when `AxiamConfig.expectedIssuer` is set. |
| 6 | `aud` | Checked only when `AxiamConfig.expectedAudience` is set (string and array forms both honoured). |
| 7 | clock skew | One named 60s constant, `AxiamRequestAuthenticator.clockSkewTolerance`, on rules 2 and 3. Not settable. |

Every rule fails **closed** — a required claim that is absent, unparseable, or of the wrong JSON
type rejects the token.

Because the JWKS is **organization-wide**, a valid signature alone does not prove the token was
issued for your tenant. Access tokens carry the tenant **UUID**, so configure `tenantID` (not
only `tenantSlug`) on a client used as a resource-server guard:

```swift
let config = try AxiamConfig(
    baseURL: URL(string: "https://id.example.com")!,
    tenantID: "6f1c…-uuid",             // matched against the token's tenant_id claim
    tenantSlug: "acme",
    expectedIssuer: "https://id.example.com",   // optional; unset ⇒ `iss` not checked
    expectedAudience: "axiam:user"              // optional; unset ⇒ `aud` not checked
)
```

`JwksVerifier.verifySignatureOnlyUnchecked(token:)` is the raw signature primitive §10.1 permits
for integrators writing their own policy. As its name says, it checks **no** claims — it is not a
guard, and the SDK's own guards never stop there.

## Decision reason codes (CONTRACT.md §11 rule 9)

`AccessResult.reasonCode` distinguishes `no_grant` ("ask an admin for access") from
`denied_by_rule` ("an admin has already decided") — opposite instructions to the person on
the other end, which is why the contract forbids collapsing them into a bare `false`.

```swift
let decision = try await client.checkAccess("orders:read", resource: orderID)
switch decision.reasonCode {
case ReasonCode.noGrant:      showRequestAccessButton()
case ReasonCode.deniedByRule: showBlockedByPolicyMessage()
default:                      break
}
```

`ReasonCode` is a caseless enum of constants rather than a `String`-backed enum with cases,
so an unrecognised code is surfaced verbatim and never changes `allowed`; `nil` means the
server did not send one. `can()` still answers `false` for either refusal — the clause is
about *reporting*, not enforcement.

## Retry, memo, shutdown and telemetry (§16–§19)

Retry is **on by default** and applies only to operations that change no server state —
`checkAccess`, `can`, `batchCheck` and the JWKS fetch. That is not the same as "HTTP GET": the
authorization check is a `POST` with a body and is the operation this policy exists for. `login`,
`verifyMfa`, `logout` and `refresh` are never retried automatically, both because they change
state and because their credentials are single-use.

The policy is 3 attempts, 200 ms base, 5 s cap, **full jitter** over `[0, backoff]`, and
`Retry-After` honored as a **floor** — it can lengthen a wait, never shorten one, so a
`Retry-After: 0` cannot defeat the backoff. Only the switch is public; the attempt cap, base and
cap are deliberately not settable, because §16.1 permits *lowering* the budget and never raising
it.

```swift
let config = try AxiamConfig(
    baseURL: url,
    tenantSlug: "acme",
    retryEnabled: false,        // exactly one attempt — you own your retry layer
    decisionMemoTtl: 5,         // §17, opt-in; nil (the default) means disabled
    telemetryHook: { event in metrics.record(event) }
)
```

> **Read-your-own-writes is not guaranteed** with the memo enabled. The staleness bound is the TTL
> in *both* directions: a grant revoked on the server can still read as allowed for up to the TTL,
> and a grant just *added* can still read as denied for up to the TTL. An admin UI that grants a
> role and immediately re-checks is the case that breaks, and it breaks silently. A TTL above 5 s
> is **clamped** to 5 s, and the clamp is announced through the `configClamped` telemetry event
> rather than applied in silence.

`TelemetryEvent` is an `enum` with a closed case list and no dictionary payload, which is what
makes "no event carries a token" checkable by reading one declaration. Events carry the *path
template* (`/api/v1/authz/check`), never a URL with ids substituted in — a metric label with a
UUID in it is a cardinality bomb — and a retried call emits one `requestStart`/`requestEnd` pair
per **attempt**, so a caller can count real wire calls. The hook runs on the calling task and must
not block; buffering is yours to choose.

`close()` releases the HTTP client and clears the cookie jar, the CSRF token and any retained
`Sensitive` challenge token. It issues **no request** — it does not log out, because the
server-side session deliberately outlives the client object. It is idempotent, and any operation
attempted afterwards throws `NetworkError` naming the cause rather than silently reopening.
`shutdown()` remains as an alias, so existing call sites keep working.

> Swift's `deinit` cannot `await` and releasing an `AsyncHTTPClient` is async, so this SDK cannot
> make deallocation a complete shutdown. `close()` is the only complete form, and this README says
> so rather than implying it.

## OIDC / SSO relying-party helpers (§12)

"Login with AXIAM", plus the service-to-service and token-lifecycle operations that come with
it. Nine operations, all on `AxiamClient`, all built on this SDK's existing transport, `Sensitive`
wrapper and JWKS verifier — §12 adds no second HTTP path and no second key-fetching path.

```swift
let config = try AxiamConfig(
    baseURL: baseURL,
    tenantID: tenantUUID,              // §12.3 rule 4: the token endpoint needs a UUID
    oidcClientID: "my-app",
    oidcClientSecret: Sensitive(secret))  // omit for a public client
let client = try AxiamClient(config: config)

let configuration = try await client.oidcDiscover()
let request = try await client.oidcBegin(
    redirectURI: "https://app.example/callback", configuration: configuration)

// YOUR application stores these three — this SDK stores none of them (§12.3 rule 1).
session.save(state: request.state, nonce: request.nonce, verifier: request.codeVerifier)

// …after the callback:
let tokens = try await client.oidcExchange(
    code: callbackCode,
    redirectURI: "https://app.example/callback",  // byte-identical to the one above
    codeVerifier: session.verifier,
    nonce: session.nonce)
print(tokens.idClaims?.subject ?? "")
```

The rules this surface exists to enforce:

- **Stateless by default.** `oidcBegin` and `oidcExchange` keep no `state`, `nonce` or
  `codeVerifier` anywhere — not on the client, not in a global, not in an implicit cache. The
  caller owns that storage and passes the last two back explicitly.
- **`oidcBegin` performs no network I/O.** It is `await` only because `AxiamClient` is an actor.
  (Its convenience overload fetches the discovery document, which this client caches anyway.)
- **The ID token is validated in full, or the whole token set is discarded.** All seven §12.4
  rules run before `oidcExchange` returns — `alg` pinned to EdDSA before key lookup, signature by
  `kid`, exact-string issuer, audience with `azp` when plural, time with at most 60 s skew, and
  the nonce by constant-time comparison. On any failure the access and refresh tokens from the
  same response are discarded with it: there is no partial success and no "skip validation"
  option anywhere on the public API.
- **A slug-only client is refused client-side.** Five of the nine operations need a tenant
  **UUID** for the `?tenant_id=` query parameter, and a slug is never a substitute — so the SDK
  raises before the request rather than sending one that could not have succeeded.
- **`revoke` is idempotent.** A `200` for a token this client never issued is success (RFC 7009);
  a `5xx` is still a `NetworkError`, because returning void does not make a server failure a
  success.
- **No `/oauth2/userinfo`.** A relying party's claims come from the validated ID token
  (`OidcTokenSet.idClaims`); §12.3 rule 5 keeps that endpoint out of the vocabulary.

Runnable: [`Examples/OidcLogin`](Examples/OidcLogin/main.swift).

### Logout (§12.7)

`logoutURL` builds the `end_session_endpoint` redirect — from the **discovery document**, never
concatenated onto the issuer — and `verifyLogoutToken` validates a back-channel logout token the
OP pushed to your endpoint.

```swift
let url = try await client.logoutURL(idToken: tokens.idToken!, state: myState)

// On your back-channel endpoint:
let verified = try await client.verifyLogoutToken(postedToken)
// End `verified.sid` ONLY — falling back to every session for `sub` is an over-reach the
// server itself refuses to make. `verified.jwtID` is there so you can dedup; this SDK does not,
// because a library with no durable store would drop a real second logout after a restart.
```

`verifyLogoutToken` rejects a replayed ID token twice over: it requires the back-channel logout
`events` key, and it rejects any token carrying a `nonce` (Back-Channel Logout 1.0 §2.4 forbids
one, and its presence is the documented signature of exactly that replay).

## Device authorization grant (§14)

RFC 8628 — signing in something that cannot show a browser.

```swift
let tokens = try await client.deviceLogin(scope: "openid profile") { authorization in
    // Called BEFORE polling starts. Display it however the device can — screen, QR code,
    // e-ink panel. The SDK never prints it for you (§14.3 rule 2).
    print("visit \(authorization.verificationURI) and enter \(authorization.userCode)")
}
```

Polling follows §14.2 exactly, and three of its rules are the ones implementations get wrong:

- **`slow_down` raises the interval permanently**, by 5 s, and never resets it. Backing off for
  one round and returning to the original interval earns another `slow_down`, forever.
- **The interval comes from the response**, defaulting to 5 s when the server omits it. No faster
  floor is hard-coded.
- **Polling stops at `expires_in`** — and stops *before* a poll that would land past it, not
  merely when the clock has already run out. `access_denied` and `expired_token` stay distinct:
  one means a human said no, the other that nobody answered, and only the second is worth
  retrying.

Runnable: [`Examples/DeviceLogin`](Examples/DeviceLogin/main.swift).

## Token exchange (§15)

RFC 8693 — a backend holding a user's token trades it for a **narrower** one before calling the
next service.

```swift
let narrowed = try await client.tokenExchange(
    subjectToken: usersToken,
    subjectTokenType: AxiamClient.accessTokenType,  // required (§15.1), no default
    actorToken: myServiceToken,       // present → delegation; absent → impersonation
    scopes: ["orders:read"],
    audience: "inventory-service")
print(narrowed.scope ?? "")           // what you were GRANTED, which may be narrower
```

An exchange only ever narrows, and this SDK does not hide the refusals:
`unauthorized_client` surfaces verbatim (no retry, no rewriting the request into a delegation),
`invalid_scope` is never auto-narrowed and re-sent, and a cross-tenant subject token surfaces
`invalid_grant` without any attempt to refine it — the server collapses that case deliberately,
because telling it apart is a tenant-enumeration signal.

There is no refresh token, ever: `ExchangedToken` has nowhere to put one, the result never enters
the §9 refresh guard, and re-running the exchange is how you get a fresh token. The result is
also never adopted as this client's own credential — a MUST NOT where adoption elsewhere is a
MAY, because adopting it would silently re-privilege every subsequent call.

Runnable: [`Examples/TokenExchange`](Examples/TokenExchange/main.swift).

### External-IdP subject tokens (§15.7)

The same method exchanges a token minted by a **trusted external IdP** — a partner's Entra, Okta
or Keycloak — for an AXIAM token scoped to what the resolved AXIAM user may actually do. There is
no separate operation:

```swift
let narrowed = try await client.tokenExchange(
    subjectToken: partnersToken,
    subjectTokenType: AxiamClient.jwtTokenType,   // required; named, never guessed
    scopes: ["read:orders"],
    audience: "https://orders.internal")
```

- **`subjectTokenType` is yours to state, and is required** (§15.1). The SDK never decodes the
  subject token to pick it, and never overrides what you named. There is no default — omitting
  it does not compile, and a blank string is refused client-side with no wire call.
- **No actor token.** Delegation across a trust boundary is unsupported in v1; sending one is
  `invalid_request`, which the SDK will not work around by dropping it and re-sending.
- **One refusal is distinguishable.** `invalid_grant` whose `oauthErrorDescription` is `the
  subject token's issuer is not configured for token exchange` means *fix the AXIAM trust
  configuration*. Every other `invalid_grant` means *fix your token*, and is deliberately generic.
- **Forward the result as-is.** It carries an `ext_exchange` claim naming the partner issuer;
  never strip it, and never read it as an authorization input. It also cannot be exchanged again
  — exchanges do not compose.

The operator guide is `docs/api/federated-token-exchange.md`.

## UMA 2.0 — Protection API and ticket grant (§20)

The resource-server side of User-Managed Access: register what you guard, ask the authorization
server what a caller would need, and redeem the resulting ticket.

```swift
// A PAT is a client-credentials token carrying `uma_protection` — never a user token, and never
// this client's own session (§20.2 rule 1). This SDK does not mint one; obtain it however your
// deployment does and pass it in.
let pat = Sensitive(protectionApiToken)

let resource = try await client.umaRegisterResource(
    pat: pat, name: "invoice-7", type: "document", resourceScopes: ["view"])

// The returned id IS the AXIAM resource id — no translation step.
let ticket = try await client.umaRequestTicket(
    pat: pat,
    permissions: [UmaRequestedPermission(resourceID: resource.id!, resourceScopes: ["view"])])

response.headers.add(
    name: "WWW-Authenticate",
    value: AxiamClient.umaChallengeHeader(realm: "invoices", asURI: issuer, ticket: ticket))
```

…and on the client side, having caught that `401`:

```swift
if let challenge = AxiamClient.umaParseChallenge(response.headers["WWW-Authenticate"].first ?? ""),
   let ticket = challenge.ticket {
    let rpt = try await client.umaExchangeTicket(
        ticket: ticket,
        claimToken: Sensitive(usersAccessToken),
        credentials: UmaClientCredentials(clientID: id, clientSecret: Sensitive(secret)))
}
```

The rules this surface exists to enforce:

- **A ticket is never retried** — not on `5xx`, not on a timeout, not on `invalid_grant`. It is the
  one documented exception to §16's retry policy, and a security rule rather than a performance
  one: the ticket is consumed *before* the exchange is evaluated, so a failed exchange has already
  spent it and a retry is a *second redemption*. Under concurrency that is exactly the redemption
  a server whose storage engine the SDK cannot attest may admit twice
  ([`ilpanich/axiam#302`](https://github.com/ilpanich/axiam/issues/302)).
  On failure, request a **new** ticket.
- **`umaParseChallenge` does not exchange what it parsed.** The `as_uri` names an authorization
  server you have not necessarily chosen to trust; auto-exchanging would send the requesting
  party's `claim_token` to whatever host answered the `401`.
- **`claimToken` is required, never defaulted** — it is the only channel that names the requesting
  party. An empty one, an empty PAT, or a client configured with only a tenant *slug* is refused
  client-side with no wire call, so a request that could not have succeeded never spends a ticket.
- **No auto-narrowing on `access_denied`.** A partial grant is refused whole; whether two-of-three
  permissions is useful is your application's judgement, not the SDK's.
- **The RPT is never adopted** as this client's credential, and `RequestingPartyToken` has no
  refresh-token property.
- **`umaUpdateResource` replaces the scope list rather than merging it**, so omitting a scope
  removes it. There is no read-modify-write.

### Emitting the challenge from the §11 guard

`requireAccess(_:resource:scope:umaChallenge:)` mints and formats the challenge for you, so you do
not hand-roll it on every denial:

```swift
let challenger = UmaChallenger(realm: "invoices", asURI: configuration.issuer, pat: pat)
let guardFn = client.makeGuards().requireAccess(
    "invoices:read", resource: invoiceID, umaChallenge: challenger)

// A denial now throws an AuthzError whose `challenge` carries
//   UMA realm="invoices", as_uri="…", ticket="…"
// A framework adapter copies it onto the 403 it already returns.
```

Two properties are deliberate, and both are asserted by counting Protection API calls:

- **Opt-in.** Emitting a challenge means minting a credential. A guard that did that on every
  denial by default would put a Protection API call — and a live ticket — behind every
  unauthorized request, which is a denial-of-service amplifier pointed at your own authorization
  server. An allow mints nothing.
- **A minting failure is not an escalation.** An expired PAT or an unreachable Protection API
  still yields the plain `AuthzError` with no challenge — never a 503, and never an allow.

`AuthzError.challenge` is deliberately absent from its `description`: the value carries a live
ticket, and `description` is what ends up in a log line.

The requested scope is the AXIAM **action**, so the ticket asks for exactly the authority that was
refused and the engine's deny rules keep applying to whatever RPT comes back.

Both halves run in [`Examples/UmaResourceServer`](Examples/UmaResourceServer/main.swift) and
[`Examples/UmaClient`](Examples/UmaClient/main.swift).

`access_denied` answers HTTP `403` on this grant where RFC 8628's answers `400`, so the mapping
dispatches on the body's `error` field rather than the status. The code arrives on
`AuthError.oauthError`: Swift structs cannot be subclassed, so an `AuthError` carrying the protocol
code is this SDK's rendering of the contract's `OAuthProtocolError`-as-an-`AuthError`-subtype, and
the §2 taxonomy stays at exactly three cases.

## Webhook signature verification (§13)

AXIAM signs every webhook delivery with a `t=<unix_seconds>,v1=<hex>` header, where
`v1 = HMAC-SHA256(secret, "<timestamp>.<raw_body>")`. `AxiamWebhooks.verify(...)` recomputes it,
compares in constant time over the decoded bytes, and enforces a two-sided freshness window
(default 300s):

```swift
// In your webhook receiver — `rawBody` is the UNPARSED request body.
do {
    let event = try AxiamWebhooks.verify(
        secret: Sensitive(webhookSecret),   // the webhook's plaintext secret
        headers: requestHeaders,            // X-Axiam-Signature/-Timestamp/-Event/-Delivery
        body: rawBody                       // Data, exactly as received
    )
    if await seen.insertIfAbsent(event.deliveryID) {   // dedup is the receiver's job
        handle(event)
    }
} catch let error as AxiamWebhookError {
    return .init(status: .badRequest)       // fail closed; never "assume valid"
}
```

- **The body must be the raw bytes off the wire.** Decoding the JSON and re-serializing it
  changes key order and whitespace, which changes the MAC input and makes every signature fail.
  Read the body as `Data` *before* any JSON decoding (Vapor: `request.body.data`, not
  `request.content.decode(...)`).
- **`X-Axiam-Delivery` is the at-least-once dedup key.** A retry replays a *valid* signature
  inside the freshness window, so keep a short-lived seen-set of delivery ids if handling must be
  effectively-once.
- Verification is fail-closed and quiet: `AxiamWebhookError` never carries the expected
  signature or the secret. A header with no `v1` is a failure, never a pass.
- For tests, inject the clock: `AxiamWebhooks.verify(..., now: Date(timeIntervalSince1970: …))`.

### Wiring into Vapor

A first-party `AxiamVapor` product is a follow-up; wire the guard into a Vapor `AsyncMiddleware`
yourself in the meantime:

```swift
import Vapor
import AxiamSDK

struct AxiamMiddleware: AsyncMiddleware {
    let guardHandler: AxiamGuardHandler

    func respond(to request: Request, chainingTo next: AsyncResponder) async throws -> Response {
        let ctx = AxiamRequestContext(
            headers: Dictionary(request.headers.map { ($0.name, $0.value) }, uniquingKeysWith: { a, _ in a }),
            cookies: Dictionary(request.cookies.all.map { ($0.key, $0.value.string) }, uniquingKeysWith: { a, _ in a })
        )
        do {
            let user = try await guardHandler(ctx)
            request.storage[AxiamUserKey.self] = user       // available downstream via Request.storage
            return try await next.respond(to: request)
        } catch is AuthError {
            throw Abort(.unauthorized)
        } catch is AuthzError {
            throw Abort(.forbidden)
        } catch is NetworkError {
            throw Abort(.serviceUnavailable)                // §11.2: fail closed on transport failure
        }
    }
}

struct AxiamUserKey: StorageKey { typealias Value = AxiamUser }
```

## OPAQUE — RFC 9807 (§23)

`loginOpaque` proves the password to the server without the password — or anything from which it
can be cheaply recovered — ever crossing the wire. The server stores a **registration record**
sealed under a tenant-scoped oblivious PRF instead of a password hash, and what travels is a
blinded group element and a MAC, neither of which is useful without that record *and* the tenant's
OPRF seed.

```swift
let result = try await client.loginOpaque(usernameOrEmail: "alice", password: password)
```

It takes the same arguments as `login` and returns the same `LoginResult`, MFA branch included, so
switching a tenant to OPAQUE needs no change to how the result is handled. A runnable end-to-end
example, including the fallback and the enrolment call, is
[`Examples/OpaqueLogin`](Examples/OpaqueLogin/main.swift).

### What this buys, and what it does not

OPAQUE closes holes TLS 1.3 does not:

- a TLS-terminating reverse proxy, ingress controller, CDN or service mesh sees every plaintext
  password today; under OPAQUE it sees `KE1` and `KE3`;
- an accidental request-body log, a heap dump or a crash reporter can no longer capture a plaintext
  password, because the server never has one;
- **a stolen record database is not offline-crackable on its own.** This is the substantive gain
  over the SRP-6a this replaces. An SRP verifier is `g^x mod N` with a public salt: anyone holding
  the database can grind candidate passwords locally. An OPAQUE record is sealed under the tenant's
  OPRF seed, so an attacker who takes the records and not the seed has nothing to grind against.
  That property is called pre-computation resistance and SRP does not have it.

It does **not** protect against a compromised AXIAM server, and this SDK does not claim it does.

### This SDK does not implement OPAQUE, and that is the design

CONTRACT.md §23.1 forbids it. OPAQUE needs an oblivious PRF, `hash_to_curve`, `expand_message_xmd`,
an envelope construction and a three-message authenticated key exchange; eleven independent
implementations of that is eleven chances to be subtly and silently wrong, in a way no test vector
catches because the wrong answer is still a well-formed group element.

So this package binds **`libaxiam_opaque_ffi`**, the C ABI of the same audited `opaque-ke` core the
AXIAM server runs. There is no cryptography anywhere in `Sources/AxiamSDK/Opaque/`.

The library is a **per-platform release asset** of
[`ilpanich/axiam-opaque`](https://github.com/ilpanich/axiam-opaque) — deliberately *not* a SwiftPM
dependency. It is resolved with `dlopen` at run time rather than declared as a `systemLibrary`
target, so a consumer who never touches OPAQUE is not made to link it and does not fail to build
without it. Install it where the dynamic loader already looks, or point `AXIAM_OPAQUE_LIBRARY` at
the file:

```bash
export AXIAM_OPAQUE_LIBRARY=/usr/local/lib/libaxiam_opaque_ffi.dylib
```

```swift
guard client.opaqueAvailable() else {
    // The library is not installed. Ask BEFORE collecting a password.
}
```

### Swift no longer needs a `pbkdf2_sha256` tenant

The SRP client this replaces was **doubly conditional**, and the second condition was the awkward
one. Swift Crypto ships PBKDF2 and scrypt but no Argon2, and there is no Argon2 that ships on every
platform this SDK supports — so a tenant on AXIAM's *default* `argon2id` was refused outright, and
operators had to reconfigure the tenant to `pbkdf2_sha256` for Swift clients to work at all. That
meant weaker, non-memory-hard stretching chosen for a client-language reason.

That is gone. The key stretching happens inside `libaxiam_opaque_ffi`, so `argon2id` is no longer a
Swift-shaped hole — and `pbkdf2_sha256` is not an OPAQUE key-stretching function at all. `scrypt`
is the alternative, and this SDK can ask for either.

One condition remains, and it is honest rather than hidden: `opaqueAvailable()` reports whether the
library is present. Unlike the `srpAvailable` it replaces — hard-coded `true` while an `argon2id`
tenant still failed at login — a `true` here **is** a promise that every tenant will work.

### The bundled bignum is gone

`SrpBigInt`, a hand-written `[UInt64]`-limb modular exponentiation with its own Montgomery
multiplication, is deleted along with the six §23.7 SRP vectors that stood between a
carry-propagation slip and a login that failed one time in a thousand. Nothing in this SDK
now does field arithmetic. The old §23.8 caveat that it was **not constant-time** goes with it.

### The server names the cost, every time

The `*/start` response names the key-stretching function and its parameters for **that exchange**.
This SDK never caches them across exchanges and never defaults them locally:

| rule | what it means here |
|---|---|
| §23.4 rule 2 | costs come from the server per exchange — a credential enrolled under one cost keeps working after a tenant raises its policy, so a client that guessed would derive a different randomized password and report "invalid password" for a correct one |
| §23.4 rule 3 | an unrecognised `ksf` is **refused**, never substituted — substituting produces a well-formed randomized password no AXIAM server agrees with |
| §23.4 rule 5 | a cost field that does not apply to the named function is **absent, not zero** — which is why `KsfParams`' cost properties are `Int?` |
| §23.4 rule 7 | nothing is sent to `login/finish` once the envelope fails to open |

Costs are additionally range-checked here, so a refusal names the field:

| field | accepted band |
|---|---|
| `memory_kib` | 8192 – 1048576 (8 MiB – 1 GiB) |
| `iterations` | 1 – 10 |
| `parallelism` | 1 – 16 |
| `log_n` | 14 – 20 |
| `r`, `p` | 1 – 16 |

A server is trusted to name its own policy, not to name a cost that would wedge every device an
account owns. The library range-checks too; doing it here as well means the error says which field.

### One round trip, and no server-proof step

SRP had to guess a group before the server named one, and restart the exchange if it guessed wrong.
`KE1` does not depend on the key-stretching function, so there is no such dance.

And where the old §23.3 rule 6 had to mandate an `M2` check **in capitals** — because an SDK that
skipped it implemented only half the protocol and no test would notice — RFC 9807's AKE
authenticates the server during the handshake. Opening `KE2` *is* the proof that the server holds
the record. Mutual authentication is no longer something a client can forget.

### Tenant policy, and the errors that are not credential failures

`opaque_mode` is an organization baseline a tenant may tighten:

| mode | `login` | `loginOpaque` |
|---|---|---|
| `disabled` (default) | works | `.network` — `*/start` answers `404` |
| `optional` | works | works |
| `required` | `.authz` (`opaque_required`) | works |

Neither is `.auth`:

- `.network` from `loginOpaque` means *this tenant does not offer OPAQUE*, *`libaxiam_opaque_ffi` is
  not installed*, *the server named a key-stretching function this SDK cannot ask for*, or *the
  response was not the shape §23 defines* — a property of the tenant, the build or the deployment,
  never of any user. Fall back to `login`.
- `.authz` from `login` means *this tenant refuses password login*. The credentials were never
  examined. Telling a user their perfectly good password is invalid is the failure this mapping
  exists to prevent.

`.auth` from `loginOpaque` means the envelope did not open: a wrong password, an account that does
not exist, or a server that does not hold the record — indistinguishable by design, and the whole
credential check now that both halves of mutual authentication live in it. **Do not retry it over
`login`**: that hands the plaintext to an endpoint that has just failed to prove itself.

`required` refuses **every** principal in the tenant, not only the enrolled ones. Splitting the
response on whether an account has a record would turn `/auth/login` into an enumeration oracle
costing one junk password per name. It also means `required` locks out anyone not yet enrolled: a
record needs the plaintext password, and a stored Argon2id hash is not invertible, so nobody can be
enrolled retroactively. Operators turn it on last, after a password-reset campaign.

### Enrolment

The server cannot build a registration record, so any request that **sets** a password has to carry
one. `opaqueEnrollment` produces the `opaque` object for `POST /api/v1/users`,
`/auth/password/change`, `/auth/reset/confirm` and `/admin/bootstrap`. It is `Encodable` in exactly
§23.5's shape:

```swift
let enrolment = try await client.opaqueEnrollment(password: newPassword)
body["opaque"] = enrolment
```

Three things about it differ from the `srpEnrollment` it replaces, and all three are improvements:

- **It performs I/O** — one `register/start` round trip. OPAQUE's envelope is sealed under the
  server's oblivious PRF, so there is no offline computation that produces a valid record. The SRP
  version was pure and could be called anywhere; this one needs a reachable server.
- **There is no `identity` argument.** SRP derived `x` over `identity ":" password` using the
  identity the challenge endpoint handed back, so passing an email where a username was wanted
  produced a verifier no login could ever satisfy — and **renaming a user invalidated their
  verifier**, which the server had to clear. An OPAQUE record binds to a credential identifier the
  server chooses. A rename is now just a rename.
- **There is no `group` and no `kdf`.** Those come from the `register/start` response, so a caller
  cannot pick a cost the server will not honour.

Never log `registration_record`. It is the credential material.

### Cost

`loginOpaque` runs the tenant's key-stretching function — Argon2id at 19 MiB and t=2 by default,
tens to hundreds of milliseconds of CPU plus that memory — and it runs on the calling task. That
cost is the point: it is what makes a stolen record expensive to attack even by someone holding the
OPRF seed. Do not call it from a UI-blocking context.

### Cryptographic parameters

`OPAQUE-3DH` over **ristretto255**, with **SHA-512**, **HKDF-SHA-512** and **HMAC-SHA-512**. The
ciphersuite is fixed in `libaxiam_opaque_ffi`; it is not negotiated and is deliberately **not** read
from the server, because a server-selected ciphersuite is a downgrade channel.

### Handle lifetime

An exchange owns one Rust-side allocation. It is single-use — `finish` spends it — and `close()` is
idempotent, so the `defer { exchange.close() }` in `loginOpaque` and `opaqueEnrollment` is a no-op
on the success path and the thing that prevents a leak on every failure path: a refused KSF, a
malformed response, a non-200 `/start`. `deinit` is a backstop, not the mechanism.

The key-stretching handle is built **before** the exchange state is spent, and the order is
load-bearing: a server that names a cost outside the accepted band must not leave the state
unreachable.

### Zeroization

§23.4 rule 8 requires clearing what can be cleared and **saying so** where it cannot be. In Swift it
largely cannot: `String` and `Array` are copy-on-write values the runtime may have duplicated before
this SDK saw them, and there is no supported way to overwrite the storage behind one. This SDK does
not pretend otherwise. What it does do is keep the password's residency short — it is passed
straight across the ABI, and the sensitive derivations happen and are cleared on the Rust side. If a
password's residency in Swift memory matters to your threat model, Swift's value semantics are
working against you and no SDK-level change fixes that.

## WebAuthn / passkeys (§24)

Six wire operations, two ceremonies, and — on Apple platforms — three composed helpers that
do the whole thing in one call.

```swift
// Enrolment — requires a session (§24.1), refused client-side without one.
let challenge = try await client.webauthnRegisterStart()
let credential = try await client.webauthnRegisterFinish(
    stateToken: challenge.stateToken,
    credentialName: "Alice's laptop",
    response: platformResponseJSON            // verbatim
)

// Sign-in with no username at all — the authenticator picks the account.
let signIn = try await client.webauthnDiscoverableStart()
let session = try await client.webauthnDiscoverableFinish(
    stateToken: signIn.stateToken,
    response: assertionJSON
)
```

**The server chooses every option and verifies every response; this SDK passes both through
byte-for-byte** (§24.0). `WebauthnChallenge.challengeData` holds the raw JSON rather than a
decoded model, and the `*Finish` body is assembled as bytes with the caller's response
string spliced in unmodified — decoding and re-encoding it would reorder keys and round
every number through a `Double`, handing the server a byte sequence the authenticator never
signed.

### One helper set, both Apple platforms (§24.6b)

`ASAuthorizationPlatformPublicKeyCredentialProvider` and its security-key sibling exist on
iOS and macOS alike, and the presentation anchor is the only genuinely per-platform part —
which is why the caller supplies it:

```swift
final class Anchor: WebauthnPresentationAnchorProviding {
    @MainActor func webauthnPresentationAnchor() -> ASPresentationAnchor { window }
}

let credential = try await client.webauthnRegister(
    credentialName: "iPhone",
    anchor: anchor,
    attachment: .platform          // §24.6b rule 4: the ONE permitted addition
)

let session = try await client.webauthnDiscoverableLogin(
    anchor: anchor,
    conditional: client.webauthnConditionalMediationSupported
)
```

`attachment` is a hint about which authenticator the user is reaching for, and the **only**
thing this SDK ever adds to the server's options — without it a user who asked for a
security key is prompted for Face ID instead. The SDK never infers it and never defaults it.

Conditional mediation (passkey autofill) may never settle — the user simply may not pick a
passkey — so cancel the enclosing `Task` to abandon it. That surfaces as
`WebauthnFailure.cancelled`, **not** as an authentication failure (§24.6b rule 3).

**The composed helpers are additive** (§24.6b rule 1): the six wire operations stay public,
because a caller running a virtual authenticator in a test, or holding a response produced
on another device, needs the pieces.

### Linux, and the §24.6a bridge

`AuthenticationServices` does not exist there, so the helpers are compiled out and
`webauthnCeremonySupported` answers `false` — a **query, not an exception** (§24.6b rule 6),
so a caller hides a button rather than offering one that throws. `challenge.requestJson` is
the string to send to whatever *does* have an authenticator, and its response JSON comes
straight back into the matching `*Finish`. Nothing is destructured, nothing is re-encoded.

Passing something that is not JSON, or is not a JSON object, raises `AxiamError.auth`
client-side with no wire call: the SDK will not POST a body it already knows the server
cannot verify.

### The two authentication ceremonies are different flows (§24.2)

`webauthnAuthenticateStart`/`Finish` is a **second factor** — it continues a `login` that
answered `.mfaRequired` with `"webauthn"` among its methods, and the challenge token names
the user so the server can send an `allowCredentials` list. `webauthnDiscoverableStart`/
`Finish` is a **primary factor**: nothing precedes it, `allowCredentials` is empty, and the
assertion itself identifies the user. They are not one operation with an optional token —
merging them reproduces a bug the server already fixed, which is why the token is required
on one and rejected on the other.

One difference a reactor author will ask about: `discoverable/finish` fires the
`login.post_auth` hook event (§22.5) and `authenticate/finish` does not. The latter
continues a login already gated at its password step; the former has no such step.

### Two error rows that are not the §2 defaults (§24.4)

- A **403 from `register/finish`** is the tenant's *attestation policy* rejecting this
  particular authenticator. The server's message is the only place that says which one would
  be accepted, so it is lifted into the `AuthzError`'s message rather than discarded.
- A **503 from `register/start`** means the policy needs FIDO metadata the server cannot
  reach. That is a configuration state, not a transient one, and it is **not retried** — the
  second documented exception to §16 after §20's.

Worked end to end in [`Examples/WebauthnPasskeys`](Examples/WebauthnPasskeys)
(`swift run WebauthnPasskeysExample`).

## Account lifecycle and MFA enrolment (§25)

Nine operations covering the things a user does to their own account — none of which is
administration.

```swift
switch try await client.login(email: email, password: password) {
case let .mfaSetupRequired(setupToken):
    // The third outcome. The tenant requires MFA, this account has none, and the
    // server handed back a token to finish with. There is no session yet.
    let enrollment = try await client.mfaSetupEnroll(setupToken: setupToken)
    renderQR(enrollment.totpURI.expose())
    let user = try await client.mfaSetupConfirm(setupToken: setupToken, totpCode: code)
case .mfaRequired:
    try await client.verifyMfa(code)
case let .authenticated(user):
    break
}
```

> **Breaking, deliberately.** `LoginResult.mfaSetupRequired` gained an associated value in
> contract 1.28. A caller that matched it exhaustively needs one line changed; the
> alternative was an SDK that tells you enrolment is required and withholds the only thing
> that can complete it (§25.2 rule 1).

`mfaSetupConfirm` adopts credentials exactly as `login` does, because it *is* the completion
of a login (§25.2 rule 2). `mfaEnroll`/`mfaConfirm` are the voluntary pair, from inside an
existing session, and they do **not** clear the §17 decision memo — the subject has not
changed, and discarding a warm memo on an unrelated profile action costs a round trip on
every check that follows.

Enrolment is two calls and the first is not enough. §25.2 rule 4 forbids a composed one-call
helper here, because the human step in the middle — scanning the URI, reading a code — is
not something a helper can wait for, and one that returned after `enroll` would report MFA
as enabled when it is not.

Both halves of an `MfaEnrollment` are `Sensitive`, and the second one matters: the
`otpauth://` URI *contains* the secret (§25.3). Wrapping the bare secret and then logging
the URI leaks the same bytes.

### Password reset, and the two things it will not tell you

```swift
try await client.requestPasswordReset(PasswordResetRequest(email: "alice@example.com"))
// returns Void, whether or not that address has an account

let context = try await client.passwordResetContext(token: token)
if context.hasOpaquePolicy {
    // This tenant runs §23. Build a registration record from these parameters;
    // a plaintext password would be refused, and refused late (§25.4 rule 1).
}
try await client.confirmPasswordReset(
    PasswordResetConfirmation(token: token, newPassword: newPassword, tenantID: tenantID)
)
```

`requestPasswordReset` returns nothing and throws nothing on an unknown address, and this
SDK exposes no way to tell the two cases apart. That is not an omission to improve on: a
client that surfaced a "no such user" state — even one inferred from timing — would turn the
endpoint into the account-enumeration oracle its uniform response exists to prevent.
Likewise a `404` from `passwordResetContext` means unknown, expired **or** already-consumed,
and the SDK does not distinguish them either (§25.4 rule 3).

`verifyEmail` and `resendVerification` are unauthenticated — a user whose address is
unverified may have no session at all — and carry the tenant as a **body** field, since
§12.1 rule 2's `?tenant_id=` convention is scoped to the `/oauth2` endpoints.

Worked end to end in [`Examples/AccountLifecycle`](Examples/AccountLifecycle).

## Pushed Authorization Requests (§26, RFC 9126)

PAR moves the authorization request off the browser. Instead of putting `scope`,
`redirect_uri`, `state` and the PKCE challenge into a URL the user agent carries, the client
POSTs them straight to AXIAM over an authenticated back channel and puts an opaque
`request_uri` in the redirect.

```swift
let document = try await client.oidcDiscover()
guard document.pushedAuthorizationRequestEndpoint != nil else {
    // §26 is optional; fall back to the plain oidcBegin redirect.
    return
}

let begun = try client.oidcBegin(
    redirectURI: redirectURI, scope: "openid profile", configuration: document)
let pushed = try await client.oidcPar(
    request: begun, redirectURI: redirectURI, scope: "openid profile", configuration: document)

redirect(to: pushed.url)      // exactly ?client_id=…&request_uri=…
```

Three things worth knowing:

- **The server answers `201`,** not `200` — RFC 9126 §2.2 specifies *Created*. A success
  predicate written `== 200` treats every successful push as a failure.
- **The redirect URL carries exactly two parameters.** The server refuses a request that
  mixes a `request_uri` with inline authorization parameters rather than merging them;
  merging is where parameter confusion lives (§26.2 rule 2). Any query the discovered
  `authorizationEndpoint` already carried is dropped.
- **`oidcBegin` still owns `state`, `nonce` and the PKCE pair.** There is no second generator
  (§26.2 rule 1), and `PushedAuthorizationRequest` carries all three straight through to the
  exchange.

The push is **not retried** on a 5xx or a transport failure: it is a POST that creates server
state, so it falls outside §16.2's read-only eligibility exactly as `oidcExchange` does. The
safe recovery is a fresh push, which costs one round trip and cannot double-consume
anything. The `requestURI` is `Sensitive` because between the push and the redirect it is a
bearer handle to a fully-formed authorization request (§26.5).

A **FAPI 2.0 client has no alternative**: `profile: "fapi2"` refuses a registration that does
not set `require_par`, so such a client cannot authorize any other way (§21.1).

Worked end to end in [`Examples/ParLogin`](Examples/ParLogin).

## Reactors (§22) — the protocol core over your own transport

A **reactor** is an external service AXIAM consults synchronously at five points
in its own flows: it may veto a login, enrich a token, or adjust a user before
creation. This SDK ships §22.1–§22.8 and §22.14 in full — the §8 v2 verification
set on the event, the canonical serialization and MAC in both directions, the
§22.5 registry and its allow-lists, §22.8's strictest-wins default, the runtime,
and the declarative builder.

**What it does not ship is a connection.** §22.11 defers the transport, and only
the transport:

> the convenience that genuinely needed a vendored dependency was the
> **connection**, and the runtime around it needed none.

Until contract 1.28 this SDK shipped nothing from §22 at all while the section
still bound an integrator to §22.1–§22.8. The half deferred for want of a
*dependency* was the transport; the half every integrator was left to hand-roll
from prose was the **protocol** — v2 HMAC over a canonical serialization with a
`null` signature placeholder, freshness in both directions, nonce and correlation
binding, the per-event allow-lists. That is the half with the sharp edges, none
of them AMQP-shaped, and asking every integrator to reimplement it is how a
signing bug ships.

```swift
// §8b rules 1–5, BEFORE anything opens a socket. A public, tested function
// rather than a doc comment — §22.11 rule 3.
let endpoint = try amqpsEndpoint(brokerURL, caPEM: caPEM)

// §22.14: one handler per event. An unregistered name is refused AT BIND TIME,
// and the strongly-typed `on(_:_:)` cannot even spell one.
var router = ReactorRouter()
try router.on(.loginPostAuth) { event in
    let payload = try event.decodePayload(LoginPayload.self)
    return suspicious(payload) ? .allowWithStepUp : .allow
}

let config = ReactorConfig(tenantID: tenantID, reactorID: reactorID, signingKey: subkey)
try await reactorServe(config: config, transport: yourTransport, handler: router.handler())
```

**The transport protocol has exactly two capabilities** (§22.11 rule 1): take the
next delivery, and publish a reply to a named destination. It is not wider than
that on purpose — a protocol that also exposed declare, bind or queue-name
derivation would hand you the tools §22.1 forbids using. A reactor that can bind
is a reactor that can bind itself to `*.token.pre_issue` and read another
tenant's issuance events.

**It fails closed on its own errors** (§22.10 rule 2). A handler that throws, a
body it cannot verify, or a window that has closed all produce **no reply**, and
the registration's `failure_policy` decides. A runtime that answered `.allow` for
a handler that threw would have overridden the operator's `fail_closed` setting
from inside the library — which is exactly the defect §22.14 exists to keep out of
*your* code too, where a `default:` arm returning `.allow` does the same thing
from a file nobody reads. An unbound event abstains; returning `nil` is how any
handler says so.

**It does not filter a patch** (§22.4 rule 1). One forbidden key rejects the
whole patch server-side, including the fields that would have been fine — and
dropping the offender to rescue the rest would leave the author believing a field
was set when it was dropped. `ReactorEventName.allowsPatchField(_:)` will *tell*
you what the registry admits; nothing in this SDK calls it to prune anything.

**The three hot-path decision operations are not hookable** (§22.7), and they
appear in no case of `ReactorEventName`. A reactor round trip is milliseconds;
the check path's budget is microseconds. An application needing external input on
an authorization decision writes a **deny grant**, which the engine evaluates in
the hot path at hot-path cost.

**A builder rather than an attribute**, and §22.14 records why: a Swift reactor
handler is an `async` closure, and collecting `async` members by reflection costs
a runtime dependency an SDK should not add to hand out an attribute. The builder
type-checks the closure against `(ReactorEvent) async throws -> ReactorAnswer` at
compile time, which is stricter than what the reflection would have bought.
Kotlin made the same trade for the same reason.

Correctness is not asserted against this implementation's own opinion: the suite
runs the committed **§22.13 reference vectors** in both directions, generated by
the server's own sign path and vendored at
`Tests/AxiamSDKTests/Support/reactor_v2_reference_vectors.json`. Worked example,
including a transport skeleton: [`Examples/Reactor`](Examples/Reactor/main.swift).

## Development

```bash
swift build
swift test --enable-code-coverage
```

Tests run against a small in-process NIO HTTP server (no external services) and are
Linux-runnable in CI. All test PKI (Ed25519 signing keys, mTLS certs) is generated at runtime —
no private keys are committed.

## Contract & specs

This repo vendors the source-of-truth [`CONTRACT.md`](CONTRACT.md), [`openapi.json`](openapi.json)
and [`proto/`](proto) from the AXIAM platform repo; re-sync them downstream when they change.

## License

Apache-2.0 — see [LICENSE](LICENSE).
