# AXIAM Swift SDK

[![CI](https://github.com/ilpanich/axiam-swift-sdk/actions/workflows/sdk-ci-swift.yml/badge.svg?branch=main)](https://github.com/ilpanich/axiam-swift-sdk/actions/workflows/sdk-ci-swift.yml)
[![Coverage Status](https://coveralls.io/repos/github/ilpanich/axiam-swift-sdk/badge.svg?branch=main)](https://coveralls.io/github/ilpanich/axiam-swift-sdk?branch=main)
[![Swift](https://img.shields.io/badge/Swift-5.9%2B-orange.svg)](https://swift.org)
[![Platforms](https://img.shields.io/badge/platforms-macOS%20%7C%20iOS%20%7C%20Linux-lightgrey.svg)](https://swift.org)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![SPM](https://img.shields.io/badge/SwiftPM-compatible-brightgreen.svg)](https://swift.org/package-manager)
[![Docs](https://img.shields.io/badge/docs-DocC-blue.svg)](https://ilpanich.github.io/axiam-swift-sdk/)

The official Swift SDK for **AXIAM** (Access eXtended Identity and Authorization Management).

> **This SDK conforms to CONTRACT.md §1–§7, §9–§11, §13, §16–§19 and §20 (including §6.1 mTLS,
> and the §11 rule 9 decision reason codes).**

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
| §11 rule 9 decision reason codes | ✅ implemented |
| §16 bounded read-only retry, §17 decision memo, §18 `close()`, §19 telemetry hooks | ✅ implemented |
| §12 OIDC/SSO relying-party helpers | ⏭️ not implemented |
| §12.7 logout, §14 device grant, §15 token exchange | ⏭️ blocked on §12 — each builds on its discovery cache, token endpoint and ID-token validation, so implementing them here would mean shipping a second, parallel OIDC stack rather than re-syncing one |
| §20 UMA 2.0 Protection API + ticket grant | ✅ implemented — **not** blocked on §12: UMA carries its own discovery document (`/.well-known/uma2-configuration`), the Protection API is ordinary bearer-authenticated REST, and the ticket grant returns an opaque RPT with no `id_token` to validate. One GET and one POST, with no PKCE, no state store, no JWKS interaction and no §9 coupling — so none of the parallel-stack objection above applies |

## Installation

### Swift Package Manager

```swift
dependencies: [
    .package(url: "https://github.com/ilpanich/axiam-swift-sdk.git", from: "1.0.0-alpha24")
],
targets: [
    .target(name: "MyApp", dependencies: [
        .product(name: "AxiamSDK", package: "axiam-swift-sdk")
    ])
]
```

### CocoaPods

```ruby
pod 'AxiamSDK', '~> 1.0.0-alpha24'
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
  spent it and a retry is a *second redemption*. Under concurrency that is exactly the case whose
  measured residual [`ilpanich/axiam#302`](https://github.com/ilpanich/axiam/issues/302) records.
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
