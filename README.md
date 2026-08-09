# AXIAM Swift SDK

[![CI](https://github.com/ilpanich/axiam-swift-sdk/actions/workflows/sdk-ci-swift.yml/badge.svg?branch=main)](https://github.com/ilpanich/axiam-swift-sdk/actions/workflows/sdk-ci-swift.yml)
[![Coverage Status](https://coveralls.io/repos/github/ilpanich/axiam-swift-sdk/badge.svg?branch=main)](https://coveralls.io/github/ilpanich/axiam-swift-sdk?branch=main)
[![Swift](https://img.shields.io/badge/Swift-5.9%2B-orange.svg)](https://swift.org)
[![Platforms](https://img.shields.io/badge/platforms-macOS%20%7C%20iOS%20%7C%20Linux-lightgrey.svg)](https://swift.org)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![SPM](https://img.shields.io/badge/SwiftPM-compatible-brightgreen.svg)](https://swift.org/package-manager)
[![Docs](https://img.shields.io/badge/docs-DocC-blue.svg)](https://ilpanich.github.io/axiam-swift-sdk/)

The official Swift SDK for **AXIAM** (Access eXtended Identity and Authorization Management).

> **This SDK conforms to CONTRACT.md §1–§7, §9–§11 and §13 (including §6.1 mTLS, and the
> §11 rule 9 decision reason codes).**

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
| §12 OIDC/SSO relying-party helpers | ⏭️ not implemented |
| §12.7 logout, §14 device grant, §15 token exchange | ⏭️ blocked on §12 — each builds on its discovery cache, token endpoint and ID-token validation, so implementing them here would mean shipping a second, parallel OIDC stack rather than re-syncing one |

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
