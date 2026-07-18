# AXIAM Swift SDK

[![Swift](https://img.shields.io/badge/Swift-5.9%2B-orange.svg)](https://swift.org)
[![Platforms](https://img.shields.io/badge/platforms-macOS%20%7C%20iOS%20%7C%20Linux-lightgrey.svg)](https://swift.org)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![SPM](https://img.shields.io/badge/SwiftPM-compatible-brightgreen.svg)](https://swift.org/package-manager)

The official Swift SDK for **AXIAM** (Access eXtended Identity and Authorization Management).

> **This SDK conforms to CONTRACT.md §1–§7, §9–§11 (including §6.1 mTLS).**

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
| gRPC transport | ⏭️ deferred follow-up (no §-requirement for Swift) |
| §8 AMQP HMAC | ⏭️ deferred (contract lists AMQP for Rust/TS/Go/Python/Java/PHP, **not** Swift) |

## Installation

### Swift Package Manager

```swift
dependencies: [
    .package(url: "https://github.com/ilpanich/axiam-swift-sdk.git", from: "1.0.0-alpha9")
],
targets: [
    .target(name: "MyApp", dependencies: [
        .product(name: "AxiamSDK", package: "axiam-swift-sdk")
    ])
]
```

### CocoaPods

```ruby
pod 'AxiamSDK', '~> 1.0.0-alpha9'
```

## Quickstart

```swift
import AxiamSDK

let config = try AxiamConfig(
    baseURL: URL(string: "https://id.example.com")!,
    tenantSlug: "acme"            // §5: a tenant identifier is mandatory (no default tenant)
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
design (§6).

```swift
// Development self-signed server: add a custom CA (PEM) as an extra trust root (§6).
let config = try AxiamConfig(
    baseURL: URL(string: "https://localhost:8443")!,
    tenantSlug: "acme",
    customCA: try Data(contentsOf: caPemURL)
)

// IoT / service-account mutual TLS: present a client identity certificate (§6.1).
let mtls = try AxiamConfig(
    baseURL: URL(string: "https://id.example.com")!,
    tenantSlug: "acme",
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

There is no public getter for the wrapped value.

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

JWTs are verified against the org-wide JWKS (`GET /oauth2/jwks`, EdDSA/Ed25519 only; other
algorithms are rejected before key lookup). The JWKS is cached for 300s and fetched
single-flight. Expiry is enforced by the guard, not the verifier.

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
