# ``AxiamSDK``

The official Swift SDK for AXIAM (Access eXtended Identity and Authorization Management).

## Overview

`AxiamSDK` is a REST client for the AXIAM identity and authorization platform. It conforms to
the cross-language **CONTRACT.md** behavioral contract, §1–§7 and §9–§11, including §6.1 mutual
TLS (client-certificate authentication).

The client is an `actor`, so its session state — the in-memory cookie jar, the CSRF token, and
the single-flight refresh guard — is safe under concurrent use. Access and refresh tokens are
delivered by the server as `httpOnly` cookies and never handled as raw strings by your code.

```swift
let config = try AxiamConfig(
    baseURL: URL(string: "https://id.example.com")!,
    tenantSlug: "acme"
)
let client = try AxiamClient(config: config)

switch try await client.login(email: "user@example.com", password: "correct horse") {
case .authenticated(let user):
    let canEdit = try await client.can("edit", resource: "doc-uuid")
    print(user.userID, canEdit)
case .mfaRequired:
    try await client.verifyMfa("123456")
case .mfaSetupRequired:
    break
}
```

## Scope

In scope for v1: §1 methods, §2 error taxonomy, §3 CSRF, §4 cookie jar, §5 tenant context,
§6/§6.1 TLS + mTLS, §7 `Sensitive`, §9 single-flight refresh, §10 route-guard, §11 declarative
helpers, and org-wide EdDSA JWKS verification.

Out of scope for this Swift v1 (documented follow-ups): gRPC transport and §8 AMQP HMAC
consumption — the contract does not list AMQP for Swift.

## Topics

### Client

- ``AxiamClient``
- ``AxiamConfig``
- ``ClientCertificate``

### Results

- ``LoginResult``
- ``AccessResult``
- ``AccessCheck``
- ``AxiamUser``

### Errors

- ``AxiamError``
- ``AuthError``
- ``AuthzError``
- ``NetworkError``

### Security

- ``Sensitive``

### Resource-server integration

- ``AxiamRequestAuthenticator``
- ``AxiamRequestContext``
- ``AxiamGuards``
- ``AxiamGuardHandler``
