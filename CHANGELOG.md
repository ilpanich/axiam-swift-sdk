# Changelog

All notable changes to the AXIAM Swift SDK are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0-alpha18] - 2026-07-24

### Changed

- Add line-coverage regression gate (floor 92%) + publish lcov (#6)

## [1.0.0-alpha16] - 2026-07-22

### Changed

- Adopt CONTRACT 1.3; defer gRPC get_user_info

## [Unreleased]

### Changed

- Adopt CONTRACT.md 1.3: the new gRPC-only `getUserInfo` operation (CONTRACT §1.1) is
  documented as a deferred follow-up (this SDK ships no gRPC transport in v1) and the
  vendored contract/proto copies are re-synced. Per §1.1 the REST `/oauth2/userinfo` endpoint is not substituted.

## [1.0.0-alpha15] - 2026-07-21

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha12.

## [1.0.0-alpha12] - 2026-07-19

### Changed

- Add examples, align README badges, sync CONTRACT §5.1 org context (#4)

## [1.0.0-alpha11] - 2026-07-18

### Changed

- Publish theme-settings.json and root redirect (#3)

## [1.0.0-alpha10] - 2026-07-18

### Changed

- Resolve org_id from access-token claim for the refresh body (D-14) (#2)
- Force bash for gh-pages publish step
- Publish API docs to gh-pages branch
- Drop configure-pages step, mirror C SDK template
- Auto-enable GitHub Pages (enablement: true)
- Add docs publish workflow to GitHub Pages

## [Unreleased]

### Added

- Initial AXIAM Swift SDK (`AxiamSDK`), conforming to CONTRACT.md §1–§7, §9–§11
  (including §6.1 mTLS).
- `AxiamClient` actor with the canonical §1 operations: `login(email:password:)`,
  `verifyMfa(_:)`, `refresh()`, `logout()`, `checkAccess(_:resource:scope:)`,
  `can(_:resource:scope:)`, `batchCheck(_:)`.
- `AxiamConfig` requiring a tenant identifier (`tenantSlug`/`tenantID`, §5), with optional
  mutually-exclusive `orgSlug`/`orgID`, `customCA` (§6), `clientCertificate` (§6.1 mTLS), and
  timeouts.
- §2 error taxonomy: `AuthError`, `AuthzError`, `NetworkError` with the HTTP-status mapping
  table; `NetworkError` carries the underlying transport error as `cause`.
- §3 CSRF token capture and echo on state-changing requests.
- §4 in-memory, per-client cookie jar honouring domain / path / secure attributes
  (AsyncHTTPClient does not manage cookies).
- §5 `X-Tenant-ID` header injected on every request.
- §6 strict TLS verification always on, with an additive custom-CA trust root; §6.1 optional
  client-certificate mutual TLS via NIOSSL. No TLS-bypass surface exists.
- §7 `Sensitive<T>` wrapper redacting secret material (MFA challenge token, mTLS private key)
  in all textual output.
- §9 single-flight token refresh via an actor holding one shared in-flight `Task`.
- Org-wide EdDSA/Ed25519 JWKS verification with swift-crypto (`Curve25519.Signing`),
  300-second cache, single-flighted fetch, and algorithm rejection before key lookup.
- §10 framework-agnostic route guard (`AxiamRequestAuthenticator`) and §11 declarative
  helpers (`requireAuth` / `requireAccess(_:resource:)` / `requireRole(_:)`).

### Deferred (follow-ups)

- gRPC transport (no §-requirement lists it for Swift).
- §8 AMQP HMAC consumption (the contract lists AMQP for Rust/TS/Go/Python/Java/PHP, not Swift).
- A first-party `AxiamVapor` product (Vapor wiring is documented in the README instead).

[Unreleased]: https://github.com/ilpanich/axiam-swift-sdk/compare/HEAD
