# Changelog

All notable changes to the AXIAM Swift SDK are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed — BREAKING

- **The §10 route guard now applies the full CONTRACT.md §10.1 "minimum local-verification set",
  which tightens what it accepts.** Two rules change acceptance for tokens that used to pass:

  1. **`nbf` is now honoured.** `JwtClaims` did not model `nbf` at all, so a token whose
     not-before instant was in the future was accepted. It is now rejected.
  2. **An absent `exp` is now rejected** (landed as SEC-080, restated here because §10.1 requires
     the tightening be called out). A token with no `exp` is a permanent credential, not a token
     without an expiry constraint.

  **A token minted by the AXIAM server is unaffected** — it always carries `exp` and never a
  future `nbf`. The break is real for a guard fed tokens from *another* signer that shares the
  organization JWKS: such a guard may start rejecting tokens it used to accept. That is the
  intent of the change.

  Two further API changes accompany it:

  - `JwksVerifier.verify(token:)` is renamed **`verifySignatureOnlyUnchecked(token:)`**. It is
    the raw signature primitive §10.1 permits, and its name now says at the call site that it
    checks no claims. `AxiamRequestAuthenticator.authenticate(_:)` remains the guard entry point
    and routes through it. (Internal to the module; no public API is removed.)
  - `AxiamConfig.init` gains two optional trailing parameters, `expectedIssuer` and
    `expectedAudience`, both defaulting to `nil`. Callers using the memberwise initializer with
    argument labels are unaffected.

### Added

- **`iss` and `aud` verification, conditional on configuration (§10.1 rules 5 and 6).**
  `AxiamConfig.expectedIssuer` and `AxiamConfig.expectedAudience` are optional and unset by
  default: unset means the claim is not checked, exactly as §10.1 specifies. When one is set,
  `AxiamRequestAuthenticator` rejects a token whose claim is absent or does not match — an
  absent claim is never treated as "nothing to check". `aud` is decoded in both the RFC 7519
  single-string and array forms (`JwtAudience`); a wrong-typed `aud` fails the claim decode
  rather than reading as "no audience". A resource server guarding a user-facing API SHOULD set
  `expectedAudience = "axiam:user"`.
- **`AxiamRequestAuthenticator.clockSkewTolerance` (§10.1 rule 7)** — the single named, bounded
  60 s leeway applied to the `exp` and `nbf` comparisons. It is a constant, not an inline
  literal, and deliberately has no setter: the contract forbids an operator raising it to an
  unbounded value.
- `JwtClaims` now models `nbf`, `iss` and `aud`. The SDK could not check what it never decoded —
  that omission is what let rules 3, 5 and 6 go unenforced.
- The full §10.1 negative-test set (`LocalVerificationSetTests`): expired; no `exp`; non-numeric
  `exp`; future `nbf`; different tenant; no `tenant_id`; `alg: none`; an HS-signed token bearing
  an EdDSA key id; and issuer/audience mismatch and absent-claim cases. The `alg: none` and
  HS-confusion cases additionally assert that the JWKS endpoint was never contacted, pinning
  "rejected without consulting a key".
- Vendored `CONTRACT.md` re-synced to add §10.1.

### Security

- **SEC-080 — a token with no `exp` claim was previously accepted (SEC-072 residual).**
  `AxiamRequestAuthenticator.authenticate` enforced expiry as `if let exp = claims.exp, exp <
  now { throw }`; a token carrying **no** `exp` claim decodes to `nil`, so the `if let` never
  fired and the token was accepted with no expiry ever applied. A malformed non-numeric `exp`
  already failed closed (JSON decode error) — only the absent case leaked. The check is now
  `guard let exp = claims.exp else { throw }` followed by the expiry comparison, mirroring the
  C/C++ SDKs' fail-closed handling of an absent `exp`. Bounded in practice by the AXIAM server
  always minting `exp`, but the JWKS trust anchor is organization-wide, so the guard must not
  rely on that invariant holding for every signer that shares it.

- **SEC-072 — the §10 route guard now binds every verified session to the configured tenant.**
  `AxiamRequestAuthenticator` only compared tenants when the request happened to carry an
  `X-Tenant-ID` header *and* the token carried a `tenant_id` claim *and* the two differed; the
  configured tenant was used merely as a fallback field value. Since the JWKS is
  organization-wide, a validly-signed token issued for **another tenant** was accepted whenever
  the request omitted the header (or presented a self-consistent foreign pair). The new
  `assertTenant` runs on every verified token, matching `tenant_id` against the configured
  tenant identifier(s) and failing closed when the claim is absent or empty — mirroring the
  Kotlin SDK's `assertTenant` and the Python/Go guards. The `X-Tenant-ID` cross-check is kept as
  defense in depth. **Note:** AXIAM access tokens carry the tenant *UUID*, so a client used as a
  resource-server guard must be configured with `tenantID`; a slug-only configuration now
  rejects every token rather than accepting any.
- **SEC-073 — a plaintext `http://` base URL is rejected at construction (§6).** `AxiamConfig`
  validated the tenant and org identifiers but never the URL scheme, so a misconfigured base
  silently sent login credentials, session cookies, the CSRF token and the tenant header in
  cleartext while TLS "strictness" looked intact. Construction now throws `NetworkError` for any
  non-`https` base URL, with a loopback exception (`localhost`, `127.0.0.1`, `::1`) for local
  development and integration tests. This is the `X-2` hardening the Rust SDK already had
  (`ensure_secure_scheme`); there is no flag that disables it for a routable host.
- **SEC-077 — `Sensitive` equality is constant-time.** `Equatable` was a plain `==` over the
  wrapped secret, which short-circuits at the first differing byte. Equality now runs through a
  new `ConstantTime.equals` accumulator loop over the raw bytes that never returns early and
  folds the length check into the same accumulator. The conformance is constrained to the new
  `ConstantTimeComparable` protocol (`String`, `Data`, `[UInt8]`) instead of `Equatable`, so a
  wrapped type cannot silently fall back to a short-circuiting comparison. `Sensitive` remains
  deliberately **not** `Hashable` — secrets should not become `Set`/dictionary keys, where
  lookup is a hash-bucketed comparison that is not constant time.

### Added

- **T-145 / CONTRACT §13 — `AxiamWebhooks.verify(...)`**, the webhook-signature verifier every
  SDK must ship. Recomputes `HMAC-SHA256(secret, "<t>.<raw_body>")`, parses the
  `t=`/`v1=` fields of `X-Axiam-Signature` (unknown keys ignored for forward compatibility, a
  header with **no** `v1` is a failure), compares **constant-time over the decoded bytes**
  against every supplied candidate, and enforces a **two-sided** freshness window defaulting to
  300 s so a future-dated timestamp is rejected as well as a stale one. Failures surface as a
  typed `AxiamWebhookError` that never carries the expected signature or the secret. Overloads
  take the secret as `Sensitive<String>` (§7) or plain `String`, and either the raw
  `X-Axiam-Signature` value or a case-insensitive header dictionary; `now:` is the test
  injection seam. The body is taken as raw `Data` — re-serializing parsed JSON changes key order
  and whitespace and breaks the MAC, which the API docs and README state explicitly, along with
  `X-Axiam-Delivery` being the at-least-once dedup key.
- `ConstantTimeComparable` + the internal `ConstantTime.equals` primitive, shared by `Sensitive`
  equality and the webhook verifier.
- Tests: cross-tenant token rejected with and without an `X-Tenant-ID` header, token with no
  `tenant_id` claim rejected, `assertTenant` unit semantics; token with no `exp` claim rejected
  and a malformed non-numeric `exp` pinned as rejected (SEC-080); `http://` rejected, loopback
  `http://` accepted, loopback-host predicate; constant-time equality over `String`/`Data`/
  `[UInt8]` including length mismatches; and the full §13.4 webhook suite (valid+fresh, tampered
  body, re-serialized body, wrong secret, stale `t`, future `t`, malformed headers, duplicate
  `t`, non-hex `v1`, multiple candidates, timestamp-header cross-check, no-leak assertion, and
  the shared cross-SDK vector computed in test setup).

### Changed

- Vendored `CONTRACT.md` re-synced with the new **§13 Webhook Signature Verification**.

## [1.0.0-alpha23] - 2026-08-02

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha21.

## [1.0.0-alpha21] - 2026-07-30

### Changed

- Re-sync vendored CONTRACT.md to contract 1.6

### Fixed

- Identity-check the single-flight refresh slot vacate (rule 6c) + rule 6 regression tests

## [Unreleased]

### Fixed

- **§9 rule 6c (contract 1.6): the single-flight refresh slot is now vacated identity-checked.**
  `AxiamClient.refreshOnce()` cleared `refreshTask` unconditionally on both its success and its
  failure path. The invariant held only by a whole-function argument (ownership is taken and
  released with no intervening suspension point, so the slot could not change identity underneath
  an owner) — nothing local prevented a lagging attempt from wiping a *newer* leader's live entry,
  which is the shape of the bug fixed in the C++ SDK and would open the door to a second wire call
  against an already-consumed, single-use refresh token. The clear now happens only while the slot
  still holds the clearing attempt's own `Task`.

### Added

- **§9 rule 6 regression tests** (`Tests/AxiamSDKTests/RefreshRule6Tests.swift`), covering contract
  1.6's three added test requirements plus Swift-specific cancellation semantics: a caller landing
  in the publish-before-vacate bookkeeping window joins the settled outcome and adds **no** second
  wire call (6a/6b, on both the success and the §9.3 failure path); a caller arriving after full
  settlement performs its **own** wire call and receives *that* call's outcome, not the previous
  burst's (6d); a lagging attempt does not clear a newer leader's slot (6c); and cancelling the
  leading caller neither cancels the shared refresh (stranding the callers that joined it) nor
  leaves the slot permanently occupied. The tests pin the windows open deterministically with a
  new visible-for-testing `RefreshPhase` hook that is never installed in production.
- The four rule-6 invariants, and why each holds for the `actor` + shared-`Task` mechanism §9
  prescribes for Swift, are documented at the guard itself (`AxiamClient.refreshOnce()`).

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
