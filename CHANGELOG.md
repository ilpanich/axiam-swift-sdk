# Changelog

All notable changes to the AXIAM Swift SDK are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **CONTRACT.md §10.1 rule 9 extended for DPoP, and §21.7.2 proof verification
  implemented (contract 1.16/1.17).**

  `CnfClaim` gains `jkt` (RFC 9449 §6.1), and
  `AxiamRequestAuthenticator.verifyTokenBinding(_:proofs:)` applies the full
  ten-row rule against a certificate thumbprint, a verified DPoP key thumbprint,
  or **both**. A `cnf` naming both methods is a **conjunction** — satisfying only
  the more convenient one is not compliance — and a `cnf` naming nothing this SDK
  can check (including an *empty* one, which is how proto3 delivers an empty
  `CnfClaim`) is refused rather than read as unbound. `verifyCertificateBinding`
  remains for certificate-only transports and now **refuses** a DPoP-bound or
  both-bound token rather than ignoring the half it cannot check.

  New `DpopVerifier` implements all ten §21.7.2 checks and returns the proof key's
  RFC 7638 thumbprint, so a value passed to `PresentedProofs` could only have come
  from a proof that verified. `InMemoryDpopJtiStore` covers check 8 for a single
  process; the `DpopJtiStore` argument is required, not optional, because there is
  no safe default that skips replay tracking.

  `Package.swift` gains swift-crypto's `_CryptoExtras` product for RSASSA-PSS
  (PS256) — the same package already depended on, so this is a product, not a new
  dependency. `Crypto` alone covers Ed25519 and P-256.

  Not a breaking change: an unbound token is still accepted with no certificate and
  no proof, asserted directly by the first test in the new group.

- **CONTRACT.md §10.1 rule 9 — sender-constrained (certificate-bound) access tokens**
  (contract 1.15, RFC 8705 §3 / RFC 7800). A token carrying `cnf` is **not** a bearer
  token; accepting one without proving the caller holds the named key converts it back
  into one.
  - `JwtClaims.cnf` / `CnfClaim` — the decoded confirmation claim. The `x5t#S256` wire key
    is not a legal Swift identifier, so it is mapped through an explicit `CodingKey`.
  - `AxiamRequestAuthenticator.authenticateSenderConstrained(_:presentedThumbprint:)` —
    the guard entry point for a resource server that accepts bound tokens.
  - `AxiamRequestAuthenticator.certificateThumbprintS256(der:)` — RFC 8705 §3.1
    `x5t#S256`: base64url, **unpadded**, SHA-256 over the DER certificate.

  **Not a breaking change, and it does not make certificates mandatory.** An *unbound*
  token is still accepted with or without a certificate.

  `authenticate(_:)` deliberately does **not** apply rule 9: it has no transport to ask for
  a peer certificate. The thumbprint must come from the transport, never from a
  caller-settable header. A `cnf` naming an unimplemented method is **rejected**, never
  read as "unconstrained".

- **CONTRACT.md §21** — the FAPI 2.0 posture as an SDK sees it. Only rule 9 is normative
  for this SDK.

### Changed

- **Re-sync vendored `CONTRACT.md` / `openapi.json` to contract 1.15.**


### Changed

- **Re-sync vendored `CONTRACT.md` to contract 1.14** — documentation only, no code change.
  §20.2 rule 6 (a permission ticket MUST NOT be retried) cited a "measured residual
  (ilpanich/axiam#302) … roughly 1 in 640" as its second reason. That residual is closed: the
  server now decides the ticket race with a transaction its storage engine arbitrates plus a
  redemption nonce read back after the commit. **The rule is unchanged, and this SDK's
  behaviour is unchanged** — `uma_exchange_ticket` stays excluded from every automatic retry
  path. What changed is the reasoning: the first reason (a spent ticket makes the retry
  useless) always stood alone, and the second now rests on what an SDK can actually know —
  it is talking to a server whose storage engine it cannot attest, and the guarantee is
  conditional on that engine being persistent.
- **BREAKING (contract 1.13): `tokenExchange`'s `subjectTokenType` is now required**, losing its
  `= nil` default and narrowing from `String?` to `String`.

  It shipped optional, defaulting to `accessTokenType` — which satisfied §15.7's "never inspect
  the subject token" while leaving the rule it serves unenforced: a defaulted parameter *is* a
  default the SDK applies whenever the caller says nothing. §15.1 now makes it required, so
  Swift refuses the call outright: omitting the argument no longer compiles.

  The case the compiler cannot catch is a **blank** string — the shape a config-driven caller
  produces — so that is refused client-side with no wire call, naming both constants. Asserted
  over `""`, `"   "` and a tab.

  **Migration** — one argument, naming what you were previously getting by silence:

  ```swift
  let narrowed = try await client.tokenExchange(
      subjectToken: usersToken,
      subjectTokenType: AxiamClient.accessTokenType,  // <- add this
      scopes: ["orders:read"])
  ```

  This closes a gap rather than opening one: `subject_token_type` has always been required *on
  the wire*, and the SDK was covering for that with a constant which stopped being the only legal
  value when X4 landed.

### Added

- **§15.7 external-IdP subject tokens (X4).** `tokenExchange` can now exchange a token minted by a
  trusted external IdP — a partner's Entra, Okta or Keycloak — for an AXIAM token scoped to what
  the resolved AXIAM user may actually do. No new operation: the same method, plus a
  `subjectTokenType` parameter and the new `AxiamClient.jwtTokenType`. `accessTokenType` becomes
  public alongside it, so a caller naming either value does not have to retype the URN.

  **The type is the caller's to name, never the SDK's to guess.** §15.7 forbids inspecting the
  subject token to pick it, because which kind of token you hold is something only you know and a
  wrong guess is the difference between a request that is refused and one that is silently
  reinterpreted. A JWT-shaped subject token does **not** change what is sent, which is asserted by
  a test. (This shipped as `String? = nil` with an `…:access_token` default; contract 1.13 made it
  required — see *Changed* above.)

  Also asserted: an `actorToken` alongside an external subject token surfaces `invalid_request`
  with no retry and no request rewriting; a refused refresh or ID token type is never retried as a
  different type; the one normative description — `the subject token's issuer is not configured
  for token exchange`, meaning *fix the AXIAM trust config* rather than *fix your token* — reaches
  the caller intact; and nothing re-exchanges an exchanged token, which both server paths refuse
  because exchanges do not compose.

  `CONTRACT.md` and `openapi.json` re-synced from `ilpanich/axiam@main` (contract 1.11 → 1.12 plus
  §15.7), which also brings contract 1.12's `/oauth2/*` error rows dispatching on the `error`
  field at any status, and the `TokenExchangeTrust` schemas behind the X4 provider configuration.

- **§12 OIDC/SSO relying-party helpers, §12.7 logout, §14 device grant and §15 token exchange.**
  All four land together, because all four were blocked by the same thing: contract §12.6
  required this SDK to defer §12 in its entirety, and §12.7 was scoped to SDKs that ship §12.
  Contract 1.11 (ilpanich/axiam#306) lifts that deferral, and this is the port.

  The nine §12 operations are on `AxiamClient` under the names §12.2 had already reserved for
  Swift: `oidcDiscover`, `oidcBegin`, `oidcExchange`, `oidcRefresh`, `loginClientCredentials`,
  `introspect`, `revoke`, `ssoStart`, `ssoComplete`. They are built on the existing transport,
  `Sensitive` wrapper and JWKS verifier — §12 forks none of them, and adds no second
  key-fetching path.

  What is load-bearing rather than incidental, and tested as such:

  - **Statelessness** (§12.3 rule 1). `oidcBegin` returns `state`, `nonce` and `codeVerifier`
    and keeps none of them; two calls share nothing.
  - **The §12.4 checklist, with one failing test per rule** — the contract asks for exactly
    that. `alg` pinned to EdDSA before key lookup, signature by `kid`, exact-string issuer,
    audience with a mandatory `azp` when plural, time with at most 60 s skew, nonce by
    constant-time comparison. Rule 7 makes it all-or-nothing: a validation failure discards the
    access and refresh tokens from the same response, and there is no "skip validation" option
    anywhere on the public surface.
  - **A slug-only client is refused client-side**, with no wire call, on the five operations
    that need a tenant UUID (§12.3 rule 4).
  - **§14.2's polling rules**, including the one this port got wrong first and a test caught:
    the deadline check must reject a poll *scheduled* past `expires_in`, not merely one issued
    after it. Checking `now < deadline` before sleeping looks equivalent and is not — after a
    `slow_down` pushes the interval past the time remaining, that check passes, the loop sleeps
    through the deadline and polls anyway. `slow_down` raises the interval permanently by 5 s;
    `access_denied` and `expired_token` stay distinct.
  - **§15's refusals surface verbatim**: no retry on `unauthorized_client`, no auto-narrowing on
    `invalid_scope`, no attempt to refine `invalid_grant` into "wrong tenant". No refresh token
    exists on `ExchangedToken`, and the result is never adopted as this client's credential.
  - **§12.7's back-channel verifier rejects a replayed ID token twice over**: it requires the
    back-channel `events` key and rejects any token carrying a `nonce`. The result carries
    `sid`/`sub`/`jti` and is never collapsed to a boolean.

  `AxiamConfig` gains `oidcClientID`, `oidcClientSecret`, `oidcDiscoveryTTL` (clamped up to the
  five-minute floor) and `oidcClockSkew` (clamped down to 60 s). Three runnable examples:
  `Examples/OidcLogin`, `Examples/DeviceLogin`, `Examples/TokenExchange`.

- **§20.3 challenge emission from the §11 guard.** `requireAccess(_:resource:scope:umaChallenge:)`
  takes a `UmaChallenger` (realm, `as_uri`, PAT); with one, a denial mints a permission ticket for
  the action that was refused and carries the formatted `WWW-Authenticate: UMA` value on the thrown
  `AuthzError`, so a framework adapter can copy it onto the 403 it already returns.

  It is **opt-in** because emitting a challenge means minting a credential: a guard that did it by
  default would turn every unauthorized request into a Protection API call, which is a
  denial-of-service amplifier pointed at your own authorization server. An allow mints nothing.
  And a **minting failure is not an escalation** — an expired PAT or an unreachable Protection API
  still yields the plain `AuthzError`, never a 503 and never an allow. Both are asserted by
  counting Protection API calls. The requested scope is the AXIAM *action*, so the ticket asks for
  exactly the authority just refused and the engine's deny rules keep applying to whatever RPT
  comes back.

  Paired with the new `Examples/UmaResourceServer` and `Examples/UmaClient` targets, which run both
  halves — including the trust decision §20.3 keeps in the caller's hands rather than
  auto-exchanging against whatever host a 403 named.

### Changed

- **`AuthzError` gains a `challenge` property** (optional, defaulting to `nil`), holding the
  formatted challenge described above. Additive: every existing initialiser call keeps compiling,
  and an adapter that ignores it emits exactly the 403 it always did. It is deliberately **not**
  part of `description` — the value carries a live ticket (§20.6), and `description` is what ends
  up in a log line.
- **`Sensitive.expose()` is now public.** §20 hands the *requesting party's* token to the calling
  application: an RPT exists to be sent onward on the retried request, so a
  `RequestingPartyToken.accessToken` that could never be read made the ticket grant unusable
  outside this module. Widening from module-internal is additive; every textual representation
  still redacts, and the doc comment says plainly that the result must never reach a log or
  serialisation sink.

## [1.0.0-alpha24] - 2026-08-04

### Added

- Apply the full CONTRACT §10.1 local-verification set

### Changed

- Add the §10.1 rule-8 guardrail regression tests (#15)
- Device (mTLS) tokens now carry aud=axiam:m2m (#14)
- Service accounts can use login_client_credentials (#13)

### Fixed

- Require a kid when selecting a JWKS key (§13.4 observation 7) (#12)
- Reject tokens with no exp claim (SEC-080)
- Bind sessions to the configured tenant, refuse plaintext base URLs, constant-time Sensitive equality; add webhook verifier

## [Unreleased]

### Added

- **UMA 2.0 — Protection API and ticket grant (CONTRACT §20).** `umaDiscover`,
  `umaRegisterResource`, `umaReadResource`, `umaUpdateResource`, `umaDeleteResource`,
  `umaListResources`, `umaRequestTicket` and `umaExchangeTicket` on `AxiamClient`, plus the two
  synchronous challenge helpers `AxiamClient.umaParseChallenge` / `.umaChallengeHeader`. New types
  `UmaResourceSet`, `UmaRequestedPermission`, `UmaRptPermission`, `RequestingPartyToken`,
  `UmaChallenge`, `UmaClientCredentials` and `Uma2Configuration`.

  **This ships while §12 does not, and that is not an inconsistency.** §12.7, §14 and §15 stay
  blocked because each reaches for §12's discovery cache and ID-token validation. §20 does not:
  UMA carries its own discovery document, the Protection API is ordinary bearer-authenticated REST,
  and the ticket grant returns an opaque RPT with nothing to validate. No PKCE, no state store, no
  JWKS interaction, no §9 coupling.

  The load-bearing rules, all asserted in `Tests/AxiamSDKTests/UmaTests.swift`:

  - **`umaExchangeTicket` is never retried** — not on `5xx`, not on a transport failure, not on
    `invalid_grant`. This is the one documented exception to §16, and a security rule rather than a
    performance one: the ticket is consumed *before* the exchange is evaluated, so a retry is a
    second redemption — the concurrency case whose measured residual `ilpanich/axiam#302` records.
  - **`umaParseChallenge` performs no exchange.** The `as_uri` names an authorization server the
    caller has not chosen to trust.
  - **The RPT is never adopted**, and `RequestingPartyToken` has no refresh-token property.
  - **`umaUpdateResource` replaces the scope list rather than merging it** — no read-modify-write,
    so omitting a scope removes it.
  - **An empty PAT or `claimToken`, or a slug-only tenant, is refused client-side** with no wire
    call, so a request that could not have succeeded never spends a ticket.

- **Bounded read-only retry (CONTRACT §16).** `checkAccess`, `can`, `batchCheck` and
  the JWKS fetch now retry a transient failure: 3 attempts total, 200 ms base, 5 s cap,
  **full jitter** over `[0, backoff]`, and `Retry-After` honored as a **floor** — it can
  lengthen a wait, never shorten one, so a `Retry-After: 0` cannot defeat the backoff. On
  by default; `AxiamConfig(retryEnabled: false)` gives exactly one attempt for a caller
  who owns their own retry layer. The attempt cap, base and delay cap are deliberately
  **not** settable: §16.1 permits lowering or disabling, never raising, and a caller who
  can raise them turns one client into the herd a backoff exists to prevent.

  Eligibility is "changes no server state", **not** "is a `GET`". The authorization check
  is a `POST` with a body and is the operation this policy exists for; `login`,
  `verifyMfa`, `logout` and `refresh` are never retried, both because they change state
  and because their credentials are single-use. A `CancellationError` is re-thrown rather
  than retried — a cancelled task is the caller withdrawing their request, and retrying
  would keep the work alive past the point its scope was cancelled.

- **Client-side decision memo (CONTRACT §17).** `AxiamConfig.decisionMemoTtl` enables a
  bounded, TTL-clamped cache of authorization decisions. **Disabled by default** (`nil`),
  and a TTL above 5 s is clamped rather than rejected. Allows and denies are cached
  identically, `reasonCode` comes back with the decision, failures are never cached, and
  any credential change clears it. Unlike the Go, Java and C memos this one takes no lock:
  it is only ever touched from inside the `AxiamClient` actor, whose isolation already
  serialises every access.

  **Read-your-own-writes is not guaranteed.** The staleness bound is the TTL in both
  directions — a grant just *added* can still read as denied for up to the TTL — which is
  the direction that surprises people, and it breaks silently.

- **Deterministic shutdown (CONTRACT §18).** `AxiamClient.close()` releases the HTTP
  client and clears the cookie jar, the CSRF token and any retained `Sensitive` challenge
  token. It is idempotent and issues **no request**: the server-side session deliberately
  outlives the client object, so a close that logged out would silently end every user's
  session on each deploy. A call on a closed client throws `NetworkError` naming the cause
  rather than silently reopening. `shutdown()` remains as an alias, so no existing call
  site changes.

- **Telemetry hooks (CONTRACT §19).** `AxiamConfig.telemetryHook` installs a sink for
  `requestStart`, `requestEnd`, `retry`, `refresh` and `configClamped` events, so metrics
  can be wired without this package taking a dependency on any metrics library. One
  request pair per **attempt**, so a caller can count real wire calls from the events.
  `TelemetryEvent` is an `enum` with a closed case list and no dictionary payload, which
  is what makes "no event carries a token" checkable by reading one declaration, and it
  carries the path *template* rather than a URL with ids substituted in.

### Security

- **JWKS key selection is now by `kid` only (§13.4 observation 7).** `selectKey`
  fell back to "the sole EdDSA key, when unambiguous" whenever a token's header
  carried no `kid`. Kotlin, PHP and Java all reject that outright, and the
  fallback is fragile in exactly the situation key ids exist for: during a key
  rotation the JWKS holds two keys, so a token that verified yesterday starts
  failing for a reason that has nothing to do with the token.

  The same fallback was also reached when a `kid` **was** present but matched
  nothing — a stricter problem than the observation named. A token naming a key
  the server does not publish was verified against whichever single key happened
  to be there, and if it was signed by that key it was **accepted**. Confirmed by
  falsification: against the previous code, both new tests report acceptance, not
  a late signature failure.

  A `kid` is now required, and one that names no published EdDSA key is a hard
  failure. Tokens minted by the AXIAM server always carry a `kid`, so this is not
  expected to affect any working deployment.

### Changed

- Re-vendored `CONTRACT.md` at **1.10** and `openapi.json` (the server's `/uma2/*` surface).
- `AuthError` gained `oauthError` and `oauthErrorDescription`, both optional and both `nil` for
  every failure that is not an OAuth2 protocol error, so existing callers are unaffected. §20.4
  requires dispatching on the body's `error` field rather than the HTTP status — `access_denied`
  answers `403` on the ticket grant where RFC 8628's answers `400` — and the code has to reach the
  caller somewhere. The contract models it as an `OAuthProtocolError` *sub-type of* `AuthError`;
  Swift structs cannot be subclassed, so an `AuthError` that carries the code is the equivalent,
  and the §2 taxonomy stays at exactly three cases rather than gaining a fourth (which would have
  broken every exhaustive `switch` over `AxiamError`).

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
