# Changelog

All notable changes to the AXIAM Swift SDK are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0-beta08] - 2026-09-02

### Added

- **The four public login-provider operations (CONTRACT §12.1, contract 1.38).**
  `ssoProviders`, `ssoStartOauth2`, `ssoCompleteOauth2` and `ssoCompleteHandoff`
  join the nine §12 operations already on `AxiamClient`, under the names §12.2
  reserves for Swift. They are what a login *page* needs: which "Sign in with X"
  buttons to render, and how to finish the two flows that cannot set a
  `SameSite=Strict` cookie on their own response. `FederationProvider` models the
  public provider shape faithfully, including the nullable `buttonIcon` data URL,
  `hasBundledMark` and `inherited`; `FederationHandoff` carries the `axiam_handoff`
  query-parameter name and the 60-second code TTL.

  Five rules are load-bearing and each has a test.

  - **An empty list is a success, and the only success there is** (note 9). An
    unknown organization, a known one with no providers, and a request naming no
    organization at all all answer `200 []`. `ssoProviders` never turns that into a
    not-found error and never refuses client-side for missing workspace context — a
    client-side `400` would restore exactly the two-valued organization-slug oracle
    the empty list exists to remove.
  - **`protocol` selects the start operation, never `providerKind`** (note 10). It
    is surfaced as the wire `String` rather than an enum, so a protocol the server
    adds later cannot fail the decode of the whole list.
  - **PKCE on the OAuth2 path is generated and held server-side** (note 11). This
    SDK computes no verifier and no challenge and sends neither.
  - **A handoff `401` is terminal** (note 12). Unknown, expired and
    already-redeemed answer alike, the code is gone either way, and the redemption
    is issued exactly once.
  - **A `400` is a configuration error** (rule 12a, new at 1.38). §2 puts it on the
    `NetworkError` row — this taxonomy's configuration/programming-error member, as
    distinct from the `AuthError` a `401` gets — and it is not retried. A
    `redirect_uri` is never built from a value the identity provider supplied.

### Changed

- §12.1: the four public login-provider operations (contract 1.38) (#55)

- **Re-vendored contract 1.38.** `CONTRACT.md`, `openapi.json` and
  `management-registry.json` are byte-for-byte copies of the `sdks/` sources in
  [`ilpanich/axiam`](https://github.com/ilpanich/axiam) (ilpanich/axiam#398).
  `proto/` and `opaque-test-vectors.json` did not change. The §27 management
  surface was regenerated with `Scripts/gen_management.py`, as §27.8 requires
  whenever the vendored artifacts move: `openapi.json` gained fields on the
  federation-config schemas.

## [1.0.0-beta07] - 2026-08-30

### Changed

- Re-vendor AXIAM contract 1.36

- **Documented contract 1.36, which this SDK already vendors.** `CONTRACT.md`,
  `openapi.json` and `management-registry.json` were re-vendored from the
  `sdks/` sources in [`ilpanich/axiam`](https://github.com/ilpanich/axiam)
  (ilpanich/axiam#396) as part of the 1.0.0-beta06 release, whose note recorded
  only "no notable changes". That understated it — the contract moved in that
  release — and v1.0.0-beta06 is tagged, so the correction is recorded here
  rather than by editing a released section. No SDK code changed with the
  artifacts; the three entries below are why not.

- **§5.2.2 rule 4 is new, and is an errata rather than a wire change.** The
  server now scopes every *self-service* endpoint to `principal_tenant_id`
  rather than to the acting tenant — `GET`/`PUT /users/{own id}`, that user's
  `mfa-methods`, `POST /users/{own id}/reset-mfa`, `POST /auth/mfa/enroll` and
  `/confirm`, `POST /auth/webauthn/register/start` and `/finish`, `POST
  /users/me/resend-verification`, the §25 account export and erasure for the
  caller's own id, and `GET /oauth2/userinfo`. Each of those answered `404` for
  an organization-level caller that had switched to another tenant and now
  succeeds. No request or response field is added, so nothing here is a wire
  change.

  The rule also forbids the obvious workaround: an SDK MUST NOT clear or rewrite
  the acting-tenant header for those calls, because that header is what makes
  the **administrative** form of the same endpoints reach the tenant the caller
  asked for — stripping it would break reading another tenant's user in order to
  fix reading your own. This SDK was audited for such a workaround and has none:
  every request path in `AxiamClient.swift` sends `config.tenantHeaderValue`
  under `X-Tenant-ID`; no endpoint is special-cased.

- **Issue #395 is settled: the acting-tenant header is `X-Axiam-Tenant`**, and
  §5.2, §5.2.2 and §5.2.3 now name it. The note under 1.0.0-beta05 below
  recorded the contract and the server disagreeing on it; they no longer do, and
  the name this SDK documents was already the server's. §5 rule 2's
  *unconditional* `X-Tenant-ID` is deliberately **not** renamed, and the
  contract now carries a note saying why it must not be: it names the client's
  *constructor* tenant, so folding it into `X-Axiam-Tenant` would override the
  acting tenant on every request an organization-level principal made after a
  switch. Every existing §5 rule 2 send is left exactly as it was.

- **`openapi.json` gained `/api/v1/auth/me`, `/api/v1/auth/password/change` and
  `/api/v1/admin/bootstrap`.** All three were always served and always normative
  in `CONTRACT.md`; they were missing from the generated document only because
  their handlers were never listed in its `paths(…)`. `management-registry.json`
  keeps `operation_count` at **155** — bootstrap is excluded on the §27.0
  boundary — so §27 code generation is unaffected and the generated surface is
  unchanged.

## [1.0.0-beta06] - 2026-08-30

### Changed

- Maintenance release — no notable changes since v1.0.0-beta05.

## [1.0.0-beta05] - 2026-08-30

### Added

- Contract 1.35 (carrying 1.34) — principal tenant, tenant_scope, service-account RBAC

- **Contract 1.35, which carries contract 1.34 with it.** Nothing had been fanned
  out since 1.33, so this re-vendors `CONTRACT.md`, `openapi.json` and
  `management-registry.json` across both revisions. The registry still holds 155
  operations across 24 namespaces — 1.35 changed only its `spec_digest` — so the
  eight §27 operations below arrived with 1.34 and are new here regardless.

- **§27: service accounts as RBAC principals** (contract 1.34) — eight generated
  operations across `roles`, `groups` and `serviceAccounts`, with the
  `AssignRoleToServiceAccountRequest`, `RoleServiceAccountAssignment` and
  `AddServiceAccountMemberRequest` models they need.
  `roles.unassignFromServiceAccount` takes the same optional `resourceID` query
  parameter as the user and group unassign calls: omitting it removes the *global*
  grant specifically, not every grant of that role.

- **§5.2.2: the acting tenant and the principal tenant are different things**
  (contract 1.34). `AxiamUser` gains `principalTenantID`, `principalTenantSlug`,
  `orgID` and `reachableTenantIDs` — appended and defaulted on the initializer, so
  every call site written before contract 1.34 still compiles.

  `principalTenantID` is filled from `tenantID` when the server omits it. Absent
  means *equal*, not unknown: a server older than 1.34 cannot switch the acting
  tenant either, so the fallback is the only value the field could have had. Read
  `orgID` from the session instead of resolving a slug through
  `GET /api/v1/organizations`, which is `super-admin`-only and returns only the
  caller's own organization.

- **§5.2.3: tenant-scoped role assignments** (contract 1.35). `tenantScope` appears
  on the three assignment request structs and on the assignment objects the read
  paths return. Omitted means unrestricted, which is what every assignment written
  before the field existed already meant.

  `reachableTenantIDs` pairs with it on `AxiamUser`: a narrowed organization-level
  principal still reports `organizationLevel == true`, so an application gating a
  tenant switcher on that flag alone offers tenants the server refuses at the
  header.

- **`AxiamClient.opaqueEnrollmentForSelf(password:)`** — see below.

### Fixed

- **A registration record for your own password was sealed against the wrong
  tenant.** CONTRACT.md §5.2.2 rule 2: the caller's credentials live in the tenant
  the *account* lives in, not whichever tenant the client is currently pointed at,
  and a record sealed against the acting tenant is refused with "the OPAQUE session
  was issued for a different tenant".

  `opaqueEnrollment(password:)` had one behaviour for a method documented for three
  callers — user creation, change-password and reset completion — and only the
  first of those wants the acting tenant. It keeps that behaviour; the new
  `opaqueEnrollmentForSelf(password:)` seals against the principal tenant the login
  reported (naming it by id and sending no `tenant_slug`, which would otherwise
  out-vote the id server-side) and is what a self-service password change must
  call. It throws `AxiamError.network` before any login has completed, because
  there is nothing to seal against then and falling back to the acting tenant is
  the bug itself.

  The two collapse to the same request for every ordinary principal, so this only
  bit an organization-level account that had switched tenant.

- **`tenant_scope: []` no longer reaches the wire** (§5.2.3 rule 1, refused with
  `400`). `encodeIfPresent` — what gives §27.4 rule 5 its teeth — covers `nil` and
  nothing else, so an array that is present but empty is encoded. And an empty
  array is exactly what building the field from a filtered collection produces for
  "no tenants named". `Scripts/gen_management.py` now emits, for that one field:

  ```swift
  if let tenantScope, !tenantScope.isEmpty {
      try container.encode(tenantScope, forKey: .tenantScope)
  }
  ```

  The allowlist is one field wide on purpose: elsewhere an empty array is
  meaningful — a replacement body clearing a list — and `Contract135Tests` pins
  that `UpdateWebhookRequest(events: [])` still sends `"events": []`.

### Note on `X-Tenant-ID` vs `X-Axiam-Tenant`

CONTRACT.md §5.2.2 and §5.2.3 name the acting-tenant header `X-Tenant-ID`, but the
AXIAM server reads **`X-Axiam-Tenant`** (`ACTIVE_TENANT_HEADER` in
`crates/axiam-api-rest/src/extractors/auth.rs`), as do its own tests, the admin UI,
and the `openapi.json` vendored alongside that contract. The server never reads
`X-Tenant-ID` at all.

Documentation updated here names `X-Axiam-Tenant`, because a tenant switch sent
under the other name is not refused — it is ignored, and the request quietly acts on
the principal's own tenant instead. The discrepancy has been reported upstream; this
SDK's existing `X-Tenant-ID` sends are left as they are, being out of scope for a
contract re-vendor.

## [1.0.0-beta04] - 2026-08-28

### Changed

- Re-vendor the 1.0.0-beta03 spec stamp

- Pin actions by digest, record why SwiftPM needs no attestation, re-vendor contract 1.33

- **CONTRACT 1.32 — signing in an organization-level principal (§5.2.1).**
  `CONTRACT.md`, `openapi.json` and `management-registry.json` re-vendored from
  the AXIAM server, where the same bug class had made an organization-level
  administrator unable to sign in at all (ilpanich/axiam#388).

  Naming no tenant now resolves the organization's own reserved scope on
  `/auth/login`, `/auth/opaque/login/start`, `/auth/opaque/register/start` and
  `/auth/webauthn/authenticate/discoverable/start`. That reserved tenant's slug
  is `organization`, so this SDK reaches it through the ordinary initializer,
  and the "no tenant" refusal now says so:

  ```swift
  try AxiamConfig(baseURL: url, tenantSlug: "organization", orgSlug: "globex")
  ```

  Prefer that over omitting the tenant: §5 rule 2 still requires one on the
  `X-Tenant-ID` header of every request after the login.

### Fixed

- Reject a blank tenantSlug or orgSlug instead of sending it as ""

- **`AxiamConfig` now rejects a blank `tenantSlug`, `tenantID`, `orgSlug` or
  `orgID`** (CONTRACT.md §5, §5.1, §5.2.1 rule 2), whitespace included. A **nil**
  identifier stays accepted — that is what "not named" looks like, and it is the
  difference between an unset optional and a blank one.

  The §5 tenant check was an *aggregate* — `(tenantID?.isEmpty == false) ||
  (tenantSlug?.isEmpty == false)` — so a blank `tenantSlug` **beside a valid
  `tenantID`** satisfied it, and the blank one was stored and serialized into
  every login body.

  An SDK MUST NOT send an empty-string slug. Nothing can carry one, so the
  server resolves nothing — and on `/auth/opaque/login/start` it fails on the
  workspace *before* the tenant's OPAQUE mode is read, so the `404` of §23.4
  rule 10 never arrives, this SDK has no fallback to take, and sign-in fails
  even against a tenant with OPAQUE **disabled**.

## [1.0.0-beta02] - 2026-08-28

### Added

- **CONTRACT.md contract 1.31 — list search, the truthful resend, and organization scope.**
  The vendored `CONTRACT.md`, `openapi.json` and `management-registry.json` are re-synced
  from `axiam@main`, and four behaviours follow from them.

  **`PageRequest` gained a third component, `search` (§27.4 rule 4).** All twenty paginated
  operations accept an optional free-text term, matched case-insensitively by the **server**
  against the identifying fields of whatever is being listed — a name or username, plus the
  record id, so a UUID pasted out of a log line finds its row. `Page.total` then counts
  *matches*, not rows.

  It lives beside `offset` and `limit` rather than becoming an extra argument on twenty
  generated `list` methods, and that is what makes `PageRequest.next()` — and so
  `Page.nextRequest`, and so every walk written against it — carry the term across the whole
  walk. A per-method argument has nowhere to live between one request and the next, so a
  walk built on one would return the matches followed by the unfiltered tail. `nil`, `""`
  and `"   "` are the same request: no `search` parameter at all. The term is trimmed but
  never truncated — the server's length cap stays the server's, because a client-side
  truncation the server would not have made is a silently different query the caller cannot
  see.

- **`AxiamClient.resendOwnVerification()` (§25.1, §25.7).** `POST
  /api/v1/users/me/resend-verification`, session-authenticated, taking **no address** — the
  server reads it off the caller's own record, and the signature deliberately offers no way
  to name a different one. Refused client-side, with no wire call, when there is no session.

  It does not replace `resendVerification(email:tenantID:)`, and neither is routed to the
  other. The unauthenticated one takes an address from an anonymous caller, so it must
  answer identically whether the address exists, is already verified, or is rate-limited:
  anything else is an oracle for which addresses have accounts. This one is asked by a
  caller already signed in to the account it is asking about, so it tells the truth — a
  `409` raises `AxiamError.authz` and a `429` raises `AxiamError.network`, and this SDK does
  **not** fall back to the public endpoint on either (§25.7 rule 2). That fallback would
  turn both failures back into a silent success and restore the bug this operation exists to
  fix, with an extra round trip. Returning means the mail was *enqueued*, not delivered.

- **`AxiamUser.organizationLevel` (§5.2).** A completed login now reports whether the account
  it signed in is an organization-level principal — one whose record lives in its
  organization's reserved tenant, so its global grants apply in every tenant there and it can
  act on a different one by sending a different `X-Tenant-ID`, with no re-login.

  An ordinary tenant principal is a principal of exactly one tenant; the same header change
  produces a `403` for it. The flag is what an admin UI checks *before* offering a tenant
  selector, rather than discovering the answer from a failed request. It is derived from the
  response and never asserted: never sent, and `false` when absent — which is what a server
  older than contract 1.31 answers, and what the resource-server guard path yields, since
  token claims do not carry it. Added as a defaulted initializer parameter, so every existing
  `AxiamUser(...)` construction still compiles.

- **Three §27.11 model additions**, regenerated: `Tenant.kind` (`TenantKind`, the new
  `standard` | `organization` enum), `MtlsTrustAnchorResponse.trustedAnchors` (`Int?` —
  `nil` is *not* zero: "the listener trusts no CAs" and "there was no listener to ask" are
  different operational states), and `Certificate.boundServiceAccountID`.

  That last one is a **projection**, not a property of the certificate: the server resolves
  it for a whole page in one query, so `certificates.list()` populates it and
  `certificates.get(id:)` leaves it `nil`, with no second request to fill it in (§27.11
  rule 4). `Scripts/gen_management.py` learned to read the registry's
  `response.projected_fields` and fold such a field onto its base model as optional — the
  server expresses a projection as an `allOf` of the named base and an anonymous object, and
  a generator that reads only for a `$ref` sees a response with no element name at all.

### Changed

- Re-vendor openapi.json and management-registry.json from axiam main (#50)

- Contract 1.31: list search, the truthful resend, organization scope (#49)

- Re-vendor the contract artifacts: spec digest + §27.10 posture (#48)

- Cover the §27 code the first CI run showed was unreached

- Add the CONTRACT.md §27 management surface to the Swift SDK

- Re-vendor CONTRACT.md, openapi.json and the §27 registry

- **Generated enums are now open (§27.11 rule 1).** Each one gained an `unknown` case, and a
  hand-written `init(from:)` that decodes an unrecognised value to it instead of throwing.

  Throwing failed the **whole** response, so one field of one record on a page took down
  every record on it — including the ones the caller did ask for. That is the failure
  §27.11 rule 1 exists to prevent, and it is why this is a fix rather than a loosening.

  It still never reads an unrecognised value as one of the **known** cases: reading a new
  value as whichever case was declared first turns a new server state into a wrong one, and
  on this surface these values gate access. `.unknown`'s own raw value is the empty string —
  which no server value is, so carrying an unrecognised value back into an update is refused
  by the server rather than written as a spelling it never used.

  `init(rawValue:)` is **unchanged** and still strict, so code that deliberately parses a raw
  string keeps its check; only decoding is lenient. **A `switch` over one of these enums now
  needs an `.unknown` arm.**

- **CONTRACT.md §27 — the management API.** 146 operations across 24 namespaces, reached
  through namespace handles that sit directly on the client (`client.serviceAccounts
  .rotateSecret(saID:)`), which is the form §27.3's Swift row specifies. The same handles
  are also reachable behind one accessor, `client.management` (§27.2 rule 4); the two are
  equivalent, and the suite asserts it per namespace by comparing the method and path each
  actually puts on the wire.

  The models, the 24 handles and one call per operation are **generated** by
  `Scripts/gen_management.py` from the vendored `management-registry.json` and
  `openapi.json`; the output is committed, so `swift build` still needs no code-generation
  step and no Python. A new `management-drift-check` CI job re-runs the generator with
  `--check` and fails on drift — without that gate a re-vendor adding an operation would
  leave the SDK shipping a surface that disagrees with the contract while every test still
  passed, because the generated tests come from the same stale copy.

  The generated layer sits on the **existing** request path (§27.8): every operation
  inherits §3 CSRF, the §4 cookie jar, §5's tenant header, §6's TLS floor, §9's
  single-flight refresh, §16's retry policy and §19's telemetry. The suite drives the stub
  at the bottom of a real client, so an operation that opened its own request path fails
  the tests rather than passing them.

  Hand-written on top: `Page`/`PageRequest` (§27.4 rule 4 — `total` is the server's count
  and is never derived from the page in hand; auto-paging stops on an empty page, not a
  short one), `CallScope` with `inOrg(_:)` / `forTenant(_:)` returning a **new** handle
  (§27.4 rule 3), and `ManagementJSON` for the schema properties the spec leaves free-form.

  Three shape decisions worth naming, all forced by the language:

  - **Explicit `Codable` rather than synthesis.** Every model carries hand-written
    `CodingKeys`, `init(from:)` and `encode(to:)`. §27.4 rule 5 makes "absent, not null"
    normative for a sparse update, and `encodeIfPresent` says that where relying on
    synthesis says it only by convention.
  - **`Sensitive<T>` stays un-`Codable`.** Six §27.5 fields are request-side and have to
    reach the wire; rather than weaken the type for everything, the generated
    `encode(to:)` calls `.expose()` on exactly those six, generated from the registry's
    `sensitive_request_fields`.
  - **Handles are `Sendable` structs over the client actor**, and the accessors are
    `nonisolated`, so `try await client.roles.list()` needs the one `await` §27.3's Swift
    row shows rather than two.

- **§27.4 rule 7's error sub-types.** `AuthzError.managementFailure` (`.notFound` for 404,
  `.conflict` for 409) and `NetworkError.isValidation` (400/422). Swift's §2 taxonomy is an
  enum over three structs and a struct cannot be subclassed, so the sub-types are carried
  as discriminators on the existing types — the same accommodation this SDK already makes
  for `OAuthProtocolError` on `AuthError`. Both are additive: a `catch AxiamError.authz`
  written before §27 existed still catches a 404 and a 409, which is the property rule 7 is
  asking for. `ValidationError` is excluded from §16 retry, so a body the server has
  already rejected is not sent three times.

- **§27.6/§27.7 declarative manifests.** `client.manifest` gives a `ManifestApi` with
  `plan`, `apply`, `validate` and `ordered`. `Manifest { … }` is §27.7's Swift row — a
  `@resultBuilder` DSL — with the entity factories under `Declare` rather than as bare
  `Role(…)` / `Resource(…)` functions, because those four names are all generated model
  types in this module and a free function sharing a name with a type is a resolution
  puzzle at every call site. The lowering is identical, which is what §27.7 requires.
  Ordering is derived from kind and `dependsOn` and is stable across runs; nesting a
  resource derives the parent link; omission is never deletion, and `ChangeAction` has no
  `delete` case at all.

- Three worked examples: `Examples/ManagementBasics`, `Examples/ManagementManifest`, and
  `Examples/DeviceMtlsProvisioning` — the last provisioning an IoT device end to end
  (service account, device certificate from the tenant signing CA, certificate binding,
  mTLS trust anchor) and then configuring a second client with that certificate so the
  device authorizes as itself over §6.1 mTLS.

## [1.0.0-alpha44] - 2026-08-25

### Changed

- Re-vendor openapi.json at alpha43 for tenant signing CAs (axiam#379)

- **Re-vendor `openapi.json` at 1.0.0-alpha43** for AXIAM server PR #379, which
  adds **tenant signing CAs**: an intermediate CA created beneath one of the
  organization's CAs and scoped to a single tenant, so a tenant's user, service
  and device certificates chain through a CA that can be revoked, rotated or
  handed to a different operator without redistributing the anchor the rest of
  the estate trusts. `CONTRACT.md` and `proto/` were untouched by that PR and are
  already current.

  This is a specification re-sync with **no SDK surface change**. CA-certificate
  administration is not part of the SDK contract — `CONTRACT.md` §1 maps no
  method onto any `/api/v1/organizations/{org_id}/...` CA route — and this SDK
  models none of the schemas below, so nothing here gains, loses, or changes a
  symbol. The spec is vendored so what this SDK is written against keeps
  describing the server it talks to.

  What moved in the spec:

  - **`POST /api/v1/organizations/{org_id}/tenants/{tenant_id}/signing-cas`**
    (`generate_intermediate`) — create a tenant signing CA under an organization
    CA, with AXIAM generating the key. Returns `GeneratedCaCertificate`; the
    private key comes back exactly once, and not at all under `vault_pki`, where
    it was born inside Vault and no API exports it.
  - **`GET .../signing-cas`** (`list_intermediates`) — a paginated list of one
    tenant's signing CAs.
  - **`POST .../signing-cas/sign-csr`** (`sign_intermediate_csr`) — the BYOK
    counterpart: sign a PKCS#10 CSR produced elsewhere, so the private key never
    reaches AXIAM at all. The response carries no `private_key_pem` because there
    is none to carry.
  - **`CaCertificate` gains two nullable fields** — `tenant_id`, the tenant a CA
    signs for, and `parent_ca_id`, the CA in the organization that signed it.
    Both are absent for an organization-level CA, which is the trust anchor and
    the only kind that existed before this change.
  - **Four new schemas**: `CreateIntermediateCa`, `CreateIntermediateCaRequest`,
    `SignIntermediateCsr` and `SignIntermediateCsrRequest`.

  The spec version moves from **1.0.0-alpha40** to **1.0.0-alpha43**; the
  intervening alpha41 and alpha42 releases changed nothing in it but that string.

## [1.0.0-alpha43] - 2026-08-24

### Added

- Adopt Swift 6 language mode via a version-specific manifest (#43)

- **Swift 6 language mode, via a version-specific manifest.** The package now
  ships `Package@swift-6.0.swift` alongside `Package.swift`. SwiftPM selects by
  toolchain: 5.9/5.10 get the 5.9 manifest as before, and 6.0+ get the new one,
  which sets `.swiftLanguageMode(.v6)` on the library and every example. Their
  sources are therefore compiled under full strict-concurrency checking — as
  errors — wherever a Swift 6 toolchain is present, **without** raising the floor
  for consumers still on 5.9.

  **Every target** is in Swift 6 language mode — the library, all fourteen
  examples, and the test suite — and every one of them compiles with **zero**
  diagnostics. No target declares `.swiftLanguageMode(.v5)`.

  Note that omission is not an opt-out: under `swift-tools-version: 6.0`, Swift 6
  is the **default** language mode for every target, so deleting the setting from
  a target does not revert it. Only an explicit `.v5` does.

  The two obvious alternatives do not work. `-Xswiftc -swift-version 6` applies
  to the whole dependency graph including swift-nio and async-http-client, and
  `.unsafeFlags` makes a package unusable as a dependency at all.

- **Swift 6.3 is now a CI leg.** The gating matrix is floor + newest (5.9, 6.3)
  rather than 5.9/5.10 — two Swift 5 toolchains that between them proved nothing
  about Swift 6. 6.3 is the newest Swift with an official Linux container image;
  6.4 exists for Apple platforms but has no Linux image yet. 5.10 remains
  supported and still runs the full suite under the Coverage and docs workflows.

- **`SupportedVersions`** — `minimumSwiftToolsVersion`, `newestTestedSwift`, and
  `isSwiftSixLanguageMode`. The last reports which language mode a build actually
  got, which is invisible from the outside and is the difference between the
  concurrency guarantees having been *checked* and merely *intended*.

- **`VersionPolicyTests`** — asserts the constants against both manifests and the
  CI matrix, that the 6.0 manifest really declares tools-version 6.0 (the
  filename selects it, but only the declared version unlocks the language mode),
  that every target in it carries the language-mode setting and none is pinned
  back to `.v5`, that the suite itself really was compiled in Swift 6 mode
  (`#if swift(>=6.0)` reads the compiler, where the other assertions only read
  the manifest), that the newest CI leg is a 6.x toolchain so the manifest is
  exercised at all, and that **both manifests declare the same targets**. SwiftPM
  has no include mechanism, so that duplication is unavoidable and nothing but a
  test can hold it together.

- **`Examples/VersionCompatibility`** — reports the compiling toolchain and
  whether Swift 6 language mode is in effect.

- **A "Supported Swift versions" section in the README.**

### Changed

- Migrate the test suite to Swift 6 language mode

- **The test harness is migrated to Swift 6 language mode.** 48 strict-concurrency
  sites across 19 files, all of them fixture plumbing rather than anything the
  shipped SDK does. No assertion was weakened, skipped or removed to get there,
  and no site was migrated with `nonisolated(unsafe)`; the test count is
  unchanged apart from one assertion added. Four patterns cover all of it:

  - **`NSLock` in `async` test doubles** (`MockTransport`, `ScriptedTransport`,
    `RefreshProbeTransport`, and the doubles inside `OpaqueLoginTests` and
    `UmaTests`) now go through `NSLock.locked(_:)`, a synchronous-closure critical
    section that returns a snapshot. Swift 6 makes bare `lock()`/`unlock()`
    unavailable from asynchronous contexts because a lock held across a suspension
    point can deadlock the cooperative pool; these doubles already unlocked before
    every `await`, and a non-`async` closure makes that structural rather than a
    property you have to read the function to confirm.
  - **`[String: Any]` JSON fixtures captured by `@Sendable` router closures** are
    serialized to `Data` at the point the fixture is built, via the new
    `TestResponse.jsonBody(_:)`. `Data` is `Sendable`; the bytes are what the
    response was always going to carry.
  - **`TestSigner`** stores its Ed25519 seed as `Data` instead of a
    `Curve25519.Signing.PrivateKey`, which swift-crypto does not make `Sendable`,
    and is now genuinely `Sendable`. This alone cleared eight capture sites.
  - **`OidcTests`'s router harness is `static`.** A `@Sendable` closure cannot
    capture an `XCTestCase` and no annotation makes it safe to; moving the
    fixtures off the instance removes the capture rather than suppressing it.

  Three fixtures held as statics were also reworked: the WebAuthn challenge
  dictionaries are computed rather than stored (no shared state at all),
  `ReactorTests` keeps the §22.13 vector *bytes* in the static and parses per
  instance, and `DpopProofTests`'s `jti` counter is now per-instance — which is
  the lifetime it always wanted, since the store it disambiguates is rebuilt in
  `setUp`.

### Fixed

- **`OpaqueLibrary`'s memoized load state is no longer non-isolated global
  mutable state.** Two `private static var`s guarded by an `NSLock` are rejected
  outright by Swift 6's strict concurrency checking — correctly, since nothing
  in the type system enforced that every access went through the lock; that was
  a convention held by two call sites. The storage now lives in a lock-guarded
  box, which makes the invariant structural rather than conventional. Behaviour
  is unchanged: still one `dlopen` attempt per process, memoizing failure as
  well as success.

## [1.0.0-alpha41] - 2026-08-24

### Added

- Branch on login/start's `mode` when KE2 fails to open (§23.4 rule 7)

### Changed

- Re-vendor openapi.json for the vault_pki CA custodian (axiam#368)
- Re-vendor CONTRACT.md at 1.29 and openapi.json at 1.0.0-alpha40

## [1.0.0-alpha40] - 2026-08-23

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha39.

## [1.0.0-alpha39] - 2026-08-23

### Changed

- Name the conformance sections individually
- Re-vendor CONTRACT.md for the §14.1 anchor repair
- Claim the four sections this SDK already ships
- Re-vendor openapi.json at 1.0.0-alpha38

## [1.0.0-alpha38] - 2026-08-22

### Added

- The §22 reactor protocol core over a caller-supplied transport

- **CONTRACT.md §22 — the reactor protocol core, over a caller-supplied
  transport.** `Sources/AxiamSDK/Reactor/`: §22.1–§22.8 and §22.14 in full — the
  §8 v2 verification set on the event (key version, MAC, two-sided freshness,
  nonce), the canonical serialization and HMAC in both directions, the §22.5
  registry and its namespace-prefix allow-lists, §22.8's strictest-wins default,
  `reactorServe`, and the `ReactorRouter` builder.

  Contract 1.28 found the earlier deferral cut one notch too wide: the part that
  genuinely needed a vendored dependency was the *connection*, and the runtime
  around it needed none. What is still deferred is an AMQP client — conform
  `ReactorTransport`, whose two capabilities are deliberately the only two the
  runtime needs (§22.11 rule 1).

  A **builder** rather than an attribute, as §22.14 records: a Swift reactor
  handler is an `async` closure, and collecting `async` members by reflection
  costs a runtime dependency an SDK should not add to hand out an attribute.
  The builder type-checks the closure at compile time instead, and the
  strongly-typed `on(_:_:)` cannot even spell an unregistered event.

- `amqpsEndpoint` — §8b rules 1–5 as a **public, tested function** rather than a
  doc comment (§22.11 rule 3). It refuses every scheme but `amqps://` including
  `amqp://`, with **no loopback exception** (§8b rule 8); requires a client
  certificate and its key together; carries a custom CA bundle for a
  privately-issued broker certificate; and offers no verification-skip parameter
  under any name and no way to express a plaintext fallback.

- `Tests/AxiamSDKTests/ReactorTests.swift` (44), run against the committed
  §22.13 reference vectors, vendored as a test resource — generated by the
  server's own sign path, so a byte out of place in the canonical form is caught
  against a number the server computed rather than against this
  implementation's own opinion.

- `Examples/Reactor`, a `swift run ReactorExample` target: the §8b guard, the
  builder, and the runtime over a transport skeleton.

- CONTRACT.md §24 — WebAuthn / passkeys. The six relying-party operations and
  §24.6a's JSON bridge on **every** target, plus §24.6b's linked-API ceremony
  helpers (`webauthnRegister`, `webauthnLogin`, `webauthnDiscoverableLogin`) on
  iOS 16+ and macOS 13+, behind `#if canImport(AuthenticationServices)`.

  One helper set for both Apple platforms, not an iOS one and a macOS one:
  the credential providers exist on both, and the presentation anchor — the
  only genuinely per-platform part — is supplied by the caller through
  `WebauthnPresentationAnchorProviding`. The Linux build keeps the RP layer and
  the bridge, and `webauthnCeremonySupported` answers `false` there rather than
  throwing (§24.6b rule 6).

  `WebauthnFailure.classify` maps a platform error name to the five §24.6b
  rule 5 outcomes, and is present on every build — a browser front end relaying
  a `DOMException` name to a Swift service has the same five.

- CONTRACT.md §25 — account lifecycle and MFA enrolment: voluntary and forced
  TOTP enrolment, email verification, and the password-reset triple including
  the `reset/context` call a tenant with §23 enabled requires before a new
  password can be built.

- CONTRACT.md §26 — Pushed Authorization Requests, RFC 9126 (`oidcPar`,
  `PushedAuthorizationRequest`). Required for a FAPI 2.0 client, which cannot
  authorize any other way (§21.1).

- `Examples/WebauthnPasskeys`, `Examples/AccountLifecycle` and
  `Examples/ParLogin`, each a `swift run` target.

### Changed

- Await the actor-isolated oidcBegin in the PAR tests

- Await the actor-isolated oidcBegin in the PAR example

- Make LoginSuccessResponse.toUser internal

- Re-vendor CONTRACT.md at 1.28

- Add WebAuthn, account lifecycle and PAR (CONTRACT §24–§26)

- **Re-vendor `openapi.json`** for AXIAM server PR #368, which adds a third CA
  key custodian, `vault_pki`, having HashiCorp Vault's PKI secrets engine
  generate the CA key inside Vault and sign on AXIAM's behalf. The spec version
  is unchanged at **1.0.0-alpha40**; `CONTRACT.md` and `proto/` are untouched by
  that PR and are already current.

  This is a specification re-sync with **no SDK surface change**. CA-certificate
  administration is not part of the SDK contract — `CONTRACT.md` §1 maps no
  method onto `/api/v1/organizations/{org_id}/ca-certificates`, and this SDK
  models none of the five schemas below — so nothing here gains, loses, or
  changes a symbol. It is vendored so the spec this SDK is written against keeps
  describing the server it talks to.

  What moved in the spec:

  - `CaCertificate` gains a nullable `chain_pem`: the issuers above
    `public_cert_pem`, concatenated PEM, nearest issuer first and the root last.
    Absent for a CA that is its own root, which is every CA AXIAM generated
    before this. Present for a `vault_pki` CA, where it is the only copy of the
    root certificate anything outside Vault will ever see.
  - `CaCertificate.public_cert_pem` is now documented as the certificate that
    *signs*, which under `vault_pki` custody is the intermediate rather than the
    root beneath which it was created. The field itself is unchanged.
  - `GeneratedCaCertificate.private_key_pem` is **no longer required**. Under
    `vault_pki` custody the key is born inside Vault and no API exports it, so
    there is nothing to return. The field is omitted rather than sent as `null`,
    which keeps a client that has always read it working unchanged against every
    custodian that does produce a key.
  - `GeneratedCertificate` gains a nullable `chain_pem`, present only when the
    signer returned one — the `vault_pki` case, where the root's certificate
    exists nowhere a client could fetch it from.
  - `CreateCaCertificate` and `CreateCaCertificateRequest` gain the optional
    `issue_from_root`, `intermediate_subject` and `intermediate_validity_days`.
    All three are `vault_pki`-only and ignored by every other custodian.
    `issue_from_root` defaults to off: a root that signs only one intermediate
    can have that intermediate revoked and replaced without redistributing the
    trust anchor, and a root that signs leaves directly cannot.

- **CONTRACT.md §23.4 rule 7 (contract 1.29): what happens after `KE2` fails to
  open now depends on the tenant's `opaque_mode`.** `POST
  /api/v1/auth/opaque/login/start` gained an optional `mode` field carrying
  `"optional"` or `"required"` (never `"disabled"` — that path answers `404`),
  and `loginOpaque` branches on it and on nothing else:

  - `"optional"` — `loginOpaque` **retries over `login(email:password:)`** with
    the same credentials before reporting any failure, and returns that call's
    outcome: its success on success, its error on failure. `optional` is the
    mid-migration state — every account has no OPAQUE record the moment an
    operator enables it and acquires one only when its password is next set — so
    an SDK that treated the failed exchange as final locked out every user of the
    tenant, which made enabling `optional` indistinguishable from enabling
    `required` with nobody enrolled.
  - `"required"`, **a response with no `mode` field at all** (a server older than
    the field), and any value this SDK does not recognise — `.auth`, the exchange
    is over, and nothing is retried. Failing closed is the default.

  Unchanged: `KE3` is still never sent once the envelope fails to open, the error
  is still the existing `AxiamError.auth`, a `.network` failure (a refused
  key-stretching function, a malformed response) never triggers the retry, and a
  `404` from `/auth/opaque/*` is still the distinguishable "this tenant has
  OPAQUE disabled" network error.

  `mode` is **not** downgrade protection and is not documented as such: a hostile
  server that wanted the plaintext could answer `404` and get a caller's fallback
  whatever it puts here. What closes that is `required` server-side, which
  refuses `/auth/login` for every principal before examining any credential.

- Re-vendor `CONTRACT.md` at **1.29** and `openapi.json` at
  **1.0.0-alpha40**, byte-identical to the platform repo's `sdks/`. §23.4 rule 7
  above is the one normative change; the rest is additive.

- Re-vendor `CONTRACT.md`. Repairs §14.1's link to the `device_login` heading,
  which dropped a hyphen the em dash leaves behind and so rendered as a link
  that went nowhere; the same heading's other two links were already correct.
  Link target only — no normative change and no contract-version bump.

- **Conformance statement names §17 and §19 individually.** `§16–§19` was a
  range where the contract asks for individual naming. §16 and §18 are now
  absent rather than folded in — the contract makes them MUST-level and says
  they are not named — with a note saying so, so their absence does not read as
  a narrowing.

- **Conformance statement now names §22, §24, §25 and §26.** All four have been
  implemented since contract 1.28 and documented in the Scope table; the headline
  statement had not caught up, so this SDK was formally claiming less than it
  ships. §22 is stated with its §22.11 rule 4 qualifier: the reactor protocol is
  in the library, the transport is caller-supplied.

- Re-vendor `openapi.json` at **1.0.0-alpha38**. The server registered the four
  GDPR data-subject endpoints (`POST /api/v1/account/export`,
  `GET /api/v1/account/export/{token}`, `POST /api/v1/account/delete`,
  `GET /api/v1/auth/account/delete/cancel`), taking the document to 181
  operations across 121 paths. Purely additive, and no SDK surface changes with
  it: nothing in this repo is generated from the spec, so the cross-repo
  artifact-drift gate was the only thing reporting `STALE`.

- **Breaking:** `LoginResult.mfaSetupRequired` gained an associated value —
  the setup token (§25.2 rule 1). A caller that matched it exhaustively needs
  one line changed. Taken because the alternative was an SDK that reports a
  recoverable, guided state and withholds the only thing that can complete it.

- `OidcConfiguration` gained `pushedAuthorizationRequestEndpoint`, optional and
  parsed from discovery.

- Re-vendored `CONTRACT.md` and `openapi.json` at contract 1.28.

## [1.0.0-alpha37] - 2026-08-21

### Changed

- Cover the OIDC grants, introspection and UMA guards that had none

## [1.0.0-alpha34] - 2026-08-21

### Added

- Replace SRP-6a with OPAQUE (RFC 9807)

- OPAQUE (RFC 9807) login and enrolment (CONTRACT §23): `loginOpaque` and
  `opaqueEnrollment` on `AxiamClient`, plus `opaqueAvailable()` for choosing the
  password path up front. `loginOpaque` returns the same `LoginResult` as
  `login`, MFA branch included.

- `Examples/OpaqueLogin` (`OpaqueLoginExample`).

- `opaqueEnrollment` refuses a `register/start` response with no
  `registration_response` rather than sealing an envelope against an empty
  string, which would produce a record no server can ever accept.

### Changed

- Link to the AXIAM platform documentation site

- Re-vendor openapi.json at alpha32 (#35)

- Cover the enrolment refusals; exclude the un-runnable ABI edge from the coverage gate

- **BREAKING** — the OPAQUE protocol is NOT implemented in this SDK. CONTRACT
  §23.1 forbids it, so the client half is a `dlopen`/`dlsym` binding to
  `libaxiam_opaque_ffi` — the same implementation the AXIAM server links,
  published as a per-platform asset on the axiam-opaque release page. It is
  resolved at run time rather than declared as a SwiftPM `systemLibrary`
  target, so a consumer who never touches OPAQUE is not made to link it. Put
  the library on the loader path or point `AXIAM_OPAQUE_LIBRARY` at it.

- **Swift no longer needs a `pbkdf2_sha256` tenant.** The SRP client refused an
  `argon2id` tenant outright — Swift has no Argon2 that ships on every
  supported platform — so AXIAM's *default* KDF was unreachable here and
  operators had to weaken the tenant for Swift callers. Key stretching now
  happens inside the native library, so `argon2id` and `scrypt` both work. The
  one remaining condition is having the library, which `opaqueAvailable()`
  reports honestly: unlike `srpAvailable`, which was hard-coded `true` while an
  `argon2id` tenant still failed at login, a `true` here is a promise that every
  tenant will work.

- `opaqueEnrollment` performs I/O — one `register/start` round trip — where
  `srpEnrollment` was pure. OPAQUE's envelope is sealed under the server's
  oblivious PRF, so there is no offline computation that produces a valid
  record. It also loses the `identity` argument: a record binds to a credential
  identifier the server chooses, so passing an email where a username was wanted
  can no longer produce an unusable credential, and **renaming a user no longer
  invalidates it**.

- Re-vendor `openapi.json` at **1.0.0-alpha32**, matching the server. The
  content was already byte-identical in every path and schema; only
  `info.version` differed, which is what the cross-repo artifact-drift gate
  reports as `STALE`.

### Removed

- **BREAKING** — SRP-6a. `loginSrp`, `srpEnrollment`, `srpAvailable`, the
  `Sources/AxiamSDK/Srp/` module (including the hand-written `SrpBigInt`
  modular exponentiation), `srp-test-vectors.json` and `Examples/SrpLogin` are
  all gone. AXIAM's server-side SRP endpoints are removed in the same release,
  so keeping the client would leave a method that only ever returns 404.

### Fixed

- Drop autoreleasepool, which corelibs Foundation does not vend on Linux

- Await the actor-isolated opaqueAvailable() probe

## [1.0.0-alpha31] - 2026-08-20

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha30.

## [1.0.0-alpha30] - 2026-08-20

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha29.

## [1.0.0-alpha29] - 2026-08-20

### Added

- SRP-6a login client with a bundled bignum (CONTRACT §23) (#33)

## [1.0.0-alpha28] - 2026-08-19

### Changed

- Re-vendor openapi.json at 1.0.0-alpha27 (#32)

## [1.0.0-alpha27] - 2026-08-17

### Changed

- Re-vendor CONTRACT.md 1.23 (§8b rules 7 and 8)
- Re-vendor CONTRACT.md 1.22 and openapi.json from the server repo

## [1.0.0-alpha25] - 2026-08-16

### Added

- Extend §10.1 rule 9 for DPoP and implement §21.7.2 (#27)
- SubjectTokenType is required (contract 1.13)
- §15.7 — external-IdP subject tokens at the exchange (X4)
- §12, §12.7, §14 and §15 — the ported deferral (contract 1.11)
- §20.3 — emit a UMA challenge from the §11 guard (#20)
- §20 UMA 2.0 — Protection API and ticket grant (#19)
- §16 retry, §17 decision memo, §18 close(), §19 telemetry (D5)
- §11 rule 9 decision reason codes; contract re-sync (D6) (#16)
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

- Point the Scope table at CONTRACT.md §22.11, the deferred reactor runtime (#29)
- Re-vendor CONTRACT.md 1.19, openapi.json and proto/ from main (R5.8) (#28)
- Contract 1.15 — §10.1 rule 9, sender-constrained access tokens (#26)
- Retire the "measured residual" justification (contract 1.14)
- Re-sync to contract 1.14 (#302 closed)
- Runnable §16–§19 example for the Swift SDK (F3)
- Re-vendor `openapi.json` at 1.0.0-alpha27 — the copy was pinned at alpha26 and
  failing the cross-repo artifact-drift gate
- **README's Scope table now points at CONTRACT.md §22.11 (the deferred reactor
  runtime).** §22.11 carries a SHOULD that these READMEs point at it "so an
  integrator finds the wire chapter rather than concluding reactors are
  unavailable" — the Scope table listed §8 AMQP as deferred and said nothing about
  §22, which is exactly where a reader would draw that wrong conclusion. The new
  row says the accurate thing: §22.11 defers the `reactorServe` *helper* for the
  same reason §8 has never listed Swift — no vendorable AMQP client for this
  target — but §22.1–§22.8 is a wire protocol and binds a hand-rolled integrator in
  full, and the §22.13 vectors are the conformance surface.

  Documentation only: no code change, and **no §22 conformance claim** — §22.11's
  MUST NOT forbids claiming the chapter while shipping no runtime, and the
  conformance statement is untouched.
- **Re-sync vendored `CONTRACT.md` / `openapi.json` to contract 1.15.**
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

- Add the §10.1 rule-8 guardrail regression tests (#15)
- Device (mTLS) tokens now carry aud=axiam:m2m (#14)
- Service accounts can use login_client_credentials (#13)
- Re-vendored `CONTRACT.md` at **1.10** and `openapi.json` (the server's `/uma2/*` surface).
- `AuthError` gained `oauthError` and `oauthErrorDescription`, both optional and both `nil` for
  every failure that is not an OAuth2 protocol error, so existing callers are unaffected. §20.4
  requires dispatching on the body's `error` field rather than the HTTP status — `access_denied`
  answers `403` on the ticket grant where RFC 8628's answers `400` — and the code has to reach the
  caller somewhere. The contract models it as an `OAuthProtocolError` *sub-type of* `AuthError`;
  Swift structs cannot be subclassed, so an `AuthError` that carries the code is the equivalent,
  and the §2 taxonomy stays at exactly three cases rather than gaining a fourth (which would have
  broken every exhaustive `switch` over `AxiamError`).
- Vendored `CONTRACT.md` re-synced with the new **§13 Webhook Signature Verification**.

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

### Fixed

- Require a kid when selecting a JWKS key (§13.4 observation 7) (#12)
- Reject tokens with no exp claim (SEC-080)
- Bind sessions to the configured tenant, refuse plaintext base URLs, constant-time Sensitive equality; add webhook verifier

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

## [1.0.0-alpha23] - 2026-08-02

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha21.

## [1.0.0-alpha21] - 2026-07-30

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

### Changed

- Re-sync vendored CONTRACT.md to contract 1.6

### Fixed

- Identity-check the single-flight refresh slot vacate (rule 6c) + rule 6 regression tests
- **§9 rule 6c (contract 1.6): the single-flight refresh slot is now vacated identity-checked.**
  `AxiamClient.refreshOnce()` cleared `refreshTask` unconditionally on both its success and its
  failure path. The invariant held only by a whole-function argument (ownership is taken and
  released with no intervening suspension point, so the slot could not change identity underneath
  an owner) — nothing local prevented a lagging attempt from wiping a *newer* leader's live entry,
  which is the shape of the bug fixed in the C++ SDK and would open the door to a second wire call
  against an already-consumed, single-use refresh token. The clear now happens only while the slot
  still holds the clearing attempt's own `Task`.

## [1.0.0-alpha18] - 2026-07-24

### Changed

- Add line-coverage regression gate (floor 92%) + publish lcov (#6)

## [1.0.0-alpha16] - 2026-07-22

### Changed

- Adopt CONTRACT 1.3; defer gRPC get_user_info
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

### Changed

- Resolve org_id from access-token claim for the refresh body (D-14) (#2)
- Force bash for gh-pages publish step
- Publish API docs to gh-pages branch
- Drop configure-pages step, mirror C SDK template
- Auto-enable GitHub Pages (enablement: true)
- Add docs publish workflow to GitHub Pages

### Deferred (follow-ups)

- gRPC transport (no §-requirement lists it for Swift).
- §8 AMQP HMAC consumption (the contract lists AMQP for Rust/TS/Go/Python/Java/PHP, not Swift).
- A first-party `AxiamVapor` product (Vapor wiring is documented in the README instead).

[Unreleased]: https://github.com/ilpanich/axiam-swift-sdk/compare/HEAD
