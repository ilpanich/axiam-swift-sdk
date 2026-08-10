# AxiamSDK Examples

Self-contained, runnable examples for the AXIAM Swift SDK. Each is wired into
[`Package.swift`](../Package.swift) as an `.executableTarget`, so it builds with the
package and runs via `swift run`.

| Example | Target | Covers |
|---------|--------|--------|
| [`LoginMFA/main.swift`](LoginMFA/main.swift) | `LoginMFAExample` | Two-phase `login` / `verifyMfa` flow (CONTRACT.md §1, §5, §5.1) |
| [`RestAuthz/main.swift`](RestAuthz/main.swift) | `RestAuthzExample` | REST authorization: `checkAccess`, `can`, `batchCheck` (§1) |
| [`TelemetryHook/main.swift`](TelemetryHook/main.swift) | `TelemetryHookExample` | The D5 surface: §16 retry, §17 memo + clamp, §18 `close()`, §19 hooks |

## Running

```bash
swift build --target LoginMFAExample     # build one example
swift run   LoginMFAExample              # build + run
swift run   RestAuthzExample
swift run   TelemetryHookExample
```

The examples compile without a live server. Running them end-to-end requires a
reachable AXIAM server matching the configured base URL — with one deliberate
exception: `TelemetryHookExample` is *meant* to be run without one. Its whole point is
that the failure path emits exactly the events the success path does, so pointing it at
a dead port produces a complete, real demonstration:

```
WARN: decisionMemoTtl=60.0s was clamped to 5.0s (§17.1 rule 2)
check failed: network(NetworkError: Transport failure calling /api/v1/authz/check)
--- telemetry ---
  checkAccess/failure: count=3 mean=10001ms
  retries checkAccess: 2
  refreshes: 0
```

Three attempts with two retries between them is the §16 budget; being able to count them
at all is what §19.2 rule 5's one-pair-per-**attempt** rule buys. Its default base URL is
`https://127.0.0.1:59999` rather than `https://localhost:8443` for that reason — the
other examples want a server, this one wants no server.

## Configuration (environment variables)

Every example reads its connection details from the environment, falling back to
the defaults below:

| Variable | Default |
|----------|---------|
| `AXIAM_BASE_URL` | `https://localhost:8443` |
| `AXIAM_TENANT_SLUG` | `acme` |
| `AXIAM_ORG_SLUG` | `acme` |
| `AXIAM_EMAIL` | `user@example.com` |
| `AXIAM_PASSWORD` | `changeme` |
| `AXIAM_TOTP_CODE` | `000000` (LoginMFA only) |
| `AXIAM_RESOURCE_ID` | `00000000-0000-0000-0000-000000000000` (RestAuthz only) |

## Organization context (§5.1)

Both examples build `AxiamConfig` with **both** `tenantSlug` (§5 — a tenant identifier
is mandatory; there is no default tenant) **and** `orgSlug` (§5.1). Login and refresh
require organization context because a tenant slug is only unique within an
organization; a login carrying no org identifier is rejected by the server with
HTTP 400 `must provide org_id or org_slug`. Use `orgID:` instead of `orgSlug:` when you
have the organization UUID (the two are mutually exclusive).
