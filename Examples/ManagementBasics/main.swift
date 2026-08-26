// ManagementBasics — the CONTRACT.md §27 management surface.
//
// 146 operations across 24 namespaces, reached through namespace handles that sit directly
// on the client: `client.roles`, `client.serviceAccounts` — the form §27.3's Swift row
// specifies (property, camelCase, async). Nothing here opens its own connection: §27.8
// requires the generated layer sit on the SDK's existing request path, so every call below
// inherits §3 CSRF, the §4 cookie jar, §5's tenant header, §6's TLS floor, §9's
// single-flight refresh, §16's retry policy and §19's telemetry by construction.
//
// What this program demonstrates, in order:
//
//   1. Paging that does not lie (§27.4 rule 4) — `total` is the server's count across every
//      page and is NOT the length of the page in your hand.
//   2. Per-call scope (§27.4 rule 3) — `inOrg` / `forTenant` return a NEW handle.
//   3. A sparse update (§27.4 rule 5) — only the fields you set are sent.
//   4. The error sub-types (§27.4 rule 7), including the two that are not where you would
//      guess.
//
// It writes nothing unless AXIAM_WRITE=1 is set, so it is safe to point at a real tenant to
// see what is there.
//
// Build:  swift build --target ManagementBasicsExample
// Run:    swift run ManagementBasicsExample

import Foundation
import AxiamSDK

func env(_ key: String, default fallback: String) -> String {
    ProcessInfo.processInfo.environment[key] ?? fallback
}

let baseURLString = env("AXIAM_BASE_URL", default: "https://localhost:8443")
guard let baseURL = URL(string: baseURLString) else {
    fatalError("Invalid AXIAM_BASE_URL: \(baseURLString)")
}

// §27.4 rule 3 substitutes `{tenant_id}` and `{org_id}` from here. They must be UUIDs: a
// slug is a valid §5 tenant identifier but is not a path segment, and a management call on
// a slug-only client fails client-side with no request rather than sending `/acme/`.
let config = try AxiamConfig(
    baseURL: baseURL,
    tenantID: env("AXIAM_TENANT_ID", default: "11111111-1111-1111-1111-111111111111"),
    orgID: env("AXIAM_ORG_ID", default: "11111111-1111-1111-1111-111111111111"))
let client = try AxiamClient(config: config)

do {
    // §27.4 rule 1: no session, no wire call. Every management operation refuses locally
    // when the client is unauthenticated, rather than sending a request the server will
    // reject — an unauthenticated management call is a programming error, not a 401 to
    // handle, and sending it would leave a rejected administrative request in the audit log.
    _ = try await client.login(
        email: env("AXIAM_EMAIL", default: "admin@example.com"),
        password: env("AXIAM_PASSWORD", default: "changeme"))

    // ---- 1. Paging (§27.4 rule 4) -------------------------------------
    //
    // `page.total` is the SERVER's count across all pages. `page.count` is how many came
    // back in this one. They are separate properties precisely so a management tool cannot
    // accidentally report "4 roles" after reading the first page of four hundred.
    let page = try await client.roles.list()
    print("roles: \(page.count) on this page, \(page.total) in the tenant")
    for role in page {
        print("  \(role.name)\(role.isGlobal ? "  [global]" : "")")
    }

    // Auto-paging stops on an EMPTY page, not a short one — a server may return fewer rows
    // than asked for and still have more.
    var request = PageRequest()
    var walked = 0
    while true {
        let batch = try await client.roles.list(page: request)
        if batch.isEmpty {
            break  // The stop condition. NOT `batch.count < request.limit`.
        }
        walked += batch.count
        request = batch.nextRequest
    }
    print("walked \(walked) roles across every page")

    // The same 24 handles are also reachable behind one accessor (§27.2 rule 4), which
    // reads better where a call site is already dense with §1 operations. The two forms are
    // equivalent — the suite asserts it per namespace by comparing what each puts on the wire.
    let alsoRoles = try await client.management.roles.list()
    print("same call, other spelling: \(alsoRoles.total) roles")

    // ---- 2. Per-call scope (§27.4 rule 3) -----------------------------
    //
    // `forTenant` returns a NEW handle rather than repointing this one. On a management
    // surface, a shared handle another code path had re-scoped would not merely read the
    // wrong tenant — it would WRITE to it.
    let otherTenant = env("AXIAM_OTHER_TENANT_ID", default: "")
    if !otherTenant.isEmpty {
        let elsewhere = try await client.roles.forTenant(otherTenant).list()
        print("tenant \(otherTenant) has \(elsewhere.total) roles")
        // `client.roles` is still pointed at this client's own tenant here.
    }

    guard env("AXIAM_WRITE", default: "") == "1" else {
        print("\n(set AXIAM_WRITE=1 to run the write half)")
        exit(0)
    }

    // ---- 3. Create, then a SPARSE update (§27.4 rule 5) ---------------
    let role = try await client.roles.create(body: CreateRoleRequest(
        description: "Created by the ManagementBasics example",
        isGlobal: false,
        name: "example-editor"))
    print("\ncreated role \(role.id)")

    // Sparse means ABSENT, not null. Only `description` is set below, so only `description`
    // appears in the request body — `name` and `isGlobal` keep whatever the server holds. A
    // replacement body would require all three; `CreateRoleRequest` has no defaults, which
    // is what makes the two impossible to confuse by accident.
    let updated = try await client.roles.update(
        roleID: role.id,
        body: UpdateRole(description: "Description changed; name and isGlobal untouched"))
    print("updated: name is still \(updated.name)")

    // §27.4 rule 6: deletes are NOT idempotent. Deleting this twice gives a 404 on the
    // second call and the SDK does not swallow it — "it was already gone" and "I deleted it"
    // are different facts, and a provisioning tool that cannot tell them apart cannot audit
    // itself.
    try await client.roles.delete(roleID: role.id)
    print("deleted")

    // ---- 4. The §27.4 rule 7 error map --------------------------------
    //
    // Swift's §2 taxonomy is an enum over three structs, and a struct cannot be subclassed,
    // so the sub-types rule 7 names are carried as a discriminator on the existing struct —
    // exactly as this SDK already carries `OAuthProtocolError` as an `AuthError`. A
    // `catch AxiamError.authz` written before §27 existed still catches a 404 and a 409,
    // which is the property rule 7 is actually asking for.
} catch AxiamError.authz(let error) where error.managementFailure == .notFound {
    // 404. Under `.authz`, which is the surprising part and the deliberate part: AXIAM
    // answers 404 for an object in another tenant EXACTLY SO a probing caller cannot
    // distinguish "does not exist" from "exists, not yours". Classifying it as an
    // authorization outcome keeps the SDK from re-drawing a line the server refused to draw.
    print("not found (or not yours): \(error.message)")
    exit(1)
} catch AxiamError.authz(let error) where error.managementFailure == .conflict {
    // 409. Also under `.authz` — §2 already mapped 409 there, and rule 7 keeps that mapping
    // rather than moving it.
    print("conflict: \(error.message)")
    exit(1)
} catch AxiamError.network(let error) where error.isValidation {
    // 400/422. Under `.network`, inherited from §2's own 400 row. That has one consequence
    // worth knowing: §16 retries network failures, so this case is explicitly excluded from
    // retry — a body the server has already rejected does not get sent three times.
    print("rejected: \(error.message)")
    exit(1)
} catch {
    print("management call failed: \(error)")
    exit(1)
}
