// ManagementManifest — the CONTRACT.md §27.6/§27.7 declarative layer.
//
// The imperative surface in Examples/ManagementBasics is fine for one change. It is a poor
// way to describe a TENANT, because re-running it either fails on the second run or makes
// you hand-write "does this exist already?" around every object. A manifest is re-runnable
// by construction: apply it twice and the second run sends nothing.
//
// Four properties are worth knowing before pointing this at production:
//
//   * `plan` writes nothing. It reads the tenant and reports the difference — safe in CI,
//     safe on a schedule, safe against a live tenant.
//   * `apply` stops at the first failure and does NOT roll back (§27.7). The report names
//     what landed, what failed and what was never attempted, so a partial apply is a state
//     you resume from. An automatic rollback would fire a second wave of writes at exactly
//     the moment the server is telling you something is wrong.
//   * Ordering is DERIVED, not declared. By kind, then dependency, then key — so shuffling
//     the declarations below changes nothing, and two runs of the same manifest produce the
//     same plan in the same order.
//   * Omission is never deletion. `ChangeAction` has no `delete` case at all, so an
//     incomplete manifest cannot become a destructive one.
//
// The manifest is built with §27.7's Swift form: a `@resultBuilder` DSL. That is sugar over
// a plain value — it lowers to the same `Manifest` a config file decodes into and goes
// through the same `plan`/`apply`. A declarative form that talked to the network itself
// would be a second implementation of §27.6, and the two would disagree.
//
// Runs plan-only unless AXIAM_APPLY=1 is set.
//
// Build:  swift build --target ManagementManifestExample
// Run:    swift run ManagementManifestExample

import Foundation
import AxiamSDK

func env(_ key: String, default fallback: String) -> String {
    ProcessInfo.processInfo.environment[key] ?? fallback
}

// The tenant this program insists must exist.
//
// Entities are addressed by a manifest-local `key`, never by a server-assigned UUID — that
// is what lets the same manifest mean the same thing against a fresh tenant and an existing
// one, since a UUID does not exist until the first apply.
//
// Note the declaration order: group first, resource last — deliberately backwards.
// `ManifestApi.ordered` derives apply order from kind and `dependsOn`, so this comes out
// resource, permission, role, group.
let documentsTenant = Manifest {
    Declare.group(
        "editors", name: "editors", description: "People who may edit documents",
        dependsOn: "editor")

    Declare.role(
        "editor", name: "editor", description: "Read and write documents",
        // A role cannot grant a permission that does not exist yet. `kind` already orders
        // permissions before roles; this names WHICH permission, so the dependency is
        // explicit rather than incidental.
        dependsOn: "documents-write")

    Declare.permission(
        "documents-read", name: "documents:read", description: "Read a document",
        action: "documents:read", dependsOn: "root")

    Declare.permission(
        "documents-write", name: "documents:write", description: "Write a document",
        action: "documents:write", dependsOn: "root")

    // Nesting derives the parent link, which is the one thing nesting is for here: a parent
    // resource must be applied before its children, and writing `dependsOn: "root"` on each
    // child by hand is exactly the bookkeeping a DSL should remove.
    Declare.resource("root", name: "documents", description: "The document tree",
                     type: "folder") {
        Declare.resource("drafts", name: "drafts", type: "folder")
        Declare.resource("published", name: "published", type: "folder")
    }
}

let baseURLString = env("AXIAM_BASE_URL", default: "https://localhost:8443")
guard let baseURL = URL(string: baseURLString) else {
    fatalError("Invalid AXIAM_BASE_URL: \(baseURLString)")
}

let config = try AxiamConfig(
    baseURL: baseURL,
    tenantID: env("AXIAM_TENANT_ID", default: "11111111-1111-1111-1111-111111111111"),
    orgID: env("AXIAM_ORG_ID", default: "11111111-1111-1111-1111-111111111111"))
let client = try AxiamClient(config: config)

do {
    _ = try await client.login(
        email: env("AXIAM_EMAIL", default: "admin@example.com"),
        password: env("AXIAM_PASSWORD", default: "changeme"))

    // Validation is separable from planning on purpose: a duplicate key, a `dependsOn`
    // naming nothing, or a dependency cycle is decidable from the manifest alone, so a
    // service can check its manifest at start-up rather than discovering it is incoherent at
    // apply time. `plan` runs this itself before its first read, so calling it here is belt
    // and braces — cheap belt, no network.
    try ManifestApi.validate(documentsTenant)

    // ---- plan: reads only --------------------------------------------
    let plan = try await client.manifest.plan(documentsTenant)

    print("plan (\(plan.changes.count) entities considered, "
          + "\(plan.pending.count) would change):")
    for change in plan.changes {
        print("  \(change.describe)")
    }

    if plan.isConverged {
        print("\nTenant already matches. An apply would send nothing.")
        exit(0)
    }

    guard env("AXIAM_APPLY", default: "") == "1" else {
        print("\n(set AXIAM_APPLY=1 to apply this plan)")
        exit(0)
    }

    // ---- apply: stops at the first failure, does not roll back -------
    //
    // `apply` re-plans internally rather than taking the plan above, because what it applies
    // must be computed against the tenant's state NOW. A plan from a minute ago describes a
    // tenant that may have moved, and applying it would either duplicate work or fail on a
    // conflict — either way acting on a world that no longer exists.
    let report = try await client.manifest.apply(documentsTenant)

    for line in report.describe {
        print(line)
    }

    guard report.isComplete else {
        // Not an error to paper over: this is the recovery instruction. Fix the cause and
        // re-run — the changes that already landed plan as `unchanged` next time, so a
        // resumed apply picks up exactly where this one stopped.
        print("""

            apply stopped early: \(report.failure)
            \(report.applied.count) applied, \(report.remaining.count) never attempted. \
            Re-run after fixing the cause.
            """)
        exit(1)
    }

    print("\nConverged. Run this again and it will send nothing.")
} catch let error as ManifestError {
    // Refused BEFORE any request went out. Every use of this type is a refusal to START: a
    // manifest with a dangling reference or a cycle cannot be applied coherently, and
    // discovering that halfway through — with no rollback — is strictly worse than refusing
    // up front.
    print("manifest rejected: \(error.message)")
    exit(2)
} catch {
    print("failed: \(error)")
    exit(1)
}
