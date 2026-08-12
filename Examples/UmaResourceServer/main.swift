// UmaResourceServer — UMA 2.0 (CONTRACT.md §20), the RESOURCE-SERVER half of the pair.
//
// The situation: this service holds invoices that belong to *users*, not to itself. When
// someone asks for one, the useful answer is not just "no" — it is "not with what you're
// carrying, and here is where to go and get better". That actionable refusal is what UMA
// adds over plain RBAC.
//
// What this shows, in order:
//
//   1. Mint a PAT — a client-credentials token carrying `uma_protection`. §20.2 rule 1
//      requires a *client* token: a minted ticket is bound to the client_id that minted
//      it, so a user token cannot stand in. This SDK implements no client-credentials
//      grant of its own (§12 is deferred here), so the PAT arrives from the environment,
//      obtained by whatever mints tokens for this deployment.
//   2. Register the resource this service guards. The returned id IS the AXIAM resource
//      id — there is no parallel resource store to keep in sync.
//   3. Build the §11 guard with a UmaChallenger, so a denial carries a fresh ticket.
//
// Its counterpart is Examples/UmaClient, which consumes that header.
//
// Build:  swift build --target UmaResourceServerExample
// Run:    swift run UmaResourceServerExample

import Foundation
import AxiamSDK

func env(_ key: String, default fallback: String) -> String {
    ProcessInfo.processInfo.environment[key] ?? fallback
}

let baseURLString = env("AXIAM_BASE_URL", default: "https://localhost:8443")
guard let baseURL = URL(string: baseURLString) else {
    fatalError("Invalid AXIAM_BASE_URL: \(baseURLString)")
}

// ---- 1. The PAT ----
//
// §20.2 rule 1: a client-credentials token carrying `uma_protection`. Not a user token,
// and not this client's ambient session — the SDK will not substitute either, and the
// Protection API would refuse them anyway.
let pat = Sensitive(env("AXIAM_PAT", default: "a-protection-api-token"))

let config = try AxiamConfig(baseURL: baseURL, tenantSlug: env("AXIAM_TENANT_SLUG", default: "acme"))
let client = try AxiamClient(config: config)

do {
    // ---- 2. Registration ----
    //
    // Registering the same name twice creates two resources, so a real service registers
    // once at provisioning time and stores the id, or reconciles by listing. Inline here
    // because it is the step that shows the returned id is the AXIAM resource id.
    let registered = try await client.umaRegisterResource(
        pat: pat,
        name: "invoice-7",
        type: "invoice",
        // The declared scopes are the allow-list the permission endpoint validates a
        // ticket request against. A resource registered with none can never appear in a
        // ticket.
        resourceScopes: ["invoices:read", "invoices:approve"]
    )
    let invoiceID = registered.id ?? "(the server assigns one on registration)"
    print("registered invoice-7 as \(invoiceID)")

    // ---- 3. The challenger ----
    //
    // `asURI` names where the caller should redeem the ticket. Read it from the discovery
    // document rather than assembling it by hand — a deployment is free to move its
    // endpoints, which is why UMA ships a discovery document at all.
    let configuration = try await client.umaDiscover()
    let challenger = UmaChallenger(realm: "invoices", asURI: configuration.issuer, pat: pat)

    // The load-bearing argument is `umaChallenge`. Without it this is an ordinary §11
    // guard and a denial is a bare AuthzError; with it, the error carries a ticket and
    // the framework adapter can hand the caller something to act on.
    let guardFn = client.makeGuards().requireAccess(
        "invoices:read", resource: invoiceID, umaChallenge: challenger)

    // What a guarded route does, without a framework in the way. A real adapter maps the
    // thrown AuthzError to a 403 and copies `challenge` onto the response.
    let context = AxiamRequestContext(headers: [
        "Authorization": "Bearer \(env("AXIAM_USER_TOKEN", default: "the-callers-access-token"))"
    ])
    let user = try await guardFn(context)

    // Reached only when the engine allowed it — including honouring any deny rule, which
    // UMA does not bypass: the ticket minted on a refusal asks for the same action this
    // check just evaluated, so the same grants and denies apply to whatever RPT comes
    // back.
    print("allowed: \(user.userID) may read invoice-7")
} catch let error as AuthzError {
    print("refused: \(error.message)")
    // The header itself is NOT printed: it carries a live ticket (§20.6), and a
    // credential in a log line is a credential in a log line, 60-second life or not.
    print("challenge present: \(error.challenge != nil ? "yes" : "no")")
} catch {
    print("failed: \(error)")
}

try? await client.shutdown()
