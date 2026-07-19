// RestAuthz — the REST authorization surface: `can`, `checkAccess`, `batchCheck`
// (CONTRACT.md §1).
//
// It logs in first (see Examples/LoginMFA for the full MFA-aware flow), then exercises
// POST /api/v1/authz/check and POST /api/v1/authz/check/batch.
//
// §5.1: login requires organization context alongside tenant context — the config is
// built with BOTH `tenantSlug` (§5) and `orgSlug` (§5.1), so the login body carries an
// org identifier (the server rejects a login with none: HTTP 400).
//
// This example is illustrative and self-contained: it reads connection details from
// environment variables (with defaults) and compiles without a live AXIAM server.
//
// Build:  swift build --target RestAuthzExample
// Run:    swift run RestAuthzExample

import Foundation
import AxiamSDK

func env(_ key: String, default fallback: String) -> String {
    ProcessInfo.processInfo.environment[key] ?? fallback
}

let baseURLString = env("AXIAM_BASE_URL", default: "https://localhost:8443")
let tenantSlug = env("AXIAM_TENANT_SLUG", default: "acme")
let orgSlug = env("AXIAM_ORG_SLUG", default: "acme")
let email = env("AXIAM_EMAIL", default: "user@example.com")
let password = env("AXIAM_PASSWORD", default: "changeme")
let resourceID = env("AXIAM_RESOURCE_ID", default: "00000000-0000-0000-0000-000000000000")

guard let baseURL = URL(string: baseURLString) else {
    fatalError("Invalid AXIAM_BASE_URL: \(baseURLString)")
}

// §5 + §5.1: tenant and organization context are both supplied for login/refresh.
let config = try AxiamConfig(baseURL: baseURL, tenantSlug: tenantSlug, orgSlug: orgSlug)
let client = try AxiamClient(config: config)

do {
    switch try await client.login(email: email, password: password) {
    case .mfaRequired:
        print("MFA is required for this account — see Examples/LoginMFA first.")
    case .mfaSetupRequired:
        print("MFA enrolment required — see Examples/LoginMFA first.")
    case .authenticated(let user):
        print("Logged in as \(user.userID)")

        // POST /api/v1/authz/check — single access check.
        let result = try await client.checkAccess("edit", resource: resourceID)
        print("checkAccess(edit) -> allowed: \(result.allowed), reason: \(result.reason ?? "nil")")

        // can() — the browser/UI-facing alias for checkAccess; returns only the Bool.
        let canDelete = try await client.can("delete", resource: resourceID, scope: "field:title")
        print("can(delete, scope: field:title) -> \(canDelete)")

        // POST /api/v1/authz/check/batch — ordered batch; results preserve input order.
        let results = try await client.batchCheck([
            AccessCheck(action: "read", resource: resourceID),
            AccessCheck(action: "write", resource: resourceID, scope: "admin"),
        ])
        for (index, entry) in results.enumerated() {
            print("batchCheck[\(index)] -> allowed: \(entry.allowed)")
        }

        try await client.logout()
    }
} catch AxiamError.auth(let error) {
    print("Authentication failed: \(error.message)")
} catch AxiamError.authz(let error) {
    print("Authorization denied: \(error.message)")
} catch AxiamError.network(let error) {
    print("Transport failure: \(error.message)")
}

try await client.shutdown()
