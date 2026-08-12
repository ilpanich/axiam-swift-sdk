// UmaClient — UMA 2.0 (CONTRACT.md §20), the CLIENT half of the pair.
//
// Run Examples/UmaResourceServer first; this program consumes the challenge that one
// emits.
//
// The flow, which is the whole reason UMA exists:
//
//   1. Ask for the invoice with the user's ordinary token. The resource server refuses —
//      but its 403 carries `WWW-Authenticate: UMA` naming a ticket and an authorization
//      server.
//   2. PARSE the challenge. Note what happens next, and what does not: parsing performs
//      no exchange (§20.3). The as_uri in that header is a host the *server we just
//      failed against* chose; auto-redeeming would send the user's token wherever a 403
//      pointed.
//   3. Decide to trust it, then EXCHANGE the ticket for an RPT.
//   4. Retry with the RPT.
//
// Step 3 is a decision, not a formality — this example makes it explicitly, by comparing
// the nominated as_uri against the issuer this client already trusts, and refusing when
// they differ.
//
// Build:  swift build --target UmaClientExample
// Run:    swift run UmaClientExample

import Foundation
import AxiamSDK

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

func env(_ key: String, default fallback: String) -> String {
    ProcessInfo.processInfo.environment[key] ?? fallback
}

let baseURLString = env("AXIAM_BASE_URL", default: "https://localhost:8443")
guard let baseURL = URL(string: baseURLString) else {
    fatalError("Invalid AXIAM_BASE_URL: \(baseURLString)")
}

let resourceServer = env("AXIAM_RESOURCE_SERVER", default: "http://127.0.0.1:8081")
// The resource server printed this id when it registered.
let invoiceID = env("AXIAM_INVOICE_ID", default: "00000000-0000-0000-0000-000000000000")
// The requesting party's own token — what this program would normally send and, in step
// 3, the claim_token that names *who* is asking.
let userToken = env("AXIAM_USER_TOKEN", default: "the-requesting-partys-access-token")

// The exchange is a token-endpoint grant, so the client authenticates with its own
// credentials (§20.1: client_secret_post).
let credentials = UmaClientCredentials(
    clientID: env("AXIAM_OIDC_CLIENT_ID", default: "invoices-client"),
    clientSecret: Sensitive(env("AXIAM_OIDC_CLIENT_SECRET", default: "client-secret"))
)

let config = try AxiamConfig(baseURL: baseURL, tenantSlug: env("AXIAM_TENANT_SLUG", default: "acme"))
let client = try AxiamClient(config: config)

/// A bearer-authenticated GET against the resource server. Plain URLSession rather than
/// the SDK client: the resource server is this program's own peer, not the AXIAM
/// deployment.
func get(_ url: URL, token: String) async throws -> (Int, [AnyHashable: Any]) {
    var request = URLRequest(url: url)
    request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
    // The completion-handler form rather than the async one: `URLSession.data(for:)` is
    // not available in swift-corelibs-foundation on Linux, and an example that only
    // builds on Apple platforms is not much of an example.
    return try await withCheckedThrowingContinuation { continuation in
        URLSession.shared.dataTask(with: request) { _, response, error in
            if let error {
                continuation.resume(throwing: error)
                return
            }
            guard let http = response as? HTTPURLResponse else {
                continuation.resume(returning: (0, [:]))
                return
            }
            continuation.resume(returning: (http.statusCode, http.allHeaderFields))
        }.resume()
    }
}

do {
    let url = URL(string: "\(resourceServer)/invoices/\(invoiceID)")!

    // ---- 1. The refusal ----
    let (status, headers) = try await get(url, token: userToken)
    print("first attempt: \(status)")

    let headerValue = headers.first { ($0.key as? String)?.lowercased() == "www-authenticate" }?.value as? String
    guard let headerValue else {
        // A resource server that refuses without a challenge is telling you it has
        // nothing to offer — there is no ticket to redeem, and retrying the same request
        // would be pointless.
        print("no WWW-Authenticate header: this refusal is not actionable.")
        try? await client.shutdown()
        exit(0)
    }

    // ---- 2. Parse, and only parse ----
    guard let challenge = AxiamClient.umaParseChallenge(headerValue), let ticket = challenge.ticket else {
        print("the challenge names no ticket; nothing to redeem.")
        try? await client.shutdown()
        exit(0)
    }

    // Nothing from the challenge is echoed, and there are two separate reasons for that.
    //
    // The ticket, because §20.6 says so: its 60-second life does not make it harmless —
    // for those 60 seconds it IS the credential that converts into an RPT, so a header in
    // a log line is a live credential in a log line.
    //
    // The realm and as_uri, because they are strings a *remote* server chose. They are
    // not secrets, but echoing attacker-controlled text into a terminal or a log file is
    // its own small hazard (escape sequences, log forging), and an example is the last
    // place to teach the habit. What matters here is the shape of the challenge, not its
    // contents.
    print("challenge parsed: as_uri present=\(challenge.asURI != nil), ticket present=true")

    // ---- 3. The trust decision ----
    //
    // This is the step §20.3 exists to keep in the caller's hands. The SDK parsed the
    // header and stopped; deciding whether to send the user's token to the host it names
    // is this program's call, and it is a real one — a compromised or merely
    // misconfigured resource server could nominate anything here.
    let configuration = try await client.umaDiscover()
    if let nominated = challenge.asURI,
       nominated.trimmingSlash != configuration.issuer.trimmingSlash {
        // Neither side of the comparison is echoed. The nominated value for the reasons
        // above; our own issuer because printing values read back off a configured client
        // is a habit that is fine here and wrong three refactors later. The decision and
        // its outcome are what a reader needs; the values are two lines away in a
        // debugger.
        print("refusing to redeem: the challenge nominates an authorization server")
        print("that is not the issuer this client already trusts.")
        print("this is the auto-exchange §20.3 forbids, and why it forbids it.")
        try? await client.shutdown()
        exit(0)
    }
    print("as_uri matches the issuer we already trust; redeeming.")

    // ---- 4. Exchange, then retry ----
    //
    // One request. A ticket is spent whether or not this succeeds (§20.2 rule 6), so on
    // failure the next step is a *new* ticket — which means going back to step 1, not
    // resending this one.
    let rpt: RequestingPartyToken
    do {
        rpt = try await client.umaExchangeTicket(
            ticket: ticket, claimToken: Sensitive(userToken), credentials: credentials)
    } catch {
        print("exchange failed; the ticket is spent either way —")
        print("request a new one by retrying the call from step 1.")
        try? await client.shutdown()
        exit(0)
    }
    print("got an RPT, valid for \(rpt.expiresIn)s")

    let (retryStatus, _) = try await get(url, token: rpt.accessToken.expose())
    print("second attempt: \(retryStatus)")
} catch {
    print("failed: \(error)")
}

try? await client.shutdown()

private extension String {
    /// Compares issuers without letting a trailing slash decide a security question.
    var trimmingSlash: String { hasSuffix("/") ? String(dropLast()) : self }
}
