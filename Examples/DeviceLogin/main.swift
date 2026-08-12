// DeviceLogin — the §14 RFC 8628 device authorization grant: signing in something that cannot
// show a browser. A TV, a CLI, a headless commissioning tool.
//
// `deviceLogin` composes the whole flow: start the grant, hand YOU the codes, then poll to
// completion. The callback is the load-bearing part — §14.3 rule 2 forbids this SDK from
// printing the codes on your behalf, because a device shows them however it can: a screen, a QR
// code, an e-ink panel. Polling does not begin until the callback has returned.
//
// Build:  swift build --target DeviceLoginExample
// Run:    swift run DeviceLoginExample

import Foundation
import AxiamSDK

func env(_ key: String, default fallback: String) -> String {
    ProcessInfo.processInfo.environment[key] ?? fallback
}

let baseURLString = env("AXIAM_BASE_URL", default: "https://localhost:8443")
guard let baseURL = URL(string: baseURLString) else {
    fatalError("Invalid AXIAM_BASE_URL: \(baseURLString)")
}

// No client secret: §14.1 makes `device_authorize` unauthenticated, because a device that
// cannot show a browser also cannot keep a secret. The SDK will not send one here.
let config = try AxiamConfig(
    baseURL: baseURL,
    tenantID: env("AXIAM_TENANT_ID", default: "00000000-0000-0000-0000-000000000000"),
    oidcClientID: env("AXIAM_OIDC_CLIENT_ID", default: "living-room-tv"))
let client = try AxiamClient(config: config)

do {
    let tokens = try await client.deviceLogin(scope: "openid profile") { authorization in
        // This is where a real device renders. The verification_uri_complete embeds the user
        // code so a device that can draw a QR code makes the user type nothing — it is surfaced
        // when the server sends it, and never synthesised by concatenation when it does not
        // (§14.3): its format is the server's to choose.
        if let complete = authorization.verificationURIComplete {
            print("scan: \(complete)")
        }
        print("or visit \(authorization.verificationURI) and enter: \(authorization.userCode)")
        print("(expires in \(authorization.expiresIn)s, polling every \(authorization.interval)s)")
    }

    print("approved. access token expires in \(tokens.expiresIn)s")
    if let claims = tokens.idClaims {
        print("signed in as \(claims.subject)")
    }
} catch let error as AxiamError {
    // §14.2 rule 3 keeps the two refusals distinct, and this is why: one means a human said no,
    // the other that nobody answered. A device retries the second and stops asking after the
    // first — it cannot tell them apart if the SDK collapsed them.
    if case let .auth(authError) = error {
        switch authError.oauthError {
        case "access_denied":
            print("the user refused. Do not retry automatically.")
        case "expired_token":
            print("nobody approved in time. Starting again is reasonable.")
        default:
            print("device login failed: \(authError.oauthError ?? "no code")")
        }
    } else {
        print("device login failed: \(error)")
    }
}

try? await client.shutdown()
