import XCTest
import Foundation
@testable import AxiamSDK

/// CONTRACT.md §12.1 rule 12b (contract 1.66, #837): a federated sign-in is completed through
/// the cookie jar that started it. This is the confirming test the rule asks of every SDK: the
/// `axiam_fed_bind` cookie an `ssoStart` response sets is presented on the following
/// `ssoComplete` from the same client, and absent from a second client's.
///
/// Writing it found a §4 defect here: `ssoStart` and `ssoStartOauth2` went through
/// `oidcJSONPost` -> `umaSendAbsolute`, which neither stores nor presents a cookie, so the
/// binding never reached the jar. Both now go through `federationSessionPost` (`rawSend`).
final class Contract166FederatedBindingTests: XCTestCase {
    /// 32 bytes, base64url without padding — the shape the server issues.
    private static let binding = "Zm9vYmFyYmF6cXV4cXV1eGNvcmdlZ3JhdWx0Z2FycGx"

    func testSsoCompletePresentsTheBindingCookieOfItsOwnStartAndNoOtherClientDoes() async throws {
        XCTAssertEqual(Self.binding.count, 43)
        let binding = Self.binding
        let server = TestHTTPServer(router: { request, _ in
            if request.uri.hasSuffix("/auth/federation/oidc/start") {
                // Plain-http mock: the server's cookie_secure is off, so the name carries no
                // `__Host-` prefix and the cookie no `Secure` attribute.
                return .json(200, [
                    "authorize_url": "https://idp.example.test/authorize",
                    "state": "federation-state",
                    "expires_in_secs": 600,
                ], headers: [
                    ("Set-Cookie", "axiam_fed_bind=\(binding); Path=/; HttpOnly; SameSite=Strict"),
                ])
            }
            if request.uri.hasSuffix("/auth/federation/oidc/callback") {
                return .json(200, [
                    "user_id": "u-1", "session_id": "sess-sso-1", "expires_in": 900,
                    "redirect_uri": "https://app.example/done",
                ], headers: [("Set-Cookie", "axiam_access=sso-tok; Path=/; HttpOnly")])
            }
            return .json(404, [:])
        })
        let port = try server.start()
        let client = try AxiamClient(config: TestKit.makeConfig(port: port))
        let other = try AxiamClient(config: TestKit.makeConfig(port: port))
        func cleanUp() async {
            try? await client.shutdown()
            try? await other.shutdown()
            server.stop()
        }

        do {
            let start = try await client.ssoStart(
                federationConfigID: "fed-1", redirectURI: "https://app.test/cb")
            _ = try await client.ssoComplete(code: "upstream-code", state: start.state)
            _ = try await other.ssoComplete(code: "upstream-code", state: start.state)

            let completions = server.state.requests(pathContaining: "/auth/federation/oidc/callback")
            XCTAssertEqual(completions.count, 2)
            let own = completions.first?.header("Cookie") ?? ""
            XCTAssertTrue(
                own.contains("axiam_fed_bind=\(binding)"),
                "the completion from the starting client must present its binding (§12.1 rule 12b, §4)")
            let foreign = completions.last?.header("Cookie") ?? ""
            XCTAssertFalse(
                foreign.contains("axiam_fed_bind"),
                "a second client has its own jar and never presents the first client's binding")
        } catch {
            await cleanUp()
            throw error
        }
        await cleanUp()
    }
}
