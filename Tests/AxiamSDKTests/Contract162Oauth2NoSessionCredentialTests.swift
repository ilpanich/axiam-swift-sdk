import Foundation
import XCTest
@testable import AxiamSDK

/// CONTRACT.md §14.6 and §12.1 rule 3 (contract 1.62, review finding C162-05; contract 1.63 item (a)): no session or
/// adopted credential reaches an `/oauth2/*` request.
///
/// The `/oauth2/*` endpoints authenticate the **client**, through the form body. A client that
/// also holds a login session (its cookie jar and CSRF token) or an adopted device bearer
/// (`authenticateDevice()`) must not send either to them: an access token has no business at the
/// device-authorization or token endpoint, and the server ignores a non-Basic `Authorization`
/// header, so a leak would pass every functional test. This test holds both credentials and
/// asserts that none of `Authorization`, `Cookie` or `X-CSRF-Token` rides any `/oauth2/*` call.
final class Contract162Oauth2NoSessionCredentialTests: XCTestCase {

    private static let base = "https://iam.example.com"

    /// Records every request; answers the discovery document, a login that sets a session
    /// cookie, the mTLS device login, and the `/oauth2/*` endpoints this test exercises.
    private final class RecordingTransport: HTTPTransport, @unchecked Sendable {
        private let lock = NSLock()
        private var seen: [(path: String, headers: [(String, String)])] = []

        var requests: [(path: String, headers: [(String, String)])] {
            lock.locked { seen }
        }

        func execute(_ spec: HTTPRequestSpec, timeout: TimeInterval) async throws -> HTTPResponseData {
            lock.locked {
                seen.append((spec.url.path, spec.headers))
                let path = spec.url.path
                let json = [("Content-Type", "application/json")]
                func answer(_ object: [String: Any], status: Int = 200) -> HTTPResponseData {
                    HTTPResponseData(
                        status: status, headers: json,
                        body: (try? JSONSerialization.data(withJSONObject: object)) ?? Data())
                }
                if path.hasSuffix("/.well-known/openid-configuration") {
                    return answer([
                        "issuer": Self.base,
                        "authorization_endpoint": "\(Self.base)/oauth2/authorize",
                        "token_endpoint": "\(Self.base)/oauth2/token",
                        "jwks_uri": "\(Self.base)/oauth2/jwks",
                        "device_authorization_endpoint": "\(Self.base)/oauth2/device_authorization",
                        "introspection_endpoint": "\(Self.base)/oauth2/introspect",
                        "revocation_endpoint": "\(Self.base)/oauth2/revoke",
                    ])
                }
                if path.hasSuffix("/auth/login") {
                    return HTTPResponseData(
                        status: 200,
                        headers: json + [
                            ("Set-Cookie", "axiam_access=session-cookie-tok; Path=/; HttpOnly"),
                            ("Set-Cookie", "axiam_csrf=csrf-cookie-1; Path=/"),
                            ("X-CSRF-Token", "csrf-1"),
                        ],
                        body: (try? JSONSerialization.data(withJSONObject: TestKit.loginSuccessBody())) ?? Data())
                }
                if path.hasSuffix("/auth/device") {
                    return answer(["access_token": "device-bearer-tok", "token_type": "Bearer", "expires_in": 900])
                }
                if path.hasSuffix("/api/v1/groups") {
                    return answer([
                        "id": "g-1", "name": "ops", "description": "", "metadata": [String: Any](),
                        "tenant_id": "22222222-2222-2222-2222-222222222222",
                        "created_at": "2026-10-23T00:00:00Z", "updated_at": "2026-10-23T00:00:00Z",
                    ], status: 201)
                }
                if path.hasSuffix("/oauth2/device_authorization") {
                    return answer([
                        "device_code": "the-device-code",
                        "user_code": "WDJB-MJHT",
                        "verification_uri": "https://id.example/device",
                        "expires_in": 600,
                        "interval": 1,
                    ])
                }
                if path.hasSuffix("/oauth2/token") {
                    return answer(["access_token": "the-access-token", "token_type": "Bearer", "expires_in": 900])
                }
                if path.hasSuffix("/oauth2/introspect") {
                    return answer(["active": false])
                }
                return answer([:])
            }
        }

        func shutdown() async throws {}

        private static let base = Contract162Oauth2NoSessionCredentialTests.base
    }

    private func makeClient(_ transport: RecordingTransport) throws -> AxiamClient {
        guard let identity = OpenSSLPKI.generateSelfSigned() else {
            throw XCTSkip("openssl is required to generate the §6.1 test client identity")
        }
        let config = try AxiamConfig(
            baseURL: URL(string: Self.base)!,
            tenantID: "22222222-2222-2222-2222-222222222222",
            clientCertificate: .pem(certificate: identity.certificatePEM, privateKey: identity.keyPEM),
            retryEnabled: false,
            oidcClientID: "tv-app",
            oidcClientSecret: Sensitive("device-client-secret"))
        return AxiamClient(config: config, transport: transport)
    }

    /// Every request to a path under `/oauth2/` must carry none of the three session carriers.
    private func assertNoSessionCredential(_ transport: RecordingTransport, file: StaticString = #filePath, line: UInt = #line) {
        let oauth2 = transport.requests.filter { $0.path.contains("/oauth2/") }
        XCTAssertGreaterThanOrEqual(oauth2.count, 5, "the exercised calls reached /oauth2/*", file: file, line: line)
        for request in oauth2 {
            for name in ["Authorization", "Cookie", "X-CSRF-Token"] {
                let value = request.headers.first { $0.0.caseInsensitiveCompare(name) == .orderedSame }?.1
                XCTAssertNil(value, "\(name) must not reach \(request.path)", file: file, line: line)
            }
        }
    }

    /// A login session (cookie jar and CSRF token) is held when the `/oauth2/*` calls are made.
    func testASessionCookieAndCsrfTokenNeverReachAnOauth2Endpoint() async throws {
        let transport = RecordingTransport()
        let client = try makeClient(transport)
        _ = try await client.login(email: "alice@example.com", password: "pw")
        try await exerciseOauth2(client)
        assertNoSessionCredential(transport)
    }

    /// C163-08, the control: the login set `axiam_csrf` and `X-CSRF-Token`, and the same
    /// client's next management `POST` carries both the session cookies and the CSRF echo — so
    /// the absence asserted above is the `/oauth2/*` rule, not a session that never existed.
    func testTheSameClientsManagementPostStillCarriesTheSessionAndTheCsrfEcho() async throws {
        let transport = RecordingTransport()
        let client = try makeClient(transport)
        _ = try await client.login(email: "alice@example.com", password: "pw")
        try await exerciseOauth2(client)
        assertNoSessionCredential(transport)

        _ = try await client.groups.create(body: CreateGroupRequest(description: "", name: "ops"))
        let post = try XCTUnwrap(transport.requests.last { $0.path.hasSuffix("/api/v1/groups") })
        let cookie = post.headers.first { $0.0.caseInsensitiveCompare("Cookie") == .orderedSame }?.1
        XCTAssertTrue(cookie?.contains("axiam_access=session-cookie-tok") == true, "session cookie: \(cookie ?? "none")")
        XCTAssertTrue(cookie?.contains("axiam_csrf=csrf-cookie-1") == true, "CSRF cookie: \(cookie ?? "none")")
        let csrf = post.headers.first { $0.0.caseInsensitiveCompare("X-CSRF-Token") == .orderedSame }?.1
        XCTAssertEqual(csrf, "csrf-1")
    }

    /// An adopted device bearer (`authenticateDevice()`) is held when the calls are made. This
    /// is the case C162-05 found leaking in four other SDKs.
    func testAnAdoptedDeviceBearerNeverReachesAnOauth2Endpoint() async throws {
        let transport = RecordingTransport()
        let client = try makeClient(transport)
        _ = try await client.authenticateDevice()
        try await exerciseOauth2(client)
        assertNoSessionCredential(transport)
    }

    private func exerciseOauth2(_ client: AxiamClient) async throws {
        let authorization = try await client.deviceAuthorize(scope: "openid")
        _ = try await client.devicePoll(deviceCode: authorization.deviceCode)
        _ = try await client.introspect(token: Sensitive("some-token"))
        try await client.revoke(token: Sensitive("some-token"))
        _ = try await client.loginClientCredentials()
    }
}
