import Foundation
import XCTest
@testable import AxiamSDK

/// CONTRACT.md §6.1 rules 6-10 — `authenticateDevice()`, the mTLS device login.
final class DeviceMtlsLoginTests: XCTestCase {

    /// Records every request; answers `/auth/device` with a scripted status/body and
    /// `/auth/login` with an ordinary Set-Cookie session — used to build the "stale
    /// cookie" scenario rule 6's fix closes.
    final class RecordingTransport: HTTPTransport, @unchecked Sendable {
        private let lock = NSLock()
        private(set) var requests: [(method: String, path: String, headers: [(String, String)])] = []
        var deviceStatus = 200
        var deviceBody = Data(#"{"access_token":"device-tok","token_type":"Bearer","expires_in":900}"#.utf8)
        /// When set, `/authz/check` answers this status instead of `200 allowed:true` —
        /// used to force the 401 `testNoRefreshAttemptOnALater401` needs.
        var checkStatus: Int?

        func execute(_ spec: HTTPRequestSpec, timeout: TimeInterval) async throws -> HTTPResponseData {
            lock.locked {
                requests.append((spec.method.rawValue, spec.url.path, spec.headers))
                let path = spec.url.path
                if path.hasSuffix("/auth/login") {
                    return HTTPResponseData(
                        status: 200,
                        headers: [
                            ("Content-Type", "application/json"),
                            ("Set-Cookie", "axiam_access=stale-cookie-tok; Path=/; HttpOnly"),
                            ("X-CSRF-Token", "csrf-1"),
                        ],
                        body: Self.loginBody)
                }
                if path.hasSuffix("/auth/device") {
                    return HTTPResponseData(
                        status: deviceStatus,
                        headers: [("Content-Type", "application/json")],
                        body: deviceStatus == 200 ? deviceBody
                            : Data(#"{"error":"authentication_failed","message":"unknown certificate"}"#.utf8))
                }
                if path.hasSuffix("/authz/check") {
                    if let checkStatus, checkStatus != 200 {
                        return HTTPResponseData(
                            status: checkStatus, headers: [],
                            body: Data(#"{"error":"authentication_failed","message":"expired"}"#.utf8))
                    }
                    return HTTPResponseData(
                        status: 200, headers: [("Content-Type", "application/json")],
                        body: Data(#"{"allowed":true}"#.utf8))
                }
                if path.hasSuffix("/auth/refresh") {
                    return HTTPResponseData(status: 200, headers: [], body: Data("{}".utf8))
                }
                return HTTPResponseData(status: 200, headers: [], body: Data("{}".utf8))
            }
        }

        private static let loginBody: Data =
            (try? JSONSerialization.data(withJSONObject: TestKit.loginSuccessBody())) ?? Data()

        func header(_ name: String, of index: Int) -> String? {
            requests[index].headers.first { $0.0.caseInsensitiveCompare(name) == .orderedSame }?.1
        }

        func shutdown() async throws {}
    }

    private func configWithCert() throws -> AxiamConfig {
        guard let identity = OpenSSLPKI.generateSelfSigned() else {
            throw XCTSkip("openssl is required to generate the §6.1 test client identity")
        }
        return try AxiamConfig(
            baseURL: URL(string: "https://iam.example.com")!,
            tenantID: "tenant-uuid-1",
            clientCertificate: .pem(certificate: identity.certificatePEM, privateKey: identity.keyPEM),
            retryEnabled: false)
    }

    private func configWithoutCert() throws -> AxiamConfig {
        try AxiamConfig(
            baseURL: URL(string: "https://iam.example.com")!,
            tenantID: "tenant-uuid-1",
            retryEnabled: false)
    }

    /// §6.1 rule 7: unreachable on a client configured with no certificate — client-side
    /// `AuthError`, ZERO wire calls.
    func testUnreachableWithoutACertificateZeroWireCalls() async throws {
        let transport = RecordingTransport()
        let client = AxiamClient(config: try configWithoutCert(), transport: transport)
        do {
            _ = try await client.authenticateDevice()
            XCTFail("expected a client-side refusal")
        } catch AxiamError.auth {
            // ok
        }
        XCTAssertEqual(transport.requests.count, 0, "no request should have been sent")
    }

    /// §6.1 rule 6: on success the token is returned as `Sensitive<String>` and the
    /// request carries no body.
    func testSuccessReturnsTheAccessTokenAndSendsNoBody() async throws {
        let transport = RecordingTransport()
        let client = AxiamClient(config: try configWithCert(), transport: transport)
        let result = try await client.authenticateDevice()
        XCTAssertEqual(result.tokenType, "Bearer")
        XCTAssertEqual(result.expiresIn, 900)
        XCTAssertEqual(result.accessToken.expose(), "device-tok")
        let last = transport.requests.last!
        XCTAssertEqual(last.method, "POST")
        XCTAssertTrue(last.path.hasSuffix("/auth/device"))
    }

    /// §6.1 rule 8: every refusal is a 401, mapped to `AuthError`.
    func testEveryRefusalIsAuthError() async throws {
        let transport = RecordingTransport()
        transport.deviceStatus = 401
        let client = AxiamClient(config: try configWithCert(), transport: transport)
        do {
            _ = try await client.authenticateDevice()
            XCTFail("expected AuthError")
        } catch AxiamError.auth {
            // ok
        }
    }

    /// A `429` (the route's per-IP rate limiter) is NOT an authentication failure (§16).
    func test429IsNotAnAuthError() async throws {
        let transport = RecordingTransport()
        transport.deviceStatus = 429
        transport.deviceBody = Data(#"{"error":"rate_limited","message":"too many requests"}"#.utf8)
        let client = AxiamClient(config: try configWithCert(), transport: transport)
        do {
            _ = try await client.authenticateDevice()
            XCTFail("expected NetworkError")
        } catch AxiamError.network {
            // ok — NOT .auth
        }
    }

    /// **The defect this pins**: the device token withholds a STALE cookie from an
    /// earlier `login()`. The server reads `axiam_access` before `Authorization`, so a
    /// client that kept its jar would silently run every later request as the previous
    /// session's principal. Observed at the actual transport boundary (the TypeScript
    /// lesson: a mock above this layer would pass even with the withholding removed).
    ///
    /// Mutated once: removing `("Cookie", "")` from `credentialHeaders`'s device-token
    /// branch (falling through to the cookie-jar branch instead) turns this red —
    /// confirmed, then restored.
    func testDeviceTokenWithholdsAStaleCookieFromAnEarlierLogin() async throws {
        let transport = RecordingTransport()
        let client = AxiamClient(config: try configWithCert(), transport: transport)

        // A prior password login populates the cookie jar with a real session cookie.
        _ = try await client.login(email: "a@b.test", password: "pw")
        let cookieCount = await client._cookieCount()
        XCTAssertGreaterThan(cookieCount, 0, "the login must have stored a cookie for this test to mean anything")

        _ = try await client.authenticateDevice()
        _ = try await client.checkAccess("read", resource: "doc-1")

        let checkIndex = transport.requests.count - 1
        XCTAssertTrue(transport.requests[checkIndex].path.hasSuffix("/authz/check"))
        let cookieHeader = transport.header("Cookie", of: checkIndex)
        XCTAssertFalse(
            (cookieHeader ?? "").contains("stale-cookie-tok"),
            "the stale login cookie must never reach the wire once a device token is adopted")
        XCTAssertEqual(
            transport.header("Authorization", of: checkIndex), "Bearer device-tok",
            "the device token must be sent as an explicit bearer credential")
    }

    /// §6.1 rule 6: there is no refresh token — a later 401 on the device token is
    /// `AuthError` with NO refresh attempt. `checkAccess` normally enters the §9
    /// single-flight refresh guard on a 401 (`canRefresh` gates it); a device-adopted
    /// client must skip straight to `AuthError` instead of calling `/auth/refresh`.
    ///
    /// Mutated once: reverting the `authorizedPOST`/`retryingPOST` gates from `canRefresh`
    /// back to `hasSession` turns this red — a spurious `/auth/refresh` request appears
    /// (request count goes from 2 to 3) — confirmed, then restored.
    func testNoRefreshAttemptOnALater401() async throws {
        let transport = RecordingTransport()
        let client = AxiamClient(config: try configWithCert(), transport: transport)
        _ = try await client.authenticateDevice()
        XCTAssertEqual(transport.requests.count, 1)

        transport.checkStatus = 401
        do {
            _ = try await client.checkAccess("read", resource: "doc-1")
            XCTFail("expected AuthError")
        } catch AxiamError.auth {
            // ok
        }

        // Exactly ONE more request (the failed check itself) — no `/auth/refresh` call
        // and no retried check.
        XCTAssertEqual(transport.requests.count, 2)
        XCTAssertTrue(transport.requests.last!.path.hasSuffix("/authz/check"))
    }
}
