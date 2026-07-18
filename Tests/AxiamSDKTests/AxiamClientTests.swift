import XCTest
import Foundation
@testable import AxiamSDK

final class AxiamClientTests: XCTestCase {

    // MARK: - login happy path

    func testLoginSuccessStoresCookiesAndSession() async throws {
        try await withClient(router: { request, _ in
            XCTAssertTrue(request.uri.hasSuffix("/api/v1/auth/login"))
            return .json(200, TestKit.loginSuccessBody(), headers: [
                ("Set-Cookie", "axiam_access=tok123; Path=/; HttpOnly"),
                ("Set-Cookie", "axiam_csrf=csrf456; Path=/"),
                ("X-CSRF-Token", "csrf456"),
            ])
        }) { client, _ in
            let result = try await client.login(email: "alice@example.com", password: "pw")
            guard case let .authenticated(user) = result else {
                return XCTFail("expected authenticated, got \(result)")
            }
            XCTAssertEqual(user.userID, "user-uuid-1")
            XCTAssertEqual(user.email, "alice@example.com")
            let hasSession = await client._hasSession()
            XCTAssertTrue(hasSession)
            let cookieCount = await client._cookieCount()
            XCTAssertEqual(cookieCount, 2)
            let csrf = await client._csrfToken()
            XCTAssertEqual(csrf, "csrf456")
        }
    }

    func testLoginWrongPasswordMapsToAuthError() async throws {
        try await withClient(router: { _, _ in
            .json(401, ["error": "invalid_credentials", "message": "bad password"])
        }) { client, _ in
            do {
                _ = try await client.login(email: "a@b.c", password: "wrong")
                XCTFail("expected error")
            } catch let AxiamError.auth(error) {
                XCTAssertEqual(error.message, "bad password")
            }
        }
    }

    func testLoginMfaRequired() async throws {
        try await withClient(router: { _, _ in
            .json(202, [
                "mfa_required": true,
                "challenge_token": "chal-secret",
                "available_methods": ["totp"],
            ])
        }) { client, _ in
            let result = try await client.login(email: "a@b.c", password: "pw")
            guard case let .mfaRequired(methods) = result else {
                return XCTFail("expected mfaRequired")
            }
            XCTAssertEqual(methods, ["totp"])
            let hasChallenge = await client._hasChallenge()
            XCTAssertTrue(hasChallenge)
            let hasSession = await client._hasSession()
            XCTAssertFalse(hasSession)
        }
    }

    func testLoginMfaSetupRequired() async throws {
        try await withClient(router: { _, _ in
            .json(403, ["mfa_setup_required": true, "setup_token": "setup-x"])
        }) { client, _ in
            let result = try await client.login(email: "a@b.c", password: "pw")
            guard case .mfaSetupRequired = result else {
                return XCTFail("expected mfaSetupRequired")
            }
        }
    }

    // MARK: - MFA verify

    func testVerifyMfaWithoutChallengeThrows() async throws {
        try await withClient(router: { _, _ in .json(200, [:]) }) { client, _ in
            do {
                try await client.verifyMfa("123456")
                XCTFail("expected error")
            } catch let AxiamError.auth(error) {
                XCTAssertTrue(error.message.contains("No MFA challenge"))
            }
        }
    }

    func testVerifyMfaSuccess() async throws {
        try await withClient(router: { request, state in
            if request.uri.hasSuffix("/login") {
                return .json(202, [
                    "mfa_required": true,
                    "challenge_token": "chal-secret",
                    "available_methods": ["totp"],
                ])
            }
            state.increment("mfa")
            let body = (try? JSONSerialization.jsonObject(with: request.body)) as? [String: Any]
            XCTAssertEqual(body?["challenge_token"] as? String, "chal-secret")
            XCTAssertEqual(body?["totp_code"] as? String, "123456")
            return .json(200, TestKit.loginSuccessBody(), headers: [
                ("Set-Cookie", "axiam_access=tok; Path=/; HttpOnly"),
            ])
        }) { client, server in
            _ = try await client.login(email: "a@b.c", password: "pw")
            try await client.verifyMfa("123456")
            let hasSession = await client._hasSession()
            XCTAssertTrue(hasSession)
            XCTAssertEqual(server.state.count("mfa"), 1)
        }
    }

    // MARK: - logout

    func testLogoutClearsSession() async throws {
        try await withClient(router: { request, _ in
            if request.uri.hasSuffix("/login") {
                return .json(200, TestKit.loginSuccessBody(), headers: [
                    ("Set-Cookie", "axiam_access=tok; Path=/; HttpOnly"),
                    ("X-CSRF-Token", "csrf1"),
                ])
            }
            return .json(200, [:])
        }) { client, _ in
            _ = try await client.login(email: "a@b.c", password: "pw")
            try await client.logout()
            let hasSession = await client._hasSession()
            XCTAssertFalse(hasSession)
            let csrf = await client._csrfToken()
            XCTAssertNil(csrf)
        }
    }

    // MARK: - authz

    func testCheckAccessAndCan() async throws {
        try await withClient(router: { request, _ in
            let body = (try? JSONSerialization.jsonObject(with: request.body)) as? [String: Any]
            let allowed = (body?["action"] as? String) == "read"
            return .json(200, ["allowed": allowed, "reason": allowed ? NSNull() : "denied"])
        }) { client, _ in
            let allowed = try await client.checkAccess("read", resource: "res-1")
            XCTAssertTrue(allowed.allowed)
            let denied = try await client.can("write", resource: "res-1")
            XCTAssertFalse(denied)
        }
    }

    func testCheckAccessForbiddenMapsToAuthzError() async throws {
        try await withClient(router: { _, _ in
            .json(403, ["error": "forbidden", "message": "nope", "action": "delete", "resource_id": "res-9"])
        }) { client, _ in
            do {
                _ = try await client.checkAccess("delete", resource: "res-9")
                XCTFail("expected authz error")
            } catch let AxiamError.authz(error) {
                XCTAssertEqual(error.action, "delete")
                XCTAssertEqual(error.resourceID, "res-9")
            }
        }
    }

    func testBatchCheckPreservesOrder() async throws {
        try await withClient(router: { request, _ in
            let body = (try? JSONSerialization.jsonObject(with: request.body)) as? [String: Any]
            let checks = (body?["checks"] as? [[String: Any]]) ?? []
            let results = checks.map { check -> [String: Any] in
                ["allowed": (check["action"] as? String) == "read", "reason": NSNull()]
            }
            return .json(200, ["results": results])
        }) { client, _ in
            let results = try await client.batchCheck([
                AccessCheck(action: "read", resource: "a"),
                AccessCheck(action: "write", resource: "b"),
                AccessCheck(action: "read", resource: "c"),
            ])
            XCTAssertEqual(results.map(\.allowed), [true, false, true])
        }
    }

    // MARK: - §5 tenant header + §3 CSRF echo + §4 cookies

    func testTenantHeaderInjectedOnEveryRequest() async throws {
        try await withClient(
            makeConfig: { try TestKit.makeConfig(port: $0, tenantSlug: nil, tenantID: "tenant-xyz") },
            router: { _, _ in .json(200, ["allowed": true]) }
        ) { client, server in
            _ = try await client.checkAccess("read", resource: "r")
            let req = server.state.requests.last
            XCTAssertEqual(req?.header("X-Tenant-ID"), "tenant-xyz")
        }
    }

    func testCsrfTokenEchoedOnStateChangingRequests() async throws {
        try await withClient(router: { request, _ in
            if request.uri.hasSuffix("/login") {
                return .json(200, TestKit.loginSuccessBody(), headers: [
                    ("Set-Cookie", "axiam_access=tok; Path=/; HttpOnly"),
                    ("X-CSRF-Token", "csrf-echo"),
                ])
            }
            return .json(200, ["allowed": true])
        }) { client, server in
            _ = try await client.login(email: "a@b.c", password: "pw")
            _ = try await client.checkAccess("read", resource: "r")
            let checkReq = server.state.requests(pathContaining: "authz/check").last
            XCTAssertEqual(checkReq?.header("X-CSRF-Token"), "csrf-echo")
        }
    }

    func testCookiesResentOnSubsequentRequests() async throws {
        try await withClient(router: { request, _ in
            if request.uri.hasSuffix("/login") {
                return .json(200, TestKit.loginSuccessBody(), headers: [
                    ("Set-Cookie", "axiam_access=tok; Path=/; HttpOnly"),
                ])
            }
            return .json(200, ["allowed": true])
        }) { client, server in
            _ = try await client.login(email: "a@b.c", password: "pw")
            _ = try await client.checkAccess("read", resource: "r")
            let checkReq = server.state.requests(pathContaining: "authz/check").last
            XCTAssertTrue((checkReq?.header("Cookie") ?? "").contains("axiam_access=tok"))
        }
    }

    // MARK: - 5xx / server error mapping

    func testServerErrorMapsToNetworkError() async throws {
        try await withClient(router: { _, _ in .json(500, ["message": "boom"]) }) { client, _ in
            do {
                _ = try await client.checkAccess("read", resource: "r")
                XCTFail("expected network error")
            } catch let AxiamError.network(error) {
                XCTAssertEqual(error.statusCode, 500)
            }
        }
    }
}
