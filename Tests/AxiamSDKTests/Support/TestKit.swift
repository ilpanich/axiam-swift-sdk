import XCTest
import Foundation
@testable import AxiamSDK

/// Shared helpers for building a client wired to a `TestHTTPServer`.
enum TestKit {
    static func makeConfig(port: Int, tenantSlug: String? = "acme", tenantID: String? = nil, orgSlug: String? = "globex") throws -> AxiamConfig {
        try AxiamConfig(
            baseURL: URL(string: "http://127.0.0.1:\(port)")!,
            tenantID: tenantID,
            tenantSlug: tenantSlug,
            orgSlug: orgSlug,
            requestTimeout: 10
        )
    }

    static func loginSuccessBody() -> [String: Any] {
        [
            "session_id": "sess-123",
            "expires_in": 900,
            "user": [
                "id": "user-uuid-1",
                "username": "alice",
                "email": "alice@example.com",
                "tenant_id": "tenant-uuid-1",
                "tenant_slug": "acme",
                "org_slug": "globex",
            ],
        ]
    }
}

extension XCTestCase {
    /// Run a test body against a fresh `TestHTTPServer` + `AxiamClient`, guaranteeing the client
    /// is shut down (AsyncHTTPClient's `HTTPClient` traps on deinit if not shut down) and the
    /// server is stopped, on both success and failure.
    func withClient(
        makeConfig: @escaping (Int) throws -> AxiamConfig = { try TestKit.makeConfig(port: $0) },
        router: @escaping TestRouter,
        body: (AxiamClient, TestHTTPServer) async throws -> Void
    ) async throws {
        let server = TestHTTPServer(router: router)
        let port = try server.start()
        let client = try AxiamClient(config: makeConfig(port))
        do {
            try await body(client, server)
        } catch {
            try? await client.shutdown()
            server.stop()
            throw error
        }
        try? await client.shutdown()
        server.stop()
    }
}
