import Foundation
@testable import AxiamSDK

/// A recording, scriptable transport for the CONTRACT.md §27 suite.
///
/// It sits at the BOTTOM of a real `AxiamClient`, exactly like every other harness here —
/// not in place of it. That matters for §27.8: a test that stubbed the management layer's
/// own request path would pass just as happily if the generated handles had quietly opened
/// their own, which is the one thing §27.8 forbids. Because this is the HTTP transport, a
/// management call that bypassed the client would reach nothing and fail.
final class ManagementStubTransport: HTTPTransport, @unchecked Sendable {

    /// One request as it reached the wire.
    struct Recorded: Sendable {
        let method: String
        let url: URL
        let body: Data?
        let headers: [(String, String)]

        /// The path, with no host and no query string — what a route assertion cares about.
        var path: String { url.path }

        /// The query string, or "" when there was none.
        var query: String { URLComponents(url: url, resolvingAgainstBaseURL: false)?.query ?? "" }

        /// The request body decoded as a JSON object.
        var jsonBody: [String: Any]? {
            guard let body else { return nil }
            return (try? JSONSerialization.jsonObject(with: body)) as? [String: Any]
        }

        func header(_ name: String) -> String? {
            headers.first { $0.0.lowercased() == name.lowercased() }?.1
        }
    }

    /// The login answer, serialized ONCE at type-initialization time.
    ///
    /// The test target builds in Swift 6 language mode, where a `[String: Any]` JSON
    /// fixture is a non-`Sendable` value; building it inside `execute` would put one in an
    /// asynchronous, nonisolated context on every call. Serializing at the point it is
    /// built keeps only `Data` — which is `Sendable` — anywhere near the request path.
    private static let loginBody: Data =
        (try? JSONSerialization.data(withJSONObject: TestKit.loginSuccessBody())) ?? Data()

    private let lock = NSLock()
    private var replies: [(status: Int, body: String)]
    private var served = 0
    private var recorded: [Recorded] = []

    /// `replies` are served in order to management calls. The login exchange is answered
    /// separately and is never counted against them, so a test's script lines up with the
    /// operations it is actually about.
    init(_ replies: [(status: Int, body: String)] = []) {
        self.replies = replies
    }

    /// Every management request this transport saw, in order. The login is not included.
    var requests: [Recorded] {
        lock.lock(); defer { lock.unlock() }
        return recorded
    }

    /// How many management requests were made.
    var count: Int { requests.count }

    /// The most recent management request.
    var last: Recorded? { requests.last }

    func execute(_ spec: HTTPRequestSpec, timeout: TimeInterval) async throws -> HTTPResponseData {
        if spec.url.path.hasSuffix("/auth/login") {
            return HTTPResponseData(
                status: 200,
                headers: [("Content-Type", "application/json"), ("X-CSRF-Token", "csrf-1")],
                body: Self.loginBody)
        }

        let reply = lock.locked { () -> (status: Int, body: String) in
            recorded.append(Recorded(
                method: spec.method.rawValue, url: spec.url, body: spec.body,
                headers: spec.headers))
            if served < replies.count {
                let next = replies[served]
                served += 1
                return next
            }
            // Past the end of the script, answer 204. A test that made one more call than it
            // scripted should fail on its own assertion, not on a decode of an empty 200.
            return (204, "")
        }

        return HTTPResponseData(
            status: reply.status,
            headers: [("Content-Type", "application/json")],
            body: Data(reply.body.utf8))
    }

    func shutdown() async throws {}
}

/// Builds the clients the §27 suite drives.
enum ManagementFixture {
    static let tenantID = "11111111-1111-4111-8111-111111111111"
    static let orgID = "11111111-1111-4111-8111-111111111111"
    /// Deliberately different from the client's own scope, so a §27.4 rule 3 assertion can
    /// tell an override that took effect from one that was ignored.
    static let otherOrg = "22222222-2222-4222-8222-222222222222"
    static let otherTenant = "33333333-3333-4333-8333-333333333333"

    /// A signed-in client whose management calls get `replies`, served in order.
    ///
    /// The session comes from a real login through the same transport, so §27.4 rule 1's
    /// "no session, no wire call" check sees a genuine authenticated client rather than a
    /// flag poked into place.
    static func signedIn(
        _ replies: [(status: Int, body: String)] = [],
        hook: TelemetryHook? = nil,
        retryEnabled: Bool = true
    ) async throws -> (AxiamClient, ManagementStubTransport) {
        let transport = ManagementStubTransport(replies)
        let config = try AxiamConfig(
            baseURL: URL(string: "https://iam.example.com")!,
            tenantID: tenantID,
            orgID: orgID,
            retryEnabled: retryEnabled,
            telemetryHook: hook)
        let client = AxiamClient(config: config, transport: transport)
        await client._setRetryTestSeams(jitter: { 0 }, sleep: { _ in })
        _ = try await client.login(email: "admin@acme.test", password: "correct horse")
        return (client, transport)
    }

    /// A client that has NOT logged in — for the rule 1 cases.
    static func anonymous() async throws -> (AxiamClient, ManagementStubTransport) {
        let transport = ManagementStubTransport()
        let config = try AxiamConfig(
            baseURL: URL(string: "https://iam.example.com")!,
            tenantID: tenantID,
            orgID: orgID)
        return (AxiamClient(config: config, transport: transport), transport)
    }

    /// A signed-in client with a tenant SLUG and no UUIDs, for the routes that substitute an
    /// implicit identifier and must refuse without one.
    static func unscoped(
        _ replies: [(status: Int, body: String)] = []
    ) async throws -> (AxiamClient, ManagementStubTransport) {
        let transport = ManagementStubTransport(replies)
        // A slug is a valid §5 tenant identifier but is NOT a `{tenant_id}` path segment, so
        // this client can log in and still have no UUID for §27 to substitute.
        let config = try AxiamConfig(
            baseURL: URL(string: "https://iam.example.com")!,
            tenantSlug: "acme")
        let client = AxiamClient(config: config, transport: transport)
        _ = try await client.login(email: "admin@acme.test", password: "correct horse")
        return (client, transport)
    }
}
