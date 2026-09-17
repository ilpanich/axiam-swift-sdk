import XCTest
import Foundation
@testable import AxiamSDK

/// CONTRACT.md §28 (MCP resource-server helpers, RFC 9728 + RFC 6750) — the five §28.9 required
/// tests, on the fixture §28.9 names, plus the off-by-default regression §28.5 rule 1 requires.
///
/// Tests 1 and 2 exercise ``AxiamClient/protectedResourceMetadata(resource:authorizationServers:scopesSupported:bearerMethodsSupported:resourceDocumentation:)``
/// and ``AxiamClient/bearerChallenge(resourceMetadataUrl:error:errorDescription:scope:)`` directly
/// — both are pure computation (§28.0), so neither needs a server. Tests 3–5 exercise the guard
/// integration through ``AxiamRequestAuthenticator`` and ``AxiamGuards``, the same entry points
/// every other guard test in this suite uses.
final class McpResourceServerTests: XCTestCase {
    let signer = TestSigner()

    // MARK: - §28.9's fixture

    static let resource = "https://mcp.example.com/mcp"
    static let authorizationServers = ["https://axiam.example.com"]
    static let scopesSupported = ["mcp:read", "mcp:tools"]
    static let resourceDocumentation = "https://mcp.example.com/docs"
    static let metadataPath = "/.well-known/oauth-protected-resource/mcp"
    static let metadataUrl = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
    /// Equal to ``resource`` — §28.2 rule 9.
    static let expectedAudience = "https://mcp.example.com/mcp"

    static let tenantUUID = "tenant-uuid-1"

    private func fixtureMetadata() throws -> ProtectedResourceMetadata {
        try AxiamClient.protectedResourceMetadata(
            resource: Self.resource,
            authorizationServers: Self.authorizationServers,
            scopesSupported: Self.scopesSupported,
            resourceDocumentation: Self.resourceDocumentation
        )
    }

    // MARK: - Test 1: document shape, and the validation negatives

    func testDocumentShapeMatchesTheFixture() throws {
        let metadata = try fixtureMetadata()
        XCTAssertEqual(metadata.metadataPath, Self.metadataPath)
        XCTAssertEqual(metadata.metadataUrl, Self.metadataUrl)
        XCTAssertEqual(metadata.document.resource, Self.resource)
        XCTAssertEqual(metadata.document.authorizationServers, Self.authorizationServers)
        XCTAssertEqual(metadata.document.scopesSupported, Self.scopesSupported)
        XCTAssertEqual(metadata.document.bearerMethodsSupported, ["header"])
        XCTAssertEqual(metadata.document.resourceDocumentation, Self.resourceDocumentation)

        // "Compared as parsed values" (§28.2): round-trip the pre-serialized body rather than
        // comparing bytes.
        let decoded = try JSONDecoder().decode(ProtectedResourceMetadataDocument.self, from: metadata.jsonBody)
        XCTAssertEqual(decoded, metadata.document)

        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: metadata.jsonBody) as? [String: Any])
        XCTAssertEqual(
            Set(object.keys),
            ["resource", "authorization_servers", "scopes_supported", "bearer_methods_supported", "resource_documentation"])
    }

    func testMetadataPathDerivationTable() throws {
        let cases: [(resource: String, path: String)] = [
            ("https://mcp.example.com", "/.well-known/oauth-protected-resource"),
            ("https://mcp.example.com/", "/.well-known/oauth-protected-resource"),
            ("https://mcp.example.com/mcp", "/.well-known/oauth-protected-resource/mcp"),
            ("https://mcp.example.com/mcp/", "/.well-known/oauth-protected-resource/mcp/"),
            ("https://mcp.example.com/a/b", "/.well-known/oauth-protected-resource/a/b"),
        ]
        for testCase in cases {
            let metadata = try AxiamClient.protectedResourceMetadata(
                resource: testCase.resource, authorizationServers: Self.authorizationServers)
            XCTAssertEqual(metadata.metadataPath, testCase.path, testCase.resource)
        }
    }

    func testEmptyScopesSupportedIsAcceptedAndOmitsTheMember() throws {
        let metadata = try AxiamClient.protectedResourceMetadata(
            resource: Self.resource, authorizationServers: Self.authorizationServers, scopesSupported: [])
        XCTAssertNil(metadata.document.scopesSupported)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: metadata.jsonBody) as? [String: Any])
        XCTAssertFalse(object.keys.contains("scopes_supported"))
    }

    func testAbsentResourceDocumentationOmitsTheMemberRatherThanNull() throws {
        let metadata = try AxiamClient.protectedResourceMetadata(
            resource: Self.resource, authorizationServers: Self.authorizationServers)
        XCTAssertNil(metadata.document.resourceDocumentation)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: metadata.jsonBody) as? [String: Any])
        XCTAssertFalse(object.keys.contains("resource_documentation"))
    }

    private func expectMetadataRefusal(
        resource: String = McpResourceServerTests.resource,
        authorizationServers: [String] = McpResourceServerTests.authorizationServers,
        scopesSupported: [String] = [],
        bearerMethodsSupported: [String] = ["header"],
        resourceDocumentation: String? = nil,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertThrowsError(
            try AxiamClient.protectedResourceMetadata(
                resource: resource,
                authorizationServers: authorizationServers,
                scopesSupported: scopesSupported,
                bearerMethodsSupported: bearerMethodsSupported,
                resourceDocumentation: resourceDocumentation
            ),
            file: file, line: line
        ) { error in
            guard let networkError = error as? NetworkError else {
                XCTFail("expected NetworkError, got \(error)", file: file, line: line)
                return
            }
            XCTAssertTrue(networkError.isValidation, file: file, line: line)
        }
    }

    func testRelativeResourceRefused() { expectMetadataRefusal(resource: "/mcp") }
    func testResourceWithFragmentRefused() { expectMetadataRefusal(resource: "https://mcp.example.com/mcp#frag") }
    func testResourceWithQueryRefused() { expectMetadataRefusal(resource: "https://mcp.example.com/mcp?x=1") }
    func testHttpResourceOnNonLoopbackHostRefused() { expectMetadataRefusal(resource: "http://mcp.example.com/mcp") }

    func testHttpResourceOnLoopbackHostAccepted() throws {
        let metadata = try AxiamClient.protectedResourceMetadata(
            resource: "http://127.0.0.1/mcp", authorizationServers: Self.authorizationServers)
        XCTAssertEqual(metadata.metadataUrl, "http://127.0.0.1/.well-known/oauth-protected-resource/mcp")
    }

    func testEmptyAuthorizationServersRefused() { expectMetadataRefusal(authorizationServers: []) }
    func testAuthorizationServerWithQueryRefused() {
        expectMetadataRefusal(authorizationServers: ["https://axiam.example.com?x=1"])
    }
    func testAuthorizationServerWithFragmentRefused() {
        expectMetadataRefusal(authorizationServers: ["https://axiam.example.com#frag"])
    }
    func testDuplicateAuthorizationServerRefused() {
        expectMetadataRefusal(authorizationServers: ["https://axiam.example.com", "https://axiam.example.com"])
    }
    func testDuplicateScopeRefused() {
        expectMetadataRefusal(scopesSupported: ["mcp:read", "mcp:read"])
    }
    func testBearerMethodsSupportedQueryOnlyRefused() {
        expectMetadataRefusal(bearerMethodsSupported: ["query"])
    }
    func testBearerMethodsSupportedHeaderAndBodyRefused() {
        expectMetadataRefusal(bearerMethodsSupported: ["header", "body"])
    }

    // MARK: - Test 2: challenge quoting

    func testChallengeVectorNoCredential() throws {
        let value = try AxiamClient.bearerChallenge(resourceMetadataUrl: Self.metadataUrl)
        XCTAssertEqual(value, "Bearer resource_metadata=\"\(Self.metadataUrl)\"")
    }

    func testChallengeVectorCredentialPresentedAndRejected() throws {
        let value = try AxiamClient.bearerChallenge(
            resourceMetadataUrl: Self.metadataUrl, error: BearerChallengeError.invalidToken)
        XCTAssertEqual(value, "Bearer error=\"invalid_token\", resource_metadata=\"\(Self.metadataUrl)\"")
    }

    func testChallengeVectorScopeFailure403() throws {
        let value = try AxiamClient.bearerChallenge(
            resourceMetadataUrl: Self.metadataUrl, error: BearerChallengeError.insufficientScope, scope: "mcp:tools")
        XCTAssertEqual(
            value,
            "Bearer error=\"insufficient_scope\", scope=\"mcp:tools\", resource_metadata=\"\(Self.metadataUrl)\"")
    }

    func testChallengeVectorAllFourParameters() throws {
        let value = try AxiamClient.bearerChallenge(
            resourceMetadataUrl: Self.metadataUrl,
            error: BearerChallengeError.invalidRequest,
            errorDescription: "The access token is malformed",
            scope: "mcp:read mcp:tools"
        )
        XCTAssertEqual(
            value,
            "Bearer error=\"invalid_request\", error_description=\"The access token is malformed\", "
                + "scope=\"mcp:read mcp:tools\", resource_metadata=\"\(Self.metadataUrl)\"")
    }

    private func expectChallengeRefusal(
        error: String? = nil,
        errorDescription: String? = nil,
        scope: String? = nil,
        resourceMetadataUrl: String = McpResourceServerTests.metadataUrl,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertThrowsError(
            try AxiamClient.bearerChallenge(
                resourceMetadataUrl: resourceMetadataUrl, error: error, errorDescription: errorDescription, scope: scope),
            file: file, line: line
        ) { thrown in
            guard let networkError = thrown as? NetworkError else {
                XCTFail("expected NetworkError, got \(thrown)", file: file, line: line)
                return
            }
            XCTAssertTrue(networkError.isValidation, file: file, line: line)
            // No escaping occurred: the refusal is an exception, never a challenge containing `\"`.
            XCTAssertFalse(networkError.message.contains("\\\""), file: file, line: line)
        }
    }

    func testErrorCodeInvalidGrantRefused() { expectChallengeRefusal(error: "invalid_grant") }
    func testErrorDescriptionContainingQuoteRefused() { expectChallengeRefusal(errorDescription: "bad \"quote\"") }
    func testErrorDescriptionContainingBackslashRefused() { expectChallengeRefusal(errorDescription: "bad\\slash") }
    func testErrorDescriptionContainingNewlineRefused() { expectChallengeRefusal(errorDescription: "line one\nline two") }
    func testErrorDescriptionContainingNonAsciiRefused() { expectChallengeRefusal(errorDescription: "caf\u{e9}") }
    func testScopeWithLeadingSpaceRefused() { expectChallengeRefusal(scope: " mcp:tools") }
    func testScopeWithDoubledSpaceRefused() { expectChallengeRefusal(scope: "mcp:read  mcp:tools") }
    func testEmptyScopeRefused() { expectChallengeRefusal(scope: "") }
    func testResourceMetadataContainingSpaceRefused() {
        expectChallengeRefusal(resourceMetadataUrl: "https://mcp.example.com/oauth protected-resource/mcp")
    }

    // MARK: - Shared guard fixture for tests 3–5

    /// A client whose guard has §28 turned on with the §28.9 fixture: `expectedAudience` ==
    /// `resource`, `resourceMetadataUrl` == `metadataUrl`.
    private func withMcpGuardClient(
        body: @escaping (AxiamClient, TestHTTPServer) async throws -> Void
    ) async throws {
        let signer = self.signer
        try await withClient(
            makeConfig: {
                try TestKit.makeConfig(
                    port: $0,
                    tenantSlug: nil,
                    tenantID: Self.tenantUUID,
                    expectedAudience: Self.expectedAudience,
                    resourceMetadataUrl: Self.metadataUrl
                )
            },
            router: { request, state in
                if request.uri.hasSuffix("/oauth2/jwks") {
                    state.increment("jwks")
                    return .json(200, signer.jwksJSON())
                }
                if request.uri.contains("/authz/check") {
                    state.increment("authz")
                    return Self.authzResponse(for: request)
                }
                return .json(404, [:])
            },
            body: body
        )
    }

    /// One router body for every §28.5 rule 5 case (test 4): the `action` field of the request
    /// selects which `reason_code` — if any — the fake authz server answers with, so a single
    /// route serves all four sub-cases without extra plumbing.
    private static func authzResponse(for request: TestRequest) -> TestResponse {
        let requestBody = String(data: request.body, encoding: .utf8) ?? ""
        if requestBody.contains("\"grant-no_grant\"") {
            return .json(200, ["allowed": false, "reason_code": "no_grant"])
        }
        if requestBody.contains("\"grant-denied_by_rule\"") {
            return .json(200, ["allowed": false, "reason_code": "denied_by_rule"])
        }
        if requestBody.contains("\"grant-unknown_code\"") {
            return .json(200, ["allowed": false, "reason_code": "something_this_sdk_predates"])
        }
        return .json(200, ["allowed": true])
    }

    /// A claims set satisfying §10.1 in full; `aud` defaults to the fixture's `expectedAudience`
    /// and is overridable (or omittable) for test 5.
    private func futureClaims(aud: Any? = McpResourceServerTests.expectedAudience) -> [String: Any] {
        var claims: [String: Any] = [
            "sub": "user-42",
            "tenant_id": Self.tenantUUID,
            "roles": ["admin"],
            "exp": Date().addingTimeInterval(3600).timeIntervalSince1970,
        ]
        if let aud { claims["aud"] = aud }
        return claims
    }

    // MARK: - Test 3: 401 with the challenge

    func testNoCredentialCarriesVectorOneWithNoErrorParameter() async throws {
        try await withMcpGuardClient { client, _ in
            let auth = client.makeAuthenticator()
            do {
                _ = try await auth.authenticate(AxiamRequestContext())
                XCTFail("expected rejection")
            } catch let error as AuthError {
                XCTAssertEqual(error.challenge, "Bearer resource_metadata=\"\(Self.metadataUrl)\"")
                // The §10 message is unchanged from what this SDK returns today, and carries
                // nothing derived from a token that was never presented.
                XCTAssertEqual(
                    error.message, "No AXIAM session: missing Authorization bearer token or axiam_access cookie.")
                XCTAssertNil(error.oauthErrorDescription)
            }
        }
    }

    func testExpiredTokenCarriesVectorTwo() async throws {
        var claims = futureClaims()
        claims["exp"] = Date().addingTimeInterval(-3600).timeIntervalSince1970
        let jwt = signer.makeJWT(claims: claims)
        try await withMcpGuardClient { client, _ in
            let auth = client.makeAuthenticator()
            do {
                _ = try await auth.authenticate(AxiamRequestContext(cookies: ["axiam_access": jwt]))
                XCTFail("expected rejection")
            } catch let error as AuthError {
                XCTAssertEqual(
                    error.challenge, "Bearer error=\"invalid_token\", resource_metadata=\"\(Self.metadataUrl)\"")
                // Unchanged from the pre-§28 message — no "expired" vs. "wrong audience" oracle
                // reaches the *challenge*, but the SDK's own thrown message is untouched.
                XCTAssertEqual(error.message, "AXIAM session token is expired.")
                XCTAssertNil(error.oauthErrorDescription)
            }
        }
    }

    func testMetadataDocumentPathIsExemptedAndServesTheDocumentUnauthenticated() async throws {
        try await withMcpGuardClient { client, _ in
            let auth = client.makeAuthenticator()
            // The exemption a global-middleware integrator relies on (§28.3 rule 2): this is what
            // the README's Vapor `AsyncMiddleware` checks before extracting a credential, so a
            // guard mounted globally still serves the document unauthenticated.
            XCTAssertTrue(auth.isProtectedResourceMetadataRequest(method: "GET", path: Self.metadataPath))
            XCTAssertTrue(auth.isProtectedResourceMetadataRequest(method: "get", path: Self.metadataPath))
            XCTAssertFalse(auth.isProtectedResourceMetadataRequest(method: "POST", path: Self.metadataPath))
            XCTAssertFalse(auth.isProtectedResourceMetadataRequest(method: "GET", path: "/mcp"))

            // "returns 200 and the document": the bytes a Vapor route registered at this path
            // would serve verbatim, unauthenticated, identical for every caller (§28.3 rules 1, 4).
            let metadata = try self.fixtureMetadata()
            XCTAssertEqual(metadata.metadataPath, Self.metadataPath)
            let object = try XCTUnwrap(JSONSerialization.jsonObject(with: metadata.jsonBody) as? [String: Any])
            XCTAssertEqual(object["resource"] as? String, Self.resource)
        }
    }

    // MARK: - Test 4: 403 `insufficient_scope`

    func testNoGrantDenialWithScopeCarriesVectorThreeAndUnchangedBody() async throws {
        let jwt = signer.makeJWT(claims: futureClaims())
        try await withMcpGuardClient { client, _ in
            let guards = client.makeGuards()
            let handler = guards.requireAccess("grant-no_grant", resource: "res-1", scope: "mcp:tools")
            do {
                _ = try await handler(AxiamRequestContext(cookies: ["axiam_access": jwt]))
                XCTFail("expected denial")
            } catch let error as AuthzError {
                XCTAssertEqual(
                    error.challenge,
                    "Bearer error=\"insufficient_scope\", scope=\"mcp:tools\", resource_metadata=\"\(Self.metadataUrl)\"")
                // §28.5 rule 5: the JSON body's shape is §11.2 rule 5's, unchanged —
                // `insufficient_scope` appears only inside the header.
                XCTAssertEqual(error.action, "grant-no_grant")
                XCTAssertEqual(error.resourceID, "res-1")
            }
        }
    }

    func testDeniedByRuleCarriesNoChallenge() async throws {
        try await assertNoMcpChallenge(action: "grant-denied_by_rule", scope: "mcp:tools")
    }

    func testUnrecognisedReasonCodeCarriesNoChallenge() async throws {
        try await assertNoMcpChallenge(action: "grant-unknown_code", scope: "mcp:tools")
    }

    func testDenialWithNoScopeArgumentCarriesNoChallengeEvenOnNoGrant() async throws {
        try await assertNoMcpChallenge(action: "grant-no_grant", scope: nil)
    }

    private func assertNoMcpChallenge(
        action: String, scope: String?, file: StaticString = #filePath, line: UInt = #line
    ) async throws {
        let jwt = signer.makeJWT(claims: futureClaims())
        try await withMcpGuardClient { client, _ in
            let guards = client.makeGuards()
            let handler = guards.requireAccess(action, resource: "res-1", scope: scope)
            do {
                _ = try await handler(AxiamRequestContext(cookies: ["axiam_access": jwt]))
                XCTFail("expected denial", file: file, line: line)
            } catch let error as AuthzError {
                XCTAssertNil(error.challenge, file: file, line: line)
            }
        }
    }

    // MARK: - Test 5: a token whose `aud` is not the resource is refused

    func testTokenAudNotTheResourceRefused() async throws {
        let jwt = signer.makeJWT(claims: futureClaims(aud: "https://other.example.com/mcp"))
        try await withMcpGuardClient { client, _ in
            let auth = client.makeAuthenticator()
            do {
                _ = try await auth.authenticate(AxiamRequestContext(cookies: ["axiam_access": jwt]))
                XCTFail("expected rejection")
            } catch let error as AuthError {
                XCTAssertEqual(
                    error.challenge, "Bearer error=\"invalid_token\", resource_metadata=\"\(Self.metadataUrl)\"")
            }
        }
    }

    func testGeneralPurposeUserTokenAudienceRefused() async throws {
        // A general-purpose AXIAM user token — not minted for this resource server.
        let jwt = signer.makeJWT(claims: futureClaims(aud: "axiam:user"))
        try await withMcpGuardClient { client, _ in
            let auth = client.makeAuthenticator()
            do {
                _ = try await auth.authenticate(AxiamRequestContext(cookies: ["axiam_access": jwt]))
                XCTFail("expected rejection")
            } catch let error as AuthError {
                XCTAssertEqual(
                    error.challenge, "Bearer error=\"invalid_token\", resource_metadata=\"\(Self.metadataUrl)\"")
            }
        }
    }

    func testMatchingAudienceAdmitted() async throws {
        let jwt = signer.makeJWT(claims: futureClaims(aud: Self.expectedAudience))
        try await withMcpGuardClient { client, _ in
            let auth = client.makeAuthenticator()
            let user = try await auth.authenticate(AxiamRequestContext(cookies: ["axiam_access": jwt]))
            XCTAssertEqual(user.userID, "user-42")
        }
    }

    /// The configuration negative: `resourceMetadataUrl` set with no `expectedAudience` fails at
    /// construction, naming both options (§28.5 rule 2).
    func testConstructionFailsWhenResourceMetadataUrlSetWithNoExpectedAudience() throws {
        XCTAssertThrowsError(
            try AxiamConfig(
                baseURL: URL(string: "https://127.0.0.1:1")!,
                tenantID: Self.tenantUUID,
                resourceMetadataUrl: Self.metadataUrl
            )
        ) { error in
            guard let networkError = error as? NetworkError else {
                XCTFail("expected NetworkError, got \(error)")
                return
            }
            XCTAssertTrue(networkError.isValidation)
            XCTAssertTrue(networkError.message.contains("resourceMetadataUrl"))
            XCTAssertTrue(networkError.message.contains("expectedAudience"))
        }
    }

    // MARK: - The regression that matters more than all five

    /// With `resourceMetadataUrl` unset, every response this guard produces is byte-for-byte what
    /// it was before §28 existed, and carries no `WWW-Authenticate` header (§28.5 rule 1). Asserts
    /// the header's absence explicitly on all three outcomes §28 touches: a 401 with no
    /// credential, a successful authentication, and a `no_grant` 403.
    func testWithResourceMetadataUrlUnsetNothingChanges() async throws {
        let signer = self.signer
        let jwt = signer.makeJWT(claims: futureClaims(aud: nil))
        try await withClient(
            makeConfig: { try TestKit.makeConfig(port: $0, tenantSlug: nil, tenantID: Self.tenantUUID) },
            router: { request, state in
                if request.uri.hasSuffix("/oauth2/jwks") {
                    state.increment("jwks")
                    return .json(200, signer.jwksJSON())
                }
                if request.uri.contains("/authz/check") {
                    return .json(200, ["allowed": false, "reason_code": "no_grant"])
                }
                return .json(404, [:])
            }
        ) { client, _ in
            let auth = client.makeAuthenticator()

            do {
                _ = try await auth.authenticate(AxiamRequestContext())
                XCTFail("expected rejection")
            } catch let error as AuthError {
                XCTAssertNil(error.challenge)
            }

            let user = try await auth.authenticate(AxiamRequestContext(cookies: ["axiam_access": jwt]))
            XCTAssertEqual(user.userID, "user-42")

            let guards = client.makeGuards()
            let handler = guards.requireAccess("read", resource: "res-1", scope: "mcp:tools")
            do {
                _ = try await handler(AxiamRequestContext(cookies: ["axiam_access": jwt]))
                XCTFail("expected denial")
            } catch let error as AuthzError {
                XCTAssertNil(error.challenge)
            }

            XCTAssertFalse(
                auth.isProtectedResourceMetadataRequest(method: "GET", path: "/.well-known/oauth-protected-resource"))
        }
    }
}
