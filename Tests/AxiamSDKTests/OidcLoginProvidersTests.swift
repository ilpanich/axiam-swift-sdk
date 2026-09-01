import XCTest
import Foundation
@testable import AxiamSDK

/// CONTRACT.md §12.1 — the four public login-provider operations added at contract 1.37, with
/// rule 12a added at 1.38: `sso_providers`, `sso_start_oauth2`, `sso_complete_oauth2` and
/// `sso_complete_handoff`.
///
/// Two halves, deliberately. The first asserts the wire shape against the **vendored
/// `openapi.json`** rather than against a literal in this file: a test that only checks the SDK
/// against its own constant is a tautology that survives a spec change. The second asserts the
/// load-bearing rules — 9 (an empty list is a success and the *only* success), 10 (`protocol`
/// selects the start operation), 11 (no PKCE on the OAuth2 path), 12 (a handoff `401` is
/// terminal) and 12a (a `400` is a configuration error, not a retry).
final class OidcLoginProvidersTests: XCTestCase {

    private static let tenantUUID = "22222222-2222-2222-2222-222222222222"
    private static let orgUUID = "33333333-3333-3333-3333-333333333333"
    private static let configUUID = "44444444-4444-4444-4444-444444444444"

    // MARK: - Harness

    /// Walks up from this source file to the package root, where the vendored artifacts live.
    private func repoRoot() throws -> URL {
        var dir = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()   // AxiamSDKTests
            .deletingLastPathComponent()   // Tests
            .deletingLastPathComponent()   // <root>
        var hops = 0
        while !FileManager.default.fileExists(
            atPath: dir.appendingPathComponent("Package.swift").path) {
            let parent = dir.deletingLastPathComponent()
            hops += 1
            guard parent != dir, hops < 8 else {
                throw XCTSkip("could not locate the package root from \(#filePath)")
            }
            dir = parent
        }
        return dir
    }

    private func openAPI() throws -> [String: Any] {
        let data = try Data(contentsOf: try repoRoot().appendingPathComponent("openapi.json"))
        return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    private func paths() throws -> [String: Any] {
        try XCTUnwrap(try openAPI()["paths"] as? [String: Any])
    }

    private func schema(_ name: String) throws -> [String: Any] {
        let components = try XCTUnwrap(try openAPI()["components"] as? [String: Any])
        let schemas = try XCTUnwrap(components["schemas"] as? [String: Any])
        return try XCTUnwrap(schemas[name] as? [String: Any])
    }

    /// A client whose workspace is configured the way a real login page's would be.
    private func withFederationClient(
        tenantID: String? = OidcLoginProvidersTests.tenantUUID,
        tenantSlug: String? = nil,
        orgID: String? = nil,
        orgSlug: String? = "acme",
        router: @escaping TestRouter,
        body: (AxiamClient, TestHTTPServer) async throws -> Void
    ) async throws {
        try await withClient(
            makeConfig: { port in
                try AxiamConfig(
                    baseURL: URL(string: "http://127.0.0.1:\(port)")!,
                    tenantID: tenantID,
                    tenantSlug: tenantSlug,
                    orgID: orgID,
                    orgSlug: orgSlug,
                    requestTimeout: 10)
            },
            router: router,
            body: body)
    }

    /// One provider entry, as the server serialises it.
    private static func providerJSON(
        id: String = OidcLoginProvidersTests.configUUID,
        kind: String,
        name: String,
        proto: String,
        bundledMark: Bool = true,
        buttonIcon: String? = nil,
        inherited: Bool = false
    ) -> [String: Any] {
        var entry: [String: Any] = [
            "id": id,
            "provider_kind": kind,
            "display_name": name,
            "protocol": proto,
            "has_bundled_mark": bundledMark,
            "inherited": inherited,
        ]
        if let buttonIcon { entry["button_icon"] = buttonIcon }
        return entry
    }

    /// Serves the providers listing with `providers` as its payload, and records the request.
    private static func providersRouter(
        status: Int = 200,
        providers: [[String: Any]],
        rawBody: Data? = nil
    ) -> TestRouter {
        let payload = rawBody ?? TestResponse.jsonBody(["providers": providers])
        return { request, state in
            if request.uri.contains("/api/v1/auth/federation/providers") {
                state.increment("providers")
                return TestResponse(
                    status: status,
                    headers: [("Content-Type", "application/json")],
                    body: payload)
            }
            return TestResponse(status: 404)
        }
    }

    // MARK: - Wire shape, asserted against the vendored openapi.json

    func testProvidersIsAGetWithNoRequestBodyInTheSpec() throws {
        let operation = try XCTUnwrap(
            try paths()["/api/v1/auth/federation/providers"] as? [String: Any])
        XCTAssertEqual(Array(operation.keys), ["get"], "sso_providers is the one §12 GET")
        let get = try XCTUnwrap(operation["get"] as? [String: Any])
        XCTAssertNil(get["requestBody"], "sso_providers carries no request body")
    }

    /// §12.1: the identifiers are **query** parameters here, not a body — the one place in §12
    /// where the workspace does not travel in JSON.
    func testProvidersIdentifiersAreQueryParametersInTheSpec() throws {
        let get = try XCTUnwrap(
            (try paths()["/api/v1/auth/federation/providers"] as? [String: Any])?["get"]
                as? [String: Any])
        let parameters = try XCTUnwrap(get["parameters"] as? [[String: Any]])
        let byName = Dictionary(uniqueKeysWithValues: parameters.compactMap { parameter -> (String, String)? in
            guard let name = parameter["name"] as? String,
                  let location = parameter["in"] as? String else { return nil }
            return (name, location)
        })
        for name in ["org_id", "org_slug", "tenant_id", "tenant_slug"] {
            XCTAssertEqual(byName[name], "query", "\(name) must be a query parameter")
        }
    }

    func testTheThreePostsCarryTheirContractRequestSchemas() throws {
        let expected = [
            "/api/v1/auth/federation/oauth2/start": "OAuth2StartRequest",
            "/api/v1/auth/federation/oauth2/callback": "OAuth2CallbackRequest",
            "/api/v1/auth/federation/handoff": "SsoHandoffRequest",
        ]
        let allPaths = try paths()
        for (path, schemaName) in expected {
            let operation = try XCTUnwrap(allPaths[path] as? [String: Any])
            XCTAssertEqual(Array(operation.keys), ["post"], "\(path) is a POST")
            let post = try XCTUnwrap(operation["post"] as? [String: Any])
            let content = try XCTUnwrap(
                (post["requestBody"] as? [String: Any])?["content"] as? [String: Any])
            XCTAssertEqual(Array(content.keys), ["application/json"],
                           "\(path) is application/json")
            let ref = ((content["application/json"] as? [String: Any])?["schema"]
                as? [String: Any])?["$ref"] as? String
            XCTAssertEqual(ref, "#/components/schemas/\(schemaName)")
        }
    }

    func testTheTwoCompletionsAnswerSsoLoginSuccessResponse() throws {
        let allPaths = try paths()
        for path in ["/api/v1/auth/federation/oauth2/callback",
                     "/api/v1/auth/federation/handoff"] {
            let post = try XCTUnwrap(
                (allPaths[path] as? [String: Any])?["post"] as? [String: Any])
            let responses = try XCTUnwrap(post["responses"] as? [String: Any])
            let content = try XCTUnwrap(
                (responses["200"] as? [String: Any])?["content"] as? [String: Any])
            let ref = ((content["application/json"] as? [String: Any])?["schema"]
                as? [String: Any])?["$ref"] as? String
            XCTAssertEqual(ref, "#/components/schemas/SsoLoginSuccessResponse")
        }
    }

    /// ``FederationProvider`` models every field the schema declares, and `button_icon` is the
    /// one that is optional there and therefore optional here.
    func testFederationProviderModelsTheSchemaFaithfully() throws {
        let provider = try schema("PublicFederationProvider")
        let required = Set(try XCTUnwrap(provider["required"] as? [String]))
        let properties = Set(try XCTUnwrap(provider["properties"] as? [String: Any]).keys)

        XCTAssertEqual(required, ["id", "provider_kind", "display_name", "protocol",
                                  "has_bundled_mark", "inherited"])
        XCTAssertEqual(properties, required.union(["button_icon"]))
        XCTAssertEqual(properties.subtracting(required), ["button_icon"],
                       "button_icon is the only nullable field, and is modelled as optional")

        // And the response wrapper is a single required array.
        let list = try schema("PublicFederationProvidersResponse")
        XCTAssertEqual(try XCTUnwrap(list["required"] as? [String]), ["providers"])
    }

    /// §12.1 note 11: nothing PKCE-shaped is in the OAuth2 start request or response, so the
    /// SDK has nothing to send and nothing to read.
    func testOAuth2StartCarriesNoPkceFieldInEitherDirection() throws {
        let request = try XCTUnwrap(
            try schema("OAuth2StartRequest")["properties"] as? [String: Any])
        let response = try XCTUnwrap(
            try schema("OAuth2StartResponse")["properties"] as? [String: Any])
        for field in ["code_verifier", "code_challenge", "code_challenge_method"] {
            XCTAssertNil(request[field], "\(field) must not appear in OAuth2StartRequest")
            XCTAssertNil(response[field], "\(field) must not appear in OAuth2StartResponse")
        }
    }

    // MARK: - sso_providers on the wire

    func testProvidersSendsIdentifiersInTheQueryStringAndNotTheBody() async throws {
        let router = Self.providersRouter(providers: [
            Self.providerJSON(kind: "google", name: "Google", proto: "OidcConnect"),
        ])
        try await withFederationClient(router: router) { client, server in
            _ = try await client.ssoProviders()
            let sent = try XCTUnwrap(
                server.state.requests(pathContaining: "/federation/providers").first)
            XCTAssertEqual(sent.method, "GET")
            XCTAssertTrue(sent.body.isEmpty, "sso_providers sends no body")
            XCTAssertTrue(sent.uri.contains("tenant_id=\(Self.tenantUUID)"),
                          "the tenant travels as a query parameter: \(sent.uri)")
            XCTAssertTrue(sent.uri.contains("org_slug=acme"),
                          "the org travels as a query parameter: \(sent.uri)")
        }
    }

    /// §5.1, as everywhere else in this SDK: the UUID form wins over the slug form.
    ///
    /// `AxiamConfig` accepts at most one org form, so the two are put in conflict the only
    /// way they can be — a UUID argument against a slug-configured client — which is also
    /// the case a login page actually produces.
    func testProvidersPrefersTheUuidFormOverTheSlugForm() async throws {
        let router = Self.providersRouter(providers: [])
        try await withFederationClient(orgSlug: "acme", router: router) { client, server in
            _ = try await client.ssoProviders(orgID: Self.orgUUID)
            let uri = try XCTUnwrap(
                server.state.requests(pathContaining: "/federation/providers").first).uri
            XCTAssertTrue(uri.contains("org_id=\(Self.orgUUID)"), uri)
            XCTAssertFalse(uri.contains("org_slug"), "the UUID form replaces the slug form")
            // The tenant is UUID-configured, so its own §5.1 pair resolves the same way.
            XCTAssertTrue(uri.contains("tenant_id=\(Self.tenantUUID)"), uri)
            XCTAssertFalse(uri.contains("tenant_slug"), uri)
        }
    }

    /// Call arguments override the client's configured workspace — a login page resolves the
    /// org from what the user typed, not from how the client was built.
    func testProvidersArgumentsOverrideTheConfiguredWorkspace() async throws {
        let router = Self.providersRouter(providers: [])
        try await withFederationClient(orgSlug: "acme", router: router) { client, server in
            _ = try await client.ssoProviders(orgSlug: "typed-by-the-user")
            let uri = try XCTUnwrap(
                server.state.requests(pathContaining: "/federation/providers").first).uri
            XCTAssertTrue(uri.contains("org_slug=typed-by-the-user"), uri)
            XCTAssertFalse(uri.contains("acme"), uri)
        }
    }

    func testProvidersDecodesEveryFieldIncludingTheNullableButtonIcon() async throws {
        let icon = "data:image/png;base64,iVBORw0KGgo="
        let router = Self.providersRouter(providers: [
            Self.providerJSON(kind: "google", name: "Google", proto: "OidcConnect",
                              bundledMark: true, buttonIcon: nil, inherited: true),
            Self.providerJSON(id: "55555555-5555-5555-5555-555555555555",
                              kind: "generic_oauth2", name: "Acme SSO", proto: "OAuth2",
                              bundledMark: false, buttonIcon: icon, inherited: false),
        ])
        try await withFederationClient(router: router) { client, _ in
            let providers = try await client.ssoProviders()
            XCTAssertEqual(providers.count, 2)

            XCTAssertEqual(providers[0].providerKind, "google")
            XCTAssertEqual(providers[0].displayName, "Google")
            XCTAssertEqual(providers[0].`protocol`, FederationProvider.protocolOidcConnect)
            XCTAssertTrue(providers[0].hasBundledMark)
            XCTAssertNil(providers[0].buttonIcon, "absent for most providers")
            XCTAssertTrue(providers[0].inherited, "§12.1 note 13, resolved server-side")

            XCTAssertEqual(providers[1].id, "55555555-5555-5555-5555-555555555555")
            XCTAssertEqual(providers[1].`protocol`, FederationProvider.protocolOAuth2)
            XCTAssertFalse(providers[1].hasBundledMark)
            XCTAssertEqual(providers[1].buttonIcon, icon)
            XCTAssertFalse(providers[1].inherited)
        }
    }

    /// A protocol this SDK does not know must not fail the decode of the whole list — which is
    /// why ``FederationProvider/protocol`` is a `String` and not a closed enum.
    func testProvidersKeepsAnUnknownProtocolRatherThanFailingTheList() async throws {
        let router = Self.providersRouter(providers: [
            Self.providerJSON(kind: "google", name: "Google", proto: "OidcConnect"),
            Self.providerJSON(kind: "future_kind", name: "Later", proto: "SomethingNewer"),
        ])
        try await withFederationClient(router: router) { client, _ in
            let providers = try await client.ssoProviders()
            XCTAssertEqual(providers.count, 2)
            XCTAssertEqual(providers[1].`protocol`, "SomethingNewer")
        }
    }

    // MARK: - §12.1 note 9 — an empty list is a success, and the only success

    func testEmptyListIsASuccessForAnUnknownOrganization() async throws {
        let router = Self.providersRouter(providers: [])
        try await withFederationClient(orgSlug: "no-such-org", router: router) { client, _ in
            let providers = try await client.ssoProviders()
            XCTAssertTrue(providers.isEmpty,
                          "an unknown org answers 200 [] and MUST NOT become a not-found error")
        }
    }

    func testEmptyListIsASuccessForAKnownOrganizationWithNoProviders() async throws {
        let router = Self.providersRouter(providers: [])
        try await withFederationClient(router: router) { client, _ in
            let providers = try await client.ssoProviders()
            XCTAssertTrue(providers.isEmpty)
        }
    }

    /// The third arm, and the one an SDK is most tempted to get wrong: naming **no** workspace
    /// at all is still a request, still a `200`, and still an empty list. A client-side refusal
    /// here would restore exactly the two-valued oracle note 9 removes.
    func testProvidersWithNoWorkspaceAtAllStillReachesTheWireAndSucceeds() async throws {
        let router = Self.providersRouter(providers: [])
        // §5 makes a tenant identifier non-optional in `AxiamConfig`, so the narrowest a
        // request can get here is "no organization named at all" — which is exactly the arm
        // note 9 calls out, and the one a login page hits before the user has typed a slug.
        try await withFederationClient(orgID: nil, orgSlug: nil, router: router) { client, server in
            let providers = try await client.ssoProviders()
            XCTAssertTrue(providers.isEmpty)
            XCTAssertEqual(server.state.count("providers"), 1,
                           "the call must reach the wire, not be refused client-side")
            let uri = try XCTUnwrap(
                server.state.requests(pathContaining: "/federation/providers").first).uri
            XCTAssertFalse(uri.contains("org_"), "nothing is invented for a missing org: \(uri)")
        }
    }

    /// The three cases above are indistinguishable by construction: same status, same body.
    func testTheThreeEmptyCasesAreIndistinguishable() async throws {
        let router = Self.providersRouter(providers: [])
        let slugs: [String?] = ["no-such-org", "acme", nil]
        for slug in slugs {
            try await withFederationClient(orgSlug: slug, router: router) { client, server in
                let providers = try await client.ssoProviders()
                XCTAssertTrue(providers.isEmpty, "org_slug=\(slug ?? "<none>")")
                XCTAssertEqual(server.state.count("providers"), 1,
                               "every arm is one request answering 200 []")
            }
        }
    }

    /// A non-2xx is still an error, though: note 9 makes the *empty list* a success, not every
    /// answer the endpoint can give.
    func testProvidersStillMapsANon2xxThroughTheSection2Taxonomy() async throws {
        let router = Self.providersRouter(status: 503, providers: [])
        try await withFederationClient(router: router) { client, _ in
            do {
                _ = try await client.ssoProviders()
                XCTFail("a 503 is not an empty list")
            } catch let error as AxiamError {
                guard case .network = error else { return XCTFail("expected a NetworkError") }
            }
        }
    }

    func testProvidersSurfacesAMalformedBodyAsANetworkError() async throws {
        let router = Self.providersRouter(
            providers: [], rawBody: Data("{\"providers\":\"not-a-list\"}".utf8))
        try await withFederationClient(router: router) { client, _ in
            do {
                _ = try await client.ssoProviders()
                XCTFail("a malformed providers list is not a success")
            } catch let error as AxiamError {
                guard case .network = error else { return XCTFail("expected a NetworkError") }
            }
        }
    }

    // MARK: - §12.1 note 10 — `protocol` selects the start operation

    /// All three branches, dispatched on `protocol` alone. The `Saml` entry deliberately has a
    /// `provider_kind` of `google`: an SDK that guessed from the kind would send it to
    /// `sso_start` and be refused with `400`.
    func testProtocolSelectsTheStartOperationAndProviderKindNeverDoes() async throws {
        let router = Self.providersRouter(providers: [
            Self.providerJSON(id: "11111111-1111-1111-1111-111111111111",
                              kind: "google", name: "Google", proto: "OidcConnect"),
            Self.providerJSON(id: "22222222-0000-0000-0000-000000000002",
                              kind: "github", name: "GitHub", proto: "OAuth2"),
            Self.providerJSON(id: "33333333-0000-0000-0000-000000000003",
                              kind: "google", name: "Google Workspace SAML", proto: "Saml"),
        ])
        try await withFederationClient(router: router) { client, _ in
            let providers = try await client.ssoProviders()
            XCTAssertEqual(providers.count, 3)

            // The dispatch a login page performs, written out so all three arms are covered.
            var routed: [String] = []
            for provider in providers {
                switch provider.`protocol` {
                case FederationProvider.protocolOidcConnect: routed.append("sso_start")
                case FederationProvider.protocolOAuth2: routed.append("sso_start_oauth2")
                case FederationProvider.protocolSaml: routed.append("saml_login")
                default: routed.append("unsupported")
                }
            }
            XCTAssertEqual(routed, ["sso_start", "sso_start_oauth2", "saml_login"])

            // The third entry's kind is `google`; only its protocol says SAML.
            XCTAssertEqual(providers[2].providerKind, "google")
            XCTAssertEqual(providers[2].`protocol`, FederationProvider.protocolSaml)
        }
    }

    func testTheThreeProtocolConstantsAreTheContractStrings() {
        XCTAssertEqual(FederationProvider.protocolOidcConnect, "OidcConnect")
        XCTAssertEqual(FederationProvider.protocolOAuth2, "OAuth2")
        XCTAssertEqual(FederationProvider.protocolSaml, "Saml")
    }

    // MARK: - sso_start_oauth2

    func testStartOauth2PostsToItsOwnPathAndCarriesNoPkce() async throws {
        let body = TestResponse.jsonBody([
            "authorize_url": "https://github.com/login/oauth/authorize?state=s",
            "state": "the-state",
            "expires_in_secs": 300,
        ])
        let router: TestRouter = { request, state in
            guard request.uri.contains("/api/v1/auth/federation/oauth2/start") else {
                return TestResponse(status: 404)
            }
            state.increment("start")
            return TestResponse(
                status: 200, headers: [("Content-Type", "application/json")], body: body)
        }
        try await withFederationClient(router: router) { client, server in
            let result = try await client.ssoStartOauth2(
                federationConfigID: Self.configUUID, redirectURI: "https://app.test/cb")
            XCTAssertEqual(result.state, "the-state")
            XCTAssertEqual(result.expiresInSecs, 300)
            XCTAssertTrue(result.authorizeURL.hasPrefix("https://github.com/"))

            let sent = try XCTUnwrap(server.state.requests(pathContaining: "/oauth2/start").first)
            XCTAssertEqual(sent.method, "POST")
            XCTAssertEqual(sent.header("Content-Type"), "application/json")
            let json = try XCTUnwrap(
                JSONSerialization.jsonObject(with: sent.body) as? [String: Any])
            XCTAssertEqual(json["federation_config_id"] as? String, Self.configUUID)
            XCTAssertEqual(json["redirect_uri"] as? String, "https://app.test/cb")
            XCTAssertEqual(json["tenant_id"] as? String, Self.tenantUUID, "§5.1 in the body")
            // §12.1 note 11: PKCE is generated and held server-side. The SDK sends none.
            for field in ["code_verifier", "code_challenge", "code_challenge_method"] {
                XCTAssertNil(json[field], "\(field) must never be sent on this path")
            }
        }
    }

    /// §12.1 note 8 — these endpoints are unauthenticated, so a first call sends no CSRF header
    /// rather than inventing one.
    func testStartOauth2SendsNoCsrfHeaderOnAFirstCall() async throws {
        let body = TestResponse.jsonBody([
            "authorize_url": "https://github.com/login/oauth/authorize",
            "state": "s", "expires_in_secs": 300,
        ])
        let router: TestRouter = { _, _ in
            TestResponse(status: 200, headers: [("Content-Type", "application/json")], body: body)
        }
        try await withFederationClient(router: router) { client, server in
            _ = try await client.ssoStartOauth2(
                federationConfigID: Self.configUUID, redirectURI: "https://app.test/cb")
            let sent = try XCTUnwrap(server.state.requests(pathContaining: "/oauth2/start").first)
            XCTAssertNil(sent.header("X-CSRF-Token"))
        }
    }

    /// §12.1 rule 12a. A `400` means the deployment does not accept this `redirect_uri`'s
    /// origin; §2 puts that in ``NetworkError`` — the configuration/programming-error member —
    /// and it is **not** the ``AuthError`` a `401` gets, and not retried.
    func testStartOauth2SurfacesA400AsAConfigurationErrorAndDoesNotRetryIt() async throws {
        let router: TestRouter = { _, state in
            state.increment("start")
            return TestResponse.json(400, ["error": "redirect_uri origin is not permitted"])
        }
        try await withFederationClient(router: router) { client, server in
            do {
                _ = try await client.ssoStartOauth2(
                    federationConfigID: Self.configUUID,
                    redirectURI: "https://attacker.test/cb")
                XCTFail("a rejected redirect_uri origin must not look like success")
            } catch let error as AxiamError {
                guard case .network(let networkError) = error else {
                    return XCTFail("rule 12a: a 400 is the taxonomy's configuration error")
                }
                XCTAssertEqual(networkError.statusCode, 400)
            }
            XCTAssertEqual(server.state.count("start"), 1, "rule 12a: never retried")
        }
    }

    /// The same `400`'s companion: a `401` is an ``AuthError``. Asserting both keeps rule 12a's
    /// distinction from collapsing into "any federation failure".
    func testStartOauth2MapsA401ToAnAuthErrorNotAConfigurationError() async throws {
        let router: TestRouter = { _, _ in TestResponse.json(401, ["error": "unknown workspace"]) }
        try await withFederationClient(router: router) { client, _ in
            do {
                _ = try await client.ssoStartOauth2(
                    federationConfigID: Self.configUUID, redirectURI: "https://app.test/cb")
                XCTFail("expected the uniform 401")
            } catch let error as AxiamError {
                guard case .auth = error else { return XCTFail("a 401 is an AuthError") }
            }
        }
    }

    func testStartOauth2SurfacesAMalformedBodyAsANetworkError() async throws {
        let router: TestRouter = { _, _ in
            TestResponse(status: 200, headers: [("Content-Type", "application/json")],
                         body: Data("{\"state\":\"s\"}".utf8))
        }
        try await withFederationClient(router: router) { client, _ in
            do {
                _ = try await client.ssoStartOauth2(
                    federationConfigID: Self.configUUID, redirectURI: "https://app.test/cb")
                XCTFail("a response missing authorize_url is not a success")
            } catch let error as AxiamError {
                guard case .network = error else { return XCTFail("expected a NetworkError") }
            }
        }
    }

    // MARK: - sso_complete_oauth2

    private static func sessionRouter(
        path: String,
        status: Int = 200,
        counterKey: String
    ) -> TestRouter {
        let body = TestResponse.jsonBody([
            "user_id": "66666666-6666-6666-6666-666666666666",
            "session_id": "77777777-7777-7777-7777-777777777777",
            "expires_in": 3600,
            "redirect_uri": "https://app.test/dashboard",
        ])
        return { request, state in
            guard request.uri.contains(path) else { return TestResponse(status: 404) }
            state.increment(counterKey)
            if status != 200 {
                return TestResponse.json(status, ["error": "no"])
            }
            return TestResponse(
                status: 200,
                headers: [
                    ("Content-Type", "application/json"),
                    ("Set-Cookie", "axiam_session=abc; Path=/; HttpOnly"),
                ],
                body: body)
        }
    }

    func testCompleteOauth2PostsStateAndCodeAndLandsTheSessionCookie() async throws {
        let router = Self.sessionRouter(
            path: "/api/v1/auth/federation/oauth2/callback", counterKey: "callback")
        try await withFederationClient(router: router) { client, server in
            let result = try await client.ssoCompleteOauth2(code: "the-code", state: "the-state")
            XCTAssertEqual(result.userID, "66666666-6666-6666-6666-666666666666")
            XCTAssertEqual(result.sessionID, "77777777-7777-7777-7777-777777777777")
            XCTAssertEqual(result.expiresIn, 3600)
            XCTAssertEqual(result.redirectURI, "https://app.test/dashboard")

            let sent = try XCTUnwrap(
                server.state.requests(pathContaining: "/oauth2/callback").first)
            XCTAssertEqual(sent.method, "POST")
            XCTAssertEqual(sent.header("Content-Type"), "application/json")
            let json = try XCTUnwrap(
                JSONSerialization.jsonObject(with: sent.body) as? [String: Any])
            XCTAssertEqual(json as? [String: String], ["code": "the-code", "state": "the-state"])

            // §12.1 note 6: the session is the Set-Cookie, not anything in the body.
            let cookie = await client._cookieValue("axiam_session")
            XCTAssertEqual(cookie, "abc")
        }
    }

    func testCompleteOauth2MapsA401ToAnAuthError() async throws {
        let router = Self.sessionRouter(
            path: "/api/v1/auth/federation/oauth2/callback", status: 401, counterKey: "callback")
        try await withFederationClient(router: router) { client, _ in
            do {
                _ = try await client.ssoCompleteOauth2(code: "c", state: "s")
                XCTFail("an expired state is not a success")
            } catch let error as AxiamError {
                guard case .auth = error else { return XCTFail("a 401 is an AuthError") }
            }
        }
    }

    func testCompleteOauth2SurfacesAMalformedBodyAsANetworkError() async throws {
        let router: TestRouter = { _, _ in
            TestResponse(status: 200, headers: [("Content-Type", "application/json")],
                         body: Data("{\"user_id\":\"u\"}".utf8))
        }
        try await withFederationClient(router: router) { client, _ in
            do {
                _ = try await client.ssoCompleteOauth2(code: "c", state: "s")
                XCTFail("a response missing session_id is not a success")
            } catch let error as AxiamError {
                guard case .network = error else { return XCTFail("expected a NetworkError") }
            }
        }
    }

    // MARK: - sso_complete_handoff, and §12.1 note 12

    func testCompleteHandoffPostsOnlyTheCodeAndLandsTheSessionCookie() async throws {
        let router = Self.sessionRouter(
            path: "/api/v1/auth/federation/handoff", counterKey: "handoff")
        try await withFederationClient(router: router) { client, server in
            let result = try await client.ssoCompleteHandoff(code: "the-handoff-code")
            XCTAssertEqual(result.sessionID, "77777777-7777-7777-7777-777777777777")

            let sent = try XCTUnwrap(
                server.state.requests(pathContaining: "/federation/handoff").first)
            XCTAssertEqual(sent.method, "POST")
            let json = try XCTUnwrap(
                JSONSerialization.jsonObject(with: sent.body) as? [String: Any])
            XCTAssertEqual(json as? [String: String], ["code": "the-handoff-code"],
                           "the code is the whole request; no state, no workspace")

            let cookie = await client._cookieValue("axiam_session")
            XCTAssertEqual(cookie, "abc")
        }
    }

    /// §12.1 note 12: unknown, expired and already-redeemed all answer the same `401`, and the
    /// code is gone either way — so the `401` is terminal and the redemption is issued **once**.
    func testHandoff401IsTerminalAndTheRedemptionIsNeverRetried() async throws {
        let router = Self.sessionRouter(
            path: "/api/v1/auth/federation/handoff", status: 401, counterKey: "handoff")
        try await withFederationClient(router: router) { client, server in
            do {
                _ = try await client.ssoCompleteHandoff(code: "spent-code")
                XCTFail("a spent handoff code must not look like a session")
            } catch let error as AxiamError {
                guard case .auth = error else { return XCTFail("a 401 is an AuthError") }
            }
            XCTAssertEqual(server.state.count("handoff"), 1,
                           "note 12: a failed redemption is never retried")
        }
    }

    func testHandoffConstantsAreTheContractValues() {
        XCTAssertEqual(FederationHandoff.queryParameter, "axiam_handoff")
        XCTAssertEqual(FederationHandoff.codeTTLSeconds, 60)
    }

    // MARK: - §12.3 cross-cutting rules, applied to the new operations

    /// §18.1 rule 4: a closed client refuses, and refuses before reaching the wire.
    func testAllFourOperationsRefuseOnAClosedClient() async throws {
        let router = Self.providersRouter(providers: [])
        let server = TestHTTPServer(router: router)
        let port = try server.start()
        defer { server.stop() }
        let client = try AxiamClient(config: AxiamConfig(
            baseURL: URL(string: "http://127.0.0.1:\(port)")!,
            tenantID: Self.tenantUUID,
            requestTimeout: 10))
        try await client.shutdown()

        func expectRefusal(_ label: String, _ operation: () async throws -> Void) async {
            do {
                try await operation()
                XCTFail("\(label): a closed client must refuse (§18.1 rule 4)")
            } catch let error as AxiamError {
                guard case .network = error else {
                    return XCTFail("\(label): expected a NetworkError")
                }
            } catch {
                XCTFail("\(label): expected an AxiamError, got \(error)")
            }
        }

        await expectRefusal("ssoProviders") { _ = try await client.ssoProviders() }
        await expectRefusal("ssoStartOauth2") {
            _ = try await client.ssoStartOauth2(federationConfigID: "c", redirectURI: "u")
        }
        await expectRefusal("ssoCompleteOauth2") {
            _ = try await client.ssoCompleteOauth2(code: "c", state: "s")
        }
        await expectRefusal("ssoCompleteHandoff") {
            _ = try await client.ssoCompleteHandoff(code: "c")
        }
        XCTAssertEqual(server.state.count("providers"), 0, "nothing reaches the wire")
    }

    /// §12.3 rule 1: this SDK stores none of §12's results. Two calls produce two requests —
    /// there is no provider-list cache to go stale against a workspace switch.
    func testProvidersIsNotCached() async throws {
        let router = Self.providersRouter(providers: [])
        try await withFederationClient(router: router) { client, server in
            _ = try await client.ssoProviders()
            _ = try await client.ssoProviders()
            XCTAssertEqual(server.state.count("providers"), 2)
        }
    }
}
