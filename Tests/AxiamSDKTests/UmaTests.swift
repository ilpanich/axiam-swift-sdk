import XCTest
@testable import AxiamSDK

/// UMA 2.0 — CONTRACT.md §20.7 required assertions.
///
/// Most of §20 is a list of things an SDK must *not* helpfully do, so most of these tests assert
/// an absence. The centrepiece is §20.2 rule 6: **a permission ticket is never retried.**
///
/// That rule is the one documented exception to §16, and the only way to assert it is to count
/// requests. A ticket is consumed *before* the exchange is evaluated, so a failed exchange has
/// already spent it — and under concurrency a retry is precisely the concurrent redemption a
/// server whose storage engine this SDK cannot attest may admit twice (`ilpanich/axiam#302`).
/// "Exactly one request" is a security assertion here, not a performance one.
final class UmaTests: XCTestCase {

    private static let pat = "pat-token-value"
    private static let ticket = "ticket-value"
    private static let claimToken = "claim-token-value"
    private static let rpt = "rpt-token-value"
    private static let resourceID = "99999999-8888-7777-6666-555555555555"
    private static let tenantUUID = "22222222-2222-2222-2222-222222222222"

    private func makeClient(_ transport: UmaTransport) throws -> AxiamClient {
        let config = try AxiamConfig(baseURL: URL(string: "https://api.test")!, tenantID: Self.tenantUUID)
        return AxiamClient(config: config, transport: transport)
    }

    private static func credentials() -> UmaClientCredentials {
        UmaClientCredentials(clientID: "orders-resource-server", clientSecret: Sensitive("resource-server-secret"))
    }

    // MARK: - §20.1 the Protection API

    func testRegistrationRoundTripsAndTheIDIsUsableAsATicketResourceID() async throws {
        let transport = UmaTransport()
        transport.rregResponse = .json(201, [
            "_id": Self.resourceID, "name": "invoice-7", "type": "document", "resource_scopes": ["view"],
        ])
        transport.permResponse = .json(201, ["ticket": Self.ticket])
        let client = try makeClient(transport)

        let registered = try await client.umaRegisterResource(
            pat: Sensitive(Self.pat), name: "invoice-7", type: "document", resourceScopes: ["view"])
        XCTAssertEqual(registered.id, Self.resourceID)

        // §20.1: `_id` IS the AXIAM resource id, not a parallel identifier — it goes straight back
        // out as a requested permission with no translation step.
        let ticket = try await client.umaRequestTicket(
            pat: Sensitive(Self.pat),
            permissions: [UmaRequestedPermission(resourceID: registered.id!, resourceScopes: ["view"])])

        XCTAssertEqual(ticket.wrapped, Self.ticket)
        let sent = try XCTUnwrap(transport.jsonBody(forPathSuffix: "/uma2/perm") as? [[String: Any]])
        XCTAssertEqual(sent.first?["resource_id"] as? String, Self.resourceID)
    }

    func testAnOmittedTypeIsLeftOutRatherThanSentEmpty() async throws {
        let transport = UmaTransport()
        transport.rregResponse = .json(201, ["_id": Self.resourceID, "name": "invoice-7", "resource_scopes": ["view"]])
        let client = try makeClient(transport)

        _ = try await client.umaRegisterResource(pat: Sensitive(Self.pat), name: "invoice-7", resourceScopes: ["view"])

        // §12.1: an absent optional field is omitted, never sent empty — here so the server applies
        // its own `uma_resource` default rather than storing "".
        let sent = try XCTUnwrap(transport.jsonBody(forPathSuffix: "/uma2/rreg/resource_set") as? [String: Any])
        XCTAssertNil(sent["type"])
    }

    func testAnUpdateSendsExactlyTheScopesGivenWithNoReadFirst() async throws {
        let transport = UmaTransport()
        transport.rregResponse = .json(200, [
            "_id": Self.resourceID, "name": "invoice-7", "type": "document", "resource_scopes": ["view"],
        ])
        let client = try makeClient(transport)

        _ = try await client.umaUpdateResource(
            pat: Sensitive(Self.pat), id: Self.resourceID, name: "invoice-7", type: "document",
            resourceScopes: ["view"])

        // §20.2 rule 8: the update replaces the scope list. A read-modify-write would show up here
        // as a second rreg call, and would silently make removing a scope impossible through the
        // SDK.
        XCTAssertEqual(transport.count(pathSuffix: "/uma2/rreg/resource_set/\(Self.resourceID)"), 1)
        XCTAssertEqual(transport.methods(forPathSuffix: "/uma2/rreg/resource_set/\(Self.resourceID)"), ["PUT"])
        let sent = try XCTUnwrap(
            transport.jsonBody(forPathSuffix: "/uma2/rreg/resource_set/\(Self.resourceID)") as? [String: Any])
        XCTAssertEqual(sent["resource_scopes"] as? [String], ["view"])
    }

    func testAnUndeclaredScopeSurfacesThe400Unchanged() async throws {
        let transport = UmaTransport()
        transport.permResponse = .json(400, ["message": "scope not declared on resource"])
        let client = try makeClient(transport)

        do {
            _ = try await client.umaRequestTicket(
                pat: Sensitive(Self.pat),
                permissions: [UmaRequestedPermission(resourceID: Self.resourceID, resourceScopes: ["delete"])])
            XCTFail("expected the 400 to surface")
        } catch AxiamError.network {
            // §2: a 400 is a NetworkError, and §20.4 leaves it there.
        }
        XCTAssertEqual(transport.count(pathSuffix: "/uma2/perm"), 1)
    }

    func testATokenThatIsNotAPATSurfacesTheServers403() async throws {
        let transport = UmaTransport()
        transport.permResponse = .json(403, [
            "error": "authorization_denied",
            "message": "the protection API requires the 'uma_protection' scope",
        ])
        let client = try makeClient(transport)

        // §20.2 rule 1: a user access token is not a PAT. The SDK does not pre-judge the token's
        // subject kind — it lets the server's refusal through as an AuthzError, the §2 mapping for
        // a 403, rather than an OAuth2 protocol error (those rows belong to the token endpoint).
        do {
            _ = try await client.umaRequestTicket(
                pat: Sensitive("a-user-token"),
                permissions: [UmaRequestedPermission(resourceID: Self.resourceID, resourceScopes: ["view"])])
            XCTFail("expected the 403 to surface")
        } catch AxiamError.authz {
            // expected
        }
    }

    func testTheProtectionApiCarriesThePATAndNoSessionCookie() async throws {
        let transport = UmaTransport()
        transport.rregResponse = .json(200, [Self.resourceID])
        let client = try makeClient(transport)

        let ids = try await client.umaListResources(pat: Sensitive(Self.pat))

        XCTAssertEqual(ids, [Self.resourceID])
        // §20.2 rule 1: a minted ticket is bound to the client_id that minted it, so the
        // Protection API credential is the caller's explicit PAT — and nothing else rides along.
        let headers = transport.headers(forPathSuffix: "/uma2/rreg/resource_set")
        XCTAssertEqual(headers["authorization"], "Bearer \(Self.pat)")
        XCTAssertNil(headers["cookie"])
    }

    func testAnEmptyPATIsRefusedClientSideWithNoWireCall() async throws {
        let transport = UmaTransport()
        let client = try makeClient(transport)

        do {
            try await client.umaDeleteResource(pat: Sensitive(""), id: Self.resourceID)
            XCTFail("expected an AuthError")
        } catch AxiamError.auth {
            // An omitted PAT must not become "send it with whatever credential is lying around".
        }
        XCTAssertEqual(transport.count(pathSuffix: "/uma2/rreg/resource_set/\(Self.resourceID)"), 0)
    }

    func testReadAndDeleteUseTheirOwnMethods() async throws {
        let transport = UmaTransport()
        transport.rregResponse = .json(200, [
            "_id": Self.resourceID, "name": "invoice-7", "type": "document",
            "resource_scopes": ["view", "edit"],
        ])
        let client = try makeClient(transport)

        let resource = try await client.umaReadResource(pat: Sensitive(Self.pat), id: Self.resourceID)
        // §20.6: scopes and the resource id are NOT sensitive and must stay readable — an
        // application cannot act on a resource it may not inspect.
        XCTAssertEqual(resource.resourceScopes, ["view", "edit"])

        transport.rregResponse = .empty(204)
        try await client.umaDeleteResource(pat: Sensitive(Self.pat), id: Self.resourceID)

        XCTAssertEqual(
            transport.methods(forPathSuffix: "/uma2/rreg/resource_set/\(Self.resourceID)"), ["GET", "DELETE"])
    }

    func testDiscoveryIsFetchedOnceAndCached() async throws {
        let transport = UmaTransport()
        transport.rregResponse = .json(200, [Self.resourceID])
        let client = try makeClient(transport)

        _ = try await client.umaListResources(pat: Sensitive(Self.pat))
        _ = try await client.umaListResources(pat: Sensitive(Self.pat))

        // An endpoint map is not a credential; re-fetching it per guarded request is a
        // self-inflicted round trip.
        XCTAssertEqual(transport.count(pathSuffix: "/.well-known/uma2-configuration"), 1)
    }

    // MARK: - §20.2 rule 6 — the ticket grant is never retried

    func testTheTicketGrantIsNotRetriedOnA5xx() async throws {
        let transport = UmaTransport()
        transport.tokenResponse = .empty(500)
        let client = try makeClient(transport)

        do {
            _ = try await client.umaExchangeTicket(
                ticket: Sensitive(Self.ticket), claimToken: Sensitive(Self.claimToken),
                credentials: Self.credentials())
            XCTFail("expected the 500 to surface")
        } catch {
            // expected
        }

        XCTAssertEqual(
            transport.count(pathSuffix: "/oauth2/token"), 1,
            "the ticket grant must issue exactly one request — retrying a spent ticket is the "
            + "concurrent redemption ilpanich/axiam#302 describes")
    }

    func testTheTicketGrantIsNotRetriedOnATransportFailure() async throws {
        let transport = UmaTransport()
        transport.tokenResponse = .failure
        let client = try makeClient(transport)

        do {
            _ = try await client.umaExchangeTicket(
                ticket: Sensitive(Self.ticket), claimToken: Sensitive(Self.claimToken),
                credentials: Self.credentials())
            XCTFail("expected the transport failure to surface")
        } catch {
            // expected
        }

        // §20.2 rule 6 names the timeout explicitly: a request that never answered may well have
        // reached the server and spent the ticket. Silence is not evidence it did not.
        XCTAssertEqual(transport.count(pathSuffix: "/oauth2/token"), 1)
    }

    func testTheTicketGrantIsNotRetriedOnInvalidGrant() async throws {
        let transport = UmaTransport()
        transport.tokenResponse = .json(400, [
            "error": "invalid_grant",
            "error_description": "permission ticket is invalid, expired, or already used",
        ])
        let client = try makeClient(transport)

        do {
            _ = try await client.umaExchangeTicket(
                ticket: Sensitive(Self.ticket), claimToken: Sensitive(Self.claimToken),
                credentials: Self.credentials())
            XCTFail("expected invalid_grant to surface")
        } catch AxiamError.auth(let error) {
            // §20.4: unknown, expired, already-used and wrong-client all collapse into this one
            // code, and the SDK must not re-derive which — the server withheld the distinction
            // because it lets a caller probe for live ticket handles.
            XCTAssertEqual(error.oauthError, "invalid_grant")
        }
        XCTAssertEqual(transport.count(pathSuffix: "/oauth2/token"), 1)
    }

    func testA403AccessDeniedIsSurfacedAsItselfAndNotAutoNarrowed() async throws {
        let transport = UmaTransport()
        transport.tokenResponse = .json(403, [
            "error": "access_denied",
            "error_description": "the requesting party is not authorized for every requested permission",
        ])
        let client = try makeClient(transport)

        do {
            _ = try await client.umaExchangeTicket(
                ticket: Sensitive(Self.ticket), claimToken: Sensitive(Self.claimToken),
                credentials: Self.credentials())
            XCTFail("expected access_denied to surface")
        } catch AxiamError.auth(let error) {
            // §20.4: access_denied answers HTTP 403 here where RFC 8628's answers 400. Dispatching
            // on the `error` field rather than the status is what keeps this correct — a
            // status-driven mapper would have produced an AuthzError with no code to read.
            XCTAssertEqual(error.oauthError, "access_denied")
        }

        // §20.2 rule 3: a partial grant is refused whole. Whether two-of-three permissions is
        // useful is the application's judgement, not this SDK's.
        XCTAssertEqual(
            transport.count(pathSuffix: "/oauth2/token"), 1,
            "a refused ticket must not be re-requested with fewer scopes")
    }

    func testANonOAuth2ErrorBodyStillGetsTheStatusMapping() async throws {
        let transport = UmaTransport()
        transport.tokenResponse = .raw(502, Data("<html>gateway</html>".utf8))
        let client = try makeClient(transport)

        do {
            _ = try await client.umaExchangeTicket(
                ticket: Sensitive(Self.ticket), claimToken: Sensitive(Self.claimToken),
                credentials: Self.credentials())
            XCTFail("expected the 502 to surface")
        } catch AxiamError.network {
            // The widened `error`-field dispatch must not turn a proxy's HTML 502 into an
            // authentication error with an empty code.
        }
    }

    // MARK: - §20.1/§20.2 — what the grant sends, and what the result is not

    func testTheTicketGrantSendsTheRequiredClaimTokenAndItsFormat() async throws {
        let transport = UmaTransport()
        transport.tokenResponse = .json(200, [
            "access_token": Self.rpt, "token_type": "Bearer", "expires_in": 300,
        ])
        let client = try makeClient(transport)

        let rpt = try await client.umaExchangeTicket(
            ticket: Sensitive(Self.ticket), claimToken: Sensitive(Self.claimToken),
            credentials: Self.credentials())

        let form = transport.formBody(forPathSuffix: "/oauth2/token")
        XCTAssertEqual(form["grant_type"], "urn:ietf:params:oauth:grant-type:uma-ticket")
        XCTAssertEqual(form["ticket"], Self.ticket)
        // §20.2 rule 2: required, never defaulted — it is the only channel that names the
        // requesting party, and defaulting it to the resource server's own PAT would mint an RPT
        // for the resource server instead of for the user.
        XCTAssertEqual(form["claim_token"], Self.claimToken)
        XCTAssertEqual(form["claim_token_format"], "urn:ietf:params:oauth:token-type:access_token")
        // A token-endpoint grant: the client authenticates through the body.
        XCTAssertEqual(form["client_secret"], "resource-server-secret")
        // §12.1 note 2, which §20.1 applies to this grant unchanged.
        XCTAssertTrue(transport.paths.contains { $0.contains("tenant_id=\(Self.tenantUUID)") })

        XCTAssertEqual(rpt.accessToken.wrapped, Self.rpt)
        XCTAssertEqual(rpt.expiresIn, 300)
    }

    func testAnAbsentClaimTokenIsRefusedClientSideWithNoWireCall() async throws {
        let transport = UmaTransport()
        let client = try makeClient(transport)

        do {
            _ = try await client.umaExchangeTicket(
                ticket: Sensitive(Self.ticket), claimToken: Sensitive(""), credentials: Self.credentials())
            XCTFail("expected an AuthError")
        } catch AxiamError.auth {
            // Refusing client-side keeps the ticket unspent for a request that could not have
            // succeeded (§20.2 rules 2 and 6 together).
        }
        XCTAssertEqual(transport.count(pathSuffix: "/oauth2/token"), 0)
    }

    func testATenantSlugCannotBeSubstitutedForTheTenantUUID() async throws {
        let transport = UmaTransport()
        let config = try AxiamConfig(baseURL: URL(string: "https://api.test")!, tenantSlug: "acme")
        let client = AxiamClient(config: config, transport: transport)

        do {
            _ = try await client.umaExchangeTicket(
                ticket: Sensitive(Self.ticket), claimToken: Sensitive(Self.claimToken),
                credentials: Self.credentials())
            XCTFail("expected an AuthError")
        } catch AxiamError.auth {
            // §12.3 rule 4: the query parameter is a UUID and a slug is not one. Failing here
            // rather than on the wire is what keeps the ticket unspent.
        }
        XCTAssertEqual(transport.count(pathSuffix: "/oauth2/token"), 0)
    }

    func testTheResultHasNoRefreshTokenEvenWhenTheServerSendsOne() async throws {
        let transport = UmaTransport()
        // Deliberately hostile fixture: the grant issues no refresh token, so the result type has
        // no property for one and there is nothing to synthesise.
        transport.tokenResponse = .json(200, [
            "access_token": Self.rpt, "token_type": "Bearer", "expires_in": 300,
            "refresh_token": "should-not-exist",
        ])
        let client = try makeClient(transport)

        let rpt = try await client.umaExchangeTicket(
            ticket: Sensitive(Self.ticket), claimToken: Sensitive(Self.claimToken),
            credentials: Self.credentials())

        XCTAssertFalse("\(rpt)".contains("should-not-exist"))
    }

    // MARK: - §20.3 the challenge helpers

    func testParsesAWellFormedChallenge() {
        let challenge = AxiamClient.umaParseChallenge(
            "UMA realm=\"example\", as_uri=\"https://id.example\", ticket=\"\(Self.ticket)\"")

        XCTAssertEqual(challenge?.realm, "example")
        XCTAssertEqual(challenge?.asURI, "https://id.example")
        XCTAssertEqual(challenge?.ticket?.wrapped, Self.ticket)
    }

    func testRejectsASchemeThatMerelyStartsWithUMA() {
        XCTAssertNil(AxiamClient.umaParseChallenge("Bearer realm=\"example\""))
        XCTAssertNil(AxiamClient.umaParseChallenge("UMAX realm=\"example\""))
    }

    func testParsingPerformsNoExchange() async throws {
        let transport = UmaTransport()
        _ = try makeClient(transport)

        let challenge = AxiamClient.umaParseChallenge(
            "UMA realm=\"example\", as_uri=\"https://api.test\", ticket=\"\(Self.ticket)\"")

        XCTAssertEqual(challenge?.ticket?.wrapped, Self.ticket)
        // §20.3: the as_uri names an authorization server this client has not chosen to trust.
        // Auto-exchanging would send the requesting party's claim_token to whatever host answered
        // the 401.
        XCTAssertEqual(transport.paths.count, 0)
    }

    func testRoundTripsThroughTheEmitHalf() {
        let header = AxiamClient.umaChallengeHeader(
            realm: "example", asURI: "https://id.example", ticket: Sensitive(Self.ticket))

        let challenge = AxiamClient.umaParseChallenge(header)
        XCTAssertEqual(challenge?.asURI, "https://id.example")
        XCTAssertEqual(challenge?.ticket?.wrapped, Self.ticket)
    }

    // MARK: - §20.6 redaction

    func testNoTicketOrRPTRendersWhenDescribedOrInterpolated() async throws {
        let transport = UmaTransport()
        transport.permResponse = .json(201, ["ticket": Self.ticket])
        transport.tokenResponse = .json(200, [
            "access_token": Self.rpt, "token_type": "Bearer", "expires_in": 300,
        ])
        let client = try makeClient(transport)

        let ticket = try await client.umaRequestTicket(
            pat: Sensitive(Self.pat),
            permissions: [UmaRequestedPermission(resourceID: Self.resourceID, resourceScopes: ["view"])])
        let rpt = try await client.umaExchangeTicket(
            ticket: ticket, claimToken: Sensitive(Self.claimToken), credentials: Self.credentials())
        let challenge = try XCTUnwrap(AxiamClient.umaParseChallenge("UMA ticket=\"\(Self.ticket)\""))

        // §20.6: the ticket's 60-second lifetime is exactly what invites treating it as harmless.
        // For those 60 seconds it is the credential that converts into an RPT.
        for rendered in ["\(ticket)", "\(ticket.self)", "\(rpt)", "\(challenge)", String(describing: challenge)] {
            XCTAssertFalse(rendered.contains(Self.ticket), "leaked the ticket: \(rendered)")
            XCTAssertFalse(rendered.contains(Self.rpt), "leaked the RPT: \(rendered)")
        }
    }

    func testAFailedExchangeNeverEchoesTheTicketOrClaimToken() async throws {
        let transport = UmaTransport()
        transport.tokenResponse = .json(400, ["error": "invalid_grant", "error_description": "spent"])
        let client = try makeClient(transport)

        do {
            _ = try await client.umaExchangeTicket(
                ticket: Sensitive(Self.ticket), claimToken: Sensitive(Self.claimToken),
                credentials: Self.credentials())
            XCTFail("expected invalid_grant")
        } catch AxiamError.auth(let error) {
            // A failed exchange is exactly when a naive implementation logs the request body.
            let rendered = error.description + (error.oauthError ?? "") + (error.oauthErrorDescription ?? "")
            XCTAssertFalse(rendered.contains(Self.ticket))
            XCTAssertFalse(rendered.contains(Self.claimToken))
        }
    }
    // MARK: - §20 argument guards and challenge tolerance

    /// §20.1: a ticket is required, and the refusal happens client-side.
    ///
    /// The `claimToken` guard immediately below it is already covered; this one
    /// was not, which meant the first of two adjacent guards was unverified
    /// while the second looked tested.
    func testAnEmptyTicketIsRefusedClientSideWithNoWireCall() async throws {
        let transport = UmaTransport()
        let client = try makeClient(transport)
        do {
            _ = try await client.umaExchangeTicket(
                ticket: Sensitive(""),
                claimToken: Sensitive("a-claim-token"),
                credentials: Self.credentials())
            XCTFail("an empty ticket must be refused before the wire")
        } catch let error as AxiamError {
            guard case .auth = error else { return XCTFail("expected an AuthError") }
            XCTAssertTrue(transport.paths.isEmpty, "nothing may reach the network")
        }
    }

    /// UMA 2.0 permits a server to add its own challenge parameters. Ignoring
    /// an unknown one rather than rejecting the whole header is what keeps the
    /// ticket — refusing would throw away the very thing the challenge exists
    /// to deliver.
    func testAnUnknownChallengeParameterIsIgnoredAndTheTicketSurvives() throws {
        let header = #"UMA realm="axiam", as_uri="https://as.test", ticket="tkt-1", future_param="x""#
        let parsed = try XCTUnwrap(AxiamClient.umaParseChallenge(header))
        XCTAssertEqual(parsed.realm, "axiam")
        XCTAssertEqual(parsed.asURI, "https://as.test")
        XCTAssertEqual(parsed.ticket?.wrapped, "tkt-1")
    }

    /// The public memberwise initializer of a value type callers are expected
    /// to construct themselves. Never exercised, so a change to its stored
    /// properties would have compiled and shipped untested.
    func testRptPermissionIsConstructibleByCallers() {
        let permission = UmaRptPermission(
            resourceID: "res-1", resourceScopes: ["read", "write"], exp: 4_102_444_800)
        XCTAssertEqual(permission.resourceID, "res-1")
        XCTAssertEqual(permission.resourceScopes, ["read", "write"])
        XCTAssertEqual(permission.exp, 4_102_444_800)
    }
}

// MARK: - Harness

/// A recording `HTTPTransport` that serves the §20 endpoints.
///
/// It exists for its **counters**: §20.2 rule 6 can only be asserted by counting wire calls, so
/// every request that reaches this transport is recorded with its path, method, headers and body.
/// A path with no configured response answers `501`, so a test that reaches an endpoint it did not
/// expect fails loudly rather than passing on a silent default.
final class UmaTransport: HTTPTransport, @unchecked Sendable {
    enum Reply {
        case json(Int, Any)
        case raw(Int, Data)
        case empty(Int)
        /// No HTTP response at all — the timeout case §20.2 rule 6 names explicitly.
        case failure
    }

    private let lock = NSLock()
    private var records: [(path: String, method: String, headers: [String: String], body: Data?)] = []

    var rregResponse: Reply?
    var permResponse: Reply?
    var tokenResponse: Reply?

    var paths: [String] {
        lock.lock(); defer { lock.unlock() }
        return records.map(\.path)
    }

    func count(pathSuffix: String) -> Int {
        lock.lock(); defer { lock.unlock() }
        return records.filter { URL(string: $0.path)?.path == pathSuffix }.count
    }

    func methods(forPathSuffix suffix: String) -> [String] {
        lock.lock(); defer { lock.unlock() }
        return records.filter { URL(string: $0.path)?.path == suffix }.map(\.method)
    }

    func headers(forPathSuffix suffix: String) -> [String: String] {
        lock.lock(); defer { lock.unlock() }
        return records.last { URL(string: $0.path)?.path == suffix }?.headers ?? [:]
    }

    func jsonBody(forPathSuffix suffix: String) -> Any? {
        lock.lock(); defer { lock.unlock() }
        guard let body = records.last(where: { URL(string: $0.path)?.path == suffix })?.body else { return nil }
        return try? JSONSerialization.jsonObject(with: body)
    }

    func formBody(forPathSuffix suffix: String) -> [String: String] {
        lock.lock()
        let body = records.last { URL(string: $0.path)?.path == suffix }?.body
        lock.unlock()
        guard let body, let text = String(data: body, encoding: .utf8) else { return [:] }
        var form: [String: String] = [:]
        for pair in text.split(separator: "&") {
            guard let equals = pair.firstIndex(of: "=") else { continue }
            let key = String(pair[pair.startIndex..<equals]).removingPercentEncoding ?? ""
            let value = String(pair[pair.index(after: equals)...]).removingPercentEncoding ?? ""
            form[key] = value
        }
        return form
    }

    func execute(_ spec: HTTPRequestSpec, timeout: TimeInterval) async throws -> HTTPResponseData {
        var headerMap: [String: String] = [:]
        for (name, value) in spec.headers { headerMap[name.lowercased()] = value }

        // Record the request and snapshot the scripted answers in one synchronous critical
        // section; everything after it runs with no lock held.
        let (rreg, perm, token) = lock.locked { () -> (Reply?, Reply?, Reply?) in
            records.append((
                path: spec.url.absoluteString, method: spec.method.rawValue,
                headers: headerMap, body: spec.body))
            return (rregResponse, permResponse, tokenResponse)
        }

        let path = spec.url.path
        if path.hasSuffix("/.well-known/uma2-configuration") {
            return Self.render(.json(200, [
                "issuer": "https://api.test",
                "token_endpoint": "https://api.test/oauth2/token",
                "introspection_endpoint": "https://api.test/oauth2/introspect",
                "permission_endpoint": "https://api.test/uma2/perm",
                "resource_registration_endpoint": "https://api.test/uma2/rreg/resource_set",
                "jwks_uri": "https://api.test/.well-known/jwks.json",
                "grant_types_supported": ["urn:ietf:params:oauth:grant-type:uma-ticket"],
                "uma_profiles_supported": [],
                "permission_ticket_lifetime": 60,
            ]))
        }
        if path.hasSuffix("/oauth2/token") { return try Self.render(token) }
        if path.hasSuffix("/uma2/perm") { return try Self.render(perm) }
        if path.contains("/uma2/rreg/resource_set") { return try Self.render(rreg) }
        return Self.render(.empty(404))
    }

    func shutdown() async throws {}

    private static func render(_ reply: Reply?) throws -> HTTPResponseData {
        guard let reply else { return render(.empty(501)) }
        if case .failure = reply {
            throw AxiamError.network(NetworkError("connection reset"))
        }
        return render(reply)
    }

    private static func render(_ reply: Reply) -> HTTPResponseData {
        switch reply {
        case .json(let status, let object):
            let body = (try? JSONSerialization.data(withJSONObject: object)) ?? Data()
            return HTTPResponseData(
                status: status, headers: [("Content-Type", "application/json")], body: body)
        case .raw(let status, let body):
            return HTTPResponseData(status: status, headers: [("Content-Type", "text/html")], body: body)
        case .empty(let status):
            return HTTPResponseData(status: status, headers: [], body: Data())
        case .failure:
            return HTTPResponseData(status: 0, headers: [], body: Data())
        }
    }

}