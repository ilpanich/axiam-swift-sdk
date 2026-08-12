import XCTest
import Foundation
@testable import AxiamSDK

/// The §20.3 emit half, wired into the §11 `requireAccess` guard.
///
/// Everything asserted here is about the *deny* path, because that is the only path that mints
/// anything:
///
/// 1. A denial with a challenger mints exactly one ticket and carries it on the thrown error.
/// 2. An allow mints nothing — a guard that minted on the happy path would put a Protection API
///    call in front of every authorized request.
/// 3. A minting failure still denies, without a challenge. An outage must not turn a deny into a
///    503, and must never turn it into an allow.
final class UmaChallengeGuardTests: XCTestCase {
    let signer = TestSigner()

    private static let tenantUUID = "tenant-uuid-1"
    private static let resourceID = "99999999-8888-7777-6666-555555555555"
    private static let pat = "pat-token-value"
    private static let ticket = "ticket-value"

    /// Serves JWKS, the authz check, UMA discovery and the permission endpoint, counting each.
    private func makeRouter(authzAllowed: Bool, permStatus: Int = 201) -> TestRouter {
        let signer = self.signer
        return { request, state in
            if request.uri.hasSuffix("/oauth2/jwks") {
                return .json(200, signer.jwksJSON())
            }
            if request.uri.contains("/authz/check") {
                return .json(200, ["allowed": authzAllowed, "reason": authzAllowed ? NSNull() : "denied"])
            }
            if request.uri.hasSuffix("/.well-known/uma2-configuration") {
                // Endpoints are absolute in this document (§20.1), so they are built from the
                // Host the test server is actually listening on rather than a fixed port.
                let base = "http://\(request.header("Host") ?? "127.0.0.1")"
                return .json(200, [
                    "issuer": base,
                    "token_endpoint": "\(base)/oauth2/token",
                    "introspection_endpoint": "\(base)/oauth2/introspect",
                    "permission_endpoint": "\(base)/uma2/perm",
                    "resource_registration_endpoint": "\(base)/uma2/rreg/resource_set",
                    "jwks_uri": "\(base)/.well-known/jwks.json",
                    "grant_types_supported": ["urn:ietf:params:oauth:grant-type:uma-ticket"],
                    "uma_profiles_supported": [],
                    "permission_ticket_lifetime": 60,
                ])
            }
            if request.uri.hasSuffix("/uma2/perm") {
                state.increment("perm")
                guard permStatus == 201 else { return .json(permStatus, ["error": "server_error"]) }
                return .json(201, ["ticket": Self.ticket])
            }
            return .json(404, [:])
        }
    }

    private func futureClaims() -> [String: Any] {
        [
            "sub": "user-42",
            "tenant_id": Self.tenantUUID,
            "roles": ["reader"],
            "exp": Date().addingTimeInterval(3600).timeIntervalSince1970,
        ]
    }

    private func withGuardClient(
        router: @escaping TestRouter,
        body: (AxiamClient, TestHTTPServer) async throws -> Void
    ) async throws {
        try await withClient(
            makeConfig: { try TestKit.makeConfig(port: $0, tenantSlug: nil, tenantID: Self.tenantUUID) },
            router: router,
            body: body
        )
    }

    private func challenger() -> UmaChallenger {
        UmaChallenger(realm: "invoices", asURI: "https://id.example", pat: Sensitive(Self.pat))
    }

    func testADenialMintsOneTicketAndCarriesTheChallenge() async throws {
        let jwt = signer.makeJWT(claims: futureClaims())
        try await withGuardClient(router: makeRouter(authzAllowed: false)) { client, server in
            let guardFn = client.makeGuards().requireAccess(
                "invoices:read", resource: Self.resourceID, umaChallenge: self.challenger())

            do {
                _ = try await guardFn(AxiamRequestContext(cookies: ["axiam_access": jwt]))
                XCTFail("expected denial")
            } catch let error as AuthzError {
                XCTAssertEqual(error.action, "invoices:read")
                XCTAssertEqual(server.state.count("perm"), 1, "one ticket, not two")

                // The emitted value is the one this SDK's own parser consumes — the round trip
                // is the point of shipping both halves.
                let header = try XCTUnwrap(error.challenge)
                let parsed = try XCTUnwrap(AxiamClient.umaParseChallenge(header))
                XCTAssertEqual(parsed.realm, "invoices")
                XCTAssertEqual(parsed.asURI, "https://id.example")
                XCTAssertEqual(parsed.ticket?.wrapped, Self.ticket)
            }
        }
    }

    func testTheTicketAsksForTheActionThatWasRefused() async throws {
        let jwt = signer.makeJWT(claims: futureClaims())
        try await withGuardClient(router: makeRouter(authzAllowed: false)) { client, server in
            let guardFn = client.makeGuards().requireAccess(
                "invoices:approve", resource: Self.resourceID, umaChallenge: self.challenger())

            _ = try? await guardFn(AxiamRequestContext(cookies: ["axiam_access": jwt]))

            // §20.2: the UMA scope is the AXIAM *action*. Asking for anything else would mint a
            // ticket for authority other than the one just refused — and would step outside the
            // grants the engine evaluated, deny rules included.
            let permRequest = try XCTUnwrap(server.state.requests(pathContaining: "/uma2/perm").last)
            let body = try XCTUnwrap(
                JSONSerialization.jsonObject(with: permRequest.body) as? [[String: Any]])
            XCTAssertEqual(body.count, 1)
            XCTAssertEqual(body[0]["resource_id"] as? String, Self.resourceID)
            XCTAssertEqual(body[0]["resource_scopes"] as? [String], ["invoices:approve"])
        }
    }

    func testAnAllowMintsNothing() async throws {
        let jwt = signer.makeJWT(claims: futureClaims())
        try await withGuardClient(router: makeRouter(authzAllowed: true)) { client, server in
            let guardFn = client.makeGuards().requireAccess(
                "invoices:read", resource: Self.resourceID, umaChallenge: self.challenger())

            let user = try await guardFn(AxiamRequestContext(cookies: ["axiam_access": jwt]))

            XCTAssertEqual(user.userID, "user-42")
            // Minting on the happy path would put a Protection API call — and a live credential —
            // in front of every authorized request.
            XCTAssertEqual(server.state.count("perm"), 0)
        }
    }

    func testAMintingFailureStillDeniesWithoutAChallenge() async throws {
        let jwt = signer.makeJWT(claims: futureClaims())
        try await withGuardClient(router: makeRouter(authzAllowed: false, permStatus: 500)) { client, _ in
            let guardFn = client.makeGuards().requireAccess(
                "invoices:read", resource: Self.resourceID, umaChallenge: self.challenger())

            do {
                _ = try await guardFn(AxiamRequestContext(cookies: ["axiam_access": jwt]))
                XCTFail("expected denial")
            } catch let error as AuthzError {
                // Failure is not escalation: the caller was going to be refused, and a Protection
                // API outage must not turn that into a 503 — nor, far worse, into an allow.
                XCTAssertNil(error.challenge)
                XCTAssertEqual(error.action, "invoices:read")
            }
        }
    }

    func testWithoutAChallengerADenialCarriesNothing() async throws {
        let jwt = signer.makeJWT(claims: futureClaims())
        try await withGuardClient(router: makeRouter(authzAllowed: false)) { client, server in
            let guardFn = client.makeGuards().requireAccess("invoices:read", resource: Self.resourceID)

            do {
                _ = try await guardFn(AxiamRequestContext(cookies: ["axiam_access": jwt]))
                XCTFail("expected denial")
            } catch let error as AuthzError {
                // Opt-in means opt-in: an application that never asked for UMA semantics gets no
                // Protection API traffic from its guards.
                XCTAssertNil(error.challenge)
                XCTAssertEqual(server.state.count("perm"), 0)
            }
        }
    }

    func testTheErrorDescriptionNeverCarriesTheTicket() async throws {
        // §20.6: the challenge holds a live credential for its 60 seconds. `description` is what
        // ends up in a log line, so the ticket must not be reachable through it.
        let error = AuthzError(
            "Access denied for 'invoices:read'.",
            action: "invoices:read",
            resourceID: Self.resourceID,
            challenge: "UMA realm=\"invoices\", as_uri=\"https://id.example\", ticket=\"\(Self.ticket)\""
        )

        XCTAssertFalse(error.description.contains(Self.ticket))
        XCTAssertFalse("\(error)".contains(Self.ticket))
    }
}
