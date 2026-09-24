import Foundation
import XCTest
@testable import AxiamSDK

/// The C-5 lesson (axiam-csharp-sdk, sent back; the same bug was found in the merged Go
/// and TypeScript ports): every call that completes a NEW session must reset the §5.2
/// acting-tenant gate to unknown and clear the §17 memo, UNLESS its own response reports
/// `LoginUserInfo`. That includes every SSO/federation completion (`ssoComplete`,
/// `ssoCompleteOauth2`, `ssoCompleteHandoff`) and a plain WebAuthn authentication.
///
/// The mechanism in this SDK: `AxiamClient.sessionUser` (nil = "gate unknown") is what
/// `actingTenant(_:)` gates against. `adoptSessionAfterCeremony(user:)` is now
/// unconditional — `sessionUser = user`, not `if let user { sessionUser = user }` — so a
/// completion that adopts no `LoginUserInfo` resets it to `nil` rather than leaving a
/// PREVIOUS session's `organizationLevel`/`reachableTenantIDs` in place for a principal
/// the response never described.
final class SessionResetOnCompletionTests: XCTestCase {

    private static let restrictedTenant = "33333333-3333-4333-8333-333333333333"
    private static let otherTenant = "66666666-6666-4666-8666-666666666666"
    private static let stateToken = "state-token-fixture"
    private static let authenticationResponse = """
        {"id":"bmV3LWNyZWQ","rawId":"bmV3LWNyZWQ",\
        "response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",\
        "authenticatorData":"YXV0aC1kYXRh","signature":"c2ln","userHandle":"dXNlci1oYW5kbGU"},\
        "type":"public-key","clientExtensionResults":{}}
        """

    /// A restricted organization-level principal: real reach the gate must forget once a
    /// completion carrying no `LoginUserInfo` lands — this is the principal whose
    /// STALE `reachableTenantIDs` would otherwise wrongly bind `actingTenant(_:)`'s
    /// decision for whatever NEW principal actually completed the session.
    private static func restrictedLoginBody() -> [String: Any] {
        var body = TestKit.loginSuccessBody()
        var user = body["user"] as! [String: Any]
        user["organization_level"] = true
        user["reachable_tenant_ids"] = [restrictedTenant]
        body["user"] = user
        return body
    }

    // MARK: - Plain WebAuthn authentication (no LoginUserInfo)

    func testWebauthnAuthenticateFinishResetsTheActingTenantGate() async throws {
        try await withClient(router: { request, _ in
            if request.uri.hasSuffix("/auth/login") {
                return .json(200, Self.restrictedLoginBody())
            }
            if request.uri.hasSuffix("/webauthn/authenticate/finish") {
                return .json(200, [
                    "access_token": "tok", "refresh_token": "rtok",
                    "session_id": "sess-1", "expires_in": 900,
                ])
            }
            return .json(404, [:])
        }) { client, _ in
            guard case .authenticated = try await client.login(email: "a@b.test", password: "pw") else {
                return XCTFail("expected authenticated")
            }
            // Before the completion: the gate is the restricted principal's, so a
            // tenant OUTSIDE its reach is refused client-side.
            do {
                try await client.actingTenant(UUID(uuidString: Self.otherTenant)!)
                XCTFail("expected the pre-completion gate to refuse an unreachable tenant")
            } catch AxiamError.auth {}

            _ = try await client.webauthnAuthenticateFinish(
                stateToken: Sensitive(Self.stateToken), response: Self.authenticationResponse)

            // After: the gate is reset to UNKNOWN — nothing to gate on, so the SAME
            // tenant switch is no longer refused client-side (the server decides).
            try await client.actingTenant(UUID(uuidString: Self.otherTenant)!)
        }
    }

    /// The twin: a REFUSED completion leaves the gate exactly as it was.
    func testARefusedWebauthnAuthenticateFinishLeavesTheGateAsItWas() async throws {
        try await withClient(router: { request, _ in
            if request.uri.hasSuffix("/auth/login") {
                return .json(200, Self.restrictedLoginBody())
            }
            if request.uri.hasSuffix("/webauthn/authenticate/finish") {
                return .json(400, ["error": "validation_error", "message": "bad assertion"])
            }
            return .json(404, [:])
        }) { client, _ in
            guard case .authenticated = try await client.login(email: "a@b.test", password: "pw") else {
                return XCTFail("expected authenticated")
            }
            do {
                _ = try await client.webauthnAuthenticateFinish(
                    stateToken: Sensitive(Self.stateToken), response: Self.authenticationResponse)
                XCTFail("expected the finish to fail")
            } catch {}

            // The gate is UNCHANGED: still the restricted principal's.
            do {
                try await client.actingTenant(UUID(uuidString: Self.otherTenant)!)
                XCTFail("a refused completion must leave the gate as it was")
            } catch AxiamError.auth {}
        }
    }

    // MARK: - SSO / federation completions

    private static func ssoCompleteBody() -> [String: Any] {
        ["user_id": "u-1", "session_id": "sess-sso-1", "expires_in": 900, "redirect_uri": "https://app.example/done"]
    }

    func testSsoCompleteOauth2ResetsTheActingTenantGate() async throws {
        try await withClient(router: { request, _ in
            if request.uri.hasSuffix("/auth/login") {
                return .json(200, Self.restrictedLoginBody())
            }
            if request.uri.hasSuffix("/auth/federation/oauth2/callback") {
                return .json(200, Self.ssoCompleteBody(), headers: [
                    ("Set-Cookie", "axiam_access=sso-tok; Path=/; HttpOnly"),
                ])
            }
            return .json(404, [:])
        }) { client, _ in
            guard case .authenticated = try await client.login(email: "a@b.test", password: "pw") else {
                return XCTFail("expected authenticated")
            }
            _ = try await client.ssoCompleteOauth2(code: "c1", state: "s1")
            // Reset: no client-side refusal for a tenant outside the OLD restricted reach.
            try await client.actingTenant(UUID(uuidString: Self.otherTenant)!)
        }
    }

    func testARefusedSsoCompleteOauth2LeavesTheGateAsItWas() async throws {
        try await withClient(router: { request, _ in
            if request.uri.hasSuffix("/auth/login") {
                return .json(200, Self.restrictedLoginBody())
            }
            if request.uri.hasSuffix("/auth/federation/oauth2/callback") {
                return .json(401, ["error": "authentication_failed", "message": "bad code"])
            }
            return .json(404, [:])
        }) { client, _ in
            guard case .authenticated = try await client.login(email: "a@b.test", password: "pw") else {
                return XCTFail("expected authenticated")
            }
            do {
                _ = try await client.ssoCompleteOauth2(code: "bad", state: "s1")
                XCTFail("expected the completion to fail")
            } catch {}
            do {
                try await client.actingTenant(UUID(uuidString: Self.otherTenant)!)
                XCTFail("a refused completion must leave the gate as it was")
            } catch AxiamError.auth {}
        }
    }

    func testSsoCompleteHandoffResetsTheActingTenantGate() async throws {
        try await withClient(router: { request, _ in
            if request.uri.hasSuffix("/auth/login") {
                return .json(200, Self.restrictedLoginBody())
            }
            if request.uri.hasSuffix("/auth/federation/handoff") {
                return .json(200, Self.ssoCompleteBody(), headers: [
                    ("Set-Cookie", "axiam_access=sso-tok; Path=/; HttpOnly"),
                ])
            }
            return .json(404, [:])
        }) { client, _ in
            guard case .authenticated = try await client.login(email: "a@b.test", password: "pw") else {
                return XCTFail("expected authenticated")
            }
            _ = try await client.ssoCompleteHandoff(code: "handoff-1")
            try await client.actingTenant(UUID(uuidString: Self.otherTenant)!)
        }
    }

    /// **`ssoComplete(code:state:)` — the third federation completion, found only while
    /// applying this same lesson.** Before this fix it went through `oidcJSONPost` ->
    /// `umaSendAbsolute`, which deliberately attaches AND captures NO cookie at all
    /// (correct for the §20 discovery calls it otherwise serves) — so the session this
    /// call's own doc comment promises ("the session arrives as Set-Cookie and lands in
    /// this client's jar") never actually landed, on top of never resetting the gate.
    /// Routed through `completeFederationSession` now, exactly like the other two.
    func testSsoCompleteOidcCallbackAdoptsTheCookieAndResetsTheGate() async throws {
        try await withClient(router: { request, _ in
            if request.uri.hasSuffix("/auth/login") {
                return .json(200, Self.restrictedLoginBody())
            }
            if request.uri.hasSuffix("/auth/federation/oidc/callback") {
                return .json(200, Self.ssoCompleteBody(), headers: [
                    ("Set-Cookie", "axiam_access=oidc-tok; Path=/; HttpOnly"),
                ])
            }
            return .json(404, [:])
        }) { client, _ in
            guard case .authenticated = try await client.login(email: "a@b.test", password: "pw") else {
                return XCTFail("expected authenticated")
            }
            let before = await client._cookieCount()

            _ = try await client.ssoComplete(code: "c1", state: "s1")

            let after = await client._cookieCount()
            XCTAssertGreaterThan(after, before, "the completion's Set-Cookie must land in the jar")
            try await client.actingTenant(UUID(uuidString: Self.otherTenant)!)
        }
    }
}
