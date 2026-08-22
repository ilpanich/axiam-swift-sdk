import XCTest
import Foundation
@testable import AxiamSDK

/// CONTRACT.md §24 — the WebAuthn relying-party layer and the §24.6a JSON bridge.
///
/// Two assertions are worth reading twice:
///
/// - `testRegisterStart503IsNotRetried` asserts on the **request count**, not the exception
///   type, because §24.4 rule 2 regresses the moment someone tidies a retry predicate — and
///   a type assertion would still pass.
/// - `testStateTokenIsNeverParsed` hands the SDK a state token that is not a JWT at all. If
///   anything decoded one, this is where it would fail.
final class WebauthnTests: XCTestCase {

    private static let stateToken = "state-token-fixture-value-do-not-log"
    private static let challengeToken = "challenge-token-fixture-do-not-log"
    private static let accessToken = "access-token-fixture-do-not-log"
    private static let refreshToken = "refresh-token-fixture-do-not-log"

    /// Deliberately "unusual but valid": every optional field populated, so the
    /// pass-through assertion has something to catch an over-eager implementation dropping.
    private static let creationChallenge: [String: Any] = [
        "publicKey": [
            "challenge": "Y2hhbGxlbmdlLWJ5dGVz",
            "rp": ["id": "axiam.test", "name": "AXIAM Test"],
            "user": ["id": "dXNlci1oYW5kbGU", "name": "alice", "displayName": "Alice"],
            "pubKeyCredParams": [
                ["type": "public-key", "alg": -7],
                ["type": "public-key", "alg": -8],
                ["type": "public-key", "alg": -257],
            ],
            "timeout": 60000,
            "excludeCredentials": [
                ["id": "ZXhpc3Rpbmc", "type": "public-key", "transports": ["usb", "nfc"]],
            ],
            "authenticatorSelection": [
                "residentKey": "required",
                "requireResidentKey": true,
                "userVerification": "required",
            ],
            "attestation": "direct",
            "extensions": ["credProps": true],
        ],
    ]

    private static let minimalCreationChallenge: [String: Any] = [
        "publicKey": [
            "challenge": "bWluaW1hbA",
            "rp": ["name": "AXIAM Test"],
            "user": ["id": "dQ", "name": "bob", "displayName": "Bob"],
            "pubKeyCredParams": [["type": "public-key", "alg": -7]],
        ],
    ]

    private static let discoverableChallenge: [String: Any] = [
        "publicKey": [
            "challenge": "ZGlzY292ZXJhYmxl",
            "rpId": "axiam.test",
            "allowCredentials": [String](),
            "userVerification": "required",
        ],
    ]

    /// Carries an unknown key the SDK must forward rather than strip.
    private static let registrationResponse = """
        {"id":"bmV3LWNyZWQ","rawId":"bmV3LWNyZWQ",\
        "response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0",\
        "attestationObject":"o2NmbXRkbm9uZQ","transports":["internal"],\
        "vendorSpecific":"must-survive"},\
        "type":"public-key","clientExtensionResults":{"credProps":{"rk":true}}}
        """

    private static let authenticationResponse = """
        {"id":"bmV3LWNyZWQ","rawId":"bmV3LWNyZWQ",\
        "response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",\
        "authenticatorData":"YXV0aC1kYXRh","signature":"c2ln","userHandle":"dXNlci1oYW5kbGU"},\
        "type":"public-key","clientExtensionResults":{}}
        """

    private static func challengeBody(
        _ challenge: [String: Any],
        stateToken: String = WebauthnTests.stateToken
    ) -> [String: Any] {
        ["challenge": challenge, "state_token": stateToken]
    }

    private static func credentialBody() -> [String: Any] {
        [
            "id": "cred-uuid-1",
            "credential_id": "bmV3LWNyZWQ",
            "name": "Alice's laptop",
            "credential_type": "passkey",
            "created_at": "2026-08-22T10:00:00Z",
        ]
    }

    private static func webauthnLoginBody() -> [String: Any] {
        [
            "access_token": accessToken,
            "refresh_token": refreshToken,
            "session_id": "sess-webauthn-1",
            "expires_in": 900,
        ]
    }

    /// A login 200 that seeds the session — what the SDK reads as "signed in" (§24.1).
    private static func signInResponse() -> TestResponse {
        .json(200, TestKit.loginSuccessBody(), headers: [
            ("Set-Cookie", "axiam_access=tok123; Path=/; HttpOnly"),
            ("X-CSRF-Token", "csrf456"),
        ])
    }

    // MARK: - §24.0 options and responses pass through untouched

    func testOptionsPassThroughStructurallyUnchanged() async throws {
        try await withClient(router: { request, _ in
            if request.uri.hasSuffix("/auth/login") { return Self.signInResponse() }
            return .json(200, Self.challengeBody(Self.creationChallenge))
        }) { client, _ in
            _ = try await client.login(email: "a@b.c", password: "pw")
            let challenge = try await client.webauthnRegisterStart()

            // Structural equality, not a spot-check of three fields: the failure mode this
            // guards is an SDK that quietly drops the one option it did not recognise.
            let served = try JSONSerialization.data(withJSONObject: Self.creationChallenge)
            XCTAssertEqual(
                NSDictionary(dictionary: try XCTUnwrap(challenge.challengeObject())),
                NSDictionary(
                    dictionary: try XCTUnwrap(
                        JSONSerialization.jsonObject(with: served) as? [String: Any]
                    )
                )
            )
        }
    }

    func testSynthesizesNoFieldTheServerOmitted() async throws {
        try await withClient(router: { request, _ in
            if request.uri.hasSuffix("/auth/login") { return Self.signInResponse() }
            return .json(200, Self.challengeBody(Self.minimalCreationChallenge))
        }) { client, _ in
            _ = try await client.login(email: "a@b.c", password: "pw")
            let challenge = try await client.webauthnRegisterStart()
            let options = try XCTUnwrap(
                challenge.challengeObject()?["publicKey"] as? [String: Any]
            )

            XCTAssertNil(options["authenticatorSelection"], "the SDK must not invent a selection")
            XCTAssertNil(options["timeout"], "the SDK must not invent a timeout")
            XCTAssertNil(options["attestation"], "the SDK must not invent a conveyance")
        }
    }

    func testAuthenticatorResponseReachesTheWireByteForByte() async throws {
        try await withClient(router: { request, _ in
            if request.uri.hasSuffix("/auth/login") { return Self.signInResponse() }
            return .json(201, Self.credentialBody())
        }) { client, server in
            _ = try await client.login(email: "a@b.c", password: "pw")
            _ = try await client.webauthnRegisterFinish(
                stateToken: Sensitive(Self.stateToken),
                credentialName: "Alice's laptop",
                response: Self.registrationResponse
            )

            let sent = String(
                decoding: try XCTUnwrap(server.state.requests(pathContaining: "register/finish").first).body,
                as: UTF8.self
            )
            // The literal substring, not a parsed comparison: this is the assertion that
            // catches a re-encode (§24.0), which a structural comparison would pass.
            XCTAssertTrue(
                sent.contains(Self.registrationResponse),
                "the response JSON was re-encoded on the way to the wire: \(sent)"
            )
            XCTAssertTrue(sent.contains("must-survive"), "an unknown field was dropped")
        }
    }

    // MARK: - §24.1 register requires a session

    func testRegisterWithoutASessionMakesZeroWireCalls() async throws {
        try await withClient(router: { _, _ in
            .json(200, [:])
        }) { client, server in
            do {
                _ = try await client.webauthnRegisterStart()
                XCTFail("expected an auth error")
            } catch AxiamError.auth {
                // expected
            }
            do {
                _ = try await client.webauthnRegisterFinish(
                    stateToken: Sensitive(Self.stateToken),
                    credentialName: "k",
                    response: Self.registrationResponse
                )
                XCTFail("expected an auth error")
            } catch AxiamError.auth {
                // expected
            }

            // Asserted on the transport, not the exception type: §24.1 requires the
            // refusal to be client-side.
            XCTAssertEqual(server.state.requests.count, 0)
        }
    }

    func testRegisterFinishReturnsTheCredential() async throws {
        try await withClient(router: { request, _ in
            if request.uri.hasSuffix("/auth/login") { return Self.signInResponse() }
            return .json(201, Self.credentialBody())
        }) { client, _ in
            _ = try await client.login(email: "a@b.c", password: "pw")
            let credential = try await client.webauthnRegisterFinish(
                stateToken: Sensitive(Self.stateToken),
                credentialName: "Alice's laptop",
                response: Self.registrationResponse
            )

            XCTAssertEqual(credential.credentialID, "bmV3LWNyZWQ")
            XCTAssertEqual(credential.credentialType, "passkey")
            XCTAssertNil(credential.lastUsedAt, "a never-used credential has no lastUsedAt")
        }
    }

    // MARK: - §24.2 two ceremonies, not one with a flag

    func testAuthenticateStartSendsTheChallengeToken() async throws {
        try await withClient(router: { _, _ in
            .json(200, Self.challengeBody(Self.discoverableChallenge))
        }) { client, server in
            _ = try await client.webauthnAuthenticateStart(
                challengeToken: Sensitive(Self.challengeToken)
            )

            let sent = try XCTUnwrap(server.state.requests(pathContaining: "authenticate/start").first)
            let body = try XCTUnwrap(
                JSONSerialization.jsonObject(with: sent.body) as? [String: Any]
            )
            XCTAssertEqual(body["challenge_token"] as? String, Self.challengeToken)
        }
    }

    func testAuthenticateStartWithoutATokenIsRefusedClientSide() async throws {
        try await withClient(router: { _, _ in
            .json(200, [:])
        }) { client, server in
            do {
                // §24.2: the two ceremonies are separate operations. The second-factor one
                // cannot run without the token that names the user.
                _ = try await client.webauthnAuthenticateStart()
                XCTFail("expected an auth error")
            } catch AxiamError.auth {
                // expected
            }
            XCTAssertEqual(server.state.requests.count, 0)
        }
    }

    func testDiscoverableStartSendsAWorkspaceAndNoChallengeToken() async throws {
        try await withClient(router: { _, _ in
            .json(200, Self.challengeBody(Self.discoverableChallenge))
        }) { client, server in
            _ = try await client.webauthnDiscoverableStart()

            let sent = try XCTUnwrap(
                server.state.requests(pathContaining: "discoverable/start").first
            )
            let body = try XCTUnwrap(
                JSONSerialization.jsonObject(with: sent.body) as? [String: Any]
            )
            XCTAssertNil(
                body["challenge_token"],
                "merging the two ceremonies reproduces a bug the server already fixed (§24.2)"
            )
            // §24.1: unlike the /oauth2 endpoints this one accepts slugs, and the SDK fills
            // the workspace from its own configuration.
            XCTAssertEqual(body["org_slug"] as? String, "globex")
            XCTAssertEqual(body["tenant_slug"] as? String, "acme")
        }
    }

    func testExplicitWorkspaceOverridesTheClientConfiguration() async throws {
        try await withClient(router: { _, _ in
            .json(200, Self.challengeBody(Self.discoverableChallenge))
        }) { client, server in
            _ = try await client.webauthnDiscoverableStart(
                workspace: WebauthnWorkspace(
                    orgSlug: "other-org",
                    tenantID: "22222222-2222-2222-2222-222222222222"
                )
            )

            let sent = try XCTUnwrap(
                server.state.requests(pathContaining: "discoverable/start").first
            )
            let body = try XCTUnwrap(
                JSONSerialization.jsonObject(with: sent.body) as? [String: Any]
            )
            XCTAssertEqual(body["org_slug"] as? String, "other-org")
            XCTAssertEqual(body["tenant_id"] as? String, "22222222-2222-2222-2222-222222222222")
            XCTAssertNil(body["tenant_slug"], "a resolved tenant_id makes tenant_slug ambiguous")
        }
    }

    func testAClientWithNoOrganizationCannotStartADiscoverableCeremony() async throws {
        try await withClient(
            makeConfig: { try TestKit.makeConfig(port: $0, orgSlug: nil) },
            router: { _, _ in .json(200, [:]) }
        ) { client, server in
            do {
                _ = try await client.webauthnDiscoverableStart()
                XCTFail("expected an auth error")
            } catch AxiamError.auth {
                // expected
            }
            XCTAssertEqual(server.state.requests.count, 0)
        }
    }

    // MARK: - §24.3 credential adoption

    func testACompletedCeremonyLeavesTheClientAuthenticated() async throws {
        try await withClient(router: { _, _ in
            .json(200, Self.webauthnLoginBody(), headers: [
                ("Set-Cookie", "axiam_access=tok-webauthn; Path=/; HttpOnly"),
                ("X-CSRF-Token", "csrf-webauthn"),
            ])
        }) { client, _ in
            let result = try await client.webauthnDiscoverableFinish(
                stateToken: Sensitive(Self.stateToken),
                response: Self.authenticationResponse
            )

            XCTAssertEqual(result.expiresIn, 900)
            XCTAssertEqual(result.sessionID, "sess-webauthn-1")

            // §24.3 rule 1: the client's OWN authenticated state, not just that a token
            // came back. A cookie-jar SDK additionally captured the CSRF token.
            let hasSession = await client._hasSession()
            XCTAssertTrue(hasSession)
            let csrf = await client._csrfToken()
            XCTAssertEqual(csrf, "csrf-webauthn")
        }
    }

    // MARK: - §24.4 the two error rows that are not the §2 defaults

    func testRegisterStart503IsNotRetried() async throws {
        try await withClient(router: { request, _ in
            if request.uri.hasSuffix("/auth/login") { return Self.signInResponse() }
            return .json(503, ["message": "FIDO metadata unavailable"])
        }) { client, server in
            _ = try await client.login(email: "a@b.c", password: "pw")
            do {
                _ = try await client.webauthnRegisterStart()
                XCTFail("expected a failure")
            } catch {
                // expected
            }

            // §24.4 rule 2, asserted on the request count: a 503 here is a server
            // CONFIGURATION state, retrying changes nothing, and this regresses silently
            // the moment the retry predicate is tidied.
            XCTAssertEqual(
                server.state.requests(pathContaining: "register/start").count,
                1,
                "the 503 must not be retried"
            )
        }
    }

    func testRegisterFinish403KeepsTheAttestationPolicyMessage() async throws {
        try await withClient(router: { request, _ in
            if request.uri.hasSuffix("/auth/login") { return Self.signInResponse() }
            return .json(403, ["message": "this security key is not FIDO certified"])
        }) { client, _ in
            _ = try await client.login(email: "a@b.c", password: "pw")
            do {
                _ = try await client.webauthnRegisterFinish(
                    stateToken: Sensitive(Self.stateToken),
                    credentialName: "key",
                    response: Self.registrationResponse
                )
                XCTFail("expected an authz error")
            } catch let AxiamError.authz(error) {
                // §24.4 rule 1: the policy message is the only way the person holding the
                // key learns a different one would work.
                XCTAssertTrue(
                    error.message.contains("FIDO certified"),
                    "the attestation policy message was lost: \(error.message)"
                )
            }
        }
    }

    func testAFailedAssertionIsAnAuthError() async throws {
        try await withClient(router: { _, _ in
            .json(401, ["message": "assertion failed"])
        }) { client, _ in
            do {
                _ = try await client.webauthnDiscoverableFinish(
                    stateToken: Sensitive(Self.stateToken),
                    response: Self.authenticationResponse
                )
                XCTFail("expected an auth error")
            } catch AxiamError.auth {
                // expected
            }
        }
    }

    // MARK: - §24.5 opaque and sensitive

    func testStateTokenIsNeverParsed() async throws {
        // Not a JWT, not base64, not three dot-separated parts. If anything decoded it,
        // this round trip would not survive.
        let nonsense = "-----definitely not a jwt-----"
        try await withClient(router: { request, _ in
            if request.uri.contains("discoverable/start") {
                return .json(200, Self.challengeBody(Self.discoverableChallenge, stateToken: nonsense))
            }
            return .json(200, Self.webauthnLoginBody())
        }) { client, server in
            let challenge = try await client.webauthnDiscoverableStart()
            XCTAssertEqual(challenge.stateToken.expose(), nonsense)

            _ = try await client.webauthnDiscoverableFinish(
                stateToken: challenge.stateToken,
                response: Self.authenticationResponse
            )

            let sent = try XCTUnwrap(
                server.state.requests(pathContaining: "discoverable/finish").first
            )
            let body = try XCTUnwrap(
                JSONSerialization.jsonObject(with: sent.body) as? [String: Any]
            )
            XCTAssertEqual(body["state_token"] as? String, nonsense)
        }
    }

    func testNoFixtureTokenAppearsInARenderedValue() async throws {
        try await withClient(router: { request, _ in
            if request.uri.hasSuffix("/auth/login") { return Self.signInResponse() }
            if request.uri.contains("register/start") {
                return .json(200, Self.challengeBody(Self.creationChallenge))
            }
            return .json(200, Self.webauthnLoginBody())
        }) { client, _ in
            _ = try await client.login(email: "a@b.c", password: "pw")
            let challenge = try await client.webauthnRegisterStart()
            XCTAssertEqual("\(challenge.stateToken)", "[SENSITIVE]")
            XCTAssertFalse("\(challenge.stateToken)".contains(Self.stateToken))

            let login = try await client.webauthnDiscoverableFinish(
                stateToken: Sensitive(Self.stateToken),
                response: Self.authenticationResponse
            )
            XCTAssertFalse("\(login.accessToken)".contains(Self.accessToken))
            XCTAssertFalse("\(login.refreshToken)".contains(Self.refreshToken))
        }
    }

    // MARK: - §24.6a the JSON bridge

    func testRequestJsonRoundTripsAndDropsThePublicKeyWrapper() async throws {
        try await withClient(router: { request, _ in
            if request.uri.hasSuffix("/auth/login") { return Self.signInResponse() }
            return .json(200, Self.challengeBody(Self.creationChallenge))
        }) { client, _ in
            _ = try await client.login(email: "a@b.c", password: "pw")
            let challenge = try await client.webauthnRegisterStart()
            let parsed = try XCTUnwrap(
                JSONSerialization.jsonObject(with: Data(challenge.requestJson.utf8)) as? [String: Any]
            )

            // The inner options object: the publicKey wrapper belongs to the DOM's
            // CredentialCreationOptions, and the platform JSON APIs — the very ones this
            // accessor exists for — do not want it.
            XCTAssertNil(parsed["publicKey"])
            let expected = try XCTUnwrap(Self.creationChallenge["publicKey"] as? [String: Any])
            XCTAssertEqual(NSDictionary(dictionary: parsed), NSDictionary(dictionary: expected))
            XCTAssertEqual(parsed["attestation"] as? String, "direct")
            XCTAssertEqual(parsed["timeout"] as? Int, 60000)
        }
    }

    func testAResponseThatIsNotAJsonObjectIsRefusedBeforeTheWire() async throws {
        try await withClient(router: { _, _ in
            .json(200, [:])
        }) { client, server in
            for bad in ["not json at all", "[\"an\",\"array\"]"] {
                do {
                    _ = try await client.webauthnDiscoverableFinish(
                        stateToken: Sensitive(Self.stateToken),
                        response: bad
                    )
                    XCTFail("expected an auth error for \(bad)")
                } catch AxiamError.auth {
                    // expected
                }
            }
            XCTAssertEqual(
                server.state.requests.count,
                0,
                "the SDK must not POST a body it cannot verify"
            )
        }
    }

    func testTheErrorClassificationIsReachableWithoutALinkedApi() {
        // §24.6b rule 5, required of this SDK on EVERY build — including Linux, where no
        // ceremony helper exists but a browser front end still relays DOMException names.
        XCTAssertEqual(WebauthnFailure.classify("NotAllowedError"), .cancelled)
        XCTAssertEqual(WebauthnFailure.classify("InvalidStateError"), .alreadyRegistered)
        XCTAssertEqual(WebauthnFailure.classify("AbortError"), .timeout)
        XCTAssertEqual(WebauthnFailure.classify("NotSupportedError"), .unsupported)
        XCTAssertEqual(WebauthnFailure.classify("SecurityError"), .unsupported)
        XCTAssertEqual(WebauthnFailure.classify("SomethingElseError"), .unknown)
        XCTAssertEqual(WebauthnFailure.classify(nil), .unknown)

        // ASAuthorizationError.canceled spells it with one L.
        XCTAssertEqual(WebauthnFailure.classify("canceled"), .cancelled)
    }

    func testAlreadyRegisteredIsDistinguishableFromCancelled() {
        XCTAssertNotEqual(
            WebauthnFailure.classify("InvalidStateError"),
            WebauthnFailure.classify("NotAllowedError")
        )
        // The only classification whose remedy is "use a different device".
        XCTAssertTrue(WebauthnFailure.alreadyRegistered.message.contains("different device"))
        // And the one that must not accuse the user: it also covers a silent timeout,
        // which the spec refuses to distinguish.
        XCTAssertTrue(WebauthnFailure.cancelled.message.contains("cancelled or timed out"))
    }

    func testFeatureDetectionAnswersRatherThanThrows() async throws {
        try await withClient(router: { _, _ in .json(200, [:]) }) { client, _ in
            // §24.6b rule 6: a query, not an exception, so a caller hides a button rather
            // than offering one that throws. On Linux both are false; on Apple platforms
            // the first is true. Either way, neither throws.
            _ = client.webauthnCeremonySupported
            _ = client.webauthnConditionalMediationSupported
            #if !canImport(AuthenticationServices)
            XCTAssertFalse(client.webauthnCeremonySupported)
            XCTAssertFalse(client.webauthnConditionalMediationSupported)
            #endif
        }
    }
}
