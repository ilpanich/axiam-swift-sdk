import XCTest
import Foundation
@testable import AxiamSDK

/// CONTRACT.md §25 — account lifecycle and MFA enrolment.
///
/// The two assertions worth reading twice are the §25.4 pair:
/// `testRequestPasswordResetSaysNothingAboutWhetherTheAccountExists` pins the
/// account-enumeration guarantee to the SDK's *surface* rather than to the server's
/// behaviour, and `testResetContextSendsTheTokenAsAQueryParameter` exists because building
/// that URL by path-joining percent-escapes the `?` INTO the path — a bug that produces a
/// 404 reading exactly like an expired token.
final class AccountLifecycleTests: XCTestCase {

    private static let setupToken = "setup-token-fixture-do-not-log"
    private static let resetToken = "reset-token-fixture-do-not-log"
    private static let secret = "JBSWY3DPEHPK3PXP"
    private static let tenantUUID = "22222222-2222-2222-2222-222222222222"

    private static func enrollmentBody() -> [String: Any] {
        [
            "secret_base32": secret,
            "totp_uri": "otpauth://totp/AXIAM:alice?secret=\(secret)&issuer=AXIAM",
        ]
    }

    // MARK: - §25.2 rule 1: login gains a third outcome

    func testLogin403MfaSetupRequiredIsTheThirdOutcome() async throws {
        try await withClient(router: { _, _ in
            .json(403, ["mfa_setup_required": true, "setup_token": Self.setupToken])
        }) { client, _ in
            let result = try await client.login(email: "a@b.c", password: "pw")

            guard case let .mfaSetupRequired(setupToken) = result else {
                return XCTFail("a tenant that requires MFA on an account without it is not "
                    + "a failure; got \(result)")
            }
            XCTAssertEqual(setupToken.expose(), Self.setupToken)
            XCTAssertEqual("\(setupToken)", "[SENSITIVE]")

            let hasSession = await client._hasSession()
            XCTAssertFalse(hasSession, "there is no session until setup/confirm completes it")
        }
    }

    func testAnOrdinary403IsStillAFailure() async throws {
        try await withClient(router: { _, _ in
            // §25.2 rule 1 keys the third outcome on the error BODY, never on the status
            // alone: a plain 403 must keep throwing, and must keep its §2 authz mapping.
            .json(403, ["error": "authorization_denied", "message": "tenant suspended"])
        }) { client, _ in
            do {
                _ = try await client.login(email: "a@b.c", password: "pw")
                XCTFail("expected an authz error")
            } catch AxiamError.authz {
                // expected
            }
        }
    }

    func testA403WithoutASetupTokenIsStillAFailure() async throws {
        try await withClient(router: { _, _ in
            // The flag alone is not the outcome: without the token the caller could not
            // recover, and reporting a recoverable state they cannot act on is worse than
            // reporting the refusal.
            .json(403, ["mfa_setup_required": true])
        }) { client, _ in
            do {
                _ = try await client.login(email: "a@b.c", password: "pw")
                XCTFail("expected an authz error")
            } catch AxiamError.authz {
                // expected
            }
        }
    }

    // MARK: - §25.1 voluntary enrolment

    func testMfaEnrollReturnsTheSecretAndItsUri() async throws {
        try await withClient(router: { _, _ in
            .json(200, Self.enrollmentBody())
        }) { client, server in
            let enrollment = try await client.mfaEnroll()

            XCTAssertEqual(enrollment.secretBase32.expose(), Self.secret)
            XCTAssertTrue(enrollment.totpURI.expose().hasPrefix("otpauth://totp/"))
            XCTAssertEqual(server.state.requests(pathContaining: "mfa/enroll").count, 1)
        }
    }

    func testBothHalvesOfAnEnrolmentAreSensitive() async throws {
        try await withClient(router: { _, _ in
            .json(200, Self.enrollmentBody())
        }) { client, _ in
            let enrollment = try await client.mfaEnroll()

            // §25.3: the otpauth URI CONTAINS the secret. Wrapping only the bare secret and
            // printing the URI leaks the same bytes — this is the mistake the rule names,
            // which is why the scan is for the SECRET VALUE, not the field name.
            XCTAssertFalse("\(enrollment.secretBase32)".contains(Self.secret))
            XCTAssertFalse("\(enrollment.totpURI)".contains(Self.secret))
            XCTAssertFalse("\(enrollment)".contains(Self.secret))
        }
    }

    func testMfaConfirmReportsWhetherTheFactorIsLive() async throws {
        try await withClient(router: { _, _ in
            .json(200, ["mfa_enabled": true])
        }) { client, server in
            let enabled = try await client.mfaConfirm("123456")
            XCTAssertTrue(enabled)

            let sent = try XCTUnwrap(server.state.requests(pathContaining: "mfa/confirm").first)
            let body = try XCTUnwrap(JSONSerialization.jsonObject(with: sent.body) as? [String: Any])
            XCTAssertEqual(body["totp_code"] as? String, "123456")
        }
    }

    func testAWrongCodeIsAnAuthError() async throws {
        try await withClient(router: { _, _ in
            .json(401, ["message": "invalid code"])
        }) { client, _ in
            do {
                _ = try await client.mfaConfirm("000000")
                XCTFail("expected an auth error")
            } catch AxiamError.auth {
                // expected
            }
        }
    }

    // MARK: - §25.1 / §25.2 rule 2: forced enrolment completes a login

    func testMfaSetupEnrollAuthenticatesWithTheSetupTokenAlone() async throws {
        try await withClient(router: { _, _ in
            .json(200, Self.enrollmentBody())
        }) { client, server in
            _ = try await client.mfaSetupEnroll(setupToken: Sensitive(Self.setupToken))

            let sent = try XCTUnwrap(
                server.state.requests(pathContaining: "mfa/setup/enroll").first
            )
            let body = try XCTUnwrap(JSONSerialization.jsonObject(with: sent.body) as? [String: Any])
            // There is no session yet — the setup token IS the credential.
            XCTAssertEqual(body["setup_token"] as? String, Self.setupToken)
        }
    }

    func testMfaSetupConfirmAdoptsTheSessionLikeALogin() async throws {
        try await withClient(router: { _, _ in
            .json(200, TestKit.loginSuccessBody(), headers: [
                ("Set-Cookie", "axiam_access=tok-setup; Path=/; HttpOnly"),
                ("X-CSRF-Token", "csrf-setup"),
            ])
        }) { client, server in
            let user = try await client.mfaSetupConfirm(
                setupToken: Sensitive(Self.setupToken),
                totpCode: "123456"
            )

            // §25.2 rule 2: this IS the completion of a login, so the credentials it
            // returns are adopted exactly as login() adopts them.
            XCTAssertEqual(user.userID, "user-uuid-1")
            let hasSession = await client._hasSession()
            XCTAssertTrue(hasSession)
            let csrf = await client._csrfToken()
            XCTAssertEqual(csrf, "csrf-setup")

            let sent = try XCTUnwrap(
                server.state.requests(pathContaining: "mfa/setup/confirm").first
            )
            let body = try XCTUnwrap(JSONSerialization.jsonObject(with: sent.body) as? [String: Any])
            XCTAssertEqual(body["setup_token"] as? String, Self.setupToken)
            XCTAssertEqual(body["totp_code"] as? String, "123456")
        }
    }

    // MARK: - §25.1 email verification

    func testVerifyEmailNeedsNoSessionAndCarriesTheTenantInTheBody() async throws {
        try await withClient(router: { _, _ in
            TestResponse(status: 204)
        }) { client, server in
            try await client.verifyEmail(
                token: Sensitive("verify-token"),
                tenantID: Self.tenantUUID
            )

            let sent = try XCTUnwrap(server.state.requests(pathContaining: "verify-email").first)
            let body = try XCTUnwrap(JSONSerialization.jsonObject(with: sent.body) as? [String: Any])
            // Not ?tenant_id=: §12.1 rule 2's query convention is scoped to the /oauth2
            // endpoints, and this is not one of those.
            XCTAssertEqual(body["tenant_id"] as? String, Self.tenantUUID)
            XCTAssertEqual(body["token"] as? String, "verify-token")
            XCTAssertFalse(sent.uri.contains("tenant_id="))
        }
    }

    func testResendVerificationAccepts202() async throws {
        try await withClient(router: { _, _ in
            TestResponse(status: 202)
        }) { client, server in
            try await client.resendVerification(
                email: "alice@example.com",
                tenantID: Self.tenantUUID
            )
            XCTAssertEqual(server.state.requests(pathContaining: "resend-verification").count, 1)
        }
    }

    func testAnExpiredVerificationTokenIsAnError() async throws {
        try await withClient(router: { _, _ in
            .json(400, ["message": "token expired"])
        }) { client, _ in
            do {
                try await client.verifyEmail(token: Sensitive("stale"), tenantID: Self.tenantUUID)
                XCTFail("expected a network error")
            } catch AxiamError.network {
                // expected
            }
        }
    }

    // MARK: - §25.4 password reset

    func testRequestPasswordResetSaysNothingAboutWhetherTheAccountExists() async throws {
        try await withClient(router: { _, _ in
            TestResponse(status: 202)
        }) { client, server in
            // Both an existing and an unknown address answer 202 with an empty body, and
            // the SDK returns Void — there is no field, no boolean and no exception for a
            // caller to build an enumeration oracle out of.
            try await client.requestPasswordReset(PasswordResetRequest(email: "alice@example.com"))
            try await client.requestPasswordReset(PasswordResetRequest(email: "nobody@example.com"))

            XCTAssertEqual(server.state.requests(pathContaining: "auth/reset").count, 2)
        }
    }

    func testRequestPasswordResetFillsTheWorkspaceFromTheClient() async throws {
        try await withClient(router: { _, _ in
            TestResponse(status: 202)
        }) { client, server in
            try await client.requestPasswordReset(PasswordResetRequest(email: "alice@example.com"))

            let sent = try XCTUnwrap(server.state.requests(pathContaining: "auth/reset").first)
            let body = try XCTUnwrap(JSONSerialization.jsonObject(with: sent.body) as? [String: Any])
            XCTAssertEqual(body["org_slug"] as? String, "globex")
            XCTAssertEqual(body["tenant_slug"] as? String, "acme")
        }
    }

    func testAnExplicitWorkspaceWinsOverTheClientConfiguration() async throws {
        try await withClient(router: { _, _ in
            TestResponse(status: 202)
        }) { client, server in
            try await client.requestPasswordReset(PasswordResetRequest(
                email: "alice@example.com",
                orgSlug: "other-org",
                tenantID: Self.tenantUUID
            ))

            let sent = try XCTUnwrap(server.state.requests(pathContaining: "auth/reset").first)
            let body = try XCTUnwrap(JSONSerialization.jsonObject(with: sent.body) as? [String: Any])
            XCTAssertEqual(body["org_slug"] as? String, "other-org")
            XCTAssertEqual(body["tenant_id"] as? String, Self.tenantUUID)
            XCTAssertNil(body["tenant_slug"], "a resolved tenant_id makes tenant_slug ambiguous")
        }
    }

    func testResetContextSendsTheTokenAsAQueryParameter() async throws {
        try await withClient(router: { _, _ in
            .json(200, ["opaque": NSNull()])
        }) { client, server in
            _ = try await client.passwordResetContext(token: Sensitive(Self.resetToken))

            let sent = try XCTUnwrap(server.state.requests(pathContaining: "reset/context").first)
            XCTAssertEqual(sent.method, "GET")
            // Not percent-escaped into the path, which 404s in a way that reads exactly
            // like an expired token.
            XCTAssertTrue(sent.uri.hasPrefix("/api/v1/auth/reset/context?token="), sent.uri)
            XCTAssertTrue(sent.uri.contains(Self.resetToken), sent.uri)
        }
    }

    func testATenantWithoutOpaqueReportsNoPolicy() async throws {
        try await withClient(router: { _, _ in
            .json(200, ["opaque": NSNull()])
        }) { client, _ in
            let context = try await client.passwordResetContext(token: Sensitive(Self.resetToken))
            XCTAssertFalse(context.hasOpaquePolicy, "no policy means the plaintext path is allowed")
            XCTAssertNil(context.opaqueData)
        }
    }

    func testATenantWithOpaqueHandsBackTheParametersUntouched() async throws {
        let opaque: [String: Any] = [
            "mode": "required",
            "cipher_suite": "ristretto255-sha512",
            "server_public_key": "c2VydmVyLXBr",
            "vendorSpecific": "must-survive",
        ]
        let encoded = TestResponse.jsonBody(["opaque": opaque])
        try await withClient(router: { _, _ in
            TestResponse(status: 200, body: encoded)
        }) { client, _ in
            let context = try await client.passwordResetContext(token: Sensitive(Self.resetToken))

            XCTAssertTrue(context.hasOpaquePolicy)
            // Structural equality: the SDK does not model, validate or re-encode the §23
            // parameter block, it forwards it.
            XCTAssertEqual(
                NSDictionary(dictionary: try XCTUnwrap(context.opaqueObject())),
                NSDictionary(dictionary: opaque)
            )
        }
    }

    func testUnknownExpiredAndConsumedResetTokensAllLookAlike() async throws {
        try await withClient(router: { _, _ in
            // §25.4 rule 3: the server refuses to distinguish these three, and the SDK must
            // not invent a distinction of its own.
            .json(404, [:])
        }) { client, _ in
            do {
                _ = try await client.passwordResetContext(token: Sensitive(Self.resetToken))
                XCTFail("expected a network error")
            } catch AxiamError.network {
                // expected
            }
        }
    }

    func testConfirmSendsThePlaintextPasswordWhenTheTenantHasNoOpaque() async throws {
        try await withClient(router: { _, _ in
            TestResponse(status: 204)
        }) { client, server in
            try await client.confirmPasswordReset(PasswordResetConfirmation(
                token: Self.resetToken,
                newPassword: "new-password",
                tenantID: Self.tenantUUID
            ))

            let sent = try XCTUnwrap(server.state.requests(pathContaining: "reset/confirm").first)
            let body = try XCTUnwrap(JSONSerialization.jsonObject(with: sent.body) as? [String: Any])
            XCTAssertEqual(body["new_password"] as? String, "new-password")
            XCTAssertEqual(body["tenant_id"] as? String, Self.tenantUUID)
            XCTAssertNil(body["opaque"])
        }
    }

    func testConfirmForwardsTheOpaqueRegistrationRecordVerbatim() async throws {
        let record: [String: Any] = [
            "registration_record": "cmVjb3Jk",
            "export_key_hint": "aGludA",
        ]
        let recordData = try JSONSerialization.data(withJSONObject: record)

        try await withClient(router: { _, _ in
            TestResponse(status: 204)
        }) { client, server in
            try await client.confirmPasswordReset(PasswordResetConfirmation(
                token: Sensitive(Self.resetToken),
                newPassword: Sensitive("unused"),
                tenantID: Self.tenantUUID,
                opaqueData: recordData
            ))

            let sent = try XCTUnwrap(server.state.requests(pathContaining: "reset/confirm").first)
            let raw = String(decoding: sent.body, as: UTF8.self)
            // Byte-for-byte: the §23 record is not modelled by this SDK, so it is spliced
            // in exactly as the §23 helpers produced it.
            XCTAssertTrue(
                raw.contains(String(decoding: recordData, as: UTF8.self)),
                "the §23 record was re-encoded: \(raw)"
            )
        }
    }

    func testARejectedResetSurfacesTheError() async throws {
        try await withClient(router: { _, _ in
            .json(400, ["message": "password does not meet policy"])
        }) { client, _ in
            do {
                try await client.confirmPasswordReset(PasswordResetConfirmation(
                    token: Self.resetToken,
                    newPassword: "x",
                    tenantID: Self.tenantUUID
                ))
                XCTFail("expected a network error")
            } catch AxiamError.network {
                // expected
            }
        }
    }

    func testNoResetSecretAppearsInARenderedValue() {
        let confirmation = PasswordResetConfirmation(
            token: Self.resetToken,
            newPassword: "a new correct horse battery staple",
            tenantID: Self.tenantUUID
        )
        XCTAssertFalse("\(confirmation.token)".contains(Self.resetToken))
        XCTAssertFalse("\(confirmation.newPassword)".contains("correct horse"))
    }
}
