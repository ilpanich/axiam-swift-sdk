import Foundation
import XCTest
@testable import AxiamSDK

/// `loginOpaque` / `opaqueEnrollment` end to end (CONTRACT.md §23).
///
/// The protocol is `libaxiam_opaque_ffi`'s and the binding is covered by `OpaqueBindingTests`.
/// What is tested here is the part the SDK owns: what goes on the wire — and, more importantly,
/// what does *not* — which failures are auth errors and which are network errors, and that a
/// failed credential check never reaches `login/finish`.
final class OpaqueLoginTests: XCTestCase {

    /// The hex `KE2` and `RegistrationResponse` the fake server answers with.
    ///
    /// Hex because that is what the wire carries; the binding hands them to the library verbatim
    /// and the fake library echoes them back inside its own payload, which is how these tests see
    /// that nothing was rewritten in between.
    private static let wireKe2 = "6b6532"
    private static let wireRegistrationResponse = "726573703a"

    private static let user = "alice"

    /// The §3 login union's `200` body, shared by `login/finish` and the plaintext `/auth/login`
    /// so a test can tell which endpoint produced a result by the username it carries.
    static func sessionBody(username: String) -> [String: Any] {
        [
            "user": [
                "id": "11111111-1111-1111-1111-111111111111",
                "username": username,
                "email": "alice@example.test",
                "tenant_id": "22222222-2222-2222-2222-222222222222",
                "tenant_slug": "acme",
                "org_slug": "globex",
            ],
            "session_id": "55555555-5555-5555-5555-555555555555",
            "expires_in": 900,
        ]
    }

    private var lib: FakeOpaqueNative!

    /// Minted per run rather than written down; nothing here depends on the value.
    private var password = ""

    override func setUp() {
        super.setUp()
        lib = FakeOpaqueNative()
        OpaqueLibrary.setForTests(lib)
        password = "correct-"
            + (0..<8).map { _ in String(format: "%02x", UInt8.random(in: 0...255)) }.joined()
    }

    override func tearDown() {
        OpaqueLibrary.resetForTests()
        lib = nil
        super.tearDown()
    }

    // MARK: - The transport

    /// A server that answers the three OPAQUE endpoints and records what it saw.
    final class OpaqueTransport: HTTPTransport, @unchecked Sendable {
        private let lock = NSLock()

        var loginStartStatus = 200
        var loginFinishStatus = 200
        var registerStartStatus = 200
        var mfaRequired = false
        var mfaSetupRequired = false
        var omitKe2 = false
        var omitRegistrationResponse = false
        var malformedStartBody = false
        var ksf = "argon2id"

        /// The tenant's `opaque_mode`, echoed in the `login/start` response.
        ///
        /// `nil` models a server older than contract 1.29, which omits the field entirely — a
        /// case §23.4 rule 7 gives a defined meaning rather than leaving open.
        var loginMode: String?

        /// What the **plaintext** `POST /auth/login` answers, for the §23.4 rule 7 retry.
        var passwordLoginStatus = 200

        private(set) var loginStartBodies: [Data] = []
        private(set) var loginFinishBodies: [Data] = []
        private(set) var registerStartBodies: [Data] = []

        /// Every body that reached `POST /api/v1/auth/login`. Under `required` and under a server
        /// that names no mode this MUST stay empty: the assertion is that no plaintext password
        /// went on the wire, which is not observable from the returned error.
        private(set) var passwordLoginBodies: [Data] = []

        private func json(_ status: Int, _ object: Any) -> HTTPResponseData {
            let data = (try? JSONSerialization.data(withJSONObject: object)) ?? Data()
            return HTTPResponseData(
                status: status, headers: [("Content-Type", "application/json")], body: data)
        }

        private func ksfFields() -> [String: Any] {
            if ksf == "scrypt" {
                return ["ksf": "scrypt", "log_n": 15, "r": 8, "p": 1]
            }
            return ["ksf": ksf, "memory_kib": 19456, "iterations": 2, "parallelism": 1]
        }

        func execute(_ spec: HTTPRequestSpec, timeout: TimeInterval) async throws
            -> HTTPResponseData
        {
            // The routing decision is one synchronous critical section — it appends to the
            // recorded-body arrays and reads the scripted flags under the lock, and there is
            // no suspension point anywhere inside it. Splitting it out is what lets that stay
            // true by construction under Swift 6's `noasync` rule for `NSLock`.
            lock.locked { respond(to: spec) }
        }

        private func respond(to spec: HTTPRequestSpec) -> HTTPResponseData {
            let path = spec.url.path
            if path.hasSuffix("/auth/opaque/login/start") {
                loginStartBodies.append(spec.body ?? Data())
                guard loginStartStatus == 200 else { return json(loginStartStatus, [:]) }
                if malformedStartBody {
                    return HTTPResponseData(
                        status: 200,
                        headers: [("Content-Type", "application/json")],
                        body: Data("not json at all".utf8))
                }
                var body: [String: Any] = ["opaque_session": "handle-42"]
                if !omitKe2 { body["ke2"] = OpaqueLoginTests.wireKe2 }
                if let mode = loginMode { body["mode"] = mode }
                body.merge(ksfFields()) { current, _ in current }
                return json(200, body)
            }

            if path.hasSuffix("/auth/opaque/login/finish") {
                loginFinishBodies.append(spec.body ?? Data())
                if mfaSetupRequired {
                    return json(403, ["mfa_setup_required": true, "setup_token": "setup"])
                }
                guard loginFinishStatus == 200 else { return json(loginFinishStatus, [:]) }
                if mfaRequired {
                    return json(202, [
                        "mfa_required": true,
                        "challenge_token": "mfa-challenge",
                        "available_methods": ["totp"],
                    ])
                }
                return json(200, OpaqueLoginTests.sessionBody(username: OpaqueLoginTests.user))
            }

            // The plaintext endpoint, reached only by §23.4 rule 7's `optional` retry.
            if path.hasSuffix("/auth/login") {
                passwordLoginBodies.append(spec.body ?? Data())
                guard passwordLoginStatus == 200 else { return json(passwordLoginStatus, [:]) }
                return json(200, OpaqueLoginTests.sessionBody(username: "alice-via-password"))
            }

            if path.hasSuffix("/auth/opaque/register/start") {
                registerStartBodies.append(spec.body ?? Data())
                guard registerStartStatus == 200 else { return json(registerStartStatus, [:]) }
                var body: [String: Any] = ["opaque_session": "reg-handle"]
                if !omitRegistrationResponse {
                    body["registration_response"] = OpaqueLoginTests.wireRegistrationResponse
                }
                body.merge(ksfFields()) { current, _ in current }
                return json(200, body)
            }

            return json(404, ["message": "not found"])
        }

        func shutdown() async throws {}
    }

    private func client(_ transport: OpaqueTransport) throws -> AxiamClient {
        let config = try AxiamConfig(
            baseURL: URL(string: "https://iam.example.com")!,
            tenantSlug: "acme",
            orgSlug: "globex"
        )
        return AxiamClient(config: config, transport: transport)
    }

    private func decoded(_ body: Data) throws -> [String: Any] {
        let object = try JSONSerialization.jsonObject(with: body)
        return object as? [String: Any] ?? [:]
    }

    // MARK: - What crosses the wire

    func testLoginStartCarriesKe1AndNoPasswordField() async throws {
        let transport = OpaqueTransport()
        _ = try await client(transport).loginOpaque(
            usernameOrEmail: Self.user, password: password)

        let body = try decoded(transport.loginStartBodies[0])
        // The entire point of the exchange. A body that still carried a password
        // would be SRP's failure mode with extra steps.
        XCTAssertNil(body["password"])
        XCTAssertEqual(body["username_or_email"] as? String, Self.user)
        XCTAssertEqual(body["tenant_slug"] as? String, "acme")
        XCTAssertEqual(
            FakeOpaqueNative.decode(body["ke1"] as? String ?? ""), "ke1:" + password)
    }

    func testRegisterStartNamesNoAccountAtAll() async throws {
        let transport = OpaqueTransport()
        let enrollment = try await client(transport).opaqueEnrollment(password: password)

        XCTAssertEqual(enrollment.opaque_session, "reg-handle")
        XCTAssertTrue(
            FakeOpaqueNative.decode(enrollment.registration_record)
                .hasPrefix("record:\(password):\(Self.wireRegistrationResponse):"))

        let body = try decoded(transport.registerStartBodies[0])
        XCTAssertNil(body["password"])
        // No username either: a record binds to a credential identifier the server
        // chooses, which is why a later rename cannot invalidate one.
        XCTAssertNil(body["username_or_email"])
        XCTAssertEqual(body["tenant_slug"] as? String, "acme")
        XCTAssertEqual(
            FakeOpaqueNative.decode(body["registration_request"] as? String ?? ""),
            "req:" + password)
    }

    func testLoginFinishEchoesTheSessionHandleTheServerIssued() async throws {
        let transport = OpaqueTransport()
        _ = try await client(transport).loginOpaque(
            usernameOrEmail: Self.user, password: password)

        let body = try decoded(transport.loginFinishBodies[0])
        XCTAssertEqual(body["opaque_session"] as? String, "handle-42")
        XCTAssertTrue(
            FakeOpaqueNative.decode(body["ke3"] as? String ?? "")
                .hasPrefix("ke3:\(password):\(Self.wireKe2):"))
    }

    func testTheServerNamedKsfIsTheOneUsed() async throws {
        // §23.4 rule 2: never local defaults. A credential enrolled under one cost
        // keeps working after a tenant raises its policy, so a client that guessed
        // would fail against a record that is perfectly good.
        let transport = OpaqueTransport()
        transport.ksf = "scrypt"
        _ = try await client(transport).loginOpaque(
            usernameOrEmail: Self.user, password: password)

        // The fake encodes the handle it was given; scrypt handles start 0xb.
        let body = try decoded(transport.loginFinishBodies[0])
        XCTAssertTrue(
            FakeOpaqueNative.decode(body["ke3"] as? String ?? "")
                .hasSuffix(":" + String(0xB_0000 + 15 + 8 + 1, radix: 16)))
    }

    // MARK: - Results

    func testASuccessfulLoginReturnsWhatLoginReturns() async throws {
        let transport = OpaqueTransport()
        let axiam = try client(transport)

        let available = await axiam.opaqueAvailable()
        XCTAssertTrue(available)

        let result = try await axiam.loginOpaque(
            usernameOrEmail: Self.user, password: password)

        guard case .authenticated(let user) = result else {
            return XCTFail("expected .authenticated, got \(result)")
        }
        XCTAssertEqual(user.userID, "11111111-1111-1111-1111-111111111111")
        XCTAssertEqual(user.tenantID, "22222222-2222-2222-2222-222222222222")
    }

    func testTheMfaRequiredBranchSurvivesTheOpaquePath() async throws {
        // One result handler must serve both login paths, so the second phase has
        // to arrive here exactly as it does from login().
        let transport = OpaqueTransport()
        transport.mfaRequired = true

        let result = try await client(transport).loginOpaque(
            usernameOrEmail: Self.user, password: password)

        guard case .mfaRequired(let methods) = result else {
            return XCTFail("expected .mfaRequired, got \(result)")
        }
        XCTAssertEqual(methods, ["totp"])
    }

    func testTheMfaSetupBranchSurvivesTheOpaquePathToo() async throws {
        // A 403 whose body says `mfa_setup_required` is the login FLOW, not an
        // authorization denial. login() disambiguates on the body shape and so
        // must this, or the one result handler §23.1 promises has a hole in it.
        let transport = OpaqueTransport()
        transport.mfaSetupRequired = true

        let result = try await client(transport).loginOpaque(
            usernameOrEmail: Self.user, password: password)

        guard case .mfaSetupRequired(let setupToken) = result else {
            return XCTFail("expected mfaSetupRequired, got \(result)")
        }
        // §25.2 rule 1: the outcome carries the token that completes the login it
        // interrupted. An enrolment branch without one tells the caller what is wrong and
        // withholds the only thing that can fix it.
        XCTAssertEqual(setupToken.expose(), "setup")
    }

    // MARK: - Failures

    /// Runs `body` and returns the error it threw, failing the test if it did not throw.
    private func error(
        from body: () async throws -> Void,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async -> Error? {
        do {
            try await body()
            XCTFail("expected an error", file: file, line: line)
            return nil
        } catch {
            return error
        }
    }

    func testADisabledTenantIsANetworkErrorACallerCanFallBackFrom() async {
        // A 404 is a property of the tenant, not of the credentials. As an auth
        // error it would be shown as "invalid password" and send a user to reset a
        // working one, while stopping a fallback to login().
        let transport = OpaqueTransport()
        transport.loginStartStatus = 404

        let thrown = await error {
            _ = try await self.client(transport).loginOpaque(
                usernameOrEmail: Self.user, password: self.password)
        }

        guard case .network(let networkError)? = thrown as? AxiamError else {
            return XCTFail("expected a network error, got \(String(describing: thrown))")
        }
        XCTAssertTrue("\(networkError)".contains("opaque_mode is disabled"))
        XCTAssertTrue(transport.loginFinishBodies.isEmpty)
    }

    func testEnrolmentReportsADisabledTenantTheSameWay() async {
        let transport = OpaqueTransport()
        transport.registerStartStatus = 404

        let thrown = await error {
            _ = try await self.client(transport).opaqueEnrollment(password: self.password)
        }

        guard case .network(let networkError)? = thrown as? AxiamError else {
            return XCTFail("expected a network error, got \(String(describing: thrown))")
        }
        XCTAssertTrue("\(networkError)".contains("opaque_mode is disabled"))
    }

    func testARegisterStartWithoutARegistrationResponseIsAMalformedResponse() async {
        // The enrolment twin of the missing-`ke2` case. Passing an empty string
        // on to the library would spend the exchange to produce a record no
        // server can ever accept.
        let transport = OpaqueTransport()
        transport.omitRegistrationResponse = true

        let thrown = await error {
            _ = try await self.client(transport).opaqueEnrollment(password: self.password)
        }

        guard case .network(let networkError)? = thrown as? AxiamError else {
            return XCTFail("expected a network error, got \(String(describing: thrown))")
        }
        XCTAssertTrue("\(networkError)".contains("no `registration_response`"))
        XCTAssertEqual(lib.statesAlive, 0)
    }

    func testA401AtRegisterStartIsAnAuthError() async {
        let transport = OpaqueTransport()
        transport.registerStartStatus = 401

        let thrown = await error {
            _ = try await self.client(transport).opaqueEnrollment(password: self.password)
        }

        guard case .auth? = thrown as? AxiamError else {
            return XCTFail("expected an auth error, got \(String(describing: thrown))")
        }
        XCTAssertEqual(lib.statesAlive, 0)
    }

    func testAMalformedStartBodyIsANetworkErrorNamingTheEndpoint() async {
        let transport = OpaqueTransport()
        transport.malformedStartBody = true

        let thrown = await error {
            _ = try await self.client(transport).loginOpaque(
                usernameOrEmail: Self.user, password: self.password)
        }

        guard case .network(let networkError)? = thrown as? AxiamError else {
            return XCTFail("expected a network error, got \(String(describing: thrown))")
        }
        XCTAssertTrue("\(networkError)".contains("login/start"))
        XCTAssertEqual(lib.statesAlive, 0)
    }

    func testAnEnrolmentRefusesAKsfItCannotAskFor() async {
        let transport = OpaqueTransport()
        transport.ksf = "bcrypt"

        let thrown = await error {
            _ = try await self.client(transport).opaqueEnrollment(password: self.password)
        }

        guard case .network(let networkError)? = thrown as? AxiamError else {
            return XCTFail("expected a network error, got \(String(describing: thrown))")
        }
        XCTAssertTrue("\(networkError)".contains("bcrypt"))
        XCTAssertEqual(lib.statesAlive, 0)
    }

    func testA401AtLoginStartIsAnAuthError() async {
        let transport = OpaqueTransport()
        transport.loginStartStatus = 401

        let thrown = await error {
            _ = try await self.client(transport).loginOpaque(
                usernameOrEmail: Self.user, password: self.password)
        }

        guard case .auth? = thrown as? AxiamError else {
            return XCTFail("expected an auth error, got \(String(describing: thrown))")
        }
    }

    func testAWrongPasswordNeverReachesLoginFinish() async {
        // §23.4 rule 7. The envelope failing to open IS the authentication check;
        // sending anything afterwards would ask the server to decide something the
        // client has already decided.
        lib.fail("login_finish")
        let transport = OpaqueTransport()

        let thrown = await error {
            _ = try await self.client(transport).loginOpaque(
                usernameOrEmail: Self.user, password: self.password)
        }

        guard case .auth? = thrown as? AxiamError else {
            return XCTFail("expected an auth error, got \(String(describing: thrown))")
        }
        XCTAssertTrue(transport.loginFinishBodies.isEmpty)
    }

    // MARK: - §23.4 rule 7: what `mode` decides (contract 1.29)

    /// A failed `KE2` under `optional` is the ORDINARY case, not a wrong password: every account
    /// has no registration record the moment an operator enables OPAQUE and acquires one only when
    /// its password is next set. Reporting the failure would lock out every user of a tenant
    /// mid-migration, which is the state `optional` exists to serve.
    func testAnOptionalTenantRetriesOverPasswordLogin() async throws {
        lib.fail("login_finish")
        let transport = OpaqueTransport()
        transport.loginMode = "optional"

        let result = try await client(transport).loginOpaque(
            usernameOrEmail: Self.user, password: password)

        // The retry's outcome IS the outcome — a successful login, not an error.
        guard case .authenticated(let user) = result else {
            return XCTFail("expected .authenticated, got \(result)")
        }
        // Answered by /auth/login, not by login/finish.
        XCTAssertEqual(user.username, "alice-via-password")

        // Rule 7's other half holds regardless of mode: KE3 was never sent.
        XCTAssertTrue(transport.loginFinishBodies.isEmpty)

        // Exactly one retry, carrying the same credentials over the plaintext path.
        XCTAssertEqual(transport.passwordLoginBodies.count, 1)
        let body = try decoded(transport.passwordLoginBodies[0])
        XCTAssertEqual(body["username_or_email"] as? String, Self.user)
        XCTAssertEqual(body["password"] as? String, password)
        XCTAssertEqual(lib.statesAlive, 0)
    }

    func testAnOptionalTenantSurfacesThePasswordLoginFailure() async {
        // The retry is not a second chance for the SDK to invent an outcome: the
        // fallback's error is what the caller gets, so a genuinely wrong password
        // still ends as an auth error rather than being swallowed.
        lib.fail("login_finish")
        let transport = OpaqueTransport()
        transport.loginMode = "optional"
        transport.passwordLoginStatus = 401

        let thrown = await error {
            _ = try await self.client(transport).loginOpaque(
                usernameOrEmail: Self.user, password: self.password)
        }

        guard case .auth? = thrown as? AxiamError else {
            return XCTFail("expected an auth error, got \(String(describing: thrown))")
        }
        XCTAssertEqual(transport.passwordLoginBodies.count, 1)
        XCTAssertTrue(transport.loginFinishBodies.isEmpty)
    }

    func testARequiredTenantNeverPutsThePlaintextOnTheWire() async {
        // `required` answers 403 opaque_required for every principal before it looks
        // at any credential, so a retry could only ever leak a plaintext password
        // for nothing.
        lib.fail("login_finish")
        let transport = OpaqueTransport()
        transport.loginMode = "required"

        let thrown = await error {
            _ = try await self.client(transport).loginOpaque(
                usernameOrEmail: Self.user, password: self.password)
        }

        guard case .auth? = thrown as? AxiamError else {
            return XCTFail("expected an auth error, got \(String(describing: thrown))")
        }
        XCTAssertTrue(transport.passwordLoginBodies.isEmpty)
        XCTAssertTrue(transport.loginFinishBodies.isEmpty)
    }

    func testAStartResponseWithNoModeFieldFailsClosed() async {
        // A server older than contract 1.29 names no mode. Absence is not "unknown,
        // so try both" — rule 7 gives it the `required` meaning, which is the side
        // that sends nothing.
        lib.fail("login_finish")
        let transport = OpaqueTransport()
        XCTAssertNil(transport.loginMode)

        let thrown = await error {
            _ = try await self.client(transport).loginOpaque(
                usernameOrEmail: Self.user, password: self.password)
        }

        guard case .auth? = thrown as? AxiamError else {
            return XCTFail("expected an auth error, got \(String(describing: thrown))")
        }
        XCTAssertTrue(transport.passwordLoginBodies.isEmpty)
        XCTAssertTrue(transport.loginFinishBodies.isEmpty)
    }

    func testAnUnrecognisedModeIsTreatedAsRequired() async {
        // Fail closed. A future mode this build has never heard of must not be the
        // one value that opens a plaintext fallback.
        lib.fail("login_finish")
        let transport = OpaqueTransport()
        transport.loginMode = "optional-ish"

        let thrown = await error {
            _ = try await self.client(transport).loginOpaque(
                usernameOrEmail: Self.user, password: self.password)
        }

        guard case .auth? = thrown as? AxiamError else {
            return XCTFail("expected an auth error, got \(String(describing: thrown))")
        }
        XCTAssertTrue(transport.passwordLoginBodies.isEmpty)
        XCTAssertTrue(transport.loginFinishBodies.isEmpty)
    }

    func testAnOptionalTenantDoesNotFallBackForANonCredentialFailure() async {
        // Rule 7's retry is for the credential check specifically. A key-stretching
        // function this build cannot ask for is a configuration gap, and retrying it
        // over the plaintext path would hide a misconfigured tenant behind a
        // password prompt.
        let transport = OpaqueTransport()
        transport.loginMode = "optional"
        transport.ksf = "bcrypt"

        let thrown = await error {
            _ = try await self.client(transport).loginOpaque(
                usernameOrEmail: Self.user, password: self.password)
        }

        guard case .network(let networkError)? = thrown as? AxiamError else {
            return XCTFail("expected a network error, got \(String(describing: thrown))")
        }
        XCTAssertTrue("\(networkError)".contains("bcrypt"))
        XCTAssertTrue(transport.passwordLoginBodies.isEmpty)
        XCTAssertTrue(transport.loginFinishBodies.isEmpty)
    }

    func testAnUnsupportedKsfIsAConfigurationErrorNotABadPassword() async {
        let transport = OpaqueTransport()
        transport.ksf = "bcrypt"

        let thrown = await error {
            _ = try await self.client(transport).loginOpaque(
                usernameOrEmail: Self.user, password: self.password)
        }

        guard case .network(let networkError)? = thrown as? AxiamError else {
            return XCTFail("expected a network error, got \(String(describing: thrown))")
        }
        XCTAssertTrue("\(networkError)".contains("bcrypt"))
        XCTAssertTrue(transport.loginFinishBodies.isEmpty)
        // The exchange was abandoned rather than spent, and loginOpaque's defer
        // must have released it -- otherwise a misconfigured tenant leaks once per
        // login attempt.
        XCTAssertEqual(lib.statesAlive, 0)
    }

    func testAStartResponseWithoutKe2IsAMalformedResponse() async {
        let transport = OpaqueTransport()
        transport.omitKe2 = true

        let thrown = await error {
            _ = try await self.client(transport).loginOpaque(
                usernameOrEmail: Self.user, password: self.password)
        }

        guard case .network(let networkError)? = thrown as? AxiamError else {
            return XCTFail("expected a network error, got \(String(describing: thrown))")
        }
        XCTAssertTrue("\(networkError)".contains("no `ke2`"))
        XCTAssertEqual(lib.statesAlive, 0)
    }

    func testA5xxAtLoginFinishIsAnError() async {
        let transport = OpaqueTransport()
        transport.loginFinishStatus = 503

        let thrown = await error {
            _ = try await self.client(transport).loginOpaque(
                usernameOrEmail: Self.user, password: self.password)
        }

        XCTAssertNotNil(thrown)
    }

    func testAnAbsentLibraryIsReportedBeforeAnyRequestIsSent() async {
        OpaqueLibrary.setForTests(nil)
        let transport = OpaqueTransport()
        let axiam = try? client(transport)
        XCTAssertNotNil(axiam)

        let available = await axiam?.opaqueAvailable()
        XCTAssertEqual(available, false)

        let thrown = await error {
            _ = try await axiam?.loginOpaque(
                usernameOrEmail: Self.user, password: self.password)
        }

        guard case .network(let networkError)? = thrown as? AxiamError else {
            return XCTFail("expected a network error, got \(String(describing: thrown))")
        }
        XCTAssertTrue("\(networkError)".contains("libaxiam_opaque_ffi"))
        XCTAssertTrue(transport.loginStartBodies.isEmpty)
    }
}
