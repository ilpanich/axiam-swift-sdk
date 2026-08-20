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
        var ksf = "argon2id"

        private(set) var loginStartBodies: [Data] = []
        private(set) var loginFinishBodies: [Data] = []
        private(set) var registerStartBodies: [Data] = []

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
            lock.lock()
            defer { lock.unlock() }

            let path = spec.url.path
            if path.hasSuffix("/auth/opaque/login/start") {
                loginStartBodies.append(spec.body ?? Data())
                guard loginStartStatus == 200 else { return json(loginStartStatus, [:]) }
                var body: [String: Any] = ["opaque_session": "handle-42"]
                if !omitKe2 { body["ke2"] = OpaqueLoginTests.wireKe2 }
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
                return json(200, [
                    "user": [
                        "id": "11111111-1111-1111-1111-111111111111",
                        "username": OpaqueLoginTests.user,
                        "email": "alice@example.test",
                        "tenant_id": "22222222-2222-2222-2222-222222222222",
                        "tenant_slug": "acme",
                        "org_slug": "globex",
                    ],
                    "session_id": "55555555-5555-5555-5555-555555555555",
                    "expires_in": 900,
                ])
            }

            if path.hasSuffix("/auth/opaque/register/start") {
                registerStartBodies.append(spec.body ?? Data())
                guard registerStartStatus == 200 else { return json(registerStartStatus, [:]) }
                var body: [String: Any] = [
                    "opaque_session": "reg-handle",
                    "registration_response": OpaqueLoginTests.wireRegistrationResponse,
                ]
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

        XCTAssertEqual(result, .mfaSetupRequired)
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
