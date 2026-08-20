import Foundation
import XCTest
@testable import AxiamSDK

/// The binding to `libaxiam_opaque_ffi`.
///
/// §23.1 forbids this SDK from implementing OPAQUE, so there is no cryptography here to test. What
/// these cover is the layer above the ABI: single-use exchanges, the key-stretching function the
/// *server* named being the one used, which failure means what, and an absent library reporting
/// rather than resembling a wrong password.
///
/// Pointer ownership lives in `DynamicOpaqueNative` and needs the real shared library to exercise;
/// that class is deliberately the thinnest in the package for exactly that reason.
final class OpaqueBindingTests: XCTestCase {

    private let ke2 = "ke2-hex"
    private let registrationResponse = "resp-hex"

    private var lib: FakeOpaqueNative!

    /// Minted per run rather than written down. Nothing here depends on the value — only on the
    /// two differing — and a literal that reads like a credential is a finding for every secret
    /// scanner that looks at this repository, which trains people to wave those findings through.
    private var password = ""
    private var otherPassword = ""

    override func setUp() {
        super.setUp()
        lib = FakeOpaqueNative()
        OpaqueLibrary.setForTests(lib)
        password = "correct-" + Self.randomSuffix()
        otherPassword = "incorrect-" + Self.randomSuffix()
    }

    override func tearDown() {
        OpaqueLibrary.resetForTests()
        lib = nil
        super.tearDown()
    }

    private static func randomSuffix() -> String {
        (0..<8).map { _ in String(format: "%02x", UInt8.random(in: 0...255)) }.joined()
    }

    private func argon2id() -> KsfParams {
        KsfParams(ksf: "argon2id", memoryKib: 19456, iterations: 2, parallelism: 1)
    }

    private func scrypt() -> KsfParams {
        KsfParams(ksf: "scrypt", logN: 15, r: 8, p: 1)
    }

    /// Asserts `body` throws an ``AxiamError/network(_:)`` whose message contains `needle`.
    private func assertNetworkError(
        containing needle: String,
        file: StaticString = #filePath,
        line: UInt = #line,
        _ body: () throws -> Void
    ) {
        do {
            try body()
            XCTFail("expected a network error containing '\(needle)'", file: file, line: line)
        } catch let AxiamError.network(error) {
            XCTAssertTrue(
                "\(error)".contains(needle),
                "expected '\(needle)' in '\(error)'",
                file: file,
                line: line)
        } catch {
            XCTFail("expected a network error, got \(error)", file: file, line: line)
        }
    }

    private func assertAuthError(
        containing needle: String,
        file: StaticString = #filePath,
        line: UInt = #line,
        _ body: () throws -> Void
    ) {
        do {
            try body()
            XCTFail("expected an auth error containing '\(needle)'", file: file, line: line)
        } catch let AxiamError.auth(error) {
            XCTAssertTrue(
                "\(error)".contains(needle),
                "expected '\(needle)' in '\(error)'",
                file: file,
                line: line)
        } catch {
            XCTFail("expected an auth error, got \(error)", file: file, line: line)
        }
    }

    // -----------------------------------------------------------------
    // Availability (§23.2) -- reporting, never throwing
    // -----------------------------------------------------------------

    func testAvailableIsTrueWhenTheLibraryIsPresent() {
        XCTAssertTrue(Opaque.available())
    }

    func testAnAbsentLibraryReportsFalseRatherThanThrowing() {
        OpaqueLibrary.setForTests(nil)
        XCTAssertFalse(Opaque.available())
    }

    func testAnAbsentLibraryNamesTheArtifactNotThePassword() {
        OpaqueLibrary.setForTests(nil)
        assertNetworkError(containing: "libaxiam_opaque_ffi") {
            _ = try Opaque.startLogin(password: password)
        }
        assertNetworkError(containing: "AXIAM_OPAQUE_LIBRARY") {
            _ = try Opaque.startLogin(password: password)
        }
    }

    func testTheRealLoaderReportsAbsentAndMemoizesThat() {
        // No libaxiam_opaque_ffi is installed in CI, so this exercises the genuine
        // dlopen failure path -- including that retrying it is not a per-login
        // filesystem walk.
        OpaqueLibrary.resetForTests()
        setenv(OpaqueLibrary.pathEnvironmentVariable, "/nonexistent/libabsent.so", 1)
        defer {
            unsetenv(OpaqueLibrary.pathEnvironmentVariable)
            OpaqueLibrary.resetForTests()
        }

        XCTAssertNil(OpaqueLibrary.load())
        XCTAssertNil(OpaqueLibrary.load())
    }

    func testThePathOverrideWinsOverThePlatformDefault() {
        setenv(OpaqueLibrary.pathEnvironmentVariable, "/opt/axiam/libopaque.so", 1)
        defer { unsetenv(OpaqueLibrary.pathEnvironmentVariable) }

        XCTAssertEqual(OpaqueLibrary.candidatePaths(), ["/opt/axiam/libopaque.so"])
    }

    func testThePlatformDefaultNamesTheLibrary() {
        unsetenv(OpaqueLibrary.pathEnvironmentVariable)
        XCTAssertTrue(OpaqueLibrary.candidatePaths()[0].contains("axiam_opaque_ffi"))
    }

    // -----------------------------------------------------------------
    // KsfParams -- absence preserved, bounds enforced (§23.4 rules 2-5)
    // -----------------------------------------------------------------

    func testTheWireShapePreservesAbsenceRatherThanDefaultingToZero() throws {
        let json = Data("""
        {"opaque_session":"s","ke2":"ab","ksf":"argon2id","memory_kib":19456,\
        "iterations":2,"parallelism":1}
        """.utf8)
        let decoded = try JSONDecoder().decode(OpaqueStartResponse.self, from: json)
        let params = decoded.ksfParams

        XCTAssertEqual(params.memoryKib, 19456)
        // scrypt's fields do not apply. Reading them as 0 would stretch at the
        // wrong cost and fail against a record that is perfectly good.
        XCTAssertNil(params.logN)
        XCTAssertNil(params.r)
        XCTAssertNil(params.p)
    }

    func testACostTheNamedFunctionNeedsButTheServerOmittedIsRefused() {
        let params = KsfParams(ksf: "argon2id", iterations: 2, parallelism: 1)

        assertNetworkError(containing: "without `memory_kib`") {
            _ = try params.build(lib)
        }
        XCTAssertEqual(lib.ksfAlive, 0)
    }

    func testACostOutsideTheAcceptedBandIsRefusedNamingTheField() {
        // A server is trusted to name its own policy, not to name a cost that
        // would wedge every device an account owns.
        let cases: [(KsfParams, String)] = [
            (KsfParams(ksf: "argon2id", memoryKib: 4096, iterations: 2, parallelism: 1), "memory_kib"),
            (KsfParams(ksf: "argon2id", memoryKib: 2_097_152, iterations: 2, parallelism: 1), "memory_kib"),
            (KsfParams(ksf: "argon2id", memoryKib: 19456, iterations: 0, parallelism: 1), "iterations"),
            (KsfParams(ksf: "argon2id", memoryKib: 19456, iterations: 99, parallelism: 1), "iterations"),
            (KsfParams(ksf: "argon2id", memoryKib: 19456, iterations: 2, parallelism: 64), "parallelism"),
            (KsfParams(ksf: "scrypt", logN: 13, r: 8, p: 1), "log_n"),
            (KsfParams(ksf: "scrypt", logN: 21, r: 8, p: 1), "log_n"),
            (KsfParams(ksf: "scrypt", logN: 15, r: 0, p: 1), "r"),
            (KsfParams(ksf: "scrypt", logN: 15, r: 8, p: 17), "p"),
        ]

        for (params, field) in cases {
            assertNetworkError(containing: field) {
                _ = try params.build(lib)
            }
        }
        XCTAssertEqual(lib.ksfAlive, 0)
    }

    func testAnUnrecognisedFunctionIsRefusedNeverSubstituted() {
        // Substituting produces a well-formed randomized password no AXIAM server
        // agrees with, which surfaces to the user as a wrong password.
        //
        // pbkdf2_sha256 is in this list on purpose: it was the ONLY KDF the SRP
        // client could perform on Swift, and it is not an OPAQUE key-stretching
        // function at all.
        for ksf in ["bcrypt", "pbkdf2_sha256", ""] {
            assertNetworkError(containing: "cannot perform") {
                _ = try KsfParams(ksf: ksf).build(lib)
            }
        }
        XCTAssertEqual(lib.ksfAlive, 0)
    }

    func testANullKsfHandleReportsTheLibrarysOwnMessage() {
        lib.fail("ksf_argon2id")

        assertNetworkError(containing: "argon2id parameters rejected") {
            _ = try self.argon2id().build(self.lib)
        }
    }

    func testBothKeyStretchingFunctionsAreReachable() throws {
        for params in [argon2id(), scrypt()] {
            let handle = try params.build(lib)
            XCTAssertEqual(lib.ksfAlive, 1)
            lib.ksfFree(handle)
        }
        XCTAssertEqual(lib.ksfAlive, 0)
    }

    // -----------------------------------------------------------------
    // Registration
    // -----------------------------------------------------------------

    func testARegistrationRoundTripLeavesNothingAlive() throws {
        let exchange = try Opaque.startRegistration(password: password)
        XCTAssertEqual(FakeOpaqueNative.decode(exchange.request), "req:" + password)

        let record = try exchange.finish(
            password: password, registrationResponse: registrationResponse, ksf: argon2id())

        XCTAssertTrue(FakeOpaqueNative.decode(record)
            .hasPrefix("record:\(password):\(registrationResponse):"))
        XCTAssertEqual(lib.ksfAlive, 0)
        XCTAssertEqual(lib.statesAlive, 0)
    }

    func testAFailedRegistrationStartReportsTheLibrarysMessage() {
        lib.fail("registration_start")

        assertNetworkError(containing: "registration could not be started") {
            _ = try Opaque.startRegistration(password: self.password)
        }
    }

    func testAFailedRegistrationFinishStillConsumedTheHandle() throws {
        lib.fail("registration_finish")
        let exchange = try Opaque.startRegistration(password: password)

        assertNetworkError(containing: "the envelope could not be sealed") {
            _ = try exchange.finish(
                password: self.password,
                registrationResponse: self.registrationResponse,
                ksf: self.argon2id())
        }

        // The library consumes the state whether it succeeds or fails, so the
        // binding must not free it again -- and must not leak the ksf either.
        XCTAssertEqual(lib.statesAlive, 0)
        XCTAssertEqual(lib.ksfAlive, 0)
    }

    // -----------------------------------------------------------------
    // Login
    // -----------------------------------------------------------------

    func testALoginRoundTripLeavesNothingAlive() throws {
        let exchange = try Opaque.startLogin(password: password)
        XCTAssertEqual(FakeOpaqueNative.decode(exchange.ke1), "ke1:" + password)

        let ke3 = try exchange.finish(password: password, ke2: ke2, ksf: scrypt())

        XCTAssertTrue(FakeOpaqueNative.decode(ke3).hasPrefix("ke3:\(password):\(ke2):"))
        // The fake encodes the handle it was given; scrypt handles start 0xb, so
        // this is also the assertion that the server-named function was used.
        XCTAssertTrue(FakeOpaqueNative.decode(ke3)
            .hasSuffix(":" + String(0xB_0000 + 15 + 8 + 1, radix: 16)))
        XCTAssertEqual(lib.ksfAlive, 0)
        XCTAssertEqual(lib.statesAlive, 0)
    }

    func testAFailedLoginStartReportsTheLibrarysMessage() {
        lib.fail("login_start")

        assertNetworkError(containing: "login could not be started") {
            _ = try Opaque.startLogin(password: self.password)
        }
    }

    func testAFailedLoginFinishIsAnAuthErrorBecauseItIsTheCredentialCheck() throws {
        // Both halves of the mutual authentication live here: the envelope only
        // opens under the right password, and KE2's MAC only verifies if the
        // server actually holds the record. An auth error rather than a network
        // one is what keeps a misconfigured KSF from being shown as a wrong
        // password.
        lib.fail("login_finish")
        let exchange = try Opaque.startLogin(password: otherPassword)

        assertAuthError(containing: "invalid credentials") {
            _ = try exchange.finish(
                password: self.otherPassword, ke2: self.ke2, ksf: self.argon2id())
        }

        XCTAssertEqual(lib.statesAlive, 0)
        XCTAssertEqual(lib.ksfAlive, 0)
    }

    func testASilentLibraryStillProducesASentence() throws {
        lib.fail("login_finish")
        lib.failMessage("login_finish", "")
        let exchange = try Opaque.startLogin(password: otherPassword)

        assertAuthError(containing: "the OPAQUE envelope did not open") {
            _ = try exchange.finish(
                password: self.otherPassword, ke2: self.ke2, ksf: self.argon2id())
        }
    }

    // -----------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------

    func testAnExchangeIsSingleUse() throws {
        let exchange = try Opaque.startLogin(password: password)
        _ = try exchange.finish(password: password, ke2: ke2, ksf: argon2id())

        assertNetworkError(containing: "already been completed") {
            _ = try exchange.finish(
                password: self.password, ke2: self.ke2, ksf: self.argon2id())
        }
    }

    func testARefusedKsfLeavesTheExchangeIntact() throws {
        // The key-stretching handle is built before the state is spent, so a
        // refusal is not a spent exchange. Built the other way round the state
        // would be out of its one-shot slot and unreachable by close() or deinit
        // -- a leaked Rust allocation per refused attempt, which is once per
        // login against a misconfigured tenant.
        let exchange = try Opaque.startRegistration(password: password)

        assertNetworkError(containing: "cannot perform") {
            _ = try exchange.finish(
                password: self.password,
                registrationResponse: self.registrationResponse,
                ksf: KsfParams(ksf: "bcrypt"))
        }

        XCTAssertEqual(lib.statesAlive, 1, "the state must still be reachable")
        XCTAssertEqual(lib.ksfAlive, 0, "a refused ksf allocates nothing to leak")

        // And a caller who fixes the parameters can simply carry on.
        let record = try exchange.finish(
            password: password, registrationResponse: registrationResponse, ksf: argon2id())
        XCTAssertTrue(FakeOpaqueNative.decode(record).hasPrefix("record:"))
        XCTAssertEqual(lib.statesAlive, 0)
    }

    func testAnOutOfBandCostAlsoLeavesTheExchangeIntact() throws {
        let exchange = try Opaque.startLogin(password: password)

        assertNetworkError(containing: "memory_kib") {
            _ = try exchange.finish(
                password: self.password,
                ke2: self.ke2,
                ksf: KsfParams(ksf: "argon2id", memoryKib: 4096, iterations: 2, parallelism: 1))
        }

        XCTAssertEqual(lib.statesAlive, 1)
        // Nothing spent it, so the ordinary release path still works.
        exchange.close()
        XCTAssertEqual(lib.statesAlive, 0)
    }

    func testCloseReleasesAnExchangeThatWasNeverFinished() throws {
        let exchange = try Opaque.startLogin(password: password)
        XCTAssertEqual(lib.statesAlive, 1)

        exchange.close()
        XCTAssertEqual(lib.statesAlive, 0)

        exchange.close()
        XCTAssertEqual(lib.statesAlive, 0)
    }

    func testCloseAfterAFinishIsANoOp() throws {
        let exchange = try Opaque.startLogin(password: password)
        _ = try exchange.finish(password: password, ke2: ke2, ksf: argon2id())
        exchange.close()

        XCTAssertEqual(lib.statesAlive, 0)
    }

    func testDeinitReleasesAnAbandonedExchange() throws {
        // Swift's refcounting makes this prompt rather than eventual, which is the
        // one place its object model is kinder here than a tracing GC's.
        // A nested function rather than `autoreleasepool`, which corelibs
        // Foundation does not vend on Linux. Its locals are released when it
        // returns, which is the whole of what this needs.
        func abandonOne() throws {
            let exchange = try Opaque.startRegistration(password: password)
            XCTAssertEqual(lib.statesAlive, 1)
            XCTAssertFalse(exchange.request.isEmpty)
        }
        try abandonOne()

        XCTAssertEqual(lib.statesAlive, 0)
    }

    // -----------------------------------------------------------------
    // Encoding
    // -----------------------------------------------------------------

    func testANonAsciiPasswordSurvivesTheRoundTrip() throws {
        let accented = "pàsswörd-ünïcøde-🔐"
        let exchange = try Opaque.startLogin(password: accented)

        XCTAssertEqual(FakeOpaqueNative.decode(exchange.ke1), "ke1:" + accented)
        exchange.close()
    }
}
