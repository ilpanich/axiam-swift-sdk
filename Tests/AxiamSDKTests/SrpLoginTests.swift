import XCTest
import Foundation
@testable import AxiamSDK

/// `loginSrp` end to end against a transport that really speaks SRP-6a
/// (CONTRACT.md §23).
///
/// `SrpVectorsTests` proves the arithmetic reproduces the cross-language
/// vectors. It says nothing about the two HTTP calls around it: which identity
/// is bound into `x`, what happens when the server names a group other than the
/// one `A` was opened in, whether a tenant with SRP disabled stays
/// distinguishable from a wrong password, and — the one that matters most —
/// whether a server that cannot prove it holds the verifier is refused rather
/// than quietly accepted.
///
/// So the fake here is not a canned response: it holds a verifier, picks its own
/// `b`, and computes `B`, `M1` and `M2` from whatever `A` the client sends. A
/// client that got `u`, the padding or the identity wrong fails against it,
/// which a fixture-replaying fake could never detect.
final class SrpLoginTests: XCTestCase {

    // PBKDF2 at a low cost: the derivation under test is the transport's, not
    // the KDF's, and Swift has no Argon2 at all (§23.8).
    private static let kdf = SrpKdfParams(kdf: SrpKdfParams.pbkdf2Sha256, iterations: 1000)
    private static let identity = "alice"
    private static let password = "correct horse battery staple"

    // MARK: - The server half of one exchange

    /// One enrolled account plus this exchange's `b`.
    struct FakeSrpServer {
        let group: SrpGroup
        let modulus: SrpBigInt
        let montgomery: SrpMontgomery
        let verifier: SrpBigInt
        let ephemeral: SrpBigInt
        let serverPublic: SrpBigInt
        let salt: [UInt8]
        let identity: String

        init(groupWire: String, identity: String, password: String) throws {
            guard let group = SrpGroup.fromWire(groupWire),
                  let modulus = SrpBigInt(hex: group.modulusHex),
                  let montgomery = SrpMontgomery(modulus: modulus)
            else {
                throw AxiamError.network(NetworkError("test fixture: unusable group"))
            }
            self.group = group
            self.modulus = modulus
            self.montgomery = montgomery
            self.identity = identity

            // §23.3 rule 11: 32 fresh bytes here too, so the fixture cannot
            // accidentally depend on one particular salt.
            self.salt = Srp.generateSalt()
            let x = try Srp.deriveX(
                identity: identity, password: password, salt: salt, params: SrpLoginTests.kdf)
            let xInt = SrpBigInt(bigEndian: x).reducedOnce(modulus: modulus)
            self.verifier = montgomery.power(base: SrpBigInt(group.generator), exponent: xInt)

            var raw = Srp.generateSalt()
            raw[0] |= 0x80
            self.ephemeral = SrpBigInt(bigEndian: raw)

            // B = k*v + g^b mod N
            let k = try Srp.multiplier(group, modulus: modulus).reducedOnce(modulus: modulus)
            let kv = montgomery.modMul(k, verifier)
            let gb = montgomery.power(base: SrpBigInt(group.generator), exponent: ephemeral)
            self.serverPublic = SrpBigInt.addMod(kv, gb, modulus)
        }

        /// The §23.5 challenge body, optionally naming a different group so the
        /// client has to restart the exchange.
        func challengeBody(groupOverride: String? = nil) throws -> [String: Any] {
            [
                "srp_session": "opaque-session-token",
                "identity": identity,
                "salt": Srp.toHex(salt),
                "group": groupOverride ?? group.wireName,
                "kdf": SrpLoginTests.kdf.kdf,
                "iterations": SrpLoginTests.kdf.iterations,
                "b_pub": Srp.toHex(try Srp.pad(serverPublic, width: group.byteLength)),
            ]
        }

        /// `(M1, M2)` for the `A` the client actually sent.
        func proofs(forClientPublic clientPublicHex: String) throws -> SrpProofs {
            let paddedA = try Srp.fromHex(clientPublicHex, field: "client_public")
            let paddedB = try Srp.pad(serverPublic, width: group.byteLength)
            let u = SrpBigInt(bigEndian: Srp.hash([paddedA, paddedB]))

            // S = (A * v^u)^b mod N — the server's route to the same secret.
            let clientPublic = SrpBigInt(bigEndian: paddedA).reducedOnce(modulus: modulus)
            let vu = montgomery.power(base: verifier, exponent: u)
            let base = montgomery.modMul(clientPublic, vu)
            let shared = montgomery.power(base: base, exponent: ephemeral)
            let sessionKey = Srp.hash([try Srp.pad(shared, width: group.byteLength)])

            let hn = Srp.hash([try Srp.pad(modulus, width: group.byteLength)])
            let hg = Srp.hash([try Srp.pad(SrpBigInt(group.generator), width: group.byteLength)])
            var hxor = [UInt8](repeating: 0, count: hn.count)
            for index in hn.indices { hxor[index] = hn[index] ^ hg[index] }
            let hi = Srp.hash([Array(identity.utf8)])

            let m1 = Srp.hash([hxor, hi, salt, paddedA, paddedB, sessionKey])
            let m2 = Srp.hash([paddedA, m1, sessionKey])
            return SrpProofs(clientProof: Srp.toHex(m1), expectedServerProof: Srp.toHex(m2))
        }
    }

    // MARK: - The transport

    /// What the fake should do once the client's proof arrives.
    enum VerifyOutcome: Sendable {
        /// 200 with a correct `M2`.
        case success
        /// 202 with a correct `M2` and an MFA challenge token.
        case mfaRequired
        /// 200 with an `M2` that does not verify.
        case wrongProof
        /// 200 with no `M2` at all.
        case noProof
        /// 401 — what a wrong password produces: the exchange is well formed,
        /// `M1` simply does not match.
        case rejected
    }

    final class SrpTransport: HTTPTransport, @unchecked Sendable {
        private let lock = NSLock()
        private let server: FakeSrpServer?
        private let outcome: VerifyOutcome
        /// A canned challenge body, sent verbatim instead of the server's own.
        private let cannedChallenge: [String: Any]?
        private let cannedChallengeStatus: Int
        /// A group named on the FIRST challenge only, forcing a restart.
        private let firstGroup: String?
        /// A status for the SECOND challenge only, failing a restart.
        private let secondChallengeStatus: Int?

        private(set) var challengeCount = 0
        private(set) var verifyCount = 0
        private(set) var lastChallengeBody = Data()
        private var lastClientPublic: String?
        private(set) var lastExpectedProof: String?

        init(
            server: FakeSrpServer? = nil,
            outcome: VerifyOutcome = .success,
            cannedChallenge: [String: Any]? = nil,
            cannedChallengeStatus: Int = 200,
            firstGroup: String? = nil,
            secondChallengeStatus: Int? = nil
        ) {
            self.server = server
            self.outcome = outcome
            self.cannedChallenge = cannedChallenge
            self.cannedChallengeStatus = cannedChallengeStatus
            self.firstGroup = firstGroup
            self.secondChallengeStatus = secondChallengeStatus
        }

        private func json(_ status: Int, _ object: Any) -> HTTPResponseData {
            let data = (try? JSONSerialization.data(withJSONObject: object)) ?? Data()
            return HTTPResponseData(
                status: status, headers: [("Content-Type", "application/json")], body: data)
        }

        func execute(_ spec: HTTPRequestSpec, timeout: TimeInterval) async throws
            -> HTTPResponseData
        {
            let path = spec.url.path
            if path.hasSuffix("/auth/srp/challenge") {
                return try challenge(spec)
            }
            if path.hasSuffix("/auth/srp/verify") {
                return try verify(spec)
            }
            return json(404, ["message": "not found"])
        }

        private func challenge(_ spec: HTTPRequestSpec) throws -> HTTPResponseData {
            lock.lock()
            challengeCount += 1
            let count = challengeCount
            lastChallengeBody = spec.body ?? Data()
            lock.unlock()

            if let canned = cannedChallenge {
                return json(cannedChallengeStatus, canned)
            }
            if cannedChallengeStatus != 200 {
                return json(cannedChallengeStatus, ["message": "no"])
            }
            if let status = secondChallengeStatus, count == 2 {
                return json(status, ["message": "no"])
            }

            let parsed =
                try? JSONSerialization.jsonObject(with: spec.body ?? Data()) as? [String: Any]
            lock.lock()
            lastClientPublic = (parsed ?? [:])["client_public"] as? String
            lock.unlock()

            guard let server else { return json(404, ["message": "no server"]) }
            let override = (count == 1) ? firstGroup : nil
            return json(200, try server.challengeBody(groupOverride: override))
        }

        private func verify(_ spec: HTTPRequestSpec) throws -> HTTPResponseData {
            lock.lock()
            verifyCount += 1
            let clientPublic = lastClientPublic
            lock.unlock()

            if case .rejected = outcome {
                return json(401, ["error": "invalid_credentials", "message": "bad"])
            }
            guard let server, let clientPublic else {
                return json(500, ["message": "the challenge never ran"])
            }
            let proofs = try server.proofs(forClientPublic: clientPublic)
            lock.lock()
            lastExpectedProof = proofs.clientProof
            lock.unlock()

            let sent: [String: Any] =
                (try? JSONSerialization.jsonObject(with: spec.body ?? Data()) as? [String: Any])
                    ?? [:]
            // The fake authenticates the client for real: a client that computed
            // u, the padding or the identity differently never gets past here.
            XCTAssertEqual(
                sent["client_proof"] as? String, proofs.clientProof,
                "the SDK's M1 must match the server's own")
            XCTAssertEqual(sent["srp_session"] as? String, "opaque-session-token")

            let user: [String: Any] = [
                "id": "user-uuid-1", "username": "alice", "email": "alice@example.com",
                "tenant_id": "tenant-uuid-1", "tenant_slug": "acme", "org_slug": "globex",
            ]

            switch outcome {
            case .success:
                return json(200, [
                    "session_id": "sess-srp-1", "expires_in": 900, "user": user,
                    "server_proof": proofs.expectedServerProof,
                ])
            case .mfaRequired:
                return json(202, [
                    "mfa_required": true, "challenge_token": "srp-mfa-challenge",
                    "available_methods": ["totp"],
                    "server_proof": proofs.expectedServerProof,
                ])
            case .wrongProof:
                // Flip one hex digit: well formed, right length, still wrong.
                var wrong = Array(proofs.expectedServerProof)
                wrong[0] = wrong[0] == "0" ? "1" : "0"
                return json(200, [
                    "session_id": "sess-srp-1", "expires_in": 900, "user": user,
                    "server_proof": String(wrong),
                ])
            case .noProof:
                return json(200, [
                    "session_id": "sess-srp-1", "expires_in": 900, "user": user,
                ])
            case .rejected:
                return json(401, ["error": "invalid_credentials"])
            }
        }

        func shutdown() async throws {}
    }

    // MARK: - Helpers

    private func makeClient(_ transport: SrpTransport) throws -> AxiamClient {
        let config = try AxiamConfig(
            baseURL: URL(string: "https://iam.example.com")!,
            tenantSlug: "acme",
            orgSlug: "globex"
        )
        return AxiamClient(config: config, transport: transport)
    }

    /// A challenge that the client accepts in every field, so a test can
    /// override exactly one member and know what it is testing.
    private func wellFormedChallenge(_ overrides: [String: Any] = [:]) -> [String: Any] {
        var body: [String: Any] = [
            "srp_session": "opaque-session-token",
            "identity": SrpLoginTests.identity,
            "salt": String(repeating: "a3", count: 32),
            "group": SrpGroup.defaultWireName,
            "kdf": SrpKdfParams.pbkdf2Sha256,
            "iterations": 1000,
            "b_pub": String(repeating: "02", count: 512),
        ]
        for (key, value) in overrides { body[key] = value }
        return body
    }

    private func assertNetworkError(
        _ error: Error, contains needle: String, file: StaticString = #filePath,
        line: UInt = #line
    ) {
        guard case AxiamError.network(let networkError) = error else {
            // The type is the point: a client capability gap or a tenant setting
            // reported as a credential failure sends a user off to reset a
            // password that works perfectly.
            return XCTFail("expected .network, got \(error)", file: file, line: line)
        }
        XCTAssertTrue(
            networkError.message.contains(needle),
            "refusal must mention \(needle): \(networkError.message)", file: file, line: line)
    }

    // MARK: - The exchange

    func testFullExchangeAuthenticatesBothSidesAndOpensASession() async throws {
        let server = try FakeSrpServer(
            groupWire: SrpGroup.defaultWireName, identity: SrpLoginTests.identity,
            password: SrpLoginTests.password)
        let transport = SrpTransport(server: server, outcome: .success)
        let client = try makeClient(transport)

        // Signed in by EMAIL while the verifier is bound to the USERNAME: §23.3
        // rule 2 says `x` uses the identity the SERVER named, and this only
        // passes if the SDK honours it.
        let result = try await client.loginSrp(
            usernameOrEmail: "alice@example.com", password: SrpLoginTests.password)

        guard case .authenticated(let user) = result else {
            return XCTFail("expected an authenticated session, got \(result)")
        }
        XCTAssertEqual(user.username, "alice")
        // The opening guess was right, so there was exactly one challenge.
        XCTAssertEqual(transport.challengeCount, 1)
        XCTAssertEqual(transport.verifyCount, 1)

        // §23.3 rule 12: the password never went on the wire.
        let sent = String(decoding: transport.lastChallengeBody, as: UTF8.self)
        XCTAssertFalse(sent.contains("correct horse"))
        XCTAssertFalse(sent.contains("\"password\""))
    }

    func testANarrowerGroupRestartsTheExchange() async throws {
        // A tenant on a group other than the opening guess must work rather than
        // fail, and the restart has to draw a fresh `a`.
        let server = try FakeSrpServer(
            groupWire: "rfc5054_2048", identity: SrpLoginTests.identity,
            password: SrpLoginTests.password)
        let transport = SrpTransport(server: server, outcome: .success)
        let client = try makeClient(transport)

        let result = try await client.loginSrp(
            usernameOrEmail: SrpLoginTests.identity, password: SrpLoginTests.password)
        guard case .authenticated = result else {
            return XCTFail("expected an authenticated session, got \(result)")
        }
        XCTAssertEqual(transport.challengeCount, 2)
    }

    func testMfaRequiredReturnsTheSameBranchAsPasswordLogin() async throws {
        let server = try FakeSrpServer(
            groupWire: SrpGroup.defaultWireName, identity: SrpLoginTests.identity,
            password: SrpLoginTests.password)
        let transport = SrpTransport(server: server, outcome: .mfaRequired)
        let client = try makeClient(transport)

        let result = try await client.loginSrp(
            usernameOrEmail: SrpLoginTests.identity, password: SrpLoginTests.password)
        guard case .mfaRequired(let methods) = result else {
            return XCTFail("expected an MFA challenge, got \(result)")
        }
        XCTAssertEqual(methods, ["totp"])
    }

    func testAServerWhoseProofDoesNotVerifyGetsNoSession() async throws {
        let server = try FakeSrpServer(
            groupWire: SrpGroup.defaultWireName, identity: SrpLoginTests.identity,
            password: SrpLoginTests.password)
        let transport = SrpTransport(server: server, outcome: .wrongProof)
        let client = try makeClient(transport)

        do {
            _ = try await client.loginSrp(
                usernameOrEmail: SrpLoginTests.identity, password: SrpLoginTests.password)
            XCTFail("a server that cannot prove itself must be refused")
        } catch AxiamError.auth(let error) {
            XCTAssertTrue(error.message.contains("failed to prove"), error.message)
        }
    }

    func testAServerThatReturnsNoProofIsRefused() async throws {
        let server = try FakeSrpServer(
            groupWire: SrpGroup.defaultWireName, identity: SrpLoginTests.identity,
            password: SrpLoginTests.password)
        let transport = SrpTransport(server: server, outcome: .noProof)
        let client = try makeClient(transport)

        do {
            _ = try await client.loginSrp(
                usernameOrEmail: SrpLoginTests.identity, password: SrpLoginTests.password)
            XCTFail("a missing M2 is not an optional field")
        } catch AxiamError.auth {
            // Expected.
        }
    }

    func testARejectedProofIsAnAuthFailure() async throws {
        let server = try FakeSrpServer(
            groupWire: SrpGroup.defaultWireName, identity: SrpLoginTests.identity,
            password: SrpLoginTests.password)
        let transport = SrpTransport(server: server, outcome: .rejected)
        let client = try makeClient(transport)

        do {
            _ = try await client.loginSrp(
                usernameOrEmail: SrpLoginTests.identity, password: "not-the-real-password")
            XCTFail("a rejected proof is an auth failure")
        } catch AxiamError.auth {
            // Expected.
        }
    }

    // MARK: - Refusals that must not look like a bad password

    func testSrpDisabledIsAConfigurationFaultNotABadPassword() async throws {
        let transport = SrpTransport(cannedChallenge: [:], cannedChallengeStatus: 404)
        let client = try makeClient(transport)

        do {
            _ = try await client.loginSrp(usernameOrEmail: "alice", password: "irrelevant")
            XCTFail("a disabled tenant cannot serve a challenge")
        } catch {
            assertNetworkError(error, contains: "srp_mode")
        }
        XCTAssertEqual(transport.verifyCount, 0)
    }

    func testAGroupThisSdkDoesNotImplementIsRefused() async throws {
        // §23.4: computing in an unverified group could mean one whose discrete
        // log the server knows.
        let transport = SrpTransport(
            cannedChallenge: wellFormedChallenge(["group": "rfc5054_1024"]))
        let client = try makeClient(transport)

        do {
            _ = try await client.loginSrp(usernameOrEmail: "alice", password: "irrelevant")
            XCTFail("rfc5054_1024 is not implemented")
        } catch {
            assertNetworkError(error, contains: "rfc5054_1024")
        }
        XCTAssertEqual(transport.verifyCount, 0)
    }

    func testAKdfThisSdkCannotPerformNamesItself() async throws {
        // Substituting the other KDF derives a different x and surfaces as
        // "invalid password" — the most misleading failure available here.
        let transport = SrpTransport(cannedChallenge: wellFormedChallenge(["kdf": "scrypt"]))
        let client = try makeClient(transport)

        do {
            _ = try await client.loginSrp(usernameOrEmail: "alice", password: "irrelevant")
            XCTFail("an unknown KDF cannot be guessed at")
        } catch {
            assertNetworkError(error, contains: "scrypt")
        }
    }

    func testArgon2idIsRefusedRatherThanServedAWrongDerivation() async throws {
        // §23.8: Swift Crypto ships no Argon2 on every supported platform, so a
        // tenant configured for it is refused with a message naming the KDF —
        // not served a derivation that would produce a verifier no login can
        // satisfy. Contract 1.25 records that refusal as conformant.
        XCTAssertFalse(Srp.argon2Available)
        let transport = SrpTransport(
            cannedChallenge: wellFormedChallenge([
                "kdf": SrpKdfParams.argon2id, "iterations": 2, "memory_kib": 19456,
                "parallelism": 1,
            ]))
        let client = try makeClient(transport)

        do {
            _ = try await client.loginSrp(usernameOrEmail: "alice", password: "irrelevant")
            XCTFail("argon2id is not performable here")
        } catch {
            assertNetworkError(error, contains: "argon2id")
        }
        XCTAssertEqual(transport.verifyCount, 0)
    }

    func testAMalformedSaltIsRejectedBeforeTheKdfRuns() async throws {
        let transport = SrpTransport(cannedChallenge: wellFormedChallenge(["salt": "not-hex"]))
        let client = try makeClient(transport)

        do {
            _ = try await client.loginSrp(usernameOrEmail: "alice", password: "irrelevant")
            XCTFail("a non-hex salt is not usable")
        } catch {
            assertNetworkError(error, contains: "salt")
        }
    }

    func testBCongruentToZeroIsRefusedWithoutASecondRoundTrip() async throws {
        // §23.3 rule 5, and the classic SRP break: B ≡ 0 (mod N) makes S
        // predictable. No proof may be sent for one.
        let transport = SrpTransport(
            cannedChallenge: wellFormedChallenge(["b_pub": String(repeating: "00", count: 512)]))
        let client = try makeClient(transport)

        do {
            _ = try await client.loginSrp(usernameOrEmail: "alice", password: "irrelevant")
            XCTFail("B ≡ 0 mod N must be refused")
        } catch {
            assertNetworkError(error, contains: "invalid public value")
        }
        XCTAssertEqual(transport.verifyCount, 0)
    }

    func testAChallengeOfTheWrongShapeIsRefused() async throws {
        let transport = SrpTransport(cannedChallenge: ["not": "a challenge"])
        let client = try makeClient(transport)

        do {
            _ = try await client.loginSrp(usernameOrEmail: "alice", password: "irrelevant")
            XCTFail("a challenge missing its required members is not one")
        } catch {
            assertNetworkError(error, contains: "§23.5")
        }
    }

    func testAServerErrorOnTheChallengeIsReportedAsItself() async throws {
        let transport = SrpTransport(cannedChallengeStatus: 503)
        let client = try makeClient(transport)

        do {
            _ = try await client.loginSrp(usernameOrEmail: "alice", password: "irrelevant")
            XCTFail("a 503 is not a login")
        } catch AxiamError.auth {
            XCTFail("a 503 is not a credential failure")
        } catch {
            // Any non-auth error is correct here.
        }
        XCTAssertEqual(transport.verifyCount, 0)
    }

    func testAFailedRestartDoesNotFallBackToTheWrongGroup() async throws {
        // The restart is the one place the exchange runs the challenge twice. A
        // failure there must surface rather than a proof being sent for the
        // group the server did not name.
        let server = try FakeSrpServer(
            groupWire: SrpGroup.defaultWireName, identity: SrpLoginTests.identity,
            password: SrpLoginTests.password)
        let transport = SrpTransport(
            server: server, firstGroup: "rfc5054_2048", secondChallengeStatus: 503)
        let client = try makeClient(transport)

        do {
            _ = try await client.loginSrp(
                usernameOrEmail: SrpLoginTests.identity, password: SrpLoginTests.password)
            XCTFail("a failed restart is not a login")
        } catch {
            // Any error is correct; what matters is where it stopped.
        }
        XCTAssertEqual(transport.challengeCount, 2)
        XCTAssertEqual(transport.verifyCount, 0)
    }

    func testAClosedClientRefusesToReconnect() async throws {
        // §18.1 rule 4: use-after-close is an error, not a quiet reconnect.
        let transport = SrpTransport(cannedChallenge: wellFormedChallenge())
        let client = try makeClient(transport)
        try await client.shutdown()

        do {
            _ = try await client.loginSrp(usernameOrEmail: "alice", password: "irrelevant")
            XCTFail("a closed client must refuse")
        } catch {
            // Expected.
        }
        XCTAssertEqual(transport.challengeCount, 0)
    }

    // MARK: - Enrolment

    func testEnrolmentProducesAVerifierTheServerCanReproduce() async throws {
        let transport = SrpTransport(cannedChallenge: wellFormedChallenge())
        let client = try makeClient(transport)

        let enrolment = try await client.srpEnrollment(
            identity: "alice", password: "a-new-password", group: "rfc5054_2048",
            params: SrpLoginTests.kdf)

        XCTAssertEqual(enrolment.group, "rfc5054_2048")
        XCTAssertEqual(enrolment.kdf, SrpKdfParams.pbkdf2Sha256)
        XCTAssertEqual(enrolment.iterations, 1000)
        // §23.5 omits the Argon2id-only members entirely for PBKDF2 rather than
        // sending them as zeros.
        XCTAssertNil(enrolment.memoryKib)
        XCTAssertNil(enrolment.parallelism)
        XCTAssertEqual(enrolment.salt.count, 64)
        XCTAssertEqual(enrolment.verifier.count, 512)

        // Recompute it the way the server would, from the salt it was given.
        let group = try XCTUnwrap(SrpGroup.fromWire("rfc5054_2048"))
        let x = try Srp.deriveX(
            identity: "alice", password: "a-new-password",
            salt: try Srp.fromHex(enrolment.salt, field: "salt"), params: SrpLoginTests.kdf)
        XCTAssertEqual(try Srp.computeVerifier(group: group, x: x), enrolment.verifier)

        // Two enrolments of the same password must differ: the salt is fresh per
        // §23.3 rule 11, and a repeated verifier would leak that two accounts
        // share a password.
        let again = try await client.srpEnrollment(
            identity: "alice", password: "a-new-password", group: "rfc5054_2048",
            params: SrpLoginTests.kdf)
        XCTAssertNotEqual(again.salt, enrolment.salt)
        XCTAssertNotEqual(again.verifier, enrolment.verifier)
    }

    func testEnrolmentDefaultsToTheWidestGroupAndThePerformableKdf() async throws {
        let transport = SrpTransport(cannedChallenge: wellFormedChallenge())
        let client = try makeClient(transport)

        // Nothing named: the widest group, and the only KDF this SDK can
        // perform (§23.8) at AXIAM's cost for it.
        let enrolment = try await client.srpEnrollment(
            identity: "alice", password: "a-new-password")
        XCTAssertEqual(enrolment.group, SrpGroup.defaultWireName)
        XCTAssertEqual(enrolment.kdf, SrpKdfParams.pbkdf2Sha256)
        XCTAssertEqual(enrolment.iterations, 600_000)
        XCTAssertEqual(enrolment.verifier.count, 1024)
    }

    func testEnrolmentRefusesAGroupThisSdkDoesNotImplement() async throws {
        let transport = SrpTransport(cannedChallenge: wellFormedChallenge())
        let client = try makeClient(transport)

        do {
            _ = try await client.srpEnrollment(
                identity: "alice", password: "pw", group: "rfc5054_1024")
            XCTFail("rfc5054_1024 is not implemented")
        } catch {
            assertNetworkError(error, contains: "rfc5054_1024")
        }
    }

    func testThisBuildCanPerformSrp() async throws {
        // §23.1 puts this probe in every SDK's vocabulary. It is `true` here;
        // the Argon2 probe is the one that says no.
        let transport = SrpTransport(cannedChallenge: wellFormedChallenge())
        let client = try makeClient(transport)
        let available = await client.srpAvailable
        XCTAssertTrue(available)
    }
}
