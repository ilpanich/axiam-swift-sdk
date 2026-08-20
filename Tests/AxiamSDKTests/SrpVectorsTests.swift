import Foundation
import XCTest

@testable import AxiamSDK

/// CONTRACT.md §23.7 conformance for the SRP-6a client.
///
/// `srp-test-vectors.json` is generated from the AXIAM server implementation and
/// vendored into every SDK. Eleven independent SRP implementations do not
/// interoperate by accident; this is the file that says whether this one does.
///
/// §23.7 rule 1 requires every intermediate to be reproduced, not only the final
/// proof — an SDK that gets `u` wrong should find out at `u` rather than at "login
/// sometimes fails". That matters more here than in most SDKs: Swift has no
/// bignum in its standard library, so ``SrpBigInt`` is this project's own
/// arithmetic and these vectors are the only thing standing between a
/// carry-propagation slip and a login that fails one time in a thousand.
final class SrpVectorsTests: XCTestCase {

    struct Vector: Decodable {
        let group: String
        let identity: String
        let salt: String
        let x: String
        let k: String
        let verifier: String
        let a_priv: String
        let a_pub: String
        let b_priv: String
        let b_pub: String
        let u: String
        let session_secret: String
        let session_key: String
        let client_proof: String
        let server_proof: String
    }

    struct Fixture: Decodable {
        let vectors: [Vector]
    }

    /// Walks up from this source file to find the vendored fixture, so the test
    /// does not depend on the working directory `swift test` happens to use.
    static let vectors: [Vector] = {
        var directory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<6 {
            let candidate = directory.appendingPathComponent("srp-test-vectors.json")
            if let data = try? Data(contentsOf: candidate),
                let fixture = try? JSONDecoder().decode(Fixture.self, from: data)
            {
                return fixture.vectors
            }
            directory = directory.deletingLastPathComponent()
        }
        return []
    }()

    // MARK: - §23.7 rule 4: group constants

    /// A transcription slip in a modulus is a silent, total break: client and
    /// server would still agree with each other while the discrete-log hardness the
    /// protocol rests on quietly vanished. A round-trip test cannot catch it,
    /// because both sides share the same wrong constant.
    func testEveryGroupIsASafePrimeOfTheAdvertisedWidth() throws {
        for group in SrpGroup.all {
            let modulus = try XCTUnwrap(SrpBigInt(hex: group.modulusHex))
            XCTAssertEqual(modulus.bitWidth, group.byteLength * 8, group.wireName)
            XCTAssertTrue(Self.isProbablePrime(modulus), "\(group.wireName): N is not prime")

            // A safe prime: N = 2q + 1 with q prime.
            let q = Self.halved(modulus - SrpBigInt(1))
            XCTAssertTrue(Self.isProbablePrime(q), "\(group.wireName): (N-1)/2 is not prime")

            // g generates the order-q subgroup iff g^q == N-1 for a safe prime.
            let montgomery = try XCTUnwrap(SrpMontgomery(modulus: modulus))
            let got = montgomery.power(base: SrpBigInt(group.generator), exponent: q)
            XCTAssertEqual(got, modulus - SrpBigInt(1),
                           "\(group.wireName): g does not generate the large subgroup")
        }
    }

    func testAnUnrecognisedGroupIsRefusedRatherThanGuessed() {
        // Guessing would mean computing in a group whose safety this SDK has not
        // verified — potentially one whose discrete log the server knows.
        XCTAssertNil(SrpGroup.fromWire("rfc5054_1024"))
        XCTAssertNotNil(SrpGroup.fromWire(SrpGroup.defaultWireName))
    }

    // MARK: - The bundled arithmetic

    func testBigIntHexAndByteRoundTrips() throws {
        let value = try XCTUnwrap(SrpBigInt(hex: "0001abff"))
        XCTAssertEqual(Srp.toHex(try XCTUnwrap(value.padded(to: 4))), "0001abff")
        XCTAssertEqual(SrpBigInt(bigEndian: [0x00, 0x01, 0xab, 0xff]), value)

        // Leading zeros are insignificant and must not change the value.
        XCTAssertEqual(SrpBigInt(hex: "0000ff"), SrpBigInt(hex: "ff"))
        XCTAssertNil(SrpBigInt(hex: "zz"))
    }

    /// §23.3 rule 1. Skipping PAD() is the classic SRP interop bug: two
    /// implementations agree until a value happens to carry a leading zero byte.
    func testPadLeftPadsAndRefusesAnOverWideValue() throws {
        XCTAssertEqual(Srp.toHex(try XCTUnwrap(SrpBigInt(1).padded(to: 4))), "00000001")
        XCTAssertEqual(Srp.toHex(try XCTUnwrap(SrpBigInt(0x0102).padded(to: 2))), "0102")
        // Silently dropping high bytes would produce a wrong hash that still
        // looked well-formed.
        XCTAssertNil(SrpBigInt(hex: "0102030405")?.padded(to: 2))
    }

    /// The carry paths are where a hand-written bignum goes wrong, and they go
    /// wrong only at limb boundaries — so exercise those specifically rather than
    /// trusting the vectors to wander into them.
    func testCarryPropagationAtLimbBoundaries() throws {
        let maxLimb = try XCTUnwrap(SrpBigInt(hex: "ffffffffffffffff"))
        let one = SrpBigInt(1)
        XCTAssertEqual(maxLimb + one, try XCTUnwrap(SrpBigInt(hex: "10000000000000000")))
        XCTAssertEqual((maxLimb + one) - one, maxLimb)

        let twoLimbs = try XCTUnwrap(SrpBigInt(hex: "ffffffffffffffffffffffffffffffff"))
        XCTAssertEqual(twoLimbs + one, try XCTUnwrap(SrpBigInt(hex: "100000000000000000000000000000000")))
        XCTAssertEqual(maxLimb * maxLimb,
                       try XCTUnwrap(SrpBigInt(hex: "fffffffffffffffe0000000000000001")))
        XCTAssertEqual(maxLimb.doubled(), try XCTUnwrap(SrpBigInt(hex: "1fffffffffffffffe")))
    }

    // MARK: - §23.7 rules 1–3: the vectors

    /// Guards the fixture itself: if these stop holding, everything below silently
    /// stops testing the two things it was built to test.
    func testTheFixturesCoverTheCasesTheyExistFor() {
        XCTAssertFalse(Self.vectors.isEmpty, "srp-test-vectors.json was not found or is empty")
        XCTAssertTrue(Self.vectors.contains { $0.salt.hasPrefix("00") },
                      "§23.7 rule 2: no vector has a leading-zero salt")
        XCTAssertTrue(Self.vectors.contains { $0.x.hasPrefix("00") },
                      "§23.7 rule 2: no vector has a leading-zero x")
        XCTAssertTrue(Self.vectors.contains { $0.identity.utf8.contains { $0 > 0x7f } },
                      "§23.7 rule 3: no vector has a non-ASCII identity")
        for group in SrpGroup.all {
            XCTAssertTrue(Self.vectors.contains { $0.group == group.wireName },
                          "no vector covers \(group.wireName)")
        }
    }

    func testEveryVectorReproducesEveryIntermediate() throws {
        for vector in Self.vectors {
            let group = try XCTUnwrap(SrpGroup.fromWire(vector.group))
            let width = group.byteLength
            let modulus = try XCTUnwrap(SrpBigInt(hex: group.modulusHex))
            let montgomery = try XCTUnwrap(SrpMontgomery(modulus: modulus))
            let g = SrpBigInt(group.generator)
            let x = try XCTUnwrap(SrpBigInt(hex: vector.x)).reducedOnce(modulus: modulus)
            let a = try XCTUnwrap(SrpBigInt(hex: vector.a_priv))
            let b = try XCTUnwrap(SrpBigInt(hex: vector.b_priv))
            let label = "\(vector.group)/\(vector.identity)"

            // k = H(N | PAD(g))
            let k = try Srp.multiplier(group, modulus: modulus)
            XCTAssertEqual(Srp.toHex(try Srp.pad(k, width: 32)), vector.k, "k \(label)")

            // v = g^x mod N
            let verifier = montgomery.power(base: g, exponent: x)
            XCTAssertEqual(Srp.toHex(try Srp.pad(verifier, width: width)), vector.verifier,
                           "verifier \(label)")
            XCTAssertEqual(
                try Srp.computeVerifier(group: group, x: try Srp.fromHex(vector.x, field: "x")),
                vector.verifier, "computeVerifier \(label)")

            // A = g^a mod N
            let aPub = montgomery.power(base: g, exponent: a)
            XCTAssertEqual(Srp.toHex(try Srp.pad(aPub, width: width)), vector.a_pub, "A \(label)")

            // B = (k*v + g^b) mod N
            let bPub = SrpBigInt.addMod(
                montgomery.modMul(k.reducedOnce(modulus: modulus), verifier),
                montgomery.power(base: g, exponent: b),
                modulus)
            XCTAssertEqual(Srp.toHex(try Srp.pad(bPub, width: width)), vector.b_pub, "B \(label)")

            // u = H(PAD(A) | PAD(B))
            let u = SrpBigInt(bigEndian: Srp.hash([
                try Srp.pad(aPub, width: width), try Srp.pad(bPub, width: width),
            ]))
            XCTAssertEqual(Srp.toHex(try Srp.pad(u, width: 32)), vector.u, "u \(label)")

            // S = (B - k*g^x)^(a + u*x) mod N
            let kgx = montgomery.modMul(k.reducedOnce(modulus: modulus),
                                        montgomery.power(base: g, exponent: x))
            let base = SrpBigInt.subMod(bPub, kgx, modulus)
            let s = montgomery.power(base: base, exponent: a + (u * x))
            XCTAssertEqual(Srp.toHex(try Srp.pad(s, width: width)), vector.session_secret,
                           "S \(label)")

            // K = H(PAD(S))
            XCTAssertEqual(Srp.toHex(Srp.hash([try Srp.pad(s, width: width)])),
                           vector.session_key, "K \(label)")
        }
    }

    /// Drives the real session rather than the helpers, with `a` pinned to the
    /// vector's value — otherwise this would only test the internals.
    func testEveryVectorProducesTheContractProofs() throws {
        for vector in Self.vectors {
            let group = try XCTUnwrap(SrpGroup.fromWire(vector.group))
            let session = try SrpClientSession.withFixedEphemeral(
                group: group, ephemeralHex: vector.a_priv)
            XCTAssertEqual(session.clientPublic, vector.a_pub)

            let proofs = try session.finish(
                identity: vector.identity,
                saltHex: vector.salt,
                serverPublicHex: vector.b_pub,
                x: try Srp.fromHex(vector.x, field: "x"))
            XCTAssertEqual(proofs.clientProof, vector.client_proof)
            XCTAssertEqual(proofs.expectedServerProof, vector.server_proof)
        }
    }

    // MARK: - §23.3 protocol refusals

    /// §23.7 rule 6, with no network round trip. The classic SRP break: a client
    /// that accepts `B ≡ 0` derives a predictable `S` and would authenticate
    /// against a server that never knew the verifier.
    func testAServerPublicValueCongruentToZeroIsRefused() throws {
        let group = SrpGroup.rfc5054_2048
        let session = try SrpClientSession.begin(group: group)
        XCTAssertThrowsError(
            try session.finish(
                identity: "alice",
                saltHex: String(repeating: "0", count: 64),
                serverPublicHex: String(repeating: "0", count: group.byteLength * 2),
                x: [UInt8](repeating: 0, count: 32))
        ) { error in
            guard case let AxiamError.network(networkError) = error else {
                return XCTFail("expected a NetworkError, got \(error)")
            }
            XCTAssertTrue(networkError.message.contains("invalid public value"))
        }
    }

    func testEveryExchangeUsesAFreshClientEphemeral() throws {
        // §23.3 rule 7: reusing `a` across logins leaks the relationship between
        // two session secrets.
        let first = try SrpClientSession.begin(group: SrpGroup.rfc5054_2048)
        let second = try SrpClientSession.begin(group: SrpGroup.rfc5054_2048)
        XCTAssertNotEqual(first.clientPublic, second.clientPublic)
    }

    func testAnUnknownKdfIsRefusedRatherThanSubstituted() {
        // Substituting the other KDF derives a different x and surfaces as
        // "invalid password" — the single most misleading failure available.
        XCTAssertThrowsError(
            try Srp.deriveX(identity: "alice", password: "pw",
                            salt: [UInt8](repeating: 0, count: 32),
                            params: SrpKdfParams(kdf: "scrypt", iterations: 1))
        ) { error in
            guard case let AxiamError.network(networkError) = error else {
                return XCTFail("expected a NetworkError, got \(error)")
            }
            XCTAssertTrue(networkError.message.contains("scrypt"))
        }
    }

    /// §23.8. Swift has no Argon2 that ships on every supported platform, so the
    /// SDK refuses rather than substituting PBKDF2 — which would derive a
    /// different `x` and report a perfectly good password as wrong.
    func testArgon2idIsRefusedWithAnExplanation() {
        XCTAssertFalse(Srp.argon2Available)
        XCTAssertTrue(Srp.available)
        XCTAssertThrowsError(
            try Srp.deriveX(identity: "alice", password: "pw",
                            salt: [UInt8](repeating: 0, count: 32),
                            params: SrpKdfParams(kdf: SrpKdfParams.argon2id, iterations: 2,
                                                 memoryKib: 19456, parallelism: 1))
        ) { error in
            guard case let AxiamError.network(networkError) = error else {
                return XCTFail("expected a NetworkError, got \(error)")
            }
            XCTAssertTrue(networkError.message.contains("argon2id"))
        }
    }

    func testAMalformedHexFieldIsRefusedRatherThanTruncated() {
        for bad in ["abc", "zz", ""] {
            XCTAssertThrowsError(try Srp.fromHex(bad, field: "salt"))
        }
    }

    // MARK: - KDF

    /// Every one of these must change the output, or a verifier would be
    /// replayable against a different account or a different salt.
    func testTheKdfBindsIdentityPasswordAndSalt() throws {
        let params = SrpKdfParams(kdf: SrpKdfParams.pbkdf2Sha256, iterations: 1000)
        let saltA = [UInt8](repeating: 0x0a, count: 32)
        let saltB = [UInt8](repeating: 0x0b, count: 32)

        let base = try Srp.deriveX(identity: "alice", password: "pw", salt: saltA, params: params)
        XCTAssertEqual(base.count, 32)
        XCTAssertEqual(try Srp.deriveX(identity: "alice", password: "pw", salt: saltA, params: params), base)
        XCTAssertNotEqual(try Srp.deriveX(identity: "bob", password: "pw", salt: saltA, params: params), base)
        XCTAssertNotEqual(try Srp.deriveX(identity: "alice", password: "pw2", salt: saltA, params: params), base)
        XCTAssertNotEqual(try Srp.deriveX(identity: "alice", password: "pw", salt: saltB, params: params), base)
    }

    /// This SDK computes PBKDF2 itself over `Crypto.HMAC` rather than taking it
    /// from `_CryptoExtras` (see ``Srp``), so it is pinned against an independently
    /// computed expectation rather than only against itself. A KDF that agrees only
    /// with its own output is a KDF that interoperates with nothing.
    ///
    /// `deriveX` hashes `identity ":" password`, so the input below is
    /// `"password:"` — the expectations are PBKDF2-HMAC-SHA256 over exactly that.
    func testPbkdf2MatchesAnIndependentlyComputedVector() throws {
        let oneRound = try Srp.deriveX(
            identity: "password", password: "",
            salt: Array("salt".utf8),
            params: SrpKdfParams(kdf: SrpKdfParams.pbkdf2Sha256, iterations: 1))
        XCTAssertEqual(
            Srp.toHex(oneRound),
            "18a9550367f9af601f95ee2fd1d688791e42b4bde18c631045aaaccf9a45a726")

        // A multi-round case as well: the single-round path never exercises the
        // XOR accumulation, which is where a hand-rolled PBKDF2 goes wrong.
        let manyRounds = try Srp.deriveX(
            identity: "password", password: "",
            salt: Array("salt".utf8),
            params: SrpKdfParams(kdf: SrpKdfParams.pbkdf2Sha256, iterations: 4096))
        XCTAssertEqual(
            Srp.toHex(manyRounds),
            "b6132706250f290ca593db8186c844e55e7f61c77760f2ef7e375c53bc2b2286")
    }

    /// §23.7 rule 3 pins the UTF-8 encoding of the identity.
    func testAMangledNonAsciiIdentityIsADifferentAccount() throws {
        let params = SrpKdfParams(kdf: SrpKdfParams.pbkdf2Sha256, iterations: 1000)
        let salt = [UInt8](repeating: 0, count: 32)
        XCTAssertNotEqual(
            try Srp.deriveX(identity: "renée", password: "pw", salt: salt, params: params),
            try Srp.deriveX(identity: "renÃ©e", password: "pw", salt: salt, params: params))
    }

    func testKdfDefaultsMatchAxiamsOwnCosts() {
        let argon = SrpKdfParams(kdf: "").withDefaults()
        XCTAssertEqual(argon.kdf, SrpKdfParams.argon2id)
        XCTAssertEqual(argon.iterations, 2)
        XCTAssertEqual(argon.memoryKib, 19456)
        XCTAssertEqual(argon.parallelism, 1)

        let pbkdf2 = SrpKdfParams(kdf: SrpKdfParams.pbkdf2Sha256).withDefaults()
        XCTAssertEqual(pbkdf2.iterations, 600_000)
        XCTAssertEqual(pbkdf2.memoryKib, 0)
    }

    // MARK: - §23.3 rule 6: server proof comparison

    func testTheServerProofComparisonRejectsEverythingButAMatch() throws {
        let proof = try XCTUnwrap(Self.vectors.first).server_proof
        XCTAssertTrue(Srp.verifyServerProof(expected: proof, actual: proof))
        XCTAssertFalse(Srp.verifyServerProof(expected: proof, actual: String(proof.dropLast()) + "0"))
        XCTAssertFalse(Srp.verifyServerProof(expected: proof, actual: String(proof.prefix(32))))
        XCTAssertFalse(Srp.verifyServerProof(expected: proof, actual: ""))
        XCTAssertFalse(Srp.verifyServerProof(expected: proof, actual: nil))
    }

    // MARK: - §23.3 rule 11: enrolment salts

    func testEnrolmentSaltsAre32FreshBytes() {
        // A reused salt would make every verifier in a tenant equally attackable
        // with one precomputation.
        let first = Srp.generateSalt()
        XCTAssertEqual(first.count, 32)
        XCTAssertNotEqual(first, Srp.generateSalt())
    }

    // MARK: - Helpers

    /// Miller-Rabin with fixed bases — deterministic, and strong at these sizes.
    ///
    /// Written against the bundled arithmetic on purpose: this test asserts the
    /// moduli are safe primes, and doing so through the same code that will
    /// exponentiate them also exercises `power` on inputs the vectors never reach.
    private static func isProbablePrime(_ n: SrpBigInt) -> Bool {
        let bases: [UInt64] = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
        let one = SrpBigInt(1)
        guard SrpBigInt.compare(n, SrpBigInt(2)) >= 0 else { return false }
        for base in bases {
            let b = SrpBigInt(base)
            if n == b { return true }
        }
        guard let montgomery = SrpMontgomery(modulus: n) else { return false }

        var d = n - one
        var r = 0
        while !d.bit(0) {
            d = halved(d)
            r += 1
        }
        let nMinusOne = n - one

        for base in bases {
            var x = montgomery.power(base: SrpBigInt(base), exponent: d)
            if x == one || x == nMinusOne { continue }
            var passed = false
            var round = 1
            while round < r {
                x = montgomery.modMul(x, x)
                if x == nMinusOne {
                    passed = true
                    break
                }
                round += 1
            }
            if !passed { return false }
        }
        return true
    }

    /// `value >> 1`, built from the limbs directly — the SDK needs no right shift,
    /// so this lives with the test that does.
    private static func halved(_ value: SrpBigInt) -> SrpBigInt {
        var out = [UInt64](repeating: 0, count: value.limbs.count)
        var carry: UInt64 = 0
        for index in stride(from: value.limbs.count - 1, through: 0, by: -1) {
            let limb = value.limbs[index]
            out[index] = (limb >> 1) | (carry << 63)
            carry = limb & 1
        }
        return SrpBigInt(limbs: out)
    }
}
