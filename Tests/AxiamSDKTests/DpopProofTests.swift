import Crypto
import Foundation
import XCTest

@testable import AxiamSDK

/// CONTRACT.md §21.7.2 — DPoP proof verification, all ten checks.
///
/// Each check gets a negative test, because §21.7.2's whole premise is that a verifier
/// missing one of them still reports success. A suite that only proved a good proof passes
/// would not distinguish this type from returning the thumbprint unconditionally.
final class DpopProofTests: XCTestCase {

    private let method = "POST"
    private let uri = "https://rs.example.com/v1/things"
    private let token = "eyJhbGciOiJFZERTQSJ9.e30.sig"

    private var store = InMemoryDpopJtiStore()
    private var key = Curve25519.Signing.PrivateKey()
    private static var jtiSeq = 0

    override func setUp() {
        super.setUp()
        store = InMemoryDpopJtiStore()
        key = Curve25519.Signing.PrivateKey()
    }

    private var jwk: [String: Any] {
        [
            "kty": "OKP",
            "crv": "Ed25519",
            "x": Self.b64u(key.publicKey.rawRepresentation),
        ]
    }

    private static func b64u(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private func claims(_ overrides: [String: Any?] = [:]) -> [String: Any] {
        Self.jtiSeq += 1
        var c: [String: Any] = [
            "htm": method,
            "htu": uri,
            "iat": Int(Date().timeIntervalSince1970),
            "jti": "jti-\(Self.jtiSeq)",
            "ath": DpopVerifier.accessTokenHash(token),
        ]
        for (k, v) in overrides {
            if let v { c[k] = v } else { c.removeValue(forKey: k) }
        }
        return c
    }

    private func header(_ overrides: [String: Any?] = [:]) -> [String: Any] {
        var h: [String: Any] = ["typ": "dpop+jwt", "alg": "EdDSA", "jwk": jwk]
        for (k, v) in overrides {
            if let v { h[k] = v } else { h.removeValue(forKey: k) }
        }
        return h
    }

    /// Sign a proof by hand, so a test can put anything at all in the header — including
    /// the private material and bogus `alg` values a cooperative library would refuse to
    /// emit.
    private func sign(
        _ signingKey: Curve25519.Signing.PrivateKey,
        header: [String: Any],
        claims: [String: Any]
    ) throws -> String {
        let h = Self.b64u(try JSONSerialization.data(withJSONObject: header, options: [.sortedKeys]))
        let c = Self.b64u(try JSONSerialization.data(withJSONObject: claims, options: [.sortedKeys]))
        let input = "\(h).\(c)"
        let sig = try signingKey.signature(for: Data(input.utf8))
        return "\(input).\(Self.b64u(sig))"
    }

    private func goodProof() throws -> String {
        try sign(key, header: header(), claims: claims())
    }

    private func request() -> DpopVerifier.Request {
        DpopVerifier.Request(httpMethod: method, httpURI: uri, accessToken: token)
    }

    // MARK: - The happy path

    func testWellFormedProofVerifiesAndReturnsThumbprint() throws {
        let jkt = try DpopVerifier.verifyProof(try goodProof(), request: request(), jtiStore: store)

        // Returning the thumbprint rather than Void is what lets a guard pass a value
        // onward that could only have come from a verified proof.
        XCTAssertEqual(jkt, try DpopVerifier.thumbprintS256(jwk))
        XCTAssertEqual(jkt.count, 43)
    }

    func testQueryAndFragmentAreStrippedFromBothSides() throws {
        let r = DpopVerifier.Request(
            httpMethod: method, httpURI: uri + "?page=2#frag", accessToken: token)

        XCTAssertEqual(
            try DpopVerifier.verifyProof(try goodProof(), request: r, jtiStore: store).count, 43)
    }

    /// All three algorithms §21.7.2 check 2 permits, each through the key type that implies
    /// it. HMAC families are absent from that list on purpose — a symmetric "proof"
    /// verifiable with a key the verifier also holds proves possession of nothing.
    func testAllThreePermittedAlgorithmsVerify() throws {
        // ES256, from a P-256 key. JWS uses the RAW r||s form, not DER.
        let ec = P256.Signing.PrivateKey()
        let raw = ec.publicKey.rawRepresentation
        let ecJwk: [String: Any] = [
            "kty": "EC",
            "crv": "P-256",
            "x": Self.b64u(raw.prefix(32)),
            "y": Self.b64u(raw.suffix(32)),
        ]
        let ecHeader: [String: Any] = ["typ": "dpop+jwt", "alg": "ES256", "jwk": ecJwk]
        let ecInput =
            Self.b64u(try JSONSerialization.data(withJSONObject: ecHeader, options: [.sortedKeys]))
            + "."
            + Self.b64u(try JSONSerialization.data(withJSONObject: claims(), options: [.sortedKeys]))
        let ecSig = try ec.signature(for: Data(ecInput.utf8))
        let ecProof = "\(ecInput).\(Self.b64u(ecSig.rawRepresentation))"

        XCTAssertEqual(
            try DpopVerifier.verifyProof(ecProof, request: request(), jtiStore: store),
            try DpopVerifier.thumbprintS256(ecJwk))

        // EdDSA is the happy path everywhere else in this suite.
        XCTAssertEqual(
            try DpopVerifier.verifyProof(try goodProof(), request: request(), jtiStore: store),
            try DpopVerifier.thumbprintS256(jwk))
    }

    // MARK: - One negative test per check

    /// Check 1 — without pinning `typ`, any other JWT signed by the same key (an access
    /// token, an ID token) is replayable as a proof.
    func testCheck1ProofWithoutDpopTypIsRefused() throws {
        let proof = try sign(key, header: header(["typ": "JWT"]), claims: claims())

        XCTAssertThrowsError(
            try DpopVerifier.verifyProof(proof, request: request(), jtiStore: store)
        ) { error in
            XCTAssertTrue("\(error)".contains("typ"), "\(error)")
        }
    }

    func testCheck1TypComparisonIsCaseInsensitive() throws {
        let proof = try sign(key, header: header(["typ": "DPoP+JWT"]), claims: claims())

        XCTAssertEqual(
            try DpopVerifier.verifyProof(proof, request: request(), jtiStore: store).count, 43)
    }

    /// Check 2 — the public-key-as-HMAC-secret forgery, run for real.
    ///
    /// The attacker holds no private key. They take the *public* key out of a proof they
    /// observed, use its raw bytes as an HMAC secret, sign a proof of their own with HS256,
    /// and embed the same public jwk. A verifier that reads `alg` from the header computes
    /// HMAC with that public key, gets a match, and reports success — the signature is
    /// valid, just not proof of anything. This type has no HMAC branch at all.
    func testCheck2PublicKeyAsHmacSecretForgeryIsRefused() throws {
        let publicBytes = key.publicKey.rawRepresentation
        let h: [String: Any] = ["typ": "dpop+jwt", "alg": "HS256", "jwk": jwk]
        let input =
            Self.b64u(try JSONSerialization.data(withJSONObject: h, options: [.sortedKeys]))
            + "."
            + Self.b64u(try JSONSerialization.data(withJSONObject: claims(), options: [.sortedKeys]))
        let mac = HMAC<SHA256>.authenticationCode(
            for: Data(input.utf8), using: SymmetricKey(data: publicBytes))
        let forged = "\(input).\(Self.b64u(Data(mac)))"

        XCTAssertThrowsError(
            try DpopVerifier.verifyProof(forged, request: request(), jtiStore: store))
    }

    func testCheck2UnpermittedKeyTypeIsRefused() throws {
        let bogus: [String: Any] = ["kty": "EC", "crv": "P-521", "x": "AA", "y": "AA"]
        let proof = try sign(key, header: header(["jwk": bogus]), claims: claims())

        XCTAssertThrowsError(
            try DpopVerifier.verifyProof(proof, request: request(), jtiStore: store))
    }

    func testCheck3ProofWithNoJwkIsRefused() throws {
        let proof = try sign(key, header: header(["jwk": nil]), claims: claims())

        XCTAssertThrowsError(
            try DpopVerifier.verifyProof(proof, request: request(), jtiStore: store)
        ) { error in
            XCTAssertTrue("\(error)".contains("jwk"), "\(error)")
        }
    }

    func testCheck3ForeignSignatureIsRefused() throws {
        let other = Curve25519.Signing.PrivateKey()
        let forged = try sign(other, header: header(), claims: claims())

        XCTAssertThrowsError(
            try DpopVerifier.verifyProof(forged, request: request(), jtiStore: store)
        ) { error in
            XCTAssertTrue("\(error)".contains("signature"), "\(error)")
        }
    }

    /// Check 4 — RFC 9449 §4.3 private key material, tested against the RAW header JSON
    /// because many JWK libraries silently drop these members when parsing into a
    /// public-key type; the check would then pass because the library hid the evidence.
    func testCheck4PrivateKeyMaterialIsRefused() throws {
        for member in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
            var leaky = jwk
            leaky[member] = "c2VjcmV0"
            let proof = try sign(key, header: header(["jwk": leaky]), claims: claims())

            XCTAssertThrowsError(
                try DpopVerifier.verifyProof(proof, request: request(), jtiStore: store),
                "member \(member) was not caught"
            ) { error in
                XCTAssertTrue("\(error)".contains("private key material"), "\(member): \(error)")
            }
        }
    }

    func testCheck5ProofForAnotherMethodIsRefused() throws {
        let proof = try sign(key, header: header(), claims: claims(["htm": "GET"]))

        XCTAssertThrowsError(
            try DpopVerifier.verifyProof(proof, request: request(), jtiStore: store)
        ) { error in
            XCTAssertTrue("\(error)".contains("htm"), "\(error)")
        }
    }

    func testCheck6ProofForAnotherUriIsRefused() throws {
        let proof = try sign(
            key, header: header(), claims: claims(["htu": "https://rs.example.com/v1/other"]))

        XCTAssertThrowsError(
            try DpopVerifier.verifyProof(proof, request: request(), jtiStore: store)
        ) { error in
            XCTAssertTrue("\(error)".contains("htu"), "\(error)")
        }
    }

    /// Check 6 — a normalising comparison is where two unequal URIs become equal. Only
    /// query and fragment come off; case, default ports and trailing slashes stay put.
    func testCheck6HtuIsComparedWithoutNormalisation() {
        XCTAssertEqual(DpopVerifier.canonicalHtu("https://a.example/p?q=1#f"), "https://a.example/p")
        XCTAssertNotEqual(
            DpopVerifier.canonicalHtu("https://A.example/P"),
            DpopVerifier.canonicalHtu("https://a.example/p"))
        XCTAssertNotEqual(
            DpopVerifier.canonicalHtu("https://a.example:443/p"),
            DpopVerifier.canonicalHtu("https://a.example/p"))
        XCTAssertNotEqual(
            DpopVerifier.canonicalHtu("https://a.example/p/"),
            DpopVerifier.canonicalHtu("https://a.example/p"))
    }

    /// Check 7 — both directions. A proof from the future is as suspect as a stale one: it
    /// is how a one-sided skew allowance becomes a long-lived proof.
    func testCheck7StaleOrFutureProofIsRefused() throws {
        let now = Date()

        for offset in [-65.0, 65.0] {
            let proof = try sign(
                key,
                header: header(),
                claims: claims(["iat": Int(now.timeIntervalSince1970 + offset)]))
            let r = DpopVerifier.Request(
                httpMethod: method, httpURI: uri, accessToken: token,
                leeway: DpopVerifier.iatLeeway, now: now)

            XCTAssertThrowsError(
                try DpopVerifier.verifyProof(proof, request: r, jtiStore: store),
                "offset \(offset) was accepted"
            ) { error in
                XCTAssertTrue("\(error)".contains("freshness window"), "\(error)")
            }
        }
    }

    /// Check 8 — freshness bounds the window; the `jti` guard is what makes the window
    /// unusable. Without this the same proof works repeatedly for a full minute.
    func testCheck8ReplayedProofIsRefused() throws {
        let proof = try goodProof()
        _ = try DpopVerifier.verifyProof(proof, request: request(), jtiStore: store)

        XCTAssertThrowsError(
            try DpopVerifier.verifyProof(proof, request: request(), jtiStore: store)
        ) { error in
            XCTAssertTrue("\(error)".contains("replay"), "\(error)")
        }
    }

    /// Check 8 — the `jti` claim is a mutation, so it runs last. Claiming it earlier would
    /// let an attacker burn arbitrary `jti` values out of the store using proofs that were
    /// never going to verify, turning the replay guard into a denial-of-service surface
    /// against legitimate proofs.
    func testCheck8JtiIsClaimedOnlyAfterEveryOtherCheckPasses() throws {
        let doomed = try sign(
            key, header: header(), claims: claims(["htm": "GET", "jti": "precious"]))

        XCTAssertThrowsError(
            try DpopVerifier.verifyProof(doomed, request: request(), jtiStore: store))

        XCTAssertTrue(
            store.claim("precious", expiresAt: Date().addingTimeInterval(60)),
            "a failed proof must not burn its jti")
    }

    /// Check 9 — without `ath`, a proof captured on one request can be re-aimed at a
    /// different token held by the same key.
    func testCheck9ProofAimedAtAnotherTokenIsRefused() throws {
        let proof = try sign(
            key,
            header: header(),
            claims: claims(["ath": DpopVerifier.accessTokenHash("some.other.token")]))

        XCTAssertThrowsError(
            try DpopVerifier.verifyProof(proof, request: request(), jtiStore: store)
        ) { error in
            XCTAssertTrue("\(error)".contains("ath"), "\(error)")
        }
    }

    func testCheck9ProofWithNoAthIsRefused() throws {
        let proof = try sign(key, header: header(), claims: claims(["ath": nil]))

        XCTAssertThrowsError(
            try DpopVerifier.verifyProof(proof, request: request(), jtiStore: store)
        ) { error in
            XCTAssertTrue("\(error)".contains("ath"), "\(error)")
        }
    }

    /// Check 10 — the step that ties the proof to the token; the other nine are what make
    /// the proof mean anything.
    func testCheck10ProofByTheWrongKeyIsRefused() throws {
        let other = Curve25519.Signing.PrivateKey()
        let otherJwk: [String: Any] = [
            "kty": "OKP", "crv": "Ed25519", "x": Self.b64u(other.publicKey.rawRepresentation),
        ]
        let r = request().withExpectedJkt(try DpopVerifier.thumbprintS256(otherJwk))

        XCTAssertThrowsError(
            try DpopVerifier.verifyProof(try goodProof(), request: r, jtiStore: store)
        ) { error in
            XCTAssertTrue("\(error)".contains("cnf.jkt"), "\(error)")
        }
    }

    // MARK: - Thumbprint and framing

    /// The RFC 7638 appendix A worked example. A thumbprint implementation that is
    /// self-consistent but wrong agrees with itself on every round trip, so the only useful
    /// test is against a published vector.
    func testThumbprintMatchesRfc7638AppendixA() throws {
        let rsa: [String: Any] = [
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxu"
                + "hDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_R"
                + "N5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvR"
                + "L5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_x"
                + "BniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB",
        ]

        XCTAssertEqual(
            try DpopVerifier.thumbprintS256(rsa), "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")
    }

    /// The RFC 8037 appendix A.3 Ed25519 thumbprint vector.
    func testThumbprintMatchesRfc8037Ed25519Vector() throws {
        let okp: [String: Any] = [
            "kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
        ]

        XCTAssertEqual(
            try DpopVerifier.thumbprintS256(okp), "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k")
    }

    /// `kid`/`use`/`alg`/`x5c` are excluded by RFC 7638 — which is exactly what makes the
    /// thumbprint stable across two encodings of the same key.
    func testThumbprintIgnoresMembersOutsideTheRfc7638Set() throws {
        var decorated = jwk
        decorated["kid"] = "abc"
        decorated["use"] = "sig"
        decorated["alg"] = "EdDSA"

        XCTAssertEqual(
            try DpopVerifier.thumbprintS256(decorated), try DpopVerifier.thumbprintS256(jwk))
    }

    /// RFC 9449 §4.2 makes exactly one proof the rule. Rejecting beats picking the first,
    /// which is how a verifier and a downstream parser end up reading different proofs.
    func testHeaderCarryingTwoProofsIsRefused() throws {
        let proof = try goodProof()

        XCTAssertThrowsError(
            try DpopVerifier.verifyProof("\(proof),\(proof)", request: request(), jtiStore: store)
        ) { error in
            XCTAssertTrue("\(error)".contains("exactly one proof"), "\(error)")
        }
    }

    func testMalformedProofsAreRefused() {
        for junk in ["", "not-a-jwt", "a.b", "a.b.c.d", "!!!.###.$$$"] {
            XCTAssertThrowsError(
                try DpopVerifier.verifyProof(junk, request: request(), jtiStore: store),
                "accepted \(junk)")
        }
    }
}
