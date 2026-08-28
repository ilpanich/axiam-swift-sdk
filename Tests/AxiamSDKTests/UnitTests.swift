import XCTest
import Foundation
import NIOSSL
@testable import AxiamSDK

// MARK: - §2 error mapping table

final class ErrorMappingTests: XCTestCase {
    func testStatusToErrorTaxonomy() {
        func kind(_ status: Int) -> String {
            switch ErrorMapper.map(status: status, message: "m") {
            case .auth: return "auth"
            case .authz: return "authz"
            case .network: return "network"
            }
        }
        XCTAssertEqual(kind(400), "network")
        XCTAssertEqual(kind(401), "auth")
        XCTAssertEqual(kind(403), "authz")
        XCTAssertEqual(kind(408), "network")
        XCTAssertEqual(kind(409), "authz")
        XCTAssertEqual(kind(429), "network")
        XCTAssertEqual(kind(500), "network")
        XCTAssertEqual(kind(503), "network")
    }

    func testAuthzErrorCarriesActionAndResource() {
        guard case let .authz(error) = ErrorMapper.map(status: 403, message: "denied", action: "edit", resourceID: "r-1") else {
            return XCTFail("expected authz")
        }
        XCTAssertEqual(error.action, "edit")
        XCTAssertEqual(error.resourceID, "r-1")
    }

    func testNetworkErrorCarriesCause() {
        struct Boom: Error {}
        let error = NetworkError("failed", cause: Boom())
        XCTAssertTrue(error.cause is Boom)
    }
}

// MARK: - §5/§6 config validation

final class ConfigTests: XCTestCase {
    private let url = URL(string: "https://id.example.com")!

    func testMissingTenantThrows() {
        XCTAssertThrowsError(try AxiamConfig(baseURL: url)) { error in
            XCTAssertTrue(error is AuthError)
        }
    }

    func testTenantSlugAccepted() throws {
        let config = try AxiamConfig(baseURL: url, tenantSlug: "acme")
        XCTAssertEqual(config.tenantHeaderValue, "acme")
    }

    func testTenantIDPreferredForHeader() throws {
        let config = try AxiamConfig(baseURL: url, tenantID: "id-1", tenantSlug: "acme")
        XCTAssertEqual(config.tenantHeaderValue, "id-1")
    }

    // CONTRACT.md §5.2.1 rule 2: an SDK MUST NOT send an empty-string slug.
    //
    // Nothing can carry a blank slug, so the server resolves nothing — and on
    // /auth/opaque/login/start it fails on the workspace *before* the tenant's
    // OPAQUE mode is read, so the 404 of §23.4 rule 10 never arrives, this SDK
    // has no fallback to take, and sign-in fails even against a tenant with
    // OPAQUE disabled.
    func testBlankTenantSlugThrows() {
        for blank in ["", "   "] {
            XCTAssertThrowsError(try AxiamConfig(baseURL: url, tenantSlug: blank)) { error in
                XCTAssertTrue(error is AuthError)
            }
        }
    }

    // The case the aggregate check missed entirely: a real tenantID satisfies
    // §5, and the blank slug rides along into every login body.
    func testBlankTenantSlugThrowsEvenBesideAValidTenantID() {
        XCTAssertThrowsError(try AxiamConfig(baseURL: url, tenantID: "id-1", tenantSlug: "")) { error in
            XCTAssertTrue(error is AuthError)
        }
    }

    func testBlankOrgSlugThrows() {
        XCTAssertThrowsError(try AxiamConfig(baseURL: url, tenantSlug: "acme", orgSlug: "  ")) { error in
            XCTAssertTrue(error is AuthError)
        }
    }

    // `nil` is not blank: an unset organization identifier is legitimate (§5.1
    // — it is optional for a client that never calls login or refresh).
    // Collapsing the two would break every resource-server client.
    func testNilOrgSlugAccepted() throws {
        let config = try AxiamConfig(baseURL: url, tenantSlug: "acme")
        XCTAssertNil(config.orgSlug)
    }

    // §5.2.1: an organization-level principal signs in by naming the
    // organization's reserved tenant, whose slug is fixed in every deployment.
    // No new surface — the ordinary initializer reaches it.
    func testReservedOrganizationTenantIsNamedLikeAnyOther() throws {
        let config = try AxiamConfig(baseURL: url, tenantSlug: "organization", orgSlug: "globex")
        XCTAssertEqual(config.tenantHeaderValue, "organization")
        XCTAssertEqual(config.orgSlug, "globex")
    }

    func testBothOrgIdentifiersRejected() {
        XCTAssertThrowsError(try AxiamConfig(baseURL: url, tenantSlug: "acme", orgID: "o-1", orgSlug: "globex"))
    }

    func testTLSConfigDefaultsToFullVerification() throws {
        let config = try AxiamConfig(baseURL: url, tenantSlug: "acme")
        let tls = try config.makeTLSConfiguration()
        if case .fullVerification = tls.certificateVerification {} else {
            XCTFail("expected .fullVerification")
        }
        XCTAssertTrue(tls.certificateChain.isEmpty)
    }

    func testInvalidCustomCAThrows() throws {
        let config = try AxiamConfig(baseURL: url, tenantSlug: "acme", customCA: Data("not a pem".utf8))
        XCTAssertThrowsError(try config.makeTLSConfiguration())
    }

    // MARK: - SEC-073 §6 plaintext base URL

    func testPlaintextBaseURLRejected() {
        let plaintext = URL(string: "http://id.example.com")!
        XCTAssertThrowsError(try AxiamConfig(baseURL: plaintext, tenantSlug: "acme")) { error in
            guard let error = error as? NetworkError else {
                return XCTFail("expected NetworkError, got \(error)")
            }
            XCTAssertTrue(error.message.contains("https"), "the error must name the required scheme")
        }
    }

    func testNonHTTPSchemesRejected() {
        for raw in ["ftp://id.example.com", "ws://id.example.com", "http://id.example.com:8080/api"] {
            let url = URL(string: raw)!
            XCTAssertThrowsError(
                try AxiamConfig(baseURL: url, tenantSlug: "acme"),
                "\(raw) must be rejected"
            )
        }
    }

    func testHTTPSBaseURLAccepted() throws {
        let config = try AxiamConfig(baseURL: URL(string: "HTTPS://id.example.com")!, tenantSlug: "acme")
        XCTAssertEqual(config.tenantHeaderValue, "acme")
    }

    func testPlaintextLoopbackAllowedForDevelopment() throws {
        for raw in ["http://localhost:8080", "http://LOCALHOST:8080", "http://127.0.0.1:8080", "http://[::1]:8080"] {
            // A platform URL parser that rejects the literal outright is not what is under test
            // here; the host predicate itself is covered by `testLoopbackHostPredicate`.
            guard let url = URL(string: raw), url.host != nil else { continue }
            XCTAssertNoThrow(
                try AxiamConfig(baseURL: url, tenantSlug: "acme"),
                "loopback \(raw) must be allowed over plaintext for local development"
            )
        }
    }

    func testLoopbackHostPredicate() {
        for host in ["localhost", "LocalHost", "127.0.0.1", "::1", "[::1]"] {
            XCTAssertTrue(AxiamConfig.isLoopbackHost(host), "\(host) is loopback")
        }
        for host in ["id.example.com", "127.0.0.2", "localhost.evil.com", "notlocalhost"] {
            XCTAssertFalse(AxiamConfig.isLoopbackHost(host), "\(host) is not loopback")
        }
    }
}

// MARK: - §6.1 mTLS TLSConfiguration

final class ClientCertificateTests: XCTestCase {
    func testMTLSBuildsCertificateChainAndPrivateKey() throws {
        guard let identity = OpenSSLPKI.generateSelfSigned() else {
            throw XCTSkip("openssl not available; skipping mTLS PEM handshake-config test")
        }
        let config = try AxiamConfig(
            baseURL: URL(string: "https://id.example.com")!,
            tenantSlug: "acme",
            clientCertificate: .pem(certificate: identity.certificatePEM, privateKey: identity.keyPEM)
        )
        let tls = try config.makeTLSConfiguration()
        // Strict verification is preserved even with a client identity present (§6.1 rule 2).
        if case .fullVerification = tls.certificateVerification {} else {
            XCTFail("expected .fullVerification")
        }
        XCTAssertFalse(tls.certificateChain.isEmpty, "client cert chain must be present")
        XCTAssertNotNil(tls.privateKey, "client private key must be present")
    }

    func testInvalidClientCertPEMThrows() {
        XCTAssertThrowsError(try AxiamConfig(
            baseURL: URL(string: "https://id.example.com")!,
            tenantSlug: "acme",
            clientCertificate: .pem(certificate: Data("nope".utf8), privateKey: Data("nope".utf8))
        ).makeTLSConfiguration())
    }
}

// MARK: - §7 Sensitive redaction

final class SensitiveTests: XCTestCase {
    func testDescriptionIsRedacted() {
        let secret = Sensitive("super-secret-token")
        XCTAssertEqual(secret.description, "[SENSITIVE]")
        XCTAssertEqual("\(secret)", "[SENSITIVE]")
        XCTAssertEqual(String(reflecting: secret), "[SENSITIVE]")
        XCTAssertFalse("\(secret)".contains("super-secret"))
    }

    func testWrappedValueAccessibleInternally() {
        let secret = Sensitive(Data("key".utf8))
        XCTAssertEqual(secret.wrapped, Data("key".utf8))
    }

    func testEquatable() {
        XCTAssertEqual(Sensitive("a"), Sensitive("a"))
        XCTAssertNotEqual(Sensitive("a"), Sensitive("b"))
    }

    // MARK: - SEC-077 constant-time equality

    func testEquatableOverDataAndBytes() {
        XCTAssertEqual(Sensitive(Data("secret".utf8)), Sensitive(Data("secret".utf8)))
        XCTAssertNotEqual(Sensitive(Data("secret".utf8)), Sensitive(Data("secreu".utf8)))
        XCTAssertEqual(Sensitive([UInt8]([1, 2, 3])), Sensitive([UInt8]([1, 2, 3])))
        XCTAssertNotEqual(Sensitive([UInt8]([1, 2, 3])), Sensitive([UInt8]([1, 2, 4])))
    }

    /// Length differences must not be answered by a short-circuit: they are folded into the same
    /// accumulator, so a prefix match of any length still walks the whole input.
    func testEqualityIsLengthAwareWithoutShortCircuit() {
        XCTAssertNotEqual(Sensitive("abc"), Sensitive("abcd"))
        XCTAssertNotEqual(Sensitive("abcd"), Sensitive("abc"))
        XCTAssertNotEqual(Sensitive(""), Sensitive("a"))
        XCTAssertEqual(Sensitive(""), Sensitive(""))
    }
}

// MARK: - constant-time primitive

final class ConstantTimeTests: XCTestCase {
    func testEqualsMatchesByteEquality() {
        XCTAssertTrue(ConstantTime.equals([], []))
        XCTAssertTrue(ConstantTime.equals([0], [0]))
        XCTAssertTrue(ConstantTime.equals([1, 2, 3, 4], [1, 2, 3, 4]))
        XCTAssertFalse(ConstantTime.equals([1, 2, 3, 4], [1, 2, 3, 5]))   // differs at the last byte
        XCTAssertFalse(ConstantTime.equals([1, 2, 3, 4], [9, 2, 3, 4]))   // differs at the first byte
        XCTAssertFalse(ConstantTime.equals([], [0]))                      // zero padding is not equality
        XCTAssertFalse(ConstantTime.equals([0], []))
        XCTAssertFalse(ConstantTime.equals([1, 2], [1, 2, 0]))            // trailing zeros still differ
        XCTAssertFalse(ConstantTime.equals([1, 2, 0], [1, 2]))
    }

    func testConstantTimeBytesEncodings() {
        XCTAssertEqual("ab".constantTimeBytes, [0x61, 0x62])
        XCTAssertEqual(Data([0xFF, 0x00]).constantTimeBytes, [0xFF, 0x00])
        XCTAssertEqual([UInt8]([7]).constantTimeBytes, [7])
    }
}

// MARK: - §4 cookie jar

final class CookieJarTests: XCTestCase {
    private let url = URL(string: "https://id.example.com/api/v1/x")!

    func testParseAndResend() {
        var jar = CookieJar()
        jar.store(setCookieLines: ["axiam_access=abc; Path=/; HttpOnly; Secure"], requestURL: url)
        XCTAssertEqual(jar.value(named: "axiam_access"), "abc")
        let header = jar.cookieHeader(for: url)
        XCTAssertEqual(header, "axiam_access=abc")
    }

    func testSecureCookieNotSentOverHTTP() {
        var jar = CookieJar()
        jar.store(setCookieLines: ["s=1; Path=/; Secure"], requestURL: url)
        let httpURL = URL(string: "http://id.example.com/api")!
        XCTAssertNil(jar.cookieHeader(for: httpURL))
    }

    func testPathScoping() {
        var jar = CookieJar()
        let apiURL = URL(string: "https://id.example.com/api/thing")!
        jar.store(setCookieLines: ["p=1; Path=/api"], requestURL: apiURL)
        XCTAssertNotNil(jar.cookieHeader(for: apiURL))
        let otherURL = URL(string: "https://id.example.com/other")!
        XCTAssertNil(jar.cookieHeader(for: otherURL))
    }

    func testDomainMatching() {
        XCTAssertTrue(CookieJar.domainMatches(host: "api.example.com", domain: "example.com"))
        XCTAssertTrue(CookieJar.domainMatches(host: "example.com", domain: "example.com"))
        XCTAssertFalse(CookieJar.domainMatches(host: "evil.com", domain: "example.com"))
    }

    func testUpsertReplacesValue() {
        var jar = CookieJar()
        jar.store(setCookieLines: ["t=old; Path=/"], requestURL: url)
        jar.store(setCookieLines: ["t=new; Path=/"], requestURL: url)
        XCTAssertEqual(jar.count, 1)
        XCTAssertEqual(jar.value(named: "t"), "new")
    }
}

// MARK: - base64url

final class Base64URLTests: XCTestCase {
    func testRoundTrip() {
        let data = Data([0xFF, 0xEE, 0x00, 0x10, 0x2A])
        let encoded = TestBase64URL.encode(data)
        XCTAssertFalse(encoded.contains("="))
        XCTAssertFalse(encoded.contains("+"))
        XCTAssertFalse(encoded.contains("/"))
        XCTAssertEqual(Base64URL.decode(encoded), data)
    }
}
