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
