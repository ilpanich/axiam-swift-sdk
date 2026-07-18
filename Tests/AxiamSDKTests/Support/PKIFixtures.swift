import Foundation
import Crypto

enum TestBase64URL {
    static func encode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

/// Builds signed EdDSA JWTs and matching JWKS documents entirely in-process with swift-crypto,
/// so JWKS/guard tests need no external PKI.
struct TestSigner {
    let privateKey: Curve25519.Signing.PrivateKey
    let kid: String

    init(kid: String = "test-key-1") {
        self.privateKey = Curve25519.Signing.PrivateKey()
        self.kid = kid
    }

    /// The org JWKS document this signer's public key belongs to.
    func jwksJSON() -> [String: Any] {
        let x = TestBase64URL.encode(privateKey.publicKey.rawRepresentation)
        return [
            "keys": [
                [
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": x,
                    "kid": kid,
                    "use": "sig",
                    "alg": "EdDSA",
                ]
            ]
        ]
    }

    /// Encode + sign a compact JWT. `alg` overridable to test algorithm rejection.
    func makeJWT(claims: [String: Any], alg: String = "EdDSA", includeKid: Bool = true) -> String {
        var header: [String: Any] = ["alg": alg, "typ": "JWT"]
        if includeKid { header["kid"] = kid }
        let headerData = try! JSONSerialization.data(withJSONObject: header)
        let claimsData = try! JSONSerialization.data(withJSONObject: claims)
        let signingInput = TestBase64URL.encode(headerData) + "." + TestBase64URL.encode(claimsData)
        let signature = try! privateKey.signature(for: Data(signingInput.utf8))
        return signingInput + "." + TestBase64URL.encode(signature)
    }
}

/// Generates a throwaway self-signed certificate + private key (PEM) via the `openssl` CLI at
/// test time. Returns `nil` when openssl is unavailable, so the mTLS test can `XCTSkip` rather
/// than fail. No private key is ever committed to the repo.
enum OpenSSLPKI {
    struct Identity {
        let certificatePEM: Data
        let keyPEM: Data
    }

    static func generateSelfSigned() -> Identity? {
        guard let openssl = findOpenSSL() else { return nil }
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("axiam-pki-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let keyURL = dir.appendingPathComponent("key.pem")
        let certURL = dir.appendingPathComponent("cert.pem")

        let args = [
            "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", keyURL.path, "-out", certURL.path,
            "-days", "1", "-subj", "/CN=axiam-test-client",
        ]
        guard runProcess(openssl, args) else { return nil }
        guard
            let keyPEM = try? Data(contentsOf: keyURL),
            let certPEM = try? Data(contentsOf: certURL)
        else { return nil }
        return Identity(certificatePEM: certPEM, keyPEM: keyPEM)
    }

    private static func findOpenSSL() -> String? {
        for path in ["/usr/bin/openssl", "/usr/local/bin/openssl", "/opt/homebrew/bin/openssl", "/bin/openssl"] {
            if FileManager.default.isExecutableFile(atPath: path) { return path }
        }
        return nil
    }

    private static func runProcess(_ launchPath: String, _ arguments: [String]) -> Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: launchPath)
        process.arguments = arguments
        process.standardOutput = Pipe()
        process.standardError = Pipe()
        do {
            try process.run()
            process.waitUntilExit()
            return process.terminationStatus == 0
        } catch {
            return false
        }
    }
}
