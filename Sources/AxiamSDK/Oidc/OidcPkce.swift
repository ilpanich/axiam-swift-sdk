import Crypto
import Foundation

/// PKCE (RFC 7636) and the two correlation values `oidcBegin` generates.
///
/// All of it is local computation — §12.1 makes `oidcBegin` network-free, and this is why it
/// can be: a verifier is random bytes, and a challenge is one SHA-256 of them.
enum OidcPkce {

    /// The only method this SDK offers. RFC 7636 also defines `plain`, which sends the verifier
    /// itself in the authorization request and therefore protects against nothing; an SDK with a
    /// hash available has no reason to expose it.
    static let method = "S256"

    /// A fresh `code_verifier`: 32 random bytes, base64url without padding (43 characters —
    /// inside RFC 7636 §4.1's 43…128 range).
    static func makeVerifier() -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        for index in bytes.indices { bytes[index] = UInt8.random(in: 0...255) }
        return base64URL(Data(bytes))
    }

    /// `BASE64URL(SHA256(ASCII(verifier)))` — RFC 7636 §4.2.
    static func challenge(for verifier: String) -> String {
        base64URL(Data(SHA256.hash(data: Data(verifier.utf8))))
    }

    /// A `state` or `nonce`: 16 random bytes, base64url. Neither is a secret (§12.3 rule 2),
    /// but both must be unguessable — `state` is the CSRF binding and `nonce` the replay one.
    static func makeCorrelationValue() -> String {
        var bytes = [UInt8](repeating: 0, count: 16)
        for index in bytes.indices { bytes[index] = UInt8.random(in: 0...255) }
        return base64URL(Data(bytes))
    }

    private static func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
