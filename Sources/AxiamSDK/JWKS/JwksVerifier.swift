import Foundation
import Crypto

/// A single JSON Web Key. AXIAM issues EdDSA/Ed25519 keys only (`kty=OKP`, `crv=Ed25519`).
struct Jwk: Decodable, Sendable {
    let kty: String
    let crv: String?
    let x: String?
    let kid: String?
    let use: String?
    let alg: String?
}

struct JwksDocument: Decodable, Sendable {
    let keys: [Jwk]
}

/// The header of a JWS/JWT (`alg`, `kid`).
struct JwtHeader: Decodable, Sendable {
    let alg: String
    let kid: String?
}

/// The subset of JWT claims the guard consumes. `exp` is read by the caller/guard, never here.
struct JwtClaims: Decodable, Sendable {
    let sub: String?
    let tenant_id: String?
    let roles: [String]?
    let preferred_username: String?
    let email: String?
    let exp: Double?
}

/// The verified result of parsing a token: its claims (signature already checked).
struct VerifiedToken: Sendable {
    let claims: JwtClaims
}

/// Fetches AXIAM's org-wide JWKS (`GET {baseURL}/oauth2/jwks`), caches it for 300s, and
/// verifies EdDSA/Ed25519 JWT signatures with swift-crypto (§ JWKS in the SDK brief).
///
/// - Only `alg == "EdDSA"` tokens are accepted; any other algorithm is rejected *before* key
///   lookup (defends against alg-confusion).
/// - The verifier checks the **signature only**; expiry (`exp`) is the caller/guard's job.
/// - The network fetch is single-flighted so a burst of first-time verifications triggers one
///   HTTP request.
actor JwksVerifier {
    private let transport: HTTPTransport
    private let jwksURL: URL
    private let tenantHeaderValue: String
    private let cacheTTL: TimeInterval
    private let requestTimeout: TimeInterval

    private var cachedKeys: [Jwk] = []
    private var cachedAt: Date?
    private var inFlight: Task<[Jwk], Error>?

    /// Test seam: number of completed network fetches. Lets a test assert single-flight.
    private(set) var fetchCount: Int = 0

    init(
        transport: HTTPTransport,
        baseURL: URL,
        tenantHeaderValue: String,
        cacheTTL: TimeInterval = 300,
        requestTimeout: TimeInterval = 30
    ) {
        self.transport = transport
        self.jwksURL = baseURL.appendingPathComponent("oauth2/jwks")
        self.tenantHeaderValue = tenantHeaderValue
        self.cacheTTL = cacheTTL
        self.requestTimeout = requestTimeout
    }

    func currentFetchCount() -> Int { fetchCount }

    /// Verify a compact JWS/JWT signature against the (cached) JWKS. Returns the decoded claims.
    ///
    /// - Throws: ``AuthError`` for any structural, algorithm, key-lookup, or signature failure.
    func verify(token: String) async throws -> VerifiedToken {
        let segments = token.split(separator: ".", omittingEmptySubsequences: false)
        guard segments.count == 3 else {
            throw AuthError("Malformed JWT: expected 3 segments.")
        }
        guard
            let headerData = Base64URL.decode(String(segments[0])),
            let payloadData = Base64URL.decode(String(segments[1])),
            let signature = Base64URL.decode(String(segments[2]))
        else {
            throw AuthError("Malformed JWT: invalid base64url encoding.")
        }

        let header: JwtHeader
        do {
            header = try JSONDecoder().decode(JwtHeader.self, from: headerData)
        } catch {
            throw AuthError("Malformed JWT header.")
        }

        // Reject any non-EdDSA algorithm BEFORE looking up a key (alg-confusion defence).
        guard header.alg == "EdDSA" else {
            throw AuthError("Unsupported JWT algorithm '\(header.alg)': only EdDSA is accepted.")
        }

        let keys = try await keysForVerification()
        guard let jwk = selectKey(from: keys, kid: header.kid) else {
            throw AuthError("No matching EdDSA key in JWKS for kid '\(header.kid ?? "<none>")'.")
        }
        guard jwk.kty == "OKP", jwk.crv == "Ed25519", let x = jwk.x, let rawKey = Base64URL.decode(x) else {
            throw AuthError("JWKS key is not a usable Ed25519 (OKP) key.")
        }

        let publicKey: Curve25519.Signing.PublicKey
        do {
            publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: rawKey)
        } catch {
            throw AuthError("JWKS key material is not a valid Ed25519 public key.")
        }

        // Ed25519 signs the ASCII bytes of "base64url(header).base64url(payload)".
        let signingInput = Data((String(segments[0]) + "." + String(segments[1])).utf8)
        guard publicKey.isValidSignature(signature, for: signingInput) else {
            throw AuthError("JWT signature verification failed.")
        }

        let claims: JwtClaims
        do {
            claims = try JSONDecoder().decode(JwtClaims.self, from: payloadData)
        } catch {
            throw AuthError("Malformed JWT claims.")
        }
        return VerifiedToken(claims: claims)
    }

    private func selectKey(from keys: [Jwk], kid: String?) -> Jwk? {
        if let kid, let match = keys.first(where: { $0.kid == kid }) {
            return match
        }
        // No kid in the token: fall back to the sole EdDSA key when unambiguous.
        let edKeys = keys.filter { $0.kty == "OKP" && $0.crv == "Ed25519" }
        return edKeys.count == 1 ? edKeys.first : nil
    }

    private func keysForVerification() async throws -> [Jwk] {
        if let cachedAt, Date().timeIntervalSince(cachedAt) < cacheTTL, !cachedKeys.isEmpty {
            return cachedKeys
        }
        if let inFlight {
            return try await inFlight.value
        }
        let task = Task<[Jwk], Error> { [self] in
            try await self.fetchKeys()
        }
        inFlight = task
        defer { inFlight = nil }
        let keys = try await task.value
        cachedKeys = keys
        cachedAt = Date()
        return keys
    }

    private func fetchKeys() async throws -> [Jwk] {
        let spec = HTTPRequestSpec(
            method: .get,
            url: jwksURL,
            headers: [("Accept", "application/json"), ("X-Tenant-ID", tenantHeaderValue)],
            body: nil
        )
        let response = try await transport.execute(spec, timeout: requestTimeout)
        fetchCount += 1
        guard (200..<300).contains(response.status) else {
            throw AuthError("Failed to fetch JWKS: HTTP \(response.status).")
        }
        do {
            let doc = try JSONDecoder().decode(JwksDocument.self, from: response.body)
            return doc.keys
        } catch {
            throw AuthError("Failed to decode JWKS document.")
        }
    }
}
