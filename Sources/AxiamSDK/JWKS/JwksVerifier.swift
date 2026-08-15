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

/// A JWT `aud` claim, which RFC 7519 allows to be either a single string or an array of them.
///
/// Decoding is strict: anything that is neither shape fails the whole claim decode, so a
/// wrong-typed `aud` fails closed rather than silently reading as "no audience" (§10.1).
enum JwtAudience: Decodable, Sendable, Equatable {
    case single(String)
    case multiple([String])

    /// The audience values, normalised to a list.
    var values: [String] {
        switch self {
        case let .single(value): return [value]
        case let .multiple(values): return values
        }
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let one = try? container.decode(String.self) {
            self = .single(one)
            return
        }
        self = .multiple(try container.decode([String].self))
    }
}

/// The subset of JWT claims the guard consumes.
///
/// Every claim the §10.1 minimum local-verification set names is modelled here — an SDK cannot
/// check what it never decodes, which is how `nbf`/`iss`/`aud` went unenforced. The *checking*
/// lives in ``AxiamRequestAuthenticator``; this type only decodes, and decodes strictly: a claim
/// of the wrong JSON type (`"exp": "soon"`, `"aud": 7`) throws out of the decode rather than
/// arriving as `nil`.
struct JwtClaims: Decodable, Sendable {
    let sub: String?
    let tenant_id: String?
    let roles: [String]?
    let preferred_username: String?
    let email: String?
    let exp: Double?
    let nbf: Double?
    let iss: String?
    let aud: JwtAudience?
    /// RFC 7800 / RFC 8705 §3.1 confirmation claim — present **only** on a
    /// sender-constrained token (CONTRACT.md §10.1 rule 9, contract 1.15).
    ///
    /// Its presence changes what the token *is*. Without it the token is a bearer
    /// credential: whoever holds it may use it. With it, the token names a key, and
    /// accepting it without proving the caller holds that key converts it straight back
    /// into a bearer token.
    let cnf: CnfClaim?
}

/// RFC 7800 confirmation claim.
///
/// Deliberately a struct with one optional field rather than an enum: RFC 7800 permits
/// confirmation methods this SDK does not implement, and such a token must still *decode*.
/// What it must not do is validate — see ``certificateThumbprint``.
public struct CnfClaim: Decodable, Sendable, Equatable {
    /// RFC 8705 §3.1 `x5t#S256` — base64url (unpadded) SHA-256 of the DER client
    /// certificate the token was issued to. `nil` when the confirmation names some other
    /// method.
    public let x5tS256: String?

    /// RFC 9449 §6.1 `jkt` — the RFC 7638 SHA-256 thumbprint of the DPoP public key the
    /// token was bound to (contract 1.16). `nil` when the confirmation names some other
    /// method.
    ///
    /// Both fields non-`nil` is a **conjunction**, not a choice — see
    /// ``AxiamRequestAuthenticator/verifyTokenBinding(_:proofs:)``.
    public let jkt: String?

    private enum CodingKeys: String, CodingKey {
        // The wire key is not a legal Swift identifier, so the mapping is explicit — and
        // it is load-bearing: a claim under any other key is not what a conforming
        // resource server reads.
        case x5tS256 = "x5t#S256"
        case jkt
    }

    /// Whether this confirmation names no method this SDK can verify.
    ///
    /// The distinction this preserves: such a token is an *unverifiable constraint*,
    /// never an absent one. Reading it as "unconstrained" is the exact downgrade §10.1
    /// rule 9 exists to prevent. It is also true of an **empty** `cnf`, which is how
    /// proto3 delivers an empty `CnfClaim` over gRPC (§10.3 rule 3).
    public var namesNothingCheckable: Bool {
        (x5tS256?.isEmpty ?? true) && (jkt?.isEmpty ?? true)
    }

    /// The certificate thumbprint this token is bound to, or `nil` when the confirmation
    /// names some other (unimplemented) method.
    ///
    /// A caller that gets `nil` from a claim that *exists* is looking at a constraint it
    /// cannot check and MUST reject the token. It must never read that as
    /// "unconstrained".
    public var certificateThumbprint: String? { x5tS256 }
}

/// The verified result of parsing a token: its claims (signature already checked).
struct VerifiedToken: Sendable {
    let claims: JwtClaims
}

/// Fetches AXIAM's org-wide JWKS (`GET {baseURL}/oauth2/jwks`), caches it for 300s, and
/// verifies EdDSA/Ed25519 JWT signatures with swift-crypto (§ JWKS in the SDK brief).
///
/// - Only `alg == "EdDSA"` tokens are accepted; any other algorithm is rejected *before* key
///   lookup (defends against alg-confusion). `alg: none` and HS-family confusion therefore never
///   reach the JWKS (CONTRACT.md §10.1 rule 1).
/// - The verifier checks the **signature only**. Every claim check — `exp`, `nbf`, `tenant_id`,
///   `iss`, `aud` — belongs to ``AxiamRequestAuthenticator``, which is the guard entry point.
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

    /// **Signature-only primitive — not a guard** (CONTRACT.md §10.1).
    ///
    /// Verifies a compact JWS/JWT signature against the (cached) JWKS with `alg` pinned to EdDSA
    /// *before* key lookup, and returns the decoded claims **without checking any of them**: not
    /// `exp`, not `nbf`, not `tenant_id`, not `iss`, not `aud`. The JWKS trust anchor is
    /// organization-wide, so a valid signature is entirely compatible with a permanent,
    /// cross-tenant, foreign-audience token.
    ///
    /// ``AxiamRequestAuthenticator/authenticate(_:)`` is the guard; it routes through this and
    /// then applies the full §10.1 set. This entry point exists only for integrators deliberately
    /// implementing their own policy — hence the name.
    ///
    /// - Throws: ``AuthError`` for any structural, algorithm, key-lookup, or signature failure,
    ///   and for claims that are not decodable (e.g. a non-numeric `exp`).
    func verifySignatureOnlyUnchecked(token: String) async throws -> VerifiedToken {
        let segments = token.split(separator: ".", omittingEmptySubsequences: false)
        guard segments.count == 3 else {
            throw AuthError("Malformed JWT: expected 3 segments.")
        }
        guard let headerData = Base64URL.decode(String(segments[0])) else {
            throw AuthError("Malformed JWT: invalid base64url encoding.")
        }

        let header: JwtHeader
        do {
            header = try JSONDecoder().decode(JwtHeader.self, from: headerData)
        } catch {
            throw AuthError("Malformed JWT header.")
        }

        // §10.1 rule 1: reject any non-EdDSA algorithm BEFORE looking up a key (alg-confusion
        // defence). This runs before the payload/signature are even decoded, so `alg: none` — a
        // token whose signature segment is empty by construction — is refused on its algorithm,
        // not incidentally on its encoding.
        guard header.alg == "EdDSA" else {
            throw AuthError("Unsupported JWT algorithm '\(header.alg)': only EdDSA is accepted.")
        }

        guard
            let payloadData = Base64URL.decode(String(segments[1])),
            let signature = Base64URL.decode(String(segments[2])),
            !signature.isEmpty
        else {
            throw AuthError("Malformed JWT: invalid base64url encoding.")
        }

        let keys = try await keysForVerification()
        guard let jwk = selectKey(from: keys, kid: header.kid) else {
            throw AuthError(
                header.kid == nil
                    ? "JWT header carries no 'kid'; a key id is required to select a JWKS key."
                    : "No matching EdDSA key in JWKS for kid '\(header.kid ?? "")'."
            )
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

    /// Resolve the JWKS key a token's header names.
    ///
    /// §13.4 observation 7: this used to fall back to "the sole EdDSA key, when
    /// unambiguous" whenever the header carried no `kid`. Kotlin, PHP and Java
    /// all reject that outright, and the fallback is fragile in exactly the
    /// situation key ids exist for — during a rotation the JWKS holds two keys,
    /// so a token that verified yesterday starts failing for a reason that has
    /// nothing to do with the token.
    ///
    /// The fallback was also reached when a `kid` **was** present but matched
    /// nothing, which is worse than the case the observation names: a token
    /// naming a key the server does not have would be verified against whatever
    /// single key happened to be published. The `kid` is now required, and a
    /// `kid` that names no published key is a hard failure rather than an
    /// invitation to guess.
    private func selectKey(from keys: [Jwk], kid: String?) -> Jwk? {
        guard let kid else { return nil }
        return keys.first { $0.kid == kid && $0.kty == "OKP" && $0.crv == "Ed25519" }
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
