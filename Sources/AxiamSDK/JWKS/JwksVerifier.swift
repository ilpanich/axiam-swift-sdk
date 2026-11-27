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

/// The header of a JWS/JWT (`alg`, `kid`, `typ`).
///
/// `typ` is decoded so the access-token path can apply CONTRACT.md §10.1 rule 10. A `typ`
/// that is present but not a string fails the header decode, which is a refusal.
struct JwtHeader: Decodable, Sendable {
    let alg: String
    let kid: String?
    let typ: String?
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
///
/// `roles`, `scope` and `purpose` are deliberately **not** modelled here. A synthesized
/// `Decodable` cannot tell an absent key from an explicit `null`, and §10.1 rule 11 and §11.2
/// rule 11 turn on exactly that (and on a `roles` that is present but not an array of strings,
/// which must be a 403 and not a decode failure). They are read from the verified payload
/// itself: see ``VerifiedToken``.
struct JwtClaims: Decodable, Sendable {
    let sub: String?
    let tenant_id: String?
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
    /// OIDC Core `sid` — the session this token was minted for (CONTRACT.md §10.4,
    /// contract 1.44).
    ///
    /// Optional and frequently absent: a client-credentials token, an RPT and a token
    /// exchange have no session behind them. That distinction is load-bearing — the
    /// revocation feed never matches a token without one, and there is no `jti` fallback,
    /// because hashing `jti` instead would match nothing while looking like it worked.
    let sid: String?
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
    /// The JOSE header `typ`, verbatim (`nil` when absent) — for §10.1 rule 10.
    let typ: String?
    /// Whether the verified payload carries a `purpose` member **at all** — whatever its value,
    /// `null` included (§10.1 rule 11: presence is read from the payload, not from a claims
    /// model whose optional decodes `null` as absent).
    let carriesPurpose: Bool
    /// The `roles` claim (§11.2 rule 11): `nil` when the member is absent, is `null`, or is not
    /// a JSON array of strings; an empty array stays `[]`. The two are told apart by
    /// ``rolesClaimPresent``.
    let roles: [String]?
    /// Whether the token carries a well-formed `roles` array (empty or not).
    var rolesClaimPresent: Bool { roles != nil }
    /// The `scope` claim split on single spaces (RFC 6749 §3.3; §11.2 rule 11(d)). `nil` when the
    /// member is absent or not a string.
    let scopes: [String]?

    /// Reads the §10.1 / §11.2 members straight from the verified payload's JSON object.
    init(claims: JwtClaims, typ: String?, payload: Data) throws {
        self.claims = claims
        self.typ = typ
        // A payload that is not a JSON object cannot be read for these members: refuse it rather
        // than read "no purpose, no roles" out of it.
        guard let object = (try? JSONSerialization.jsonObject(with: payload)) as? [String: Any] else {
            throw AuthError("Malformed JWT claims.")
        }
        self.carriesPurpose = object.keys.contains("purpose")
        if let list = object["roles"] as? [Any] {
            let strings = list.compactMap { $0 as? String }
            self.roles = strings.count == list.count ? strings : nil
        } else {
            self.roles = nil
        }
        if let scope = object["scope"] as? String {
            self.scopes = scope.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
        } else {
            self.scopes = nil
        }
    }
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
/// - A token whose `kid` is not in the cached set triggers **one** re-fetch per cooldown window
///   (CONTRACT.md §12.4 rule 2), so a key rotation is picked up without waiting out the cache
///   TTL, while a stream of forged `kid`s cannot drive unbounded fetching: inside the window an
///   unknown `kid` is answered from the cached set with no network call and refused.
actor JwksVerifier {
    private let transport: HTTPTransport
    private let jwksURL: URL
    private let tenantHeaderValue: String
    private let cacheTTL: TimeInterval
    private let requestTimeout: TimeInterval
    private let unknownKidCooldown: TimeInterval
    /// How long past `cacheTTL` the held keys may still be served while every refresh fails.
    private let maxStale: TimeInterval
    private let now: @Sendable () -> Date

    /// When the last unknown-`kid` re-fetch was started; `nil` until one has been.
    private var lastUnknownKidRefetch: Date?
    /// The last failed (or empty) fetch, which rate-limits the next one by the same cooldown.
    private var lastFetchFailure: (at: Date, error: Error)?
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
        requestTimeout: TimeInterval = 30,
        unknownKidCooldown: TimeInterval = 60,
        maxStale: TimeInterval = 300,
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.transport = transport
        self.jwksURL = baseURL.appendingPathComponent("oauth2/jwks")
        self.tenantHeaderValue = tenantHeaderValue
        self.cacheTTL = cacheTTL
        self.requestTimeout = requestTimeout
        self.unknownKidCooldown = unknownKidCooldown
        self.maxStale = maxStale
        self.now = now
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

        // §12.4 rule 2: a token with no `kid` is refused outright (no single-key fallback, no
        // re-fetch: there is nothing to look for); an unknown `kid` earns at most one re-fetch per
        // cooldown window and is then refused. Both are `unknown_kid`.
        guard let kid = header.kid else {
            throw AuthError(
                "JWT header carries no 'kid'; a key id is required to select a JWKS key.",
                oauthError: "unknown_kid")
        }
        let (cached, freshlyFetched) = try await keysForVerification()
        var selected = selectKey(from: cached, kid: kid)
        if selected == nil, !freshlyFetched {
            selected = selectKey(from: try await refetchForUnknownKid(), kid: kid)
        }
        guard let jwk = selected else {
            throw AuthError("No matching EdDSA key in the JWKS for the token's 'kid'.", oauthError: "unknown_kid")
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
        return try VerifiedToken(claims: claims, typ: header.typ, payload: payloadData)
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

    /// The keys to verify against, and whether this call had to fetch them (a cold or expired
    /// cache), in which case an unknown `kid` has nothing newer to be re-fetched for.
    private func keysForVerification() async throws -> ([Jwk], Bool) {
        if let cachedAt, now().timeIntervalSince(cachedAt) < cacheTTL, !cachedKeys.isEmpty {
            return (cachedKeys, false)
        }
        // Expired or cold. A recorded failure throttles the network call only, never verification:
        // while one is inside its window, the keys already held keep verifying, but only while they
        // are at most `cacheTTL + maxStale` old. Unbounded, a key removed upstream (a rotated-out
        // compromised key) would verify for as long as the refreshes keep failing, and whoever can
        // block the fetch would prolong it.
        let stale = heldKeysWithinStaleBound()
        if !stale.isEmpty, let failure = lastFetchFailure,
           now().timeIntervalSince(failure.at) < unknownKidCooldown {
            return (stale, false)
        }
        do {
            return (try await loadKeys(), true)
        } catch {
            // Re-evaluate: the fetch may have run for up to `requestTimeout`, so the bound is
            // checked against the clock now, not against the value taken before the await.
            let stillWithinBound = heldKeysWithinStaleBound()
            if !stillWithinBound.isEmpty { return (stillWithinBound, false) }
            throw error
        }
    }

    /// The held keys, or none when they are older than `cacheTTL + maxStale`.
    private func heldKeysWithinStaleBound() -> [Jwk] {
        guard let cachedAt, now().timeIntervalSince(cachedAt) < cacheTTL + maxStale else { return [] }
        return cachedKeys
    }

    /// §12.4 rule 2: the single re-fetch an unknown `kid` is allowed per cooldown window.
    ///
    /// Returns the set the caller should select from. When the window is still open there is no
    /// new network call: the caller waits for a fetch already in flight, if there is one, and
    /// otherwise uses the current cache, so it always re-selects from the freshest set held.
    /// The window opens *before* the fetch, so a failing fetch is also rate-limited and concurrent
    /// unknown `kid`s see it already open.
    private func refetchForUnknownKid() async throws -> [Jwk] {
        let current = now()
        if let last = lastUnknownKidRefetch, current.timeIntervalSince(last) < unknownKidCooldown {
            if let inFlight { return try await inFlight.value }
            return heldKeysWithinStaleBound()
        }
        // A recorded fetch failure already throttles the network: answer from the cache and do not
        // open a re-fetch window for a fetch that was never made.
        if let failure = lastFetchFailure, current.timeIntervalSince(failure.at) < unknownKidCooldown {
            return heldKeysWithinStaleBound()
        }
        lastUnknownKidRefetch = current
        return try await loadKeys()
    }

    /// Fetch the JWKS (single-flighted) and replace the cache.
    ///
    /// A failed fetch, or one that returns no keys, is rate-limited by the same cooldown: until it
    /// elapses the recorded failure is re-thrown with no network call, so an unavailable JWKS
    /// endpoint costs one fetch per window rather than one per presented token.
    private func loadKeys() async throws -> [Jwk] {
        if let inFlight {
            return try await inFlight.value
        }
        if let failure = lastFetchFailure, now().timeIntervalSince(failure.at) < unknownKidCooldown {
            throw failure.error
        }
        let task = Task<[Jwk], Error> { [self] in
            try await self.fetchKeys()
        }
        inFlight = task
        defer { inFlight = nil }
        let keys: [Jwk]
        do {
            keys = try await task.value
            if keys.isEmpty { throw AuthError("Failed to use JWKS: the document holds no keys.") }
        } catch {
            lastFetchFailure = (at: now(), error: error)
            throw error
        }
        lastFetchFailure = nil
        cachedKeys = keys
        cachedAt = now()
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
