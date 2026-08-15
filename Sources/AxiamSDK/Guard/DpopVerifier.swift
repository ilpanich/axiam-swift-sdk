import Crypto
import Foundation
import _CryptoExtras

/// What the caller proved about **this** connection and **this** request, for
/// ``AxiamRequestAuthenticator/verifyTokenBinding(_:proofs:)``.
///
/// A struct rather than two string parameters on purpose: two same-typed optional
/// thumbprints are exactly the pair a positional call transposes silently, and transposing
/// them would check each proof against the wrong confirmation.
public struct PresentedProofs: Sendable, Equatable {
    /// The peer certificate's RFC 8705 §3.1 `x5t#S256`, taken from the TLS connection or
    /// from a *trusted* terminating proxy over a channel your application controls.
    ///
    /// **Never** from a caller-settable request header: a forgeable input makes the whole
    /// mechanism decorative.
    public let certificateThumbprint: String?

    /// The `jkt` of an **already verified** DPoP proof.
    ///
    /// Supply it only after checking the proof's signature, `htm`, `htu`, `iat` and `jti`
    /// for this request — ``DpopVerifier/verifyProof(_:request:jtiStore:)`` does all ten
    /// §21.7.2 checks and returns exactly this value. A thumbprint lifted off an unverified
    /// proof would let a proof captured from any other endpoint authorize this one.
    public let dpopThumbprint: String?

    /// Creates a proof pair.
    /// - Parameters:
    ///   - certificateThumbprint: The peer certificate's `x5t#S256`, if any.
    ///   - dpopThumbprint: The `jkt` of an already verified DPoP proof, if any.
    public init(certificateThumbprint: String? = nil, dpopThumbprint: String? = nil) {
        self.certificateThumbprint = certificateThumbprint
        self.dpopThumbprint = dpopThumbprint
    }

    /// Neither proof — the ordinary bearer case.
    public static let none = PresentedProofs()

    /// Only a client certificate was presented.
    /// - Parameter thumbprint: The peer certificate's `x5t#S256`.
    /// - Returns: A pair carrying only the certificate thumbprint.
    public static func certificate(_ thumbprint: String) -> PresentedProofs {
        PresentedProofs(certificateThumbprint: thumbprint)
    }

    /// Only a verified DPoP proof was presented.
    /// - Parameter thumbprint: The `jkt` of an already verified proof.
    /// - Returns: A pair carrying only the DPoP thumbprint.
    public static func dpop(_ thumbprint: String) -> PresentedProofs {
        PresentedProofs(dpopThumbprint: thumbprint)
    }
}

/// §21.7.2 check 8 — single-use `jti` tracking.
///
/// One method, and its contract is the point: ``claim(_:expiresAt:)`` must be atomic. A
/// contains-then-add pair read as two calls is a race that two concurrent replays of the
/// same proof can both win.
public protocol DpopJtiStore: Sendable {
    /// Record `jti` as used until `expiresAt`.
    /// - Parameters:
    ///   - jti: The proof's `jti` claim.
    ///   - expiresAt: When the entry may be forgotten.
    /// - Returns: `true` if this is the first sighting, `false` if it is a replay.
    func claim(_ jti: String, expiresAt: Date) -> Bool
}

/// A ``DpopJtiStore`` for a single process.
///
/// **Per-process, therefore per-instance.** Four replicas behind a load balancer give an
/// attacker four chances to replay a proof inside its freshness window, and a restart clears
/// the window entirely. Any deployment running more than one process needs a shared store
/// (Redis, a database table) behind this same protocol.
public final class InMemoryDpopJtiStore: DpopJtiStore, @unchecked Sendable {
    private var seen: [String: Date] = [:]
    private let lock = NSLock()

    /// Creates an empty store.
    public init() {}

    /// Record `jti` as used until `expiresAt`.
    /// - Parameters:
    ///   - jti: The proof's `jti` claim.
    ///   - expiresAt: When the entry may be forgotten.
    /// - Returns: `true` if this is the first sighting, `false` if it is a replay.
    public func claim(_ jti: String, expiresAt: Date) -> Bool {
        let now = Date()
        lock.lock()
        defer { lock.unlock() }

        // Prune under the same lock as the insert. Entries only ever live for the freshness
        // window, so this stays small without a background task.
        if seen.count > 128 {
            seen = seen.filter { $0.value > now }
        }
        if let existing = seen[jti], existing > now {
            return false
        }
        seen[jti] = expiresAt
        return true
    }
}

/// DPoP proof verification — CONTRACT.md §21.7.2 (RFC 9449), contract 1.16.
///
/// The resource-server half of DPoP: given the `DPoP` header a caller presented, decide
/// whether it proves possession for **this** request and **this** access token, and return
/// the key thumbprint that ``AxiamRequestAuthenticator/verifyTokenBinding(_:proofs:)`` then
/// matches against the token's `cnf.jkt`.
///
/// ## Why this lives in the SDK
///
/// §21.7.2 is a ten-check list, and the contract is blunt about partial implementations:
/// *"Partial verification is worse than none, because it produces a guard that reports
/// success."* Nine of the ten look optional until someone builds an attack out of the one
/// that was skipped, so they belong in one audited place rather than in every application
/// guarding an endpoint.
///
/// The two most often missing: `typ` — without pinning it to `dpop+jwt`, any *other* JWT
/// signed by the same key (an access token, an ID token) is replayable as a proof; and
/// `ath` — without it, a proof captured on one request can be re-aimed at a different token
/// held by the same key.
///
/// ## The algorithm comes from the key, never from the header
///
/// `alg: none` and RSA-public-key-as-HMAC-secret are the same bug wearing different clothes:
/// *the token told the verifier how to check the token*. This enum dispatches on the
/// embedded key's own `kty`/`crv`, so an HMAC path is never reachable no matter what the
/// header says.
public enum DpopVerifier {

    /// §21.7.2 check 7 — the `iat` acceptance window, applied in **both** directions.
    ///
    /// RFC 9449 recommends a small window without fixing a number; 60 seconds is the
    /// contract's RECOMMENDED value. A named constant, because a bare `60` three call frames
    /// deep is a number nobody ever revisits.
    public static let iatLeeway: TimeInterval = 60

    /// RFC 9449 §4.3 private key material, which must never appear in a proof's embedded
    /// public `jwk`. `k` is the symmetric-key member: its presence means the "public key" is
    /// a shared secret.
    private static let privateJwkMembers = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]

    /// What ``verifyProof(_:request:jtiStore:)`` needs to know about the current request.
    public struct Request: Sendable {
        /// The request method, e.g. `POST`.
        public let httpMethod: String
        /// The full request URI. Query and fragment are stripped during comparison, so
        /// passing it with a query string is expected.
        public let httpURI: String
        /// The token from the `Authorization` header, exactly as it arrived — this is
        /// hashed for the `ath` check.
        public let accessToken: String
        /// The token's `cnf.jkt`, when the caller has it. Supplying it performs check 10
        /// inside the call.
        public let expectedJkt: String?
        /// The `iat` window, applied in both directions.
        public let leeway: TimeInterval
        /// Override for the current time, for tests.
        public let now: Date?

        /// Creates a request description.
        /// - Parameters:
        ///   - httpMethod: The request method.
        ///   - httpURI: The full request URI.
        ///   - accessToken: The presented access token.
        ///   - expectedJkt: The token's `cnf.jkt`, if known.
        ///   - leeway: The `iat` window.
        ///   - now: Override for the current time.
        public init(
            httpMethod: String,
            httpURI: String,
            accessToken: String,
            expectedJkt: String? = nil,
            leeway: TimeInterval = DpopVerifier.iatLeeway,
            now: Date? = nil
        ) {
            self.httpMethod = httpMethod
            self.httpURI = httpURI
            self.accessToken = accessToken
            self.expectedJkt = expectedJkt
            self.leeway = leeway
            self.now = now
        }

        /// The same request, with the token's `cnf.jkt` so check 10 runs inside the call.
        /// - Parameter jkt: The token's `cnf.jkt`.
        /// - Returns: A copy carrying the expected thumbprint.
        public func withExpectedJkt(_ jkt: String) -> Request {
            Request(
                httpMethod: httpMethod,
                httpURI: httpURI,
                accessToken: accessToken,
                expectedJkt: jkt,
                leeway: leeway,
                now: now
            )
        }
    }

    /// Verify a DPoP proof against this request — all ten §21.7.2 checks.
    ///
    /// Returns the proof key's RFC 7638 thumbprint (`jkt`) on success. Feed it to
    /// ``AxiamRequestAuthenticator/verifyTokenBinding(_:proofs:)`` as the DPoP half of
    /// ``PresentedProofs``; returning it rather than `Void` is deliberate, so the value a
    /// guard passes onward could only have come from a proof that actually verified.
    ///
    /// There is no "just check the signature" mode, because that is exactly the partial
    /// verification the contract calls worse than none.
    ///
    /// - Parameters:
    ///   - proof: The raw `DPoP` header value.
    ///   - request: The method, URI and access token this proof must match.
    ///   - jtiStore: The replay guard. Required — there is no default, because every
    ///     default here is either a silent skip of replay protection or a per-process store
    ///     masquerading as a global one.
    /// - Throws: ``AuthError`` on any failing check.
    /// - Returns: The proof key's `jkt`.
    public static func verifyProof(
        _ proof: String,
        request: Request,
        jtiStore: DpopJtiStore
    ) throws -> String {
        guard !proof.isEmpty else {
            throw AuthError("DPoP proof is missing or empty.")
        }
        // RFC 9449 §4.2 makes exactly one proof the rule. Rejecting beats picking the
        // first, which is how a verifier and a downstream parser end up reading different
        // proofs.
        guard !proof.contains(","),
            !proof.trimmingCharacters(in: .whitespacesAndNewlines).contains(where: \.isWhitespace)
        else {
            throw AuthError("DPoP header must carry exactly one proof.")
        }

        let segments = proof.split(separator: ".", omittingEmptySubsequences: false)
        guard segments.count == 3 else {
            throw AuthError("DPoP proof is not a compact JWS with three segments.")
        }

        // The header as RAW JSON. §21.7.2 check 4 insists the private-material check run
        // against this rather than a parsed key type, because many JWK libraries quietly
        // drop d/p/q when parsing into a public key — the check would then pass by virtue
        // of the library having hidden the evidence.
        guard let headerData = base64URLDecode(String(segments[0])),
            let headerAny = try? JSONSerialization.jsonObject(with: headerData),
            let header = headerAny as? [String: Any]
        else {
            throw AuthError("DPoP proof header is not valid base64url JSON.")
        }

        // Check 1 — typ. First, because it is what stops any other JWT signed by the same
        // key from standing in as a proof.
        let typ = header["typ"] as? String ?? ""
        guard typ.lowercased() == "dpop+jwt" else {
            throw AuthError("DPoP proof typ header must be 'dpop+jwt', got '\(typ)'.")
        }

        // Check 3 (first half) — the header carries a public jwk.
        guard let jwk = header["jwk"] as? [String: Any] else {
            throw AuthError("DPoP proof header must carry a public 'jwk'.")
        }

        // Check 4 — no private material, against the raw header JSON.
        for member in privateJwkMembers where jwk[member] != nil {
            throw AuthError(
                "DPoP proof jwk carries private key material (\(member)) — RFC 9449 §4.3.")
        }

        // Checks 2 and 3 (second half) — the algorithm is chosen by the KEY's own type, and
        // the signature must verify under it.
        let signingInput = "\(segments[0]).\(segments[1])"
        guard let signature = base64URLDecode(String(segments[2])) else {
            throw AuthError("DPoP proof signature is not valid base64url.")
        }
        guard verifySignature(jwk: jwk, signingInput: Data(signingInput.utf8), signature: signature)
        else {
            throw AuthError("DPoP proof signature is invalid.")
        }

        guard let payloadData = base64URLDecode(String(segments[1])),
            let claimsAny = try? JSONSerialization.jsonObject(with: payloadData),
            let claims = claimsAny as? [String: Any]
        else {
            throw AuthError("DPoP proof payload is not valid base64url JSON.")
        }

        // Check 5 — htm.
        guard let htm = claims["htm"] as? String, htm == request.httpMethod else {
            throw AuthError(
                "DPoP proof htm does not match request method '\(request.httpMethod)'.")
        }

        // Check 6 — htu, with query and fragment stripped from BOTH sides and nothing else
        // touched.
        let expectedHtu = canonicalHtu(request.httpURI)
        guard let htu = claims["htu"] as? String, canonicalHtu(htu) == expectedHtu else {
            throw AuthError("DPoP proof htu does not match request URI '\(expectedHtu)'.")
        }

        // Check 7 — iat freshness, in both directions. A proof from the future is as
        // suspect as a stale one: it is how a one-sided skew allowance becomes a long-lived
        // proof.
        guard let iatSeconds = claims["iat"] as? NSNumber else {
            throw AuthError("DPoP proof iat must be a number.")
        }
        let iat = Date(timeIntervalSince1970: iatSeconds.doubleValue)
        let now = request.now ?? Date()
        guard abs(now.timeIntervalSince(iat)) <= request.leeway else {
            throw AuthError(
                "DPoP proof iat is outside the \(Int(request.leeway))s freshness window.")
        }

        // Check 9 — ath ties the proof to this specific access token.
        guard let ath = claims["ath"] as? String, !ath.isEmpty else {
            throw AuthError("DPoP proof is missing the ath claim.")
        }
        guard constantTimeEqual(ath, accessTokenHash(request.accessToken)) else {
            throw AuthError("DPoP proof ath does not match the presented access token.")
        }

        // Check 10 — the thumbprint that ties the proof to the token's cnf.
        let jkt = try thumbprintS256(jwk)
        if let expected = request.expectedJkt, !constantTimeEqual(expected, jkt) {
            throw AuthError("DPoP proof key does not match the token's cnf.jkt.")
        }

        // Check 8 — jti single-use. LAST on purpose: claiming a jti is a mutation, and
        // doing it before the cheap checks would let an attacker burn arbitrary jti values
        // out of the store with proofs that were never going to verify.
        guard let jti = claims["jti"] as? String, !jti.isEmpty else {
            throw AuthError("DPoP proof is missing a non-empty jti.")
        }
        guard jtiStore.claim(jti, expiresAt: iat.addingTimeInterval(request.leeway)) else {
            throw AuthError("DPoP proof jti has already been used (replay).")
        }

        return jkt
    }

    /// §21.7.2 checks 2 and 3 — dispatch on the key's own type, then verify.
    ///
    /// This is why the proof header's `alg` never selects anything: the key's own type
    /// determines how a signature over it can be checked, and that is not a matter the
    /// presenter gets an opinion on. There is no HMAC branch here at all, which is what
    /// defeats the public-key-as-shared-secret forgery.
    private static func verifySignature(
        jwk: [String: Any],
        signingInput: Data,
        signature: Data
    ) -> Bool {
        let kty = jwk["kty"] as? String
        let crv = jwk["crv"] as? String

        switch (kty, crv) {
        case ("OKP", "Ed25519"):
            guard let x = (jwk["x"] as? String).flatMap(base64URLDecode),
                let key = try? Curve25519.Signing.PublicKey(rawRepresentation: x)
            else { return false }
            return key.isValidSignature(signature, for: signingInput)

        case ("EC", "P-256"):
            guard let x = (jwk["x"] as? String).flatMap(base64URLDecode),
                let y = (jwk["y"] as? String).flatMap(base64URLDecode),
                let key = try? P256.Signing.PublicKey(rawRepresentation: x + y),
                // JWS ES256 signatures are raw r||s — the "raw representation" here, NOT
                // the DER form. Reading them as DER rejects every legitimate proof.
                let parsed = try? P256.Signing.ECDSASignature(rawRepresentation: signature)
            else { return false }
            return key.isValidSignature(parsed, for: signingInput)

        case ("RSA", _):
            guard let n = (jwk["n"] as? String).flatMap(base64URLDecode),
                let e = (jwk["e"] as? String).flatMap(base64URLDecode),
                let key = try? _RSA.Signing.PublicKey(n: n, e: e)
            else { return false }
            // PS256 is RSASSA-PSS, not PKCS#1 v1.5.
            return key.isValidSignature(
                _RSA.Signing.RSASignature(rawRepresentation: signature),
                for: signingInput,
                padding: .PSS
            )

        default:
            return false
        }
    }

    /// Compute the RFC 7638 SHA-256 thumbprint of a JWK — the `jkt`.
    ///
    /// Only the members RFC 7638 names for the key type take part, serialised as compact
    /// JSON with lexicographically ordered keys. Members outside that set (`kid`, `use`,
    /// `alg`, `x5c`) are excluded by the spec, which is what makes the thumbprint stable
    /// across two encodings of the same key.
    ///
    /// - Parameter jwk: The public key to fingerprint.
    /// - Throws: ``AuthError`` when the key type is unsupported or a member is missing.
    /// - Returns: The 43-character base64url thumbprint.
    public static func thumbprintS256(_ jwk: [String: Any]) throws -> String {
        func member(_ name: String) throws -> String {
            guard let value = jwk[name] as? String, !value.isEmpty else {
                throw AuthError("DPoP proof jwk is missing the required member '\(name)'.")
            }
            return value
        }

        // Built by hand rather than through a serialiser, so RFC 7638's member set and
        // their ordering are visible where they are required rather than depending on a
        // serialiser's ordering behaviour.
        let canonical: String
        switch jwk["kty"] as? String {
        case "RSA":
            canonical = "{\"e\":\(jsonString(try member("e"))),\"kty\":\"RSA\",\"n\":\(jsonString(try member("n")))}"
        case "EC":
            canonical = "{\"crv\":\(jsonString(try member("crv"))),\"kty\":\"EC\",\"x\":\(jsonString(try member("x"))),\"y\":\(jsonString(try member("y")))}"
        case "OKP":
            canonical = "{\"crv\":\(jsonString(try member("crv"))),\"kty\":\"OKP\",\"x\":\(jsonString(try member("x")))}"
        default:
            throw AuthError("DPoP proof jwk has an unsupported kty.")
        }

        return base64URLEncode(Data(SHA256.hash(data: Data(canonical.utf8))))
    }

    /// Compute the `ath` claim value for an access token — RFC 9449 §4.2.
    ///
    /// base64url-unpadded SHA-256 over the token's bytes exactly as they travelled in the
    /// `Authorization` header, not over anything decoded out of them.
    ///
    /// - Parameter accessToken: The token as it arrived.
    /// - Returns: The 43-character base64url hash.
    public static func accessTokenHash(_ accessToken: String) -> String {
        base64URLEncode(Data(SHA256.hash(data: Data(accessToken.utf8))))
    }

    /// Reduce a URI to its `htu` comparison form — §21.7.2 check 6.
    ///
    /// Query and fragment removed, and **nothing else**. No case folding, no default-port
    /// elision, no percent-decoding, no trailing-slash fixing: a normalising comparison is
    /// precisely where two unequal URIs become equal, and an attacker who finds such a pair
    /// can aim a proof at an endpoint it was never minted for.
    ///
    /// - Parameter uri: The URI to reduce.
    /// - Returns: The same URI without its query string or fragment.
    public static func canonicalHtu(_ uri: String) -> String {
        let withoutFragment = uri.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false)[0]
        return String(
            withoutFragment.split(separator: "?", maxSplits: 1, omittingEmptySubsequences: false)[0])
    }

    /// JSON-encode a string so a quote or backslash cannot break the canonical form.
    private static func jsonString(_ value: String) -> String {
        guard let data = try? JSONSerialization.data(withJSONObject: [value]),
            let array = String(data: data, encoding: .utf8)
        else {
            return "\"\(value)\""
        }
        // JSONSerialization emits ["..."]; strip the array brackets.
        return String(array.dropFirst().dropLast())
    }

    /// Constant-time string comparison.
    private static func constantTimeEqual(_ a: String, _ b: String) -> Bool {
        let lhs = Array(a.utf8)
        let rhs = Array(b.utf8)
        guard lhs.count == rhs.count else { return false }
        var diff: UInt8 = 0
        for i in 0..<lhs.count {
            diff |= lhs[i] ^ rhs[i]
        }
        return diff == 0
    }

    /// Decode unpadded base64url text.
    private static func base64URLDecode(_ text: String) -> Data? {
        var s = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while s.count % 4 != 0 { s += "=" }
        return Data(base64Encoded: s)
    }

    /// Encode bytes as unpadded base64url (RFC 7515 §2).
    private static func base64URLEncode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
