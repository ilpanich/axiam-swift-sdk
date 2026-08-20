import Crypto
import Foundation

/// The KDF and cost the server dictates for one SRP exchange (CONTRACT.md §23.5).
///
/// §23.3 rule 4: these arrive per exchange and are honoured as given. They are
/// deliberately **not** cached across logins — a verifier enrolled under different
/// costs is still valid and has to keep working.
public struct SrpKdfParams: Sendable, Equatable {

    /// The wire name of the memory-hard KDF AXIAM asks for by default.
    public static let argon2id = "argon2id"
    /// The wire name of the fallback for runtimes with no vetted Argon2.
    public static let pbkdf2Sha256 = "pbkdf2_sha256"

    /// `argon2id` or `pbkdf2_sha256`.
    public var kdf: String
    /// Argon2id's time cost, or PBKDF2's iteration count.
    public var iterations: Int
    /// Argon2id's memory cost in KiB; ignored for PBKDF2.
    public var memoryKib: Int
    /// Argon2id's lane count; ignored for PBKDF2.
    public var parallelism: Int

    public init(kdf: String, iterations: Int = 0, memoryKib: Int = 0, parallelism: Int = 0) {
        self.kdf = kdf
        self.iterations = iterations
        self.memoryKib = memoryKib
        self.parallelism = parallelism
    }

    /// This instance with any zero cost replaced by AXIAM's default for the chosen
    /// KDF.
    ///
    /// Used on the enrolment path, where the caller may know only which KDF the
    /// tenant runs. Never applied to a challenge response: a server that omits a
    /// cost it is required to send is a server this SDK should not be guessing on
    /// behalf of.
    public func withDefaults() -> SrpKdfParams {
        let resolved = kdf.isEmpty ? SrpKdfParams.argon2id : kdf
        if resolved == SrpKdfParams.pbkdf2Sha256 {
            return SrpKdfParams(kdf: resolved, iterations: iterations > 0 ? iterations : 600_000)
        }
        return SrpKdfParams(
            kdf: resolved,
            iterations: iterations > 0 ? iterations : 2,
            memoryKib: memoryKib > 0 ? memoryKib : 19456,
            parallelism: parallelism > 0 ? parallelism : 1
        )
    }
}

/// The `srp` object §23.5 defines: a verifier and the parameters it was computed
/// under.
///
/// The server cannot compute this — it never sees the plaintext — so any request
/// that **sets** a password has to carry it: `POST /api/v1/users`,
/// `/auth/password/change`, `/auth/reset/confirm` and `/admin/bootstrap`
/// (§23.3 rule 11).
///
/// Neither `salt` nor `verifier` may be logged (§23.3 rule 12), which is why this
/// type is `Encodable` for the wire but deliberately not `CustomStringConvertible`.
public struct SrpEnrollment: Sendable, Encodable, Equatable {
    public let group: String
    public let kdf: String
    public let memoryKib: Int?
    public let iterations: Int
    public let parallelism: Int?
    public let salt: String
    public let verifier: String

    private enum CodingKeys: String, CodingKey {
        case group
        case kdf
        case memoryKib = "memory_kib"
        case iterations
        case parallelism
        case salt
        case verifier
    }
}

/// The two proofs an SRP exchange produces (§23.2).
///
/// `clientProof` goes on the verify request. `expectedServerProof` stays here and
/// is compared against the response's `server_proof`: that comparison is the half
/// of SRP that authenticates the *server*, and §23.3 rule 6 makes it mandatory.
public struct SrpProofs: Sendable, Equatable {
    public let clientProof: String
    public let expectedServerProof: String
}

/// SRP-6a protocol arithmetic (CONTRACT.md §23).
///
/// Everything here is pure: no I/O, no client state, no network. The two HTTP calls
/// and the policy around them live in ``AxiamClient/loginSrp(usernameOrEmail:password:)``.
///
/// `H` is **SHA-256** throughout. RFC 5054 specifies SHA-1; AXIAM does not use
/// SHA-1 anywhere and does not start here.
public enum Srp {

    /// Whether this build can perform SRP (§23.1).
    ///
    /// Unconditional here: the bignum is bundled (see ``SrpBigInt``) and PBKDF2 is
    /// built on `Crypto.HMAC`. It exists because §23.1 puts the probe in every
    /// SDK's vocabulary, and because a `true` here is **not** a promise that every
    /// tenant will work — see ``argon2Available``.
    public static var available: Bool { true }

    /// Whether this build can perform the Argon2id KDF (§23.8).
    ///
    /// **False.** Swift Crypto ships PBKDF2 and scrypt but no Argon2, and there is
    /// no Argon2 implementation that ships on every platform this SDK supports.
    /// Rather than vendor an unvetted one — for a primitive whose whole job is to
    /// be expensive in exactly the right way — this SDK refuses `argon2id` and says
    /// so, which is what §23.3 rule 4 requires of a KDF an SDK cannot perform.
    ///
    /// A tenant that wants Swift clients on SRP sets `srp_kdf` to `pbkdf2_sha256`.
    public static var argon2Available: Bool { false }

    // MARK: - Hex

    private static let hexDigits = Array("0123456789abcdef")

    /// Lowercase hex, the encoding every SRP field uses on the wire.
    public static func toHex(_ bytes: [UInt8]) -> String {
        var out = ""
        out.reserveCapacity(bytes.count * 2)
        for byte in bytes {
            out.append(hexDigits[Int(byte >> 4)])
            out.append(hexDigits[Int(byte & 0x0f)])
        }
        return out
    }

    /// Parses a lowercase-hex wire field.
    ///
    /// Never truncates: a malformed field is refused, because silently dropping a
    /// nibble would produce a wrong hash that still looked well-formed.
    ///
    /// - Throws: ``AxiamError/network(_:)`` if `hex` is not valid hex.
    public static func fromHex(_ hex: String, field: String) throws -> [UInt8] {
        let characters = Array(hex)
        guard !characters.isEmpty, characters.count % 2 == 0 else {
            throw AxiamError.network(NetworkError("SRP: the server's \(field) is not valid hex"))
        }
        var out: [UInt8] = []
        out.reserveCapacity(characters.count / 2)
        var index = 0
        while index < characters.count {
            guard let high = characters[index].hexDigitValue,
                  let low = characters[index + 1].hexDigitValue
            else {
                throw AxiamError.network(NetworkError("SRP: the server's \(field) is not valid hex"))
            }
            out.append(UInt8(high << 4 | low))
            index += 2
        }
        return out
    }

    // MARK: - Primitives

    /// `PAD(v)` — a hex value as exactly `width` big-endian bytes (§23.3 rule 1).
    ///
    /// - Throws: ``AxiamError/network(_:)`` if the value is wider than `width` — a
    ///   caller error, not something to truncate, since dropping high bytes would
    ///   produce a wrong hash that still looked well-formed.
    static func pad(_ value: SrpBigInt, width: Int) throws -> [UInt8] {
        guard let padded = value.padded(to: width) else {
            throw AxiamError.network(NetworkError("SRP: a value is wider than the group modulus"))
        }
        return padded
    }

    /// SHA-256 over the concatenation of `parts`.
    static func hash(_ parts: [[UInt8]]) -> [UInt8] {
        var hasher = SHA256()
        for part in parts {
            hasher.update(data: part)
        }
        return Array(hasher.finalize())
    }

    /// `k = H(N | PAD(g))` — depends only on the group.
    static func multiplier(_ group: SrpGroup, modulus: SrpBigInt) throws -> SrpBigInt {
        let g = SrpBigInt(group.generator)
        return SrpBigInt(bigEndian: hash([
            try pad(modulus, width: group.byteLength),
            try pad(g, width: group.byteLength),
        ]))
    }

    /// `x = KDF(identity ":" password, salt)`, as raw bytes (§23.3 rule 3).
    ///
    /// RFC 5054's bare-hash `x` would make a leaked verifier *cheaper* to attack
    /// offline than the Argon2id hashes AXIAM stores today, which would make
    /// adopting SRP a net regression at rest — so the KDF is memory-hard, and the
    /// server dictates which one per exchange.
    ///
    /// `identity` is the one the server named in the challenge, never what the
    /// human typed (§23.3 rule 2).
    ///
    /// - Throws: ``AxiamError/network(_:)`` if `params.kdf` is not one this build
    ///   can perform.
    public static func deriveX(
        identity: String,
        password: String,
        salt: [UInt8],
        params: SrpKdfParams
    ) throws -> [UInt8] {
        let secret = Array("\(identity):\(password)".utf8)

        switch params.kdf {
        case SrpKdfParams.pbkdf2Sha256:
            return pbkdf2HmacSha256(
                password: secret,
                salt: salt,
                iterations: params.iterations > 0 ? params.iterations : 600_000
            )

        case SrpKdfParams.argon2id:
            // §23.8: Swift has no Argon2 that ships on every supported platform.
            // Refuse rather than substitute PBKDF2 — that would derive a different
            // x and surface as "invalid password", the single most misleading
            // failure this code could produce.
            throw AxiamError.network(NetworkError(
                "SRP: this SDK does not implement KDF 'argon2id'. Swift Crypto ships no Argon2 "
                + "and there is no implementation available on every platform this SDK supports, "
                + "so deriving x here would mean vendoring an unvetted one. Configure the tenant "
                + "for pbkdf2_sha256."
            ))

        default:
            // Never substitute the other KDF, for the same reason.
            throw AxiamError.network(NetworkError(
                "SRP: this SDK does not implement KDF '\(params.kdf)'; it implements pbkdf2_sha256"
            ))
        }
    }

    /// `v = g^x mod N` — the verifier the server stores instead of a password hash.
    public static func computeVerifier(group: SrpGroup, x: [UInt8]) throws -> String {
        guard let modulus = SrpBigInt(hex: group.modulusHex),
              let montgomery = SrpMontgomery(modulus: modulus)
        else {
            throw AxiamError.network(NetworkError("SRP: the group modulus is unusable"))
        }
        // x is 32 bytes and every modulus is at least 256, so no reduction is
        // needed here — but reducedOnce is free and keeps the precondition local.
        let xInt = SrpBigInt(bigEndian: x).reducedOnce(modulus: modulus)
        let verifier = montgomery.power(base: SrpBigInt(group.generator), exponent: xInt)
        return toHex(try pad(verifier, width: group.byteLength))
    }

    /// PBKDF2-HMAC-SHA256, RFC 8018 §5.2, for a 32-byte output.
    ///
    /// Hand-rolled over `Crypto.HMAC` rather than taken from `_CryptoExtras`
    /// because the derived-key length equals the hash length, so RFC 8018's block
    /// loop collapses to a single block and the whole primitive is fifteen lines.
    /// It keeps this file on the `Crypto` module alone, and keeps the SDK off an
    /// API whose parameter labels differ across the swift-crypto versions this
    /// package's version range accepts.
    private static func pbkdf2HmacSha256(
        password: [UInt8],
        salt: [UInt8],
        iterations: Int
    ) -> [UInt8] {
        let key = SymmetricKey(data: password)
        // U1 = PRF(P, S || INT(1)); the block index is 1 because dkLen == hLen.
        var block = salt
        block.append(contentsOf: [0, 0, 0, 1])
        var u = Array(HMAC<SHA256>.authenticationCode(for: block, using: key))
        var output = u
        var round = 1
        while round < max(1, iterations) {
            u = Array(HMAC<SHA256>.authenticationCode(for: u, using: key))
            for index in output.indices {
                output[index] ^= u[index]
            }
            round += 1
        }
        return output
    }

    /// 32 fresh bytes from the platform CSPRNG, for an enrolment salt
    /// (§23.3 rule 11).
    ///
    /// Drawn through `SymmetricKey`, which swift-crypto documents as seeded from
    /// the platform CSPRNG on every supported target — rather than
    /// `SystemRandomNumberGenerator`, which would need a shared instance and
    /// therefore a concurrency annotation this package's Swift 5.9 floor does not
    /// have.
    ///
    /// A reused salt would make every verifier in a tenant equally attackable with
    /// one precomputation.
    public static func generateSalt() -> [UInt8] {
        SymmetricKey(size: .bits256).withUnsafeBytes { Array($0) }
    }

    /// Constant-time comparison of the server's `M2` against the expected one
    /// (§23.3 rule 6).
    public static func verifyServerProof(expected: String, actual: String?) -> Bool {
        guard let actual, actual.count == expected.count, !expected.isEmpty else { return false }
        return ConstantTime.equals(Array(expected.lowercased().utf8), Array(actual.lowercased().utf8))
    }
}

/// One SRP exchange's client half: the ephemeral secret `a` held between the
/// challenge request and the proof that answers it (CONTRACT.md §23.2).
///
/// Single-use. `a` is drawn fresh per exchange by ``begin(group:)`` and there is no
/// way to supply one there, because reusing it across logins leaks the relationship
/// between two session secrets (§23.3 rule 7).
public struct SrpClientSession {

    /// The group this exchange runs in.
    public let group: SrpGroup

    /// `A = g^a mod N`, lowercase hex — sent with the challenge request.
    public let clientPublic: String

    private let ephemeral: SrpBigInt
    private let modulus: SrpBigInt
    private let montgomery: SrpMontgomery

    private init(group: SrpGroup, ephemeral: SrpBigInt) throws {
        guard let modulus = SrpBigInt(hex: group.modulusHex),
              let montgomery = SrpMontgomery(modulus: modulus)
        else {
            throw AxiamError.network(NetworkError("SRP: the group modulus is unusable"))
        }
        self.group = group
        self.ephemeral = ephemeral
        self.modulus = modulus
        self.montgomery = montgomery
        let publicValue = montgomery.power(base: SrpBigInt(group.generator), exponent: ephemeral)
        self.clientPublic = Srp.toHex(try Srp.pad(publicValue, width: group.byteLength))
    }

    /// Starts an exchange in `group`: draws a fresh `a` of at least 256 bits from
    /// the platform CSPRNG and computes `A`.
    public static func begin(group: SrpGroup) throws -> SrpClientSession {
        var raw = Srp.generateSalt()
        raw[0] |= 0x80  // so a is unambiguously >= 2^255
        return try SrpClientSession(group: group, ephemeral: SrpBigInt(bigEndian: raw))
    }

    /// Starts an exchange with `a` pinned to a supplied value.
    ///
    /// For the §23.7 cross-language vectors **only**: they fix `a` so every
    /// intermediate is reproducible. Never call this from application code — a
    /// predictable `a` defeats the protocol.
    public static func withFixedEphemeral(group: SrpGroup, ephemeralHex: String) throws
        -> SrpClientSession
    {
        guard let ephemeral = SrpBigInt(hex: ephemeralHex) else {
            throw AxiamError.network(NetworkError("SRP: the pinned ephemeral is not valid hex"))
        }
        return try SrpClientSession(group: group, ephemeral: ephemeral)
    }

    /// Completes the exchange: `S`, `K`, `M1` and the `M2` the server must return.
    ///
    /// - Parameters:
    ///   - identity: The identity from the challenge response, never what the user
    ///     typed (§23.3 rule 2).
    ///   - saltHex: The `salt` field of the challenge response.
    ///   - serverPublicHex: The `b_pub` field of the challenge response.
    ///   - x: The KDF output from ``Srp/deriveX(identity:password:salt:params:)``.
    /// - Throws: ``AxiamError/network(_:)`` if `B mod N == 0`, if `u` would be
    ///   zero, or if a hex field is malformed.
    public func finish(
        identity: String,
        saltHex: String,
        serverPublicHex: String,
        x: [UInt8]
    ) throws -> SrpProofs {
        let width = group.byteLength
        let salt = try Srp.fromHex(saltHex, field: "salt")
        let serverPublicBytes = try Srp.fromHex(serverPublicHex, field: "b_pub")
        let serverPublic = SrpBigInt(bigEndian: serverPublicBytes)

        // §23.3 rule 5. B ≡ 0 is the classic SRP break: S becomes predictable and
        // the exchange would authenticate against a server that never knew the
        // verifier. That is a broken or hostile server, not a wrong password.
        //
        // reducedOnce is sufficient because b_pub arrives at the group's own width,
        // so B < 2^(8*byteLength) < 2N for every RFC 5054 modulus.
        let reducedB = serverPublic.reducedOnce(modulus: modulus)
        if reducedB.isZero {
            throw AxiamError.network(
                NetworkError("SRP: the server sent an invalid public value (B mod N == 0)"))
        }

        let paddedA = try Srp.fromHex(clientPublic, field: "client_public")
        let paddedB = try Srp.pad(serverPublic, width: width)

        // u = H(PAD(A) | PAD(B))
        let u = SrpBigInt(bigEndian: Srp.hash([paddedA, paddedB]))
        if u.isZero {
            throw AxiamError.network(NetworkError("SRP: the server's parameters produce u == 0"))
        }

        let xInt = SrpBigInt(bigEndian: x).reducedOnce(modulus: modulus)
        let k = try Srp.multiplier(group, modulus: modulus)

        // S = (B - k*g^x)^(a + u*x) mod N
        let gx = montgomery.power(base: SrpBigInt(group.generator), exponent: xInt)
        let kgx = montgomery.modMul(k.reducedOnce(modulus: modulus), gx)
        let base = SrpBigInt.subMod(reducedB, kgx, modulus)
        // The exponent is NOT reduced: a + u*x is an exponent, and reducing it
        // modulo N rather than the group order would produce a different — wrong —
        // S that still looks perfectly well-formed.
        let exponent = ephemeral + (u * xInt)
        let shared = montgomery.power(base: base, exponent: exponent)

        let paddedS = try Srp.pad(shared, width: width)
        let sessionKey = Srp.hash([paddedS])

        // M1 = H(H(N) XOR H(PAD(g)) | H(I) | s | PAD(A) | PAD(B) | K)
        let hn = Srp.hash([try Srp.pad(modulus, width: width)])
        let hg = Srp.hash([try Srp.pad(SrpBigInt(group.generator), width: width)])
        var hxor = [UInt8](repeating: 0, count: hn.count)
        for index in hn.indices {
            hxor[index] = hn[index] ^ hg[index]
        }
        let hi = Srp.hash([Array(identity.utf8)])
        let m1 = Srp.hash([hxor, hi, salt, paddedA, paddedB, sessionKey])

        // M2 = H(PAD(A) | M1 | K)
        let m2 = Srp.hash([paddedA, m1, sessionKey])

        return SrpProofs(clientProof: Srp.toHex(m1), expectedServerProof: Srp.toHex(m2))
    }
}
