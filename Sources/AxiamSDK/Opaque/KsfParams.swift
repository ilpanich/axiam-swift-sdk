import Foundation

/// The key-stretching function and cost a `/start` response names (CONTRACT.md §23.4).
///
/// The cost properties are optional on purpose: they arrive flat, and a field that does not apply
/// to the named function is **absent, not zero**. Reading a missing ``memoryKib`` as `0` would
/// stretch at the wrong cost and fail against a record that is perfectly good (§23.4 rule 5).
///
/// These are never cached across exchanges and never defaulted locally. A credential enrolled
/// under one cost keeps working after a tenant raises its policy, so a client that guessed would
/// derive a different randomized password and report "invalid password" for one that is entirely
/// correct (§23.4 rule 2).
///
/// ## This is where Swift stopped needing a `pbkdf2_sha256` tenant
///
/// The SRP client this replaces refused an `argon2id` tenant outright: Swift has no Argon2 that
/// ships on every supported platform, and substituting PBKDF2 would have derived a different `x`
/// and surfaced as "invalid password". AXIAM's *default* KDF was, for Swift, unreachable. The key
/// stretching now happens inside `libaxiam_opaque_ffi`, so `argon2id` is no longer a Swift-shaped
/// hole — and `pbkdf2_sha256` is not an OPAQUE key-stretching function at all.
public struct KsfParams: Sendable, Equatable {

    /// The wire name of the memory-hard function AXIAM asks for by default.
    public static let argon2id = "argon2id"

    /// The wire name of the alternative AXIAM accepts.
    public static let scrypt = "scrypt"

    /// The bands this SDK will act on, per field.
    ///
    /// A server is trusted to name its own policy, not to name a cost that would wedge every
    /// device an account owns. The library range-checks too; doing it here as well means the
    /// refusal names the field.
    private static let bounds: [String: ClosedRange<Int>] = [
        "memory_kib": 8192...1_048_576,
        "iterations": 1...10,
        "parallelism": 1...16,
        "log_n": 14...20,
        "r": 1...16,
        "p": 1...16,
    ]

    /// The wire name of the function: `argon2id` or `scrypt`.
    public let ksf: String

    /// Argon2id's memory cost in KiB.
    public let memoryKib: Int?

    /// Argon2id's time cost.
    public let iterations: Int?

    /// Argon2id's lane count.
    public let parallelism: Int?

    /// scrypt's base-2 CPU/memory cost.
    public let logN: Int?

    /// scrypt's block size.
    public let r: Int?

    /// scrypt's parallelisation parameter.
    public let p: Int?

    /// Every field exactly as the server named it — no local defaults, no coercion of an absent
    /// cost to zero.
    public init(
        ksf: String,
        memoryKib: Int? = nil,
        iterations: Int? = nil,
        parallelism: Int? = nil,
        logN: Int? = nil,
        r: Int? = nil,
        p: Int? = nil
    ) {
        self.ksf = ksf
        self.memoryKib = memoryKib
        self.iterations = iterations
        self.parallelism = parallelism
        self.logN = logN
        self.r = r
        self.p = p
    }

    /// Builds the library's key-stretching handle from what the *server* named.
    ///
    /// An unrecognised function is refused, never substituted: substituting produces a well-formed
    /// randomized password no AXIAM server agrees with, which surfaces to the user as a wrong
    /// password (§23.4 rule 3). The returned handle must be released with `ksfFree`.
    func build(_ lib: OpaqueNative) throws -> OpaqueHandle {
        let handle: OpaqueHandle?

        switch ksf {
        case KsfParams.argon2id:
            handle = lib.ksfArgon2id(
                memoryKib: UInt32(try require("memory_kib", memoryKib)),
                iterations: UInt32(try require("iterations", iterations)),
                parallelism: UInt32(try require("parallelism", parallelism))
            )
        case KsfParams.scrypt:
            handle = lib.ksfScrypt(
                logN: UInt8(try require("log_n", logN)),
                r: UInt32(try require("r", r)),
                p: UInt32(try require("p", p))
            )
        default:
            throw AxiamError.network(NetworkError(
                "OPAQUE: this SDK cannot perform the key-stretching function the server named "
                + "(`\(ksf)`)"))
        }

        guard let handle else {
            throw AxiamError.network(NetworkError(
                "OPAQUE: " + Opaque.lastError(lib, fallback: "invalid KSF parameters")))
        }

        return handle
    }

    /// One cost the named function needs: present, and inside the band this SDK will act on.
    private func require(_ field: String, _ value: Int?) throws -> Int {
        guard let value else {
            throw AxiamError.network(NetworkError(
                "OPAQUE: the server named ksf `\(ksf)` without `\(field)`"))
        }

        // A field with no band would be a programming error here, not a server
        // problem -- every branch above names one of the six.
        guard let band = KsfParams.bounds[field], band.contains(value) else {
            let band = KsfParams.bounds[field]
            let low = band?.lowerBound ?? 0
            let high = band?.upperBound ?? 0
            throw AxiamError.network(NetworkError(
                "OPAQUE: the server named \(field)=\(value) for `\(ksf)`, outside the accepted "
                + "\(low)..\(high)"))
        }

        return value
    }
}
