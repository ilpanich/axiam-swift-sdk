import Foundation

/// Entry points into `libaxiam_opaque_ffi` (CONTRACT.md §23).
///
/// There is no cryptography in this enum, or anywhere in this package. That is deliberate and is
/// what §23.1 requires: OPAQUE needs an oblivious PRF, `hash_to_curve`, `expand_message_xmd`, an
/// envelope construction and a three-message AKE, and eleven independent implementations of that
/// is eleven chances to be subtly and silently wrong. The SRP-6a this replaces was arithmetic
/// every language can express — which here meant a hand-written big-integer modular exponentiation
/// and a `pbkdf2_sha256`-only limitation on top, because Swift has no Argon2 that ships on every
/// supported platform.
public enum Opaque {

    /// Whether this installation can perform OPAQUE (§23.2).
    ///
    /// Reports rather than throwing. Swift was already a language where the SRP equivalent could
    /// not serve every tenant; it still cannot serve every *installation*, for a different and
    /// simpler reason — the shared library is absent — but a `true` here now means every tenant
    /// works, `argon2id` included.
    public static func available() -> Bool {
        OpaqueLibrary.load() != nil
    }

    /// Blinds `password` to open an enrolment.
    ///
    /// - Throws: ``AxiamError/network(_:)`` if the library is unavailable or refuses.
    public static func startRegistration(password: String) throws -> RegistrationExchange {
        let lib = try OpaqueLibrary.require()

        guard let started = lib.registrationStart(password: password) else {
            throw AxiamError.network(NetworkError(
                "OPAQUE: " + lastError(lib, fallback: "registration could not be started")))
        }

        return RegistrationExchange(lib: lib, handle: started.state, request: started.request)
    }

    /// Blinds `password` to open a login.
    ///
    /// - Throws: ``AxiamError/network(_:)`` if the library is unavailable or refuses.
    public static func startLogin(password: String) throws -> LoginExchange {
        let lib = try OpaqueLibrary.require()

        guard let started = lib.loginStart(password: password) else {
            throw AxiamError.network(NetworkError(
                "OPAQUE: " + lastError(lib, fallback: "login could not be started")))
        }

        return LoginExchange(lib: lib, handle: started.state, ke1: started.ke1)
    }

    /// The library's description of the last failure, or `fallback`.
    ///
    /// A failure with nothing behind it is a library bug, but a caller still deserves a sentence
    /// rather than an empty one.
    static func lastError(_ lib: OpaqueNative, fallback: String) -> String {
        let message = lib.lastError()
        return message.isEmpty ? fallback : message
    }
}
