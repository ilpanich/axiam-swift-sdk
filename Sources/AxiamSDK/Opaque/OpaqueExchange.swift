import Foundation

/// One in-flight OPAQUE exchange, owning a native state handle.
///
/// The handle is **single-use**: the library consumes it in `finish` whether that succeeds or
/// fails. This class takes it out of a one-shot slot, so a second `finish` throws rather than
/// handing a dangling pointer across the ABI.
///
/// `deinit` releases an exchange the caller abandoned — a login started and never completed.
/// Swift's refcounting makes that prompt rather than eventual, which is the one place its object
/// model is kinder here than a tracing GC's.
///
/// A `class` rather than a `struct` for exactly that reason: the release has to happen when the
/// last reference goes, and value semantics would either copy the handle or fight the copy. The
/// release is a closure captured at construction rather than an overridden method, so `deinit`
/// never dispatches into a subclass whose own storage has already been torn down.
public class OpaqueExchange {

    let lib: OpaqueNative

    /// The first protocol message, hex — `RegistrationRequest` or `KE1`.
    let firstMessage: String

    private let lock = NSLock()
    private let release: (OpaqueHandle) -> Void
    private var handle: OpaqueHandle?

    init(
        lib: OpaqueNative,
        handle: OpaqueHandle,
        firstMessage: String,
        release: @escaping (OpaqueHandle) -> Void
    ) {
        self.lib = lib
        self.handle = handle
        self.firstMessage = firstMessage
        self.release = release
    }

    /// Spends the handle, or refuses if it is already spent.
    func consume() throws -> OpaqueHandle {
        lock.lock()
        defer { lock.unlock() }

        guard let spent = handle else {
            throw AxiamError.network(
                NetworkError("OPAQUE: this exchange has already been completed"))
        }
        handle = nil
        return spent
    }

    /// Releases the exchange if it was never finished.
    ///
    /// Idempotent, and a no-op once `finish` has spent the handle. Calling it is optional —
    /// `deinit` does the same thing — but an application that knows the exchange is over should
    /// not wait for a refcount to say so.
    public func close() {
        lock.lock()
        let abandoned = handle
        handle = nil
        lock.unlock()

        if let abandoned {
            release(abandoned)
        }
    }

    deinit {
        if let abandoned = handle {
            release(abandoned)
        }
    }
}

/// One in-flight enrolment (CONTRACT.md §23).
public final class RegistrationExchange: OpaqueExchange {

    init(lib: OpaqueNative, handle: OpaqueHandle, request: String) {
        super.init(lib: lib, handle: handle, firstMessage: request) { [lib] abandoned in
            lib.registrationFree(abandoned)
        }
    }

    /// The hex `RegistrationRequest` to send to `register/start`.
    public var request: String { firstMessage }

    /// Seals the envelope under the server's oblivious PRF, returning the hex
    /// `RegistrationRecord`.
    ///
    /// - Throws: ``AxiamError/network(_:)`` if the exchange is already spent, the key-stretching
    ///   function is one this SDK cannot ask for, or the library refuses the response.
    public func finish(
        password: String,
        registrationResponse: String,
        ksf: KsfParams
    ) throws -> String {
        // The key-stretching handle is built BEFORE the state is spent, and the
        // order is load-bearing. `build` refuses an unrecognised function or an
        // out-of-band cost, and if the state had already been taken out of its
        // one-shot slot by then it could never be freed -- a leaked Rust
        // allocation per refused attempt, which is once per login against a
        // misconfigured tenant. Built first, a refusal leaves the exchange
        // intact: `close()` still releases it, and a caller who fixes the
        // parameters can retry.
        let ksfHandle = try ksf.build(lib)
        defer { lib.ksfFree(ksfHandle) }

        let state = try consume()

        guard let record = lib.registrationFinish(
            state: state,
            password: password,
            registrationResponse: registrationResponse,
            ksf: ksfHandle
        ) else {
            throw AxiamError.network(NetworkError(
                "OPAQUE: " + Opaque.lastError(lib, fallback: "the envelope could not be sealed")))
        }

        return record
    }
}

/// One in-flight login (CONTRACT.md §23).
public final class LoginExchange: OpaqueExchange {

    init(lib: OpaqueNative, handle: OpaqueHandle, ke1: String) {
        super.init(lib: lib, handle: handle, firstMessage: ke1) { [lib] abandoned in
            lib.loginFree(abandoned)
        }
    }

    /// The hex `KE1` to send to `login/start`.
    public var ke1: String { firstMessage }

    /// Opens the envelope, producing `KE3`.
    ///
    /// A failure here is the **whole** of the client's authentication check, and covers both
    /// halves of the mutual authentication: the envelope only opens under the right password, and
    /// `KE2`'s MAC only verifies if the server actually holds the record. Nothing may be sent
    /// afterwards (§23.4 rule 7).
    ///
    /// That case is an ``AxiamError/auth(_:)``, unlike every other refusal in this package. The
    /// distinction is the point: a wrong password, an account that does not exist and a server
    /// that does not hold the record are indistinguishable by design and are all authentication
    /// failures, whereas a key-stretching function this build cannot perform is a configuration
    /// problem, and reporting it as "invalid password" would send an operator looking in the wrong
    /// place.
    ///
    /// - Throws: ``AxiamError/auth(_:)`` when the envelope does not open or `KE2` does not verify.
    /// - Throws: ``AxiamError/network(_:)`` if the exchange is already spent, or the
    ///   key-stretching function is one this SDK cannot ask for.
    public func finish(password: String, ke2: String, ksf: KsfParams) throws -> String {
        // Built before the state is spent -- see RegistrationExchange.finish for why.
        let ksfHandle = try ksf.build(lib)
        defer { lib.ksfFree(ksfHandle) }

        let state = try consume()

        guard let ke3 = lib.loginFinish(
            state: state,
            password: password,
            ke2: ke2,
            ksf: ksfHandle
        ) else {
            throw AxiamError.auth(AuthError(
                "invalid credentials: "
                + Opaque.lastError(lib, fallback: "the OPAQUE envelope did not open")))
        }

        return ke3
    }
}
