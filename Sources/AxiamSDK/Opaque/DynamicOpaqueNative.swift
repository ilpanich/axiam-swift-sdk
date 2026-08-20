import Foundation

#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

/// The real binding to `libaxiam_opaque_ffi`, resolved with `dlopen`/`dlsym`.
///
/// ## Why `dlopen` and not a SwiftPM `systemLibrary` target
///
/// A `systemLibrary` target makes the shared library a **link-time** requirement: every consumer
/// of this SDK would need it present to build at all, whether or not their tenant uses OPAQUE.
/// That would make ``AxiamClient/opaqueAvailable()`` a function that can only ever return `true`,
/// which is the opposite of what §23.2 asks for. Resolving at run time is what lets the library be
/// genuinely optional.
///
/// ## What this class owns
///
/// Deliberately the thinnest layer in this package. Everything above it — exchange lifecycle,
/// key-stretching selection, error mapping — lives in types a test can drive against a fake
/// ``OpaqueNative``. What is here needs the actual shared library to exercise, so there is as
/// little of it as the job allows, and the two rules it has to get right are stated where they are
/// implemented:
///
/// 1. **Every `char *` the library returns is Rust-allocated and must be freed exactly once.**
///    ``take(_:)`` copies it into a Swift `String` and frees it, on every path including the
///    failure ones — a binding that freed only on success would leak once per failed login, which
///    is the login rate an installation under attack sees.
/// 2. **A state handle is consumed by its `finish`, success or failure.** This class does not free
///    one afterwards; ``OpaqueExchange`` is what guarantees it is never used twice.
final class DynamicOpaqueNative: OpaqueNative, @unchecked Sendable {

    // The C signatures, as Swift function types. `@convention(c)` is what makes
    // `unsafeBitCast` from a dlsym result well-defined rather than hopeful.
    private typealias StringFreeFn = @convention(c) (UnsafeMutableRawPointer?) -> Void
    private typealias LastErrorFn = @convention(c) () -> UnsafePointer<CChar>?
    private typealias AvailableFn = @convention(c) () -> Int32
    private typealias KsfArgon2idFn =
        @convention(c) (UInt32, UInt32, UInt32) -> UnsafeMutableRawPointer?
    private typealias KsfScryptFn =
        @convention(c) (UInt8, UInt32, UInt32) -> UnsafeMutableRawPointer?
    private typealias KsfFreeFn = @convention(c) (UnsafeMutableRawPointer?) -> Void
    private typealias StartFn = @convention(c) (
        UnsafePointer<CChar>?,
        UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
    ) -> UnsafeMutableRawPointer?
    private typealias RegistrationFinishFn = @convention(c) (
        UnsafeMutableRawPointer?,
        UnsafePointer<CChar>?,
        UnsafePointer<CChar>?,
        UnsafeMutableRawPointer?,
        UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
    ) -> UnsafeMutablePointer<CChar>?
    private typealias LoginFinishFn = @convention(c) (
        UnsafeMutableRawPointer?,
        UnsafePointer<CChar>?,
        UnsafePointer<CChar>?,
        UnsafeMutableRawPointer?,
        UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?,
        UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
    ) -> UnsafeMutablePointer<CChar>?
    private typealias FreeFn = @convention(c) (UnsafeMutableRawPointer?) -> Void

    private let handle: UnsafeMutableRawPointer

    private let stringFreeFn: StringFreeFn
    private let lastErrorFn: LastErrorFn
    private let availableFn: AvailableFn
    private let ksfArgon2idFn: KsfArgon2idFn
    private let ksfScryptFn: KsfScryptFn
    private let ksfFreeFn: KsfFreeFn
    private let registrationStartFn: StartFn
    private let registrationFinishFn: RegistrationFinishFn
    private let registrationFreeFn: FreeFn
    private let loginStartFn: StartFn
    private let loginFinishFn: LoginFinishFn
    private let loginFreeFn: FreeFn

    /// Opens the library at `path`, or returns `nil` when it — or any symbol — is absent.
    ///
    /// Every symbol is resolved up front rather than lazily. A library that loads and is missing
    /// one export is some *other* library of the same name on the search path, and the moment to
    /// discover that is now, not at the first login.
    static func open(path: String) -> DynamicOpaqueNative? {
        // RTLD_NOW so a missing symbol is a failure to load rather than a crash at
        // the first login. Scope is left at the platform default -- private on
        // Linux already, and on Darwin the flag is spelled RTLD_LOCAL; naming it
        // only where it changes something keeps the conditional import surface at
        // one symbol.
        #if canImport(Darwin)
        let flags = RTLD_NOW | RTLD_LOCAL
        #else
        let flags = RTLD_NOW
        #endif

        guard let handle = dlopen(path, flags) else { return nil }

        func symbol(_ name: String) -> UnsafeMutableRawPointer? {
            dlsym(handle, name)
        }

        guard
            let stringFree = symbol("axiam_opaque_string_free"),
            let lastError = symbol("axiam_opaque_last_error"),
            let available = symbol("axiam_opaque_available"),
            let ksfArgon2id = symbol("axiam_opaque_ksf_argon2id"),
            let ksfScrypt = symbol("axiam_opaque_ksf_scrypt"),
            let ksfFree = symbol("axiam_opaque_ksf_free"),
            let registrationStart = symbol("axiam_opaque_registration_start"),
            let registrationFinish = symbol("axiam_opaque_registration_finish"),
            let registrationFree = symbol("axiam_opaque_registration_free"),
            let loginStart = symbol("axiam_opaque_login_start"),
            let loginFinish = symbol("axiam_opaque_login_finish"),
            let loginFree = symbol("axiam_opaque_login_free")
        else {
            dlclose(handle)
            return nil
        }

        return DynamicOpaqueNative(
            handle: handle,
            stringFreeFn: unsafeBitCast(stringFree, to: StringFreeFn.self),
            lastErrorFn: unsafeBitCast(lastError, to: LastErrorFn.self),
            availableFn: unsafeBitCast(available, to: AvailableFn.self),
            ksfArgon2idFn: unsafeBitCast(ksfArgon2id, to: KsfArgon2idFn.self),
            ksfScryptFn: unsafeBitCast(ksfScrypt, to: KsfScryptFn.self),
            ksfFreeFn: unsafeBitCast(ksfFree, to: KsfFreeFn.self),
            registrationStartFn: unsafeBitCast(registrationStart, to: StartFn.self),
            registrationFinishFn: unsafeBitCast(registrationFinish, to: RegistrationFinishFn.self),
            registrationFreeFn: unsafeBitCast(registrationFree, to: FreeFn.self),
            loginStartFn: unsafeBitCast(loginStart, to: StartFn.self),
            loginFinishFn: unsafeBitCast(loginFinish, to: LoginFinishFn.self),
            loginFreeFn: unsafeBitCast(loginFree, to: FreeFn.self)
        )
    }

    // swiftlint:disable:next function_parameter_count
    private init(
        handle: UnsafeMutableRawPointer,
        stringFreeFn: @escaping StringFreeFn,
        lastErrorFn: @escaping LastErrorFn,
        availableFn: @escaping AvailableFn,
        ksfArgon2idFn: @escaping KsfArgon2idFn,
        ksfScryptFn: @escaping KsfScryptFn,
        ksfFreeFn: @escaping KsfFreeFn,
        registrationStartFn: @escaping StartFn,
        registrationFinishFn: @escaping RegistrationFinishFn,
        registrationFreeFn: @escaping FreeFn,
        loginStartFn: @escaping StartFn,
        loginFinishFn: @escaping LoginFinishFn,
        loginFreeFn: @escaping FreeFn
    ) {
        self.handle = handle
        self.stringFreeFn = stringFreeFn
        self.lastErrorFn = lastErrorFn
        self.availableFn = availableFn
        self.ksfArgon2idFn = ksfArgon2idFn
        self.ksfScryptFn = ksfScryptFn
        self.ksfFreeFn = ksfFreeFn
        self.registrationStartFn = registrationStartFn
        self.registrationFinishFn = registrationFinishFn
        self.registrationFreeFn = registrationFreeFn
        self.loginStartFn = loginStartFn
        self.loginFinishFn = loginFinishFn
        self.loginFreeFn = loginFreeFn
    }

    // No `deinit { dlclose(handle) }`: the loader memoizes one instance for the
    // process lifetime, and closing a library whose function pointers may still
    // be reachable is a worse failure than holding a handle until exit.

    func available() -> Bool {
        availableFn() != 0
    }

    func lastError() -> String {
        guard let raw = lastErrorFn() else { return "" }
        // Borrowed, not owned: library-allocated and NOT freed here.
        return String(cString: raw)
    }

    func ksfArgon2id(memoryKib: UInt32, iterations: UInt32, parallelism: UInt32) -> OpaqueHandle? {
        ksfArgon2idFn(memoryKib, iterations, parallelism).map(OpaqueHandle.init)
    }

    func ksfScrypt(logN: UInt8, r: UInt32, p: UInt32) -> OpaqueHandle? {
        ksfScryptFn(logN, r, p).map(OpaqueHandle.init)
    }

    func ksfFree(_ ksf: OpaqueHandle) {
        ksfFreeFn(ksf.pointer)
    }

    func registrationStart(password: String) -> (state: OpaqueHandle, request: String)? {
        start(password: password, fn: registrationStartFn).map { (state: $0.0, request: $0.1) }
    }

    func registrationFinish(
        state: OpaqueHandle,
        password: String,
        registrationResponse: String,
        ksf: OpaqueHandle
    ) -> String? {
        password.withCString { passwordPtr in
            registrationResponse.withCString { responsePtr in
                let record = registrationFinishFn(
                    state.pointer, passwordPtr, responsePtr, ksf.pointer, nil)
                return record.map(take)
            }
        }
    }

    func registrationFree(_ state: OpaqueHandle) {
        registrationFreeFn(state.pointer)
    }

    func loginStart(password: String) -> (state: OpaqueHandle, ke1: String)? {
        start(password: password, fn: loginStartFn).map { (state: $0.0, ke1: $0.1) }
    }

    func loginFinish(
        state: OpaqueHandle,
        password: String,
        ke2: String,
        ksf: OpaqueHandle
    ) -> String? {
        password.withCString { passwordPtr in
            ke2.withCString { ke2Ptr in
                let ke3 = loginFinishFn(state.pointer, passwordPtr, ke2Ptr, ksf.pointer, nil, nil)
                return ke3.map(take)
            }
        }
    }

    func loginFree(_ state: OpaqueHandle) {
        loginFreeFn(state.pointer)
    }

    /// The shape both `*_start` entry points share: a state handle plus one out-parameter string.
    private func start(
        password: String,
        fn: StartFn
    ) -> (OpaqueHandle, String)? {
        var out: UnsafeMutablePointer<CChar>?
        let state = password.withCString { passwordPtr in
            withUnsafeMutablePointer(to: &out) { outPtr in
                fn(passwordPtr, outPtr)
            }
        }

        guard let state, let message = out else { return nil }

        return (OpaqueHandle(state), take(message))
    }

    /// Copies a returned string into Swift and frees the Rust allocation.
    ///
    /// `String(cString:)` copies, so the Swift value outlives the free. Doing the free in the same
    /// function that reads the value is what makes "exactly once" true by construction rather than
    /// by every caller remembering.
    private func take(_ pointer: UnsafeMutablePointer<CChar>) -> String {
        defer { stringFreeFn(UnsafeMutableRawPointer(pointer)) }
        return String(cString: pointer)
    }
}
