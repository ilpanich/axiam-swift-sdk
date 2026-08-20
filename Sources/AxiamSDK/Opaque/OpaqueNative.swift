import Foundation

/// The `libaxiam_opaque_ffi` C ABI, expressed in Swift terms.
///
/// A protocol rather than the `dlsym` calls themselves, for one reason: it is what a test can
/// implement. CONTRACT.md §23.1 forbids this SDK from implementing OPAQUE, so there is no
/// cryptography here to test — what there is, and what a fake can exercise exhaustively, is the
/// layer above: single-use exchanges, the key-stretching function the *server* named being the one
/// used, and which failure means what.
///
/// The methods take and return Swift `String`s rather than pointers. Pointer ownership — who frees
/// a returned `char *`, when a state handle is spent — is real but is entirely
/// ``DynamicOpaqueNative``'s, because it is the only implementation that has pointers at all. That
/// keeps the untestable-without-the-real-library part as small as it can be.
///
/// A `nil` return always means the library refused; ``lastError()`` says why.
protocol OpaqueNative: AnyObject, Sendable {
    /// Whether this build can perform OPAQUE.
    func available() -> Bool

    /// The library's description of the last failure, or an empty string.
    func lastError() -> String

    /// Builds an Argon2id key-stretching handle, or `nil` when the parameters are refused.
    func ksfArgon2id(memoryKib: UInt32, iterations: UInt32, parallelism: UInt32) -> OpaqueHandle?

    /// Builds a scrypt key-stretching handle, or `nil` when the parameters are refused.
    func ksfScrypt(logN: UInt8, r: UInt32, p: UInt32) -> OpaqueHandle?

    /// Releases a key-stretching handle.
    func ksfFree(_ ksf: OpaqueHandle)

    /// Begins an enrolment, returning the state handle and the hex `RegistrationRequest`.
    func registrationStart(password: String) -> (state: OpaqueHandle, request: String)?

    /// Completes an enrolment, CONSUMING `state` whether it succeeds or fails.
    func registrationFinish(
        state: OpaqueHandle,
        password: String,
        registrationResponse: String,
        ksf: OpaqueHandle
    ) -> String?

    /// Releases enrolment state that was never finished.
    func registrationFree(_ state: OpaqueHandle)

    /// Begins a login, returning the state handle and the hex `KE1`.
    func loginStart(password: String) -> (state: OpaqueHandle, ke1: String)?

    /// Completes a login, CONSUMING `state`.
    ///
    /// A `nil` return is the whole of the client's authentication check, and it covers both halves
    /// of the mutual authentication: the envelope only opens under the right password, and `KE2`'s
    /// MAC only verifies if the server actually holds the record. Per CONTRACT.md §23.4 rule 7
    /// nothing may be sent to `login/finish` after it.
    func loginFinish(
        state: OpaqueHandle,
        password: String,
        ke2: String,
        ksf: OpaqueHandle
    ) -> String?

    /// Releases login state that was never finished.
    func loginFree(_ state: OpaqueHandle)
}

/// An opaque handle the library owns and this SDK only passes back.
///
/// A boxed integer rather than a raw pointer, so a fake can mint one without allocating and the
/// protocol stays free of `Unsafe*` types. ``DynamicOpaqueNative`` is the only place that turns it
/// back into a pointer, and only for pointers the library handed it in the first place.
struct OpaqueHandle: Hashable, Sendable {
    let value: UInt

    init(value: UInt) {
        self.value = value
    }

    init(_ pointer: UnsafeMutableRawPointer) {
        self.value = UInt(bitPattern: pointer)
    }

    var pointer: UnsafeMutableRawPointer? {
        UnsafeMutableRawPointer(bitPattern: value)
    }
}
