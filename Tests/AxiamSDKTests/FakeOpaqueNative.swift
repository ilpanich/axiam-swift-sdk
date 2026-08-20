import Foundation
@testable import AxiamSDK

/// An in-process stand-in for `libaxiam_opaque_ffi`.
///
/// CONTRACT.md §23.1 forbids this SDK from implementing OPAQUE, so there is no cryptography to
/// test. What there is — and what this fake exercises — is the layer above the ABI: single-use
/// exchanges, the key-stretching function the *server* named being the one used, which failure
/// means what, and what goes on the wire.
///
/// It does **not** stand in for pointer ownership. In Swift that lives entirely inside
/// `DynamicOpaqueNative`, which needs the real shared library to exercise — which is exactly why
/// that class is the thinnest in the package. Requiring the real `cdylib` here would give a suite
/// that runs only where a per-platform release asset happens to be installed, and would be testing
/// `opaque-ke` rather than this SDK.
///
/// Every value it returns is hex, as the real ABI's are: a fake that handed back raw bytes would
/// let a binding bug survive.
final class FakeOpaqueNative: OpaqueNative, @unchecked Sendable {

    /// What `available()` answers.
    var availableValue = true

    /// Key-stretching handles built and not yet released. Must be zero after any finish.
    private(set) var ksfAlive = 0

    /// Live state handles, mapped to their kind.
    private var states: [OpaqueHandle: String] = [:]

    private var nextHandle: UInt = 0x1000
    private var failing: Set<String> = []
    private var failMessages: [String: String] = [:]
    private var lastErrorText = ""

    private let lock = NSLock()

    /// Makes an entry point return `nil` instead of working.
    func fail(_ entryPoint: String) {
        lock.lock()
        defer { lock.unlock() }
        failing.insert(entryPoint)
    }

    /// Overrides what `lastError()` reports for a failing entry point.
    ///
    /// An empty string models a library that failed without saying why — a bug, but one the caller
    /// still needs a sentence for.
    func failMessage(_ entryPoint: String, _ message: String) {
        lock.lock()
        defer { lock.unlock() }
        failMessages[entryPoint] = message
    }

    /// State handles neither consumed nor released.
    var statesAlive: Int {
        lock.lock()
        defer { lock.unlock() }
        return states.count
    }

    /// Decodes one of this fake's hex payloads.
    static func decode(_ hex: String) -> String {
        var bytes: [UInt8] = []
        var index = hex.startIndex
        while index < hex.endIndex, let next = hex.index(index, offsetBy: 2, limitedBy: hex.endIndex) {
            guard let byte = UInt8(hex[index..<next], radix: 16) else { return "" }
            bytes.append(byte)
            index = next
        }
        return String(decoding: bytes, as: UTF8.self)
    }

    private static func encode(_ text: String) -> String {
        Array(text.utf8).map { String(format: "%02x", $0) }.joined()
    }

    // -- helpers -------------------------------------------------------

    /// Caller must hold `lock`.
    private func failedLocked(_ entryPoint: String, _ message: String) -> Bool {
        guard failing.contains(entryPoint) else { return false }
        lastErrorText = failMessages[entryPoint] ?? message
        return true
    }

    /// Caller must hold `lock`.
    private func newStateLocked(_ kind: String) -> OpaqueHandle {
        nextHandle += 0x10
        let handle = OpaqueHandle(value: nextHandle)
        states[handle] = kind
        return handle
    }

    /// Caller must hold `lock`.
    private func consumeStateLocked(_ handle: OpaqueHandle, _ kind: String) {
        precondition(states[handle] == kind, "handle \(handle.value) was not a live \(kind)")
        states.removeValue(forKey: handle)
    }

    // -- the ABI -------------------------------------------------------

    func available() -> Bool { availableValue }

    func lastError() -> String {
        lock.lock()
        defer { lock.unlock() }
        return lastErrorText
    }

    func ksfArgon2id(memoryKib: UInt32, iterations: UInt32, parallelism: UInt32) -> OpaqueHandle? {
        lock.lock()
        defer { lock.unlock() }
        if failedLocked("ksf_argon2id", "argon2id parameters rejected") { return nil }
        ksfAlive += 1
        return OpaqueHandle(value: 0xA_0000 + UInt(memoryKib) + UInt(iterations) + UInt(parallelism))
    }

    func ksfScrypt(logN: UInt8, r: UInt32, p: UInt32) -> OpaqueHandle? {
        lock.lock()
        defer { lock.unlock() }
        if failedLocked("ksf_scrypt", "scrypt parameters rejected") { return nil }
        ksfAlive += 1
        return OpaqueHandle(value: 0xB_0000 + UInt(logN) + UInt(r) + UInt(p))
    }

    func ksfFree(_ ksf: OpaqueHandle) {
        lock.lock()
        defer { lock.unlock() }
        ksfAlive -= 1
    }

    func registrationStart(password: String) -> (state: OpaqueHandle, request: String)? {
        lock.lock()
        defer { lock.unlock() }
        if failedLocked("registration_start", "registration could not be started") { return nil }
        return (newStateLocked("registration"), FakeOpaqueNative.encode("req:" + password))
    }

    func registrationFinish(
        state: OpaqueHandle,
        password: String,
        registrationResponse: String,
        ksf: OpaqueHandle
    ) -> String? {
        lock.lock()
        defer { lock.unlock() }
        consumeStateLocked(state, "registration")
        if failedLocked("registration_finish", "the envelope could not be sealed") { return nil }
        return FakeOpaqueNative.encode(
            "record:\(password):\(registrationResponse):\(String(ksf.value, radix: 16))")
    }

    func registrationFree(_ state: OpaqueHandle) {
        lock.lock()
        defer { lock.unlock() }
        consumeStateLocked(state, "registration")
    }

    func loginStart(password: String) -> (state: OpaqueHandle, ke1: String)? {
        lock.lock()
        defer { lock.unlock() }
        if failedLocked("login_start", "login could not be started") { return nil }
        return (newStateLocked("login"), FakeOpaqueNative.encode("ke1:" + password))
    }

    func loginFinish(
        state: OpaqueHandle,
        password: String,
        ke2: String,
        ksf: OpaqueHandle
    ) -> String? {
        lock.lock()
        defer { lock.unlock() }
        consumeStateLocked(state, "login")
        if failedLocked("login_finish", "the envelope did not open") { return nil }
        return FakeOpaqueNative.encode("ke3:\(password):\(ke2):\(String(ksf.value, radix: 16))")
    }

    func loginFree(_ state: OpaqueHandle) {
        lock.lock()
        defer { lock.unlock() }
        consumeStateLocked(state, "login")
    }
}
