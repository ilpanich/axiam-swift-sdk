import Foundation

/// Loads `libaxiam_opaque_ffi` once per process, memoizing failure as well as success.
///
/// Two things can be absent, and both are normal:
///
/// - **The shared library.** A Rust `cdylib` published as a per-platform asset of the AXIAM
///   release, not a SwiftPM package — there is no cross-language registry to put it on.
/// - **The platform's ability to load it at all.** Resolution is `dlopen`, so a sandboxed iOS app
///   that has not embedded the framework simply will not find it.
///
/// Either absence makes ``Opaque/available()`` report `false` rather than throwing, so an
/// application chooses the password path up front instead of discovering the gap mid-login.
/// Memoizing the failure matters as much as memoizing the success: retrying `dlopen` on every
/// login is a per-request filesystem walk for a file that is not going to appear.
enum OpaqueLibrary {

    /// Overrides the search: an absolute path to the shared library.
    static let pathEnvironmentVariable = "AXIAM_OPAQUE_LIBRARY"

    /// The memoized outcome of the one `dlopen` attempt, guarded by ``lock``.
    ///
    /// A boxed reference rather than two `static var`s because Swift 6's strict
    /// concurrency checking rejects non-isolated global mutable state outright — and it is
    /// right to. Nothing in the type system was enforcing that every access went through
    /// ``lock``; that was a convention held by two call sites. Moving the storage inside a
    /// box makes the invariant structural: the only mutable state is in here, and the only
    /// code that can reach it is ``load()``, which holds the lock across the whole body.
    ///
    /// `@unchecked Sendable` is the honest annotation. The compiler cannot see that the
    /// lock serialises access, so the guarantee is stated rather than derived — exactly the
    /// situation the attribute exists for.
    private final class Memo: @unchecked Sendable {
        var library: OpaqueNative?
        var attempted = false
    }

    private static let lock = NSLock()
    private static let memo = Memo()

    /// The library, or `nil` when it is not present.
    static func load() -> OpaqueNative? {
        lock.lock()
        defer { lock.unlock() }

        if memo.attempted { return memo.library }
        memo.attempted = true

        for path in candidatePaths() {
            if let native = DynamicOpaqueNative.open(path: path), native.available() {
                memo.library = native
                return memo.library
            }
        }

        return nil
    }

    /// Where to look, most specific first.
    ///
    /// The environment variable wins when set — the escape hatch for a deployment that ships the
    /// artifact somewhere the loader would not look, which is the normal case for a container
    /// image carrying it alongside the application rather than installing it system-wide.
    ///
    /// The remaining entries are bare names, so the platform's own loader resolves them from its
    /// search path: `dlopen` is handed the string as-is.
    static func candidatePaths() -> [String] {
        if let override = ProcessInfo.processInfo.environment[pathEnvironmentVariable],
           !override.isEmpty {
            return [override]
        }

        #if canImport(Darwin)
        return ["libaxiam_opaque_ffi.dylib"]
        #else
        return ["libaxiam_opaque_ffi.so"]
        #endif
    }

    /// The library, or a refusal naming the artifact.
    ///
    /// Never an ``AxiamError/auth(_:)``: absent is a deployment fact, and reporting it as a
    /// credential failure would send a user off to reset a password that works.
    static func require() throws -> OpaqueNative {
        guard let library = load() else {
            throw AxiamError.network(NetworkError(
                "OPAQUE is not available: the shared library `libaxiam_opaque_ffi` could not be "
                + "loaded. Download the asset for your platform from the axiam release page, then "
                + "put it on the system library path or set \(pathEnvironmentVariable) to its "
                + "full path."))
        }
        return library
    }

    /// Installs a binding, bypassing the loader. Test-only.
    static func setForTests(_ stub: OpaqueNative?) {
        lock.lock()
        defer { lock.unlock() }
        memo.library = stub
        memo.attempted = true
    }

    /// Forgets the memoized load. Test-only.
    static func resetForTests() {
        lock.lock()
        defer { lock.unlock() }
        memo.library = nil
        memo.attempted = false
    }
}
