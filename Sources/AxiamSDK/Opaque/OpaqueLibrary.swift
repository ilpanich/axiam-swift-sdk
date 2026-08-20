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

    private static let lock = NSLock()
    private static var library: OpaqueNative?
    private static var attempted = false

    /// The library, or `nil` when it is not present.
    static func load() -> OpaqueNative? {
        lock.lock()
        defer { lock.unlock() }

        if attempted { return library }
        attempted = true

        for path in candidatePaths() {
            if let native = DynamicOpaqueNative.open(path: path), native.available() {
                library = native
                return library
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
        library = stub
        attempted = true
    }

    /// Forgets the memoized load. Test-only.
    static func resetForTests() {
        lock.lock()
        defer { lock.unlock() }
        library = nil
        attempted = false
    }
}
