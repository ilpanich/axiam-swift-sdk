import Foundation

/// A wrapper for secret material (§7 of CONTRACT.md).
///
/// The wrapped value is never exposed through a public getter, and every textual
/// representation (`description`, `debugDescription`, string interpolation) emits the
/// fixed placeholder `"[SENSITIVE]"`. Internal SDK code that legitimately needs the raw
/// value reads it through the module-internal ``wrapped`` accessor.
///
/// Deliberately NOT `Encodable`/`Codable`: serialising a `Sensitive` value must never
/// emit the secret it protects.
public struct Sensitive<T>: CustomStringConvertible, CustomDebugStringConvertible {
    private let value: T

    public init(_ value: T) {
        self.value = value
    }

    /// Module-internal access to the protected value. Not a public getter (§7).
    var wrapped: T { value }

    public var description: String { "[SENSITIVE]" }
    public var debugDescription: String { "[SENSITIVE]" }
}

extension Sensitive: Sendable where T: Sendable {}

extension Sensitive: Equatable where T: Equatable {
    public static func == (lhs: Sensitive<T>, rhs: Sensitive<T>) -> Bool {
        lhs.value == rhs.value
    }
}
