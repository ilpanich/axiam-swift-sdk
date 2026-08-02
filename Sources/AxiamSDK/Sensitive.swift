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

/// Equality over secret material is **constant-time** (SEC-077).
///
/// A plain `==` on the wrapped value short-circuits at the first differing byte, so the time it
/// takes to reject a candidate is proportional to how long a prefix it got right — the classic
/// signature/token oracle. The conformance is therefore constrained to
/// ``ConstantTimeComparable`` rather than `Equatable`: a wrapped type only becomes comparable by
/// providing bytes that the constant-time accumulator loop can walk to completion.
///
/// Deliberately **not** `Hashable`. `Hashable` would invite putting secrets into `Set`/dictionary
/// keys, where lookup is a hash-bucketed comparison that is not constant time, and would add a
/// second value derived from the secret with none of the redaction guarantees `Sensitive` exists
/// to provide. Compare secrets directly; do not index by them.
extension Sensitive: Equatable where T: ConstantTimeComparable {
    public static func == (lhs: Sensitive<T>, rhs: Sensitive<T>) -> Bool {
        ConstantTime.equals(lhs.value.constantTimeBytes, rhs.value.constantTimeBytes)
    }
}
