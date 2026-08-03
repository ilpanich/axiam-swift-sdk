import Foundation

/// Types whose value can be compared as raw bytes in constant time.
///
/// ``Sensitive`` conforms to `Equatable` only for wrapped types that can produce a byte
/// representation, so comparing secret material never falls back to a short-circuiting `==`
/// (SEC-077). Conform your own secret-bearing type to opt it into the same treatment.
public protocol ConstantTimeComparable {
    /// The raw bytes to compare. For textual secrets this is the UTF-8 encoding.
    var constantTimeBytes: [UInt8] { get }
}

extension String: ConstantTimeComparable {
    public var constantTimeBytes: [UInt8] { Array(utf8) }
}

extension Data: ConstantTimeComparable {
    public var constantTimeBytes: [UInt8] { [UInt8](self) }
}

extension Array: ConstantTimeComparable where Element == UInt8 {
    public var constantTimeBytes: [UInt8] { self }
}

/// Constant-time byte comparison.
///
/// The comparison walks its inputs to completion: it never returns early on the first differing
/// byte, so its running time depends only on the *lengths* of the inputs and never on where — or
/// whether — they differ. Length is not a secret at any SDK use site (a MAC has a fixed length; a
/// wrapped credential's length is not the credential), but the length check is folded into the
/// same accumulator rather than short-circuiting, so a length mismatch still performs the full
/// walk instead of leaking the position of the first difference.
enum ConstantTime {
    /// `true` when `lhs` and `rhs` are byte-identical. Data-independent in running time.
    static func equals(_ lhs: [UInt8], _ rhs: [UInt8]) -> Bool {
        // Seed the accumulator with the length difference instead of returning early on it.
        var difference = UInt32(truncatingIfNeeded: lhs.count) ^ UInt32(truncatingIfNeeded: rhs.count)
        let count = max(lhs.count, rhs.count)
        var index = 0
        while index < count {
            // Out-of-range positions read as 0. This branch depends on the (non-secret) lengths
            // only, never on byte values, and the loop always runs the full `count` iterations.
            let left = index < lhs.count ? lhs[index] : 0
            let right = index < rhs.count ? rhs[index] : 0
            difference |= UInt32(left ^ right)
            index += 1
        }
        return difference == 0
    }
}
