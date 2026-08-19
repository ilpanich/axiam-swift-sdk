import Foundation

/// A minimal unsigned big integer over `[UInt64]` limbs, sized for SRP and
/// nothing else (CONTRACT.md §23.8).
///
/// Swift has no arbitrary-precision integer in its standard library and no
/// vendorable one that ships on every target this SDK supports, so §23.8 records
/// that the Swift SDK bundles its own. This is that: the exact operations SRP
/// needs — modular exponentiation, one modular multiply, add, subtract and a
/// single conditional reduction — and no more.
///
/// **Not constant-time.** §23.8 says so in as many words, and it is worth being
/// precise about what that costs. The secret operand here is `x` (and the
/// ephemeral `a`), and the exponent bits drive a square-and-multiply loop whose
/// branch pattern a co-resident attacker with a cache side channel could in
/// principle read. That attacker is already inside your process. What this
/// arithmetic *does* buy is that the password never reaches the server — the
/// threat model §23.0 states, which is about the network path and the server,
/// not about local side channels. An SDK on a platform with a vetted
/// constant-time bignum should use it; Swift does not have one.
///
/// Limbs are little-endian: `limbs[0]` is least significant. The representation
/// is always normalised — no trailing zero limbs except for the single-limb zero.
struct SrpBigInt: Equatable {

    /// Little-endian limbs. Never empty.
    private(set) var limbs: [UInt64]

    // MARK: - Construction

    init(limbs: [UInt64]) {
        self.limbs = limbs.isEmpty ? [0] : limbs
        normalize()
    }

    init(_ value: UInt64) {
        limbs = [value]
    }

    /// Parses a hex string, ignoring case and leading zeros.
    ///
    /// - Returns: `nil` for anything that is not hex. Never truncates: silently
    ///   dropping a nibble would produce a wrong value that still looked
    ///   well-formed.
    init?(hex: String) {
        var chars = Array(hex.drop { $0 == "0" })
        if chars.isEmpty { chars = ["0"] }
        var result: [UInt64] = []
        // Pad the most significant group to a whole limb so the chunking below
        // does not have to special-case it.
        let remainder = chars.count % 16
        if remainder != 0 {
            chars = Array(repeating: "0", count: 16 - remainder) + chars
        }
        var index = chars.count
        while index > 0 {
            let start = index - 16
            var limb: UInt64 = 0
            for character in chars[start..<index] {
                guard let digit = character.hexDigitValue else { return nil }
                limb = (limb << 4) | UInt64(digit)
            }
            result.append(limb)
            index = start
        }
        self.init(limbs: result)
    }

    /// Reads a big-endian byte string as an unsigned value.
    init(bigEndian bytes: [UInt8]) {
        var result: [UInt64] = []
        var index = bytes.count
        while index > 0 {
            var limb: UInt64 = 0
            let count = min(8, index)
            for offset in 0..<count {
                limb |= UInt64(bytes[index - 1 - offset]) << (8 * offset)
            }
            result.append(limb)
            index -= count
        }
        self.init(limbs: result.isEmpty ? [0] : result)
    }

    private mutating func normalize() {
        while limbs.count > 1 && limbs[limbs.count - 1] == 0 {
            limbs.removeLast()
        }
    }

    // MARK: - Rendering

    /// `PAD(v)` — exactly `width` big-endian bytes (§23.3 rule 1).
    ///
    /// Skipping this is the classic SRP interop bug: two implementations agree
    /// until a value happens to have a leading zero byte, and then roughly one
    /// login in 256 fails in a way that reads as a flaky network.
    ///
    /// - Returns: `nil` if the value is wider than `width` — a caller error, not
    ///   something to truncate, since dropping high bytes would produce a wrong
    ///   hash that still looked well-formed.
    func padded(to width: Int) -> [UInt8]? {
        var out = [UInt8](repeating: 0, count: width)
        for (limbIndex, limb) in limbs.enumerated() {
            for byteIndex in 0..<8 {
                let byte = UInt8((limb >> (8 * byteIndex)) & 0xff)
                let position = width - 1 - (limbIndex * 8 + byteIndex)
                if position < 0 {
                    if byte != 0 { return nil }
                    continue
                }
                out[position] = byte
            }
        }
        return out
    }

    var isZero: Bool { limbs.allSatisfy { $0 == 0 } }

    /// The number of significant bits, or 0 for zero.
    var bitWidth: Int {
        for index in stride(from: limbs.count - 1, through: 0, by: -1) where limbs[index] != 0 {
            return index * 64 + (64 - limbs[index].leadingZeroBitCount)
        }
        return 0
    }

    func bit(_ index: Int) -> Bool {
        let limbIndex = index / 64
        guard limbIndex < limbs.count else { return false }
        return (limbs[limbIndex] >> (index % 64)) & 1 == 1
    }

    // MARK: - Comparison

    static func compare(_ a: SrpBigInt, _ b: SrpBigInt) -> Int {
        let count = max(a.limbs.count, b.limbs.count)
        for index in stride(from: count - 1, through: 0, by: -1) {
            let x = index < a.limbs.count ? a.limbs[index] : 0
            let y = index < b.limbs.count ? b.limbs[index] : 0
            if x != y { return x > y ? 1 : -1 }
        }
        return 0
    }

    // MARK: - Arithmetic

    static func + (a: SrpBigInt, b: SrpBigInt) -> SrpBigInt {
        let count = max(a.limbs.count, b.limbs.count)
        var out: [UInt64] = []
        out.reserveCapacity(count + 1)
        var carry: UInt64 = 0
        for index in 0..<count {
            let x = index < a.limbs.count ? a.limbs[index] : 0
            let y = index < b.limbs.count ? b.limbs[index] : 0
            let (partial, overflow1) = x.addingReportingOverflow(y)
            let (sum, overflow2) = partial.addingReportingOverflow(carry)
            out.append(sum)
            carry = (overflow1 ? 1 : 0) + (overflow2 ? 1 : 0)
        }
        if carry != 0 { out.append(carry) }
        return SrpBigInt(limbs: out)
    }

    /// `a - b`, which the caller must know is non-negative.
    ///
    /// Every call site here is guarded by a `compare` or an add-then-subtract, so
    /// an underflow would be a programming error rather than input-dependent.
    static func - (a: SrpBigInt, b: SrpBigInt) -> SrpBigInt {
        var out: [UInt64] = []
        out.reserveCapacity(a.limbs.count)
        var borrow: UInt64 = 0
        for index in 0..<a.limbs.count {
            let x = a.limbs[index]
            let y = index < b.limbs.count ? b.limbs[index] : 0
            let (partial, underflow1) = x.subtractingReportingOverflow(y)
            let (difference, underflow2) = partial.subtractingReportingOverflow(borrow)
            out.append(difference)
            borrow = (underflow1 ? 1 : 0) + (underflow2 ? 1 : 0)
        }
        return SrpBigInt(limbs: out)
    }

    /// Schoolbook multiplication. Used only for `u * x`, which is small.
    static func * (a: SrpBigInt, b: SrpBigInt) -> SrpBigInt {
        var out = [UInt64](repeating: 0, count: a.limbs.count + b.limbs.count)
        for i in 0..<a.limbs.count {
            var carry: UInt64 = 0
            for j in 0..<b.limbs.count {
                let (high, low) = a.limbs[i].multipliedFullWidth(by: b.limbs[j])
                let (sum1, overflow1) = out[i + j].addingReportingOverflow(low)
                let (sum2, overflow2) = sum1.addingReportingOverflow(carry)
                out[i + j] = sum2
                carry = high &+ (overflow1 ? 1 : 0) &+ (overflow2 ? 1 : 0)
            }
            out[i + b.limbs.count] = carry
        }
        return SrpBigInt(limbs: out)
    }

    /// `self << 1`.
    func doubled() -> SrpBigInt {
        var out: [UInt64] = []
        out.reserveCapacity(limbs.count + 1)
        var carry: UInt64 = 0
        for limb in limbs {
            out.append((limb << 1) | carry)
            carry = limb >> 63
        }
        if carry != 0 { out.append(carry) }
        return SrpBigInt(limbs: out)
    }

    // MARK: - Modular arithmetic

    /// `self mod modulus`, for a value already known to be less than `2 * modulus`.
    ///
    /// A single conditional subtraction rather than a division. Every caller can
    /// establish that bound: a value read off the wire at the group's own width is
    /// below `2^(8 * byteLength)`, and each RFC 5054 modulus is above
    /// `2^(8 * byteLength - 1)`, so at most one subtraction is ever needed.
    func reducedOnce(modulus: SrpBigInt) -> SrpBigInt {
        SrpBigInt.compare(self, modulus) >= 0 ? self - modulus : self
    }

    static func addMod(_ a: SrpBigInt, _ b: SrpBigInt, _ modulus: SrpBigInt) -> SrpBigInt {
        (a + b).reducedOnce(modulus: modulus)
    }

    static func subMod(_ a: SrpBigInt, _ b: SrpBigInt, _ modulus: SrpBigInt) -> SrpBigInt {
        compare(a, b) >= 0 ? a - b : (a + modulus) - b
    }
}

// MARK: - Montgomery arithmetic

/// Montgomery parameters for one modulus, computed once per exchange.
///
/// Montgomery rather than schoolbook division because a correct multi-limb
/// `divmod` (Knuth algorithm D) is several times the code and several times the
/// opportunity to get it wrong, and SRP needs no general division at all: every
/// reduction here is either a modular multiply or a single conditional subtract.
struct SrpMontgomery {

    let modulus: SrpBigInt
    /// `-N^-1 mod 2^64`.
    let n0: UInt64
    /// `R^2 mod N`, for converting into Montgomery form.
    let r2: SrpBigInt

    /// - Precondition: `modulus` is odd. Every RFC 5054 modulus is a safe prime,
    ///   so this holds for every group this SDK embeds.
    init?(modulus: SrpBigInt) {
        guard modulus.limbs[0] & 1 == 1 else { return nil }
        self.modulus = modulus
        self.n0 = SrpMontgomery.negativeInverse(of: modulus.limbs[0])
        self.r2 = SrpMontgomery.rSquared(modulus: modulus)
    }

    /// `-value^-1 mod 2^64` by Newton iteration.
    ///
    /// Each round doubles the number of correct low bits — 1, 2, 4, 8, 16, 32, 64
    /// — so six rounds are exact for a 64-bit word, and the wrapping arithmetic is
    /// the modulus.
    private static func negativeInverse(of value: UInt64) -> UInt64 {
        var inverse: UInt64 = 1
        for _ in 0..<6 {
            inverse = inverse &* (2 &- value &* inverse)
        }
        return 0 &- inverse
    }

    /// `R^2 mod N` by repeated doubling, so this file needs no division anywhere.
    ///
    /// `2 * 64 * k` doublings, each followed by a conditional subtraction. That is
    /// a few thousand cheap operations once per exchange, against the alternative
    /// of implementing and testing a full multi-limb division.
    private static func rSquared(modulus: SrpBigInt) -> SrpBigInt {
        var accumulator = SrpBigInt(1)
        for _ in 0..<(128 * modulus.limbs.count) {
            accumulator = accumulator.doubled().reducedOnce(modulus: modulus)
        }
        return accumulator
    }

    /// CIOS Montgomery multiplication: `a * b * R^-1 mod N`.
    func multiply(_ a: SrpBigInt, _ b: SrpBigInt) -> SrpBigInt {
        let k = modulus.limbs.count
        var t = [UInt64](repeating: 0, count: k + 2)

        for i in 0..<k {
            let ai = i < a.limbs.count ? a.limbs[i] : 0

            var carry: UInt64 = 0
            for j in 0..<k {
                let bj = j < b.limbs.count ? b.limbs[j] : 0
                let (high, low) = ai.multipliedFullWidth(by: bj)
                let (sum1, overflow1) = t[j].addingReportingOverflow(low)
                let (sum2, overflow2) = sum1.addingReportingOverflow(carry)
                t[j] = sum2
                carry = high &+ (overflow1 ? 1 : 0) &+ (overflow2 ? 1 : 0)
            }
            let (topSum, topOverflow) = t[k].addingReportingOverflow(carry)
            t[k] = topSum
            t[k + 1] = t[k + 1] &+ (topOverflow ? 1 : 0)

            let m = t[0] &* n0
            // The low limb of t + m*N is zero by construction — that is what m is
            // for — so only the carry out of it matters.
            let (mHigh, mLow) = m.multipliedFullWidth(by: modulus.limbs[0])
            let (_, lowOverflow) = t[0].addingReportingOverflow(mLow)
            carry = mHigh &+ (lowOverflow ? 1 : 0)

            for j in 1..<k {
                let (high, low) = m.multipliedFullWidth(by: modulus.limbs[j])
                let (sum1, overflow1) = t[j].addingReportingOverflow(low)
                let (sum2, overflow2) = sum1.addingReportingOverflow(carry)
                t[j - 1] = sum2
                carry = high &+ (overflow1 ? 1 : 0) &+ (overflow2 ? 1 : 0)
            }
            let (shifted, shiftOverflow) = t[k].addingReportingOverflow(carry)
            t[k - 1] = shifted
            t[k] = t[k + 1] &+ (shiftOverflow ? 1 : 0)
            t[k + 1] = 0
        }

        let result = SrpBigInt(limbs: Array(t[0...k]))
        return result.reducedOnce(modulus: modulus)
    }

    func toMontgomery(_ value: SrpBigInt) -> SrpBigInt { multiply(value, r2) }

    func fromMontgomery(_ value: SrpBigInt) -> SrpBigInt { multiply(value, SrpBigInt(1)) }

    /// `base^exponent mod N`, square-and-multiply over the exponent's bits.
    ///
    /// The exponent is used as given and is **not** reduced: `a + u*x` is an
    /// exponent, and reducing it modulo `N` rather than the group order would
    /// produce a different — wrong — result that still looks well-formed.
    func power(base: SrpBigInt, exponent: SrpBigInt) -> SrpBigInt {
        var result = toMontgomery(SrpBigInt(1))
        let b = toMontgomery(base.reducedOnce(modulus: modulus))
        var index = exponent.bitWidth - 1
        while index >= 0 {
            result = multiply(result, result)
            if exponent.bit(index) {
                result = multiply(result, b)
            }
            index -= 1
        }
        return fromMontgomery(result)
    }

    /// `a * b mod N` for two values already below `N`.
    func modMul(_ a: SrpBigInt, _ b: SrpBigInt) -> SrpBigInt {
        fromMontgomery(multiply(toMontgomery(a), toMontgomery(b)))
    }
}
