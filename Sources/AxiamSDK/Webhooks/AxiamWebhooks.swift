import Foundation
import Crypto

/// A webhook delivery whose signature has been verified (§13 of CONTRACT.md).
public struct AxiamWebhookEvent: Sendable, Equatable {
    /// The `X-Axiam-Event` value, when the caller supplied it.
    public let eventType: String?
    /// The `X-Axiam-Delivery` value, when the caller supplied it.
    ///
    /// This is the **at-least-once dedup key**: AXIAM retries a failed delivery, and a retry
    /// replays a *valid* signature inside the freshness window, so a receiver that must not act
    /// twice has to keep a short-lived seen-set of delivery ids itself.
    public let deliveryID: String?
    /// The signed unix-seconds timestamp taken from the `t=` field of `X-Axiam-Signature`.
    public let timestamp: Int64
    /// The exact raw body bytes that were verified.
    public let body: Data

    public init(eventType: String?, deliveryID: String?, timestamp: Int64, body: Data) {
        self.eventType = eventType
        self.deliveryID = deliveryID
        self.timestamp = timestamp
        self.body = body
    }

    /// The raw body decoded as UTF-8, when it is valid UTF-8.
    public var bodyString: String? { String(data: body, encoding: .utf8) }
}

/// Why a webhook signature verification failed (§13.3 rule 6).
///
/// Every case is deliberately coarse: no case, and no `description`, carries the expected
/// signature, the computed MAC, or the secret. Verification is fail-closed — there is no
/// "could not check, assume fine" outcome.
public enum AxiamWebhookError: Error, Sendable, Equatable, CustomStringConvertible {
    /// The `X-Axiam-Signature` header could not be parsed: empty, no `t=` field, more than one
    /// `t=` field, or no `v1=` field that hex-decodes.
    case malformedSignatureHeader
    /// The header parsed but carried no `v1=` signature at all. "Nothing to verify" is a
    /// failure, never a pass (§13.3 rule 3).
    case missingSignature
    /// The `t=` field is not a decimal integer.
    case invalidTimestamp
    /// A separately supplied `X-Axiam-Timestamp` disagrees with the signed `t=` field. Only the
    /// latter is covered by the MAC (§13.3 rule 2).
    case timestampHeaderMismatch
    /// `abs(now - t)` exceeds the tolerance — the delivery is stale **or** future-dated
    /// (§13.3 rule 5).
    case timestampOutsideTolerance
    /// No supplied `v1=` matched the recomputed HMAC.
    case signatureMismatch
    /// A negative tolerance was passed.
    case invalidTolerance

    public var description: String {
        switch self {
        case .malformedSignatureHeader: return "AxiamWebhookError: malformed X-Axiam-Signature header"
        case .missingSignature: return "AxiamWebhookError: X-Axiam-Signature carries no v1 signature"
        case .invalidTimestamp: return "AxiamWebhookError: X-Axiam-Signature t= is not an integer"
        case .timestampHeaderMismatch: return "AxiamWebhookError: X-Axiam-Timestamp disagrees with the signed t="
        case .timestampOutsideTolerance: return "AxiamWebhookError: webhook timestamp is outside the freshness window"
        case .signatureMismatch: return "AxiamWebhookError: webhook signature does not match"
        case .invalidTolerance: return "AxiamWebhookError: tolerance must not be negative"
        }
    }
}

/// Verifier for AXIAM's signed-timestamp webhook deliveries (§13 of CONTRACT.md, T-145).
///
/// AXIAM signs every delivery `POST` with:
///
/// | Header | Value |
/// |---|---|
/// | `X-Axiam-Timestamp` | unix seconds, decimal ASCII |
/// | `X-Axiam-Signature` | `t=<unix_seconds>,v1=<hex_lowercase>` |
/// | `X-Axiam-Event` | event type |
/// | `X-Axiam-Delivery` | delivery UUID (at-least-once dedup key) |
///
/// where `v1 = HMAC-SHA256(secret_utf8_bytes, "<timestamp>.<raw_body>")`, hex-encoded lowercase.
///
/// ## The body must be the raw bytes off the wire
///
/// Pass the **untouched** request-body bytes. Decoding the JSON and re-serializing it changes key
/// order and whitespace, which changes the MAC input and makes every signature fail (or, worse,
/// tempts an integrator into skipping verification). In a server framework this means reading the
/// body as `Data`/`ByteBuffer` **before** any JSON decoding — e.g. Vapor's
/// `request.body.data`, not `request.content.decode(...)`.
///
/// ```swift
/// let event = try AxiamWebhooks.verify(
///     secret: Sensitive(webhookSecret),      // §7: the plaintext webhook secret
///     headers: requestHeaders,               // case-insensitive lookup
///     body: rawBodyData                      // raw bytes, never re-serialized JSON
/// )
/// guard await seen.insert(event.deliveryID) else { return }   // §13.3 rule 7: dedup is yours
/// handle(event)
/// ```
public enum AxiamWebhooks {
    /// The delivery header carrying `t=<unix_seconds>,v1=<hex>`.
    public static let signatureHeaderName = "X-Axiam-Signature"
    /// The delivery header carrying the (redundant) unix-seconds timestamp.
    public static let timestampHeaderName = "X-Axiam-Timestamp"
    /// The delivery header carrying the event type.
    public static let eventHeaderName = "X-Axiam-Event"
    /// The delivery header carrying the delivery UUID (dedup key).
    public static let deliveryHeaderName = "X-Axiam-Delivery"

    /// The §13 default freshness window: 300 seconds, applied on **both** sides of `now`.
    public static let defaultTolerance: TimeInterval = 300

    // MARK: - Verification

    /// Verify a webhook delivery.
    ///
    /// - Parameters:
    ///   - secret: the webhook's plaintext secret, wrapped per §7. Its raw UTF-8 bytes are the
    ///     HMAC key.
    ///   - signatureHeader: the raw `X-Axiam-Signature` value.
    ///   - body: the **raw request body bytes**, exactly as received. See the type's discussion.
    ///   - timestampHeader: the optional `X-Axiam-Timestamp` value. When supplied it MUST equal
    ///     the signed `t=` field; only `t=` is covered by the MAC.
    ///   - eventType: the optional `X-Axiam-Event` value, echoed into the returned event.
    ///   - deliveryID: the optional `X-Axiam-Delivery` value, echoed into the returned event.
    ///   - tolerance: the two-sided freshness window. Defaults to ``defaultTolerance`` (300 s).
    ///   - now: injection seam for tests. Defaults to the current time.
    /// - Returns: the verified ``AxiamWebhookEvent``.
    /// - Throws: ``AxiamWebhookError`` — fail-closed, and never carrying the expected signature.
    @discardableResult
    public static func verify(
        secret: Sensitive<String>,
        signatureHeader: String,
        body: Data,
        timestampHeader: String? = nil,
        eventType: String? = nil,
        deliveryID: String? = nil,
        tolerance: TimeInterval = defaultTolerance,
        now: Date = Date()
    ) throws -> AxiamWebhookEvent {
        guard tolerance >= 0 else { throw AxiamWebhookError.invalidTolerance }

        // 1. Parse the header into its `t` field and its (hex-decoded) `v1` candidates.
        let parsed = try parseSignatureHeader(signatureHeader)

        // 2. `t` must be a decimal integer. The MAC covers the field's *text*, so the recomputation
        //    below uses the raw field rather than a re-rendered integer.
        guard let timestamp = Int64(parsed.timestampField) else {
            throw AxiamWebhookError.invalidTimestamp
        }

        // §13.3 rule 2: the redundant header, when supplied, must agree with the signed field.
        if let timestampHeader {
            let trimmed = timestampHeader.trimmingCharacters(in: .whitespaces)
            guard trimmed == parsed.timestampField else {
                throw AxiamWebhookError.timestampHeaderMismatch
            }
        }

        // 3. Recompute HMAC-SHA256(secret, "<t>.<raw body>") without copying the body.
        var mac = HMAC<SHA256>(key: SymmetricKey(data: Data(secret.wrapped.utf8)))
        mac.update(data: Data((parsed.timestampField + ".").utf8))
        mac.update(data: body)
        let expected = Array(mac.finalize())

        // 4. Constant-time compare over the DECODED bytes, against every candidate, with no early
        //    exit on the first match or mismatch.
        var matches = 0
        for candidate in parsed.signatures {
            matches |= ConstantTime.equals(candidate, expected) ? 1 : 0
        }
        guard matches == 1 else { throw AxiamWebhookError.signatureMismatch }

        // 5. Two-sided freshness: a future-dated `t` is rejected just like a stale one.
        let skew = abs(now.timeIntervalSince1970 - Double(timestamp))
        guard skew <= tolerance else { throw AxiamWebhookError.timestampOutsideTolerance }

        return AxiamWebhookEvent(
            eventType: eventType,
            deliveryID: deliveryID,
            timestamp: timestamp,
            body: body
        )
    }

    /// Convenience overload taking an unwrapped secret; wraps it in ``Sensitive`` (§7).
    @discardableResult
    public static func verify(
        secret: String,
        signatureHeader: String,
        body: Data,
        timestampHeader: String? = nil,
        eventType: String? = nil,
        deliveryID: String? = nil,
        tolerance: TimeInterval = defaultTolerance,
        now: Date = Date()
    ) throws -> AxiamWebhookEvent {
        try verify(
            secret: Sensitive(secret),
            signatureHeader: signatureHeader,
            body: body,
            timestampHeader: timestampHeader,
            eventType: eventType,
            deliveryID: deliveryID,
            tolerance: tolerance,
            now: now
        )
    }

    /// Convenience overload that pulls all four `X-Axiam-*` headers out of a header dictionary
    /// (case-insensitive lookup, as HTTP header names are case-insensitive).
    ///
    /// - Throws: ``AxiamWebhookError/malformedSignatureHeader`` when `X-Axiam-Signature` is absent.
    @discardableResult
    public static func verify(
        secret: Sensitive<String>,
        headers: [String: String],
        body: Data,
        tolerance: TimeInterval = defaultTolerance,
        now: Date = Date()
    ) throws -> AxiamWebhookEvent {
        guard let signature = header(signatureHeaderName, in: headers) else {
            throw AxiamWebhookError.malformedSignatureHeader
        }
        return try verify(
            secret: secret,
            signatureHeader: signature,
            body: body,
            timestampHeader: header(timestampHeaderName, in: headers),
            eventType: header(eventHeaderName, in: headers),
            deliveryID: header(deliveryHeaderName, in: headers),
            tolerance: tolerance,
            now: now
        )
    }

    // MARK: - Internals

    /// A parsed `X-Axiam-Signature`: its single `t` field (as written) and its hex-decoded `v1`
    /// candidates.
    struct ParsedSignatureHeader {
        let timestampField: String
        let signatures: [[UInt8]]
    }

    /// Parse `t=<unix>,v1=<hex>[,v1=<hex>…]`.
    ///
    /// Unknown keys and future schemes are ignored for forward compatibility, but the header MUST
    /// carry exactly one `t` and at least one `v1` that hex-decodes; anything else fails closed
    /// (§13.3 rule 3, rule 4).
    static func parseSignatureHeader(_ header: String) throws -> ParsedSignatureHeader {
        var timestampFields: [String] = []
        var signatureFields: [String] = []

        for rawPart in header.split(separator: ",", omittingEmptySubsequences: true) {
            let part = rawPart.trimmingCharacters(in: .whitespaces)
            guard let separator = part.firstIndex(of: "=") else { continue }
            let key = part[part.startIndex..<separator].trimmingCharacters(in: .whitespaces)
            let value = part[part.index(after: separator)...].trimmingCharacters(in: .whitespaces)
            switch key {
            case "t": timestampFields.append(value)
            case "v1": signatureFields.append(value)
            default: continue // forward compatibility: ignore unknown keys/schemes
            }
        }

        guard timestampFields.count == 1, !timestampFields[0].isEmpty else {
            throw AxiamWebhookError.malformedSignatureHeader
        }
        guard !signatureFields.isEmpty else {
            throw AxiamWebhookError.missingSignature
        }

        // A candidate that is not valid hex cannot match anything; drop it. If that leaves no
        // candidate at all, fail closed rather than pretending there was nothing to check.
        let decoded = signatureFields.compactMap { hexDecode($0) }
        guard !decoded.isEmpty else { throw AxiamWebhookError.malformedSignatureHeader }

        return ParsedSignatureHeader(timestampField: timestampFields[0], signatures: decoded)
    }

    /// Decode an even-length hex string (either case) to bytes; `nil` when it is not valid hex.
    static func hexDecode(_ string: String) -> [UInt8]? {
        let characters = Array(string.utf8)
        guard !characters.isEmpty, characters.count % 2 == 0 else { return nil }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(characters.count / 2)
        var index = 0
        while index < characters.count {
            guard let high = nibble(characters[index]), let low = nibble(characters[index + 1]) else {
                return nil
            }
            bytes.append(high << 4 | low)
            index += 2
        }
        return bytes
    }

    private static func nibble(_ ascii: UInt8) -> UInt8? {
        switch ascii {
        case 0x30...0x39: return ascii - 0x30          // 0-9
        case 0x61...0x66: return ascii - 0x61 + 10     // a-f
        case 0x41...0x46: return ascii - 0x41 + 10     // A-F
        default: return nil
        }
    }

    private static func header(_ name: String, in headers: [String: String]) -> String? {
        let lowered = name.lowercased()
        return headers.first(where: { $0.key.lowercased() == lowered })?.value
    }
}
