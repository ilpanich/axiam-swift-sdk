import Crypto
import Foundation

// The §22.2 wire format, in both directions.
//
// THE ONE THING THIS FILE IS CAREFUL ABOUT. Both canonical forms are built by
// hand rather than encoded from a model. The signed bytes are the message in its
// DECLARED FIELD ORDER with `hmac_signature` present and set to **null** — not
// omitted, unlike §8's own two message types — and `JSONEncoder` will order keys
// its own way and will drop or reorder the null. Every MAC here depends on
// getting that exactly right, and §22.13's committed vectors are what says it is.

/// The §22.2 primitives, exposed because §22.13 tests them directly.
public enum ReactorProtocol {
    /// §8 v2 / §22.2: a body carrying less than this is refused before anything
    /// else about it is considered — including its signature.
    public static let keyVersion = 2
    /// ±freshness window, applied in BOTH directions. A future timestamp is not
    /// "extra fresh"; it is the shape of a captured message held for later.
    public static let freshnessSkewSeconds: Int = 300

    // MARK: - Escaping

    /// serde_json's string escaping: the two mandatory escapes, the five short
    /// forms, `\u00XX` for the remaining control characters — and NOTHING else.
    /// Forward slashes stay literal and UTF-8 passes through unescaped, which is
    /// where a naive port usually diverges.
    static func quoted(_ value: String) -> String {
        var out = "\""
        for scalar in value.unicodeScalars {
            switch scalar {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\u{08}": out += "\\b"
            case "\u{0C}": out += "\\f"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            default:
                if scalar.value < 0x20 {
                    out += String(format: "\\u%04x", Int(scalar.value))
                } else {
                    out.unicodeScalars.append(scalar)
                }
            }
        }
        return out + "\""
    }

    static func hmacHex(key: Sensitive<Data>, over bytes: String) -> String {
        var mac = HMAC<SHA256>(key: SymmetricKey(data: key.wrapped))
        mac.update(data: Data(bytes.utf8))
        return Array(mac.finalize()).map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - §22.4 the reply

    /// The exact bytes a reply is signed over, before the MAC replaces the `null`
    /// placeholder. Exposed because §22.13's sign-direction vectors compare
    /// against `canonical_signed_json` byte-for-byte.
    ///
    /// Field order: correlation_id, tenant_id, event, decision, reason (OMITTED
    /// when absent), patch (OMITTED when absent), require_mfa (OMITTED when
    /// false), key_version, nonce, issued_at, hmac_signature (null while
    /// signing).
    ///
    /// The three conditional omissions are load-bearing. A reply that serializes
    /// `"require_mfa": false` rather than omitting it produces different
    /// canonical bytes and therefore a different MAC.
    public static func canonicalReply(
        correlationID: String,
        tenantID: String,
        event: ReactorEventName,
        decision: ReactorDecision,
        nonce: String,
        issuedAt: String
    ) -> String {
        var out = "{"
        out += "\"correlation_id\":\(quoted(correlationID)),"
        out += "\"tenant_id\":\(quoted(tenantID)),"
        out += "\"event\":\(quoted(event.rawValue)),"

        switch decision {
        case .allow, .allowWithStepUp:
            out += "\"decision\":\"allow\""
        case .deny(let reason):
            out += "\"decision\":\"deny\""
            // An empty reason is OMITTED, not sent as "": the server substitutes
            // "denied by reactor", and the omission changes the canonical bytes.
            if !reason.isEmpty { out += ",\"reason\":\(quoted(reason))" }
        case .mutate(let patch):
            out += "\"decision\":\"mutate\""
            if !patch.isEmpty {
                // Sorted, which is what the server's BTreeMap emits. A dictionary
                // left in its own order would produce a MAC that verifies only by
                // luck — and Swift's dictionary order is not even stable between
                // runs, so it would verify only sometimes.
                let entries = patch.keys.sorted().map { "\(quoted($0)):\(quoted(patch[$0]!))" }
                out += ",\"patch\":{\(entries.joined(separator: ","))}"
            }
        }

        if case .allowWithStepUp = decision { out += ",\"require_mfa\":true" }
        out += ",\"key_version\":\(keyVersion),"
        out += "\"nonce\":\(quoted(nonce)),"
        out += "\"issued_at\":\(quoted(issuedAt)),"
        out += "\"hmac_signature\":null}"
        return out
    }

    /// The reply as it goes on the wire: the canonical bytes with the `null`
    /// placeholder replaced by the MAC computed over them.
    ///
    /// - Throws: ``ReactorReplyError`` for the two answers this SDK refuses to
    ///   serialize — `require_mfa` on any event other than `login.post_auth`
    ///   (§22.4 row 7), and a `mutate` carrying an empty patch. Both are refusals
    ///   rather than corrections: the result is NO REPLY, and the registration's
    ///   failure policy decides.
    public static func buildReply(
        signingKey: Sensitive<Data>,
        correlationID: String,
        tenantID: String,
        event: ReactorEventName,
        decision: ReactorDecision,
        nonce: String,
        issuedAt: String
    ) throws -> String {
        if case .allowWithStepUp = decision, event != .loginPostAuth {
            throw ReactorReplyError.requireMFAOnWrongEvent(event)
        }
        if case .mutate(let patch) = decision, patch.isEmpty {
            throw ReactorReplyError.emptyMutation
        }

        let canonical = canonicalReply(
            correlationID: correlationID, tenantID: tenantID, event: event,
            decision: decision, nonce: nonce, issuedAt: issuedAt)
        let signature = hmacHex(key: signingKey, over: canonical)
        let placeholder = "\"hmac_signature\":null"
        guard let range = canonical.range(of: placeholder, options: .backwards) else {
            return canonical
        }
        return canonical.replacingCharacters(
            in: range, with: "\"hmac_signature\":\"\(signature)\"")
    }

    // MARK: - §22.3 verification

    /// Verify one delivery body against §22.3, in order: `key_version` before
    /// anything else about the body is considered; then the MAC over the body
    /// with `hmac_signature` set to **null**; then freshness in both directions;
    /// then the nonce. Identity and registry membership come after the MAC —
    /// neither is cryptography, and spending them on unauthenticated bytes tells
    /// an unauthenticated party what this reactor accepts.
    ///
    /// - Parameter seenNonces: a set carried across deliveries. Pass `nil` to
    ///   skip replay dedup — a real reactor keeps one for its whole lifetime, and
    ///   building a fresh one per delivery defeats the check entirely, which is
    ///   why ``reactorServe(config:transport:handler:)`` owns one.
    public static func verifyEvent(
        signingKey: Sensitive<Data>,
        body: Data,
        expectedTenantID: String,
        now: Date,
        seenNonces: inout [String: Date]
    ) -> Result<ReactorEvent, ReactorRefusal> {
        guard let root = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else {
            return .failure(.malformed)
        }

        // 1. key_version, before anything else about the body is considered.
        guard let version = root["key_version"] as? Int, version >= keyVersion else {
            return .failure(.keyVersionTooOld)
        }

        // Every field the canonical form reads has to be there before it reads
        // them; a body missing one is malformed, not badly signed, and saying
        // "bad signature" would send an operator looking at the wrong key.
        guard let tenantID = root["tenant_id"] as? String,
              let eventName = root["event"] as? String,
              let correlationID = root["correlation_id"] as? String,
              let nonce = root["nonce"] as? String,
              let issuedAtText = root["issued_at"] as? String,
              let timeoutMilliseconds = root["timeout_ms"] as? Int,
              let payload = root["payload"]
        else { return .failure(.malformed) }

        // 2. The MAC, over the body with hmac_signature set to null.
        guard let presented = root["hmac_signature"] as? String else {
            return .failure(.badSignature)
        }
        // `payload` is re-emitted with sorted keys. That is safe here and ONLY
        // here: the server's payload map is a BTreeMap, so its keys are already
        // in byte order. Everything else is hand-ordered because the top-level
        // order is the server's STRUCT DECLARATION order, which no encoder will
        // reproduce.
        guard let payloadData = try? JSONSerialization.data(
                withJSONObject: payload, options: [.sortedKeys, .withoutEscapingSlashes]),
              let payloadJSON = String(data: payloadData, encoding: .utf8)
        else { return .failure(.malformed) }

        var canonical = "{"
        canonical += "\"tenant_id\":\(quoted(tenantID)),"
        canonical += "\"event\":\(quoted(eventName)),"
        canonical += "\"correlation_id\":\(quoted(correlationID)),"
        canonical += "\"payload\":\(payloadJSON),"
        canonical += "\"timeout_ms\":\(timeoutMilliseconds),"
        canonical += "\"key_version\":\(version),"
        canonical += "\"nonce\":\(quoted(nonce)),"
        canonical += "\"issued_at\":\(quoted(issuedAtText)),"
        canonical += "\"hmac_signature\":null}"

        let expected = hmacHex(key: signingKey, over: canonical)
        // Constant-time. Never `==` on the hex strings.
        guard ConstantTime.equals(Array(presented.utf8), Array(expected.utf8)) else {
            return .failure(.badSignature)
        }

        // 3. Freshness, in BOTH directions.
        guard let issuedAt = ReactorTime.parse(issuedAtText) else { return .failure(.malformed) }
        let drift = now.timeIntervalSince1970 - issuedAt.timeIntervalSince1970
        guard abs(drift) <= Double(freshnessSkewSeconds) else { return .failure(.stale) }

        // 4. The nonce, against the seen-set.
        seenNonces = seenNonces.filter { $0.value > now }
        if seenNonces[nonce] != nil { return .failure(.replay) }
        seenNonces[nonce] = now.addingTimeInterval(Double(freshnessSkewSeconds) * 2)

        guard tenantID == expectedTenantID else { return .failure(.tenantMismatch) }
        guard let event = ReactorEventName(rawValue: eventName) else {
            // Also how §22.7's exclusion refuses: those operations are in no
            // registry, so a delivery naming one never reaches a handler.
            return .failure(.unknownEvent)
        }

        return .success(ReactorEvent(
            tenantID: tenantID,
            event: event,
            correlationID: correlationID,
            payloadJSON: payloadJSON,
            timeoutMilliseconds: timeoutMilliseconds,
            nonce: nonce))
    }
}

/// RFC 3339 in UTC, both ways.
///
/// Hand-rolled rather than `ISO8601DateFormatter` because the server emits
/// exactly `%Y-%m-%dT%H:%M:%SZ` and a formatter that accepted fractional seconds
/// or an offset would parse a timestamp whose bytes are not the ones inside the
/// MAC.
enum ReactorTime {
    private static let calendar: Calendar = {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(secondsFromGMT: 0)!
        return calendar
    }()

    static func parse(_ text: String) -> Date? {
        guard text.count == 20, text.hasSuffix("Z") else { return nil }
        let body = text.dropLast()
        let halves = body.split(separator: "T")
        guard halves.count == 2 else { return nil }
        let date = halves[0].split(separator: "-")
        let time = halves[1].split(separator: ":")
        guard date.count == 3, time.count == 3 else { return nil }
        guard let year = Int(date[0]), let month = Int(date[1]), let day = Int(date[2]),
              let hour = Int(time[0]), let minute = Int(time[1]), let second = Int(time[2])
        else { return nil }
        var components = DateComponents()
        components.year = year
        components.month = month
        components.day = day
        components.hour = hour
        components.minute = minute
        components.second = second
        components.timeZone = TimeZone(secondsFromGMT: 0)
        return calendar.date(from: components)
    }

    static func format(_ date: Date) -> String {
        let c = calendar.dateComponents(
            [.year, .month, .day, .hour, .minute, .second], from: date)
        return String(
            format: "%04d-%02d-%02dT%02d:%02d:%02dZ",
            c.year ?? 0, c.month ?? 0, c.day ?? 0, c.hour ?? 0, c.minute ?? 0, c.second ?? 0)
    }
}
