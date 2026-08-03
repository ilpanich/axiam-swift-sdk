import XCTest
import Foundation
import Crypto
@testable import AxiamSDK

/// §13 / T-145 — `AxiamWebhooks.verify(...)`.
///
/// The expected `v1` is always **computed here** from the spec (`HMAC-SHA256(secret,
/// "<t>.<body>")`, hex lowercase) rather than pasted in, so this suite is an independent
/// re-derivation of the server's algorithm and stays byte-pinned to the shared cross-SDK vector.
final class WebhookTests: XCTestCase {

    // The shared cross-SDK vector (CONTRACT §13.4).
    private static let vectorSecret = "whsec_test_0123456789abcdef"
    private static let vectorTimestamp: Int64 = 1_785_700_000
    private static let vectorBody = #"{"event":"user.created","id":"01JQ0000000000000000000000"}"#

    private let secret = WebhookTests.vectorSecret
    private let timestamp = WebhookTests.vectorTimestamp
    private var body: Data { Data(WebhookTests.vectorBody.utf8) }
    /// A `now` pinned to the vector's timestamp so freshness is deterministic.
    private var now: Date { Date(timeIntervalSince1970: TimeInterval(WebhookTests.vectorTimestamp)) }

    /// `HMAC-SHA256(secret, "<timestamp>.<body>")`, hex-encoded lowercase — the server's scheme.
    private func sign(secret: String, timestamp: Int64, body: Data) -> String {
        var mac = HMAC<SHA256>(key: SymmetricKey(data: Data(secret.utf8)))
        mac.update(data: Data("\(timestamp).".utf8))
        mac.update(data: body)
        return mac.finalize().map { byte -> String in
            let hex = String(byte, radix: 16)
            return hex.count == 1 ? "0" + hex : hex
        }.joined()
    }

    private func header(secret: String? = nil, timestamp: Int64? = nil, body: Data? = nil) -> String {
        let t = timestamp ?? self.timestamp
        let signature = sign(secret: secret ?? self.secret, timestamp: t, body: body ?? self.body)
        return "t=\(t),v1=\(signature)"
    }

    private func expectFailure(
        _ expected: AxiamWebhookError,
        _ file: StaticString = #filePath,
        _ line: UInt = #line,
        _ operation: () throws -> AxiamWebhookEvent
    ) {
        do {
            _ = try operation()
            XCTFail("expected \(expected)", file: file, line: line)
        } catch let error as AxiamWebhookError {
            XCTAssertEqual(error, expected, file: file, line: line)
        } catch {
            XCTFail("expected AxiamWebhookError, got \(error)", file: file, line: line)
        }
    }

    // MARK: - 1. valid + fresh

    func testValidSignatureAccepted() throws {
        let event = try AxiamWebhooks.verify(
            secret: Sensitive(secret),
            signatureHeader: header(),
            body: body,
            timestampHeader: String(timestamp),
            eventType: "user.created",
            deliveryID: "delivery-uuid-1",
            now: now
        )
        XCTAssertEqual(event.timestamp, timestamp)
        XCTAssertEqual(event.eventType, "user.created")
        XCTAssertEqual(event.deliveryID, "delivery-uuid-1")
        XCTAssertEqual(event.body, body)
        XCTAssertEqual(event.bodyString, WebhookTests.vectorBody)
    }

    /// 7. Cross-SDK pin: the shared vector, verified end-to-end through the header parser.
    func testSharedCrossSDKVector() throws {
        let signature = sign(secret: WebhookTests.vectorSecret, timestamp: WebhookTests.vectorTimestamp, body: body)
        XCTAssertEqual(signature.count, 64, "HMAC-SHA256 hex is 64 characters")
        XCTAssertEqual(signature, signature.lowercased(), "the server emits lowercase hex")

        let event = try AxiamWebhooks.verify(
            secret: WebhookTests.vectorSecret,
            signatureHeader: "t=\(WebhookTests.vectorTimestamp),v1=\(signature)",
            body: body,
            now: now
        )
        XCTAssertEqual(event.timestamp, WebhookTests.vectorTimestamp)

        // …and the same vector with one body byte flipped must be rejected.
        var tampered = [UInt8](body)
        tampered[10] ^= 0x01
        expectFailure(.signatureMismatch) {
            try AxiamWebhooks.verify(
                secret: WebhookTests.vectorSecret,
                signatureHeader: "t=\(WebhookTests.vectorTimestamp),v1=\(signature)",
                body: Data(tampered),
                now: now
            )
        }
    }

    /// The uppercase form of the same hex decodes to the same bytes and is accepted, proving the
    /// comparison happens on decoded bytes and not on the hex text.
    func testComparisonIsOverDecodedBytesNotHexText() throws {
        let signature = sign(secret: secret, timestamp: timestamp, body: body)
        XCTAssertNoThrow(
            try AxiamWebhooks.verify(
                secret: secret,
                signatureHeader: "t=\(timestamp),v1=\(signature.uppercased())",
                body: body,
                now: now
            )
        )
    }

    // MARK: - 2. tampered body

    func testTamperedBodyRejected() {
        let signatureHeader = header()
        var tampered = [UInt8](body)
        tampered[0] ^= 0x01
        expectFailure(.signatureMismatch) {
            try AxiamWebhooks.verify(
                secret: self.secret,
                signatureHeader: signatureHeader,
                body: Data(tampered),
                now: self.now
            )
        }
    }

    /// Re-serialized JSON (different key order / added whitespace) breaks the MAC — the reason the
    /// helper takes raw `Data` and the docs forbid passing a re-encoded body.
    func testReserializedBodyRejected() {
        let signatureHeader = header()
        let reserialized = Data(#"{"id":"01JQ0000000000000000000000","event":"user.created"}"#.utf8)
        expectFailure(.signatureMismatch) {
            try AxiamWebhooks.verify(
                secret: self.secret,
                signatureHeader: signatureHeader,
                body: reserialized,
                now: self.now
            )
        }
    }

    // MARK: - 3. wrong secret

    func testWrongSecretRejected() {
        let signatureHeader = header()
        expectFailure(.signatureMismatch) {
            try AxiamWebhooks.verify(
                secret: "whsec_test_0123456789abcdee",
                signatureHeader: signatureHeader,
                body: self.body,
                now: self.now
            )
        }
    }

    // MARK: - 4./5. two-sided freshness

    func testStaleTimestampRejected() {
        let signatureHeader = header()
        let late = Date(timeIntervalSince1970: TimeInterval(timestamp) + 301)
        expectFailure(.timestampOutsideTolerance) {
            try AxiamWebhooks.verify(
                secret: self.secret,
                signatureHeader: signatureHeader,
                body: self.body,
                now: late
            )
        }
    }

    func testFutureTimestampBeyondToleranceRejected() {
        let signatureHeader = header()
        let early = Date(timeIntervalSince1970: TimeInterval(timestamp) - 301)
        expectFailure(.timestampOutsideTolerance) {
            try AxiamWebhooks.verify(
                secret: self.secret,
                signatureHeader: signatureHeader,
                body: self.body,
                now: early
            )
        }
    }

    func testTimestampInsideToleranceAccepted() throws {
        for offset in [-300.0, -299.0, 0.0, 299.0, 300.0] {
            let when = Date(timeIntervalSince1970: TimeInterval(timestamp) + offset)
            XCTAssertNoThrow(
                try AxiamWebhooks.verify(
                    secret: secret,
                    signatureHeader: header(),
                    body: body,
                    now: when
                ),
                "offset \(offset)s is inside the 300s window"
            )
        }
    }

    func testCustomToleranceHonoured() {
        let signatureHeader = header()
        let when = Date(timeIntervalSince1970: TimeInterval(timestamp) + 60)
        expectFailure(.timestampOutsideTolerance) {
            try AxiamWebhooks.verify(
                secret: self.secret,
                signatureHeader: signatureHeader,
                body: self.body,
                tolerance: 30,
                now: when
            )
        }
        XCTAssertNoThrow(
            try AxiamWebhooks.verify(
                secret: secret,
                signatureHeader: signatureHeader,
                body: body,
                tolerance: 120,
                now: when
            )
        )
        expectFailure(.invalidTolerance) {
            try AxiamWebhooks.verify(
                secret: self.secret,
                signatureHeader: signatureHeader,
                body: self.body,
                tolerance: -1,
                now: self.now
            )
        }
    }

    func testDefaultToleranceIs300Seconds() {
        XCTAssertEqual(AxiamWebhooks.defaultTolerance, 300)
    }

    // MARK: - 6. malformed headers

    func testHeaderWithoutV1Rejected() {
        expectFailure(.missingSignature) {
            try AxiamWebhooks.verify(
                secret: self.secret,
                signatureHeader: "t=\(self.timestamp)",
                body: self.body,
                now: self.now
            )
        }
    }

    /// A header carrying only an unknown future scheme is "nothing to verify" — a failure, never
    /// a pass (§13.3 rule 3).
    func testHeaderWithOnlyUnknownSchemeRejected() {
        expectFailure(.missingSignature) {
            try AxiamWebhooks.verify(
                secret: self.secret,
                signatureHeader: "t=\(self.timestamp),v2=deadbeef",
                body: self.body,
                now: self.now
            )
        }
    }

    func testNonNumericTimestampRejected() {
        let signature = sign(secret: secret, timestamp: timestamp, body: body)
        expectFailure(.invalidTimestamp) {
            try AxiamWebhooks.verify(
                secret: self.secret,
                signatureHeader: "t=not-a-number,v1=\(signature)",
                body: self.body,
                now: self.now
            )
        }
    }

    func testEmptyHeaderRejected() {
        for raw in ["", "   ", ",,,", "garbage", "v1=deadbeef", "t=,v1=deadbeef"] {
            expectFailure(.malformedSignatureHeader) {
                try AxiamWebhooks.verify(
                    secret: self.secret,
                    signatureHeader: raw,
                    body: self.body,
                    now: self.now
                )
            }
        }
    }

    func testDuplicateTimestampFieldRejected() {
        let signature = sign(secret: secret, timestamp: timestamp, body: body)
        expectFailure(.malformedSignatureHeader) {
            try AxiamWebhooks.verify(
                secret: self.secret,
                signatureHeader: "t=\(self.timestamp),t=\(self.timestamp),v1=\(signature)",
                body: self.body,
                now: self.now
            )
        }
    }

    func testNonHexSignatureFailsClosed() {
        expectFailure(.malformedSignatureHeader) {
            try AxiamWebhooks.verify(
                secret: self.secret,
                signatureHeader: "t=\(self.timestamp),v1=zzzz",
                body: self.body,
                now: self.now
            )
        }
        // Odd-length hex is not decodable either.
        expectFailure(.malformedSignatureHeader) {
            try AxiamWebhooks.verify(
                secret: self.secret,
                signatureHeader: "t=\(self.timestamp),v1=abc",
                body: self.body,
                now: self.now
            )
        }
    }

    // MARK: - forward compatibility & multiple candidates

    func testUnknownKeysIgnoredAndWhitespaceTolerated() throws {
        let signature = sign(secret: secret, timestamp: timestamp, body: body)
        let event = try AxiamWebhooks.verify(
            secret: secret,
            signatureHeader: " scheme=v9 , t = \(timestamp) , v1 = \(signature) , v2=deadbeef ",
            body: body,
            now: now
        )
        XCTAssertEqual(event.timestamp, timestamp)
    }

    /// During a secret rotation the server may send several `v1` candidates; any one matching is
    /// enough, and every candidate is compared (no early exit).
    func testMultipleCandidateSignatures() throws {
        let good = sign(secret: secret, timestamp: timestamp, body: body)
        let bad = String(repeating: "00", count: 32)
        XCTAssertNoThrow(
            try AxiamWebhooks.verify(
                secret: secret,
                signatureHeader: "t=\(timestamp),v1=\(bad),v1=\(good)",
                body: body,
                now: now
            )
        )
        expectFailure(.signatureMismatch) {
            try AxiamWebhooks.verify(
                secret: self.secret,
                signatureHeader: "t=\(self.timestamp),v1=\(bad),v1=\(bad)",
                body: self.body,
                now: self.now
            )
        }
    }

    // MARK: - X-Axiam-Timestamp cross-check

    func testTimestampHeaderMustEqualSignedField() {
        let signatureHeader = header()
        expectFailure(.timestampHeaderMismatch) {
            try AxiamWebhooks.verify(
                secret: self.secret,
                signatureHeader: signatureHeader,
                body: self.body,
                timestampHeader: String(self.timestamp + 1),
                now: self.now
            )
        }
    }

    // MARK: - header-dictionary convenience

    func testVerifyFromHeaderDictionary() throws {
        let headers = [
            "x-axiam-signature": header(),                 // lookup is case-insensitive
            "X-Axiam-Timestamp": String(timestamp),
            "X-Axiam-Event": "user.created",
            "X-Axiam-Delivery": "01JQDELIVERY",
        ]
        let event = try AxiamWebhooks.verify(
            secret: Sensitive(secret),
            headers: headers,
            body: body,
            now: now
        )
        XCTAssertEqual(event.eventType, "user.created")
        XCTAssertEqual(event.deliveryID, "01JQDELIVERY", "the dedup key is surfaced to the receiver")
    }

    func testVerifyFromHeaderDictionaryWithoutSignatureRejected() {
        expectFailure(.malformedSignatureHeader) {
            try AxiamWebhooks.verify(
                secret: Sensitive(self.secret),
                headers: ["X-Axiam-Event": "user.created"],
                body: self.body,
                now: self.now
            )
        }
    }

    // MARK: - the error must not leak the expected signature

    func testErrorsDoNotLeakTheExpectedSignature() {
        let expected = sign(secret: secret, timestamp: timestamp, body: body)
        do {
            _ = try AxiamWebhooks.verify(
                secret: secret,
                signatureHeader: "t=\(timestamp),v1=\(String(repeating: "00", count: 32))",
                body: body,
                now: now
            )
            XCTFail("expected a signature mismatch")
        } catch let error as AxiamWebhookError {
            let rendered = "\(error) \(error.description)"
            XCTAssertFalse(rendered.contains(expected), "the error must not carry the expected signature")
            XCTAssertFalse(rendered.contains(secret), "the error must not carry the secret")
        } catch {
            XCTFail("expected AxiamWebhookError, got \(error)")
        }
    }

    func testErrorDescriptionsAreDistinctAndNonLeaky() {
        let all: [AxiamWebhookError] = [
            .malformedSignatureHeader,
            .missingSignature,
            .invalidTimestamp,
            .timestampHeaderMismatch,
            .timestampOutsideTolerance,
            .signatureMismatch,
            .invalidTolerance,
        ]
        for error in all {
            XCTAssertTrue(error.description.hasPrefix("AxiamWebhookError:"), "\(error)")
            XCTAssertFalse(error.description.contains(secret))
        }
        XCTAssertEqual(Set(all.map(\.description)).count, all.count, "each case needs a distinct message")
    }

    // MARK: - hex decoding

    func testHexDecode() {
        XCTAssertEqual(AxiamWebhooks.hexDecode("00ff10"), [0x00, 0xFF, 0x10])
        XCTAssertEqual(AxiamWebhooks.hexDecode("00FF10"), [0x00, 0xFF, 0x10])
        XCTAssertNil(AxiamWebhooks.hexDecode(""))
        XCTAssertNil(AxiamWebhooks.hexDecode("abc"))
        XCTAssertNil(AxiamWebhooks.hexDecode("zz"))
        XCTAssertNil(AxiamWebhooks.hexDecode("0 1"))
    }
}
