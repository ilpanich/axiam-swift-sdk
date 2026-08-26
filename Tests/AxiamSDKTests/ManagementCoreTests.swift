import XCTest
@testable import AxiamSDK

/// The hand-written half of §27, at the unit level.
///
/// Where `ManagementSemanticsTests` asserts the §27.4 rules end to end, these are the edges
/// underneath them: the paging arithmetic that decides whether an auto-page re-reads a row,
/// and the JSON value the spec's free-form objects are carried in.
final class ManagementCoreTests: XCTestCase {

    // MARK: - PageRequest (§27.4 rule 4)

    func testNextAdvancesByTheRequestedLimitNotByWhatCameBack() {
        let first = PageRequest(offset: 0, limit: 25)

        XCTAssertEqual(first.next().offset, 25)
        XCTAssertEqual(first.next().limit, 25)
        XCTAssertEqual(first.next().next().offset, 50)
    }

    func testNonsenseValuesAreClampedRatherThanSent() {
        // A negative offset and a zero limit are a caller's arithmetic bug. Sending them
        // makes it the server's 400 instead, which is a worse place to read the mistake.
        let clamped = PageRequest(offset: -10, limit: 0)

        XCTAssertEqual(clamped.offset, 0)
        XCTAssertEqual(clamped.limit, 1)
    }

    func testTheDefaultIsTheFirstPage() {
        XCTAssertEqual(PageRequest(), PageRequest(offset: 0, limit: 50))
        XCTAssertEqual(
            PageRequest().queryPairs.map(\.0), ["offset", "limit"])
        XCTAssertEqual(
            PageRequest().queryPairs.map(\.1), ["0", "50"])
    }

    // MARK: - Page

    func testTotalAndCountAreIndependent() {
        let page = Page(items: [1, 2, 3], total: 412, request: PageRequest())

        XCTAssertEqual(page.count, 3)
        XCTAssertEqual(page.total, 412)
        XCTAssertFalse(page.isEmpty)
        XCTAssertEqual(Array(page), [1, 2, 3])
        XCTAssertEqual(page.nextRequest.offset, 50)
    }

    func testAnEmptyPageIsTheStopCondition() {
        let page = Page(items: [Int](), total: 412, request: PageRequest())

        // Empty, even though the SERVER says there are 412 across all pages. Rule 4's stop
        // condition is this page being empty, not the total being exhausted — a caller who
        // stopped on `total` would loop forever against a server that over-reports.
        XCTAssertTrue(page.isEmpty)
        XCTAssertEqual(page.count, 0)
        XCTAssertEqual(page.total, 412)
    }

    // MARK: - CallScope (§27.4 rule 3)

    func testScopeOverridesAreIndependent() {
        let base = CallScope()
        XCTAssertNil(base.orgID)
        XCTAssertNil(base.tenantID)

        let org = base.withOrg("org-1")
        XCTAssertEqual(org.orgID, "org-1")
        XCTAssertNil(org.tenantID)

        let both = org.withTenant("tenant-1")
        XCTAssertEqual(both.orgID, "org-1")
        XCTAssertEqual(both.tenantID, "tenant-1")

        // And the scope it was derived from is untouched — the value-type half of the rule
        // that makes `inOrg`/`forTenant` safe on a shared handle.
        XCTAssertNil(org.tenantID)
        XCTAssertNil(base.orgID)
    }

    // MARK: - ManagementJSON

    func testEveryJsonCaseRoundTripsThroughItsOwnCoding() throws {
        let source = """
            {"string": "s", "int": 42, "double": 1.5, "bool": true, "null": null, \
            "array": [1, "two", false, null], "object": {"nested": {"deep": 1}}}
            """
        let value = try JSONDecoder().decode(ManagementJSON.self, from: Data(source.utf8))

        // Re-encoding and re-parsing must give the same tree. This is what lets a `metadata`
        // the SDK knows nothing about survive a read-modify-write: inventing a Swift type
        // for it would drop every key this SDK did not declare, and the server round-trips
        // those.
        let encoded = try JSONEncoder().encode(value)
        let again = try JSONDecoder().decode(ManagementJSON.self, from: encoded)
        XCTAssertEqual(again, value)

        XCTAssertEqual(value["string"], .string("s"))
        XCTAssertEqual(value["int"], .int(42))
        XCTAssertEqual(value["double"], .number(1.5))
        XCTAssertEqual(value["bool"], .bool(true))
        XCTAssertEqual(value["null"], .null)
        XCTAssertEqual(value["array"], .array([.int(1), .string("two"), .bool(false), .null]))
        XCTAssertEqual(value["object"], .object(["nested": .object(["deep": .int(1)])]))
    }

    func testAnIntegerStaysAnIntegerRatherThanBecomingADouble() throws {
        // `int` is a separate case from `number` on purpose. Routing every JSON number
        // through `Double` re-encodes `1` correctly only by luck of the encoder's
        // formatting, and `9007199254740993` not at all.
        let value = try JSONDecoder().decode(
            ManagementJSON.self, from: Data(#"{"n": 9007199254740993}"#.utf8))

        XCTAssertEqual(value["n"], .int(9_007_199_254_740_993))
        XCTAssertEqual(
            String(decoding: try JSONEncoder().encode(value), as: UTF8.self),
            #"{"n":9007199254740993}"#)
    }

    func testTheAccessorsAnswerNilForTheWrongShape() {
        let object = ManagementJSON.object(["a": .string("x")])
        let scalar = ManagementJSON.string("x")

        XCTAssertEqual(object.objectValue?.count, 1)
        XCTAssertEqual(object["a"]?.stringValue, "x")
        XCTAssertNil(object["missing"])

        XCTAssertNil(scalar.objectValue)
        XCTAssertNil(scalar["a"])
        XCTAssertEqual(scalar.stringValue, "x")
        XCTAssertNil(ManagementJSON.int(1).stringValue)

        XCTAssertEqual(ManagementJSON.emptyObject, .object([:]))
    }

    func testANonJsonValueIsReportedRatherThanGuessed() {
        // The decoder's final `else` — reachable only from a container that is none of the
        // seven JSON shapes. A silent default here would turn a decoding failure into a
        // plausible wrong value somewhere downstream.
        XCTAssertThrowsError(
            try JSONDecoder().decode(ManagementJSON.self, from: Data("not json".utf8)))
    }

    // MARK: - ManagementCodec

    func testAMalformedBodyBecomesANetworkErrorNotAFoundationError() {
        // §2 fixes the taxonomy at three cases. A `DecodingError` escaping as itself would
        // reach a caller from underneath a `catch AxiamError`, which is the one thing the
        // codec exists to prevent.
        XCTAssertThrowsError(
            try ManagementCodec.decode(Role.self, from: Data("{".utf8))
        ) { error in
            guard case AxiamError.network(let network) = error else {
                return XCTFail("expected a NetworkError, got \(error)")
            }
            XCTAssertNotNil(network.cause)
        }
    }

    func testAPageWithNoTotalReportsZeroRatherThanThePageLength() throws {
        // `total` comes from the SERVER. Falling back to the page length when the field is
        // missing would manufacture a plausible wrong answer — and `count` is right there
        // for anyone who wanted the other number.
        let page = try ManagementCodec.decodePage(
            Role.self,
            from: Data(#"{"items": []}"#.utf8),
            request: PageRequest())

        XCTAssertEqual(page.total, 0)
        XCTAssertEqual(page.count, 0)
    }
}
