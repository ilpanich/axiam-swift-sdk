import XCTest
@testable import AxiamSDK

/// The `ssf` management namespace — CONTRACT.md §32.8's six management tests, plus the
/// read-modify-write helper. The receiver helper's eight are in `SsfReceiverTests`.
final class SsfManagementTests: XCTestCase {

    private static let streamsPath = "/api/v1/tenants/\(ManagementFixture.tenantID)/ssf/streams"
    private static let revoked = SsfEventTypeURI.sessionRevoked

    private static func json(_ object: [String: Any]) -> String {
        String(decoding: try! JSONSerialization.data(withJSONObject: object), as: UTF8.self)
    }

    private static func headerValue() -> String { "Bearer \(SecretKit.random())" }

    private static func streamObject(_ extra: [String: Any] = [:]) -> [String: Any] {
        var body: [String: Any] = [
            "id": UUID().uuidString.lowercased(),
            "tenant_id": ManagementFixture.tenantID,
            "receiver_client_id": "rp-1",
            "audience": "https://rp.example",
            "description": NSNull(),
            "delivery_method": "push",
            "endpoint_url": "https://rp.example/ssf",
            "authorization_header_set": true,
            "events_allowed": [revoked],
            "events_requested": [revoked],
            "events_delivered": [revoked],
            "subject_format": "iss_sub",
            "status": "enabled",
            "status_reason": NSNull(),
            "status_actor": "admin",
            "last_verification_at": NSNull(),
            "created_at": "2026-10-04T00:00:00Z",
            "updated_at": "2026-10-04T00:00:00Z",
            "transmitter_active": true,
        ]
        for (key, value) in extra { body[key] = value }
        return body
    }

    private static func input(header: String?) -> SsfStreamInput {
        SsfStreamInput(
            audience: "https://rp.example",
            authorizationHeader: header.map { Sensitive($0) },
            deliveryMethod: .push,
            description: "the RP",
            endpointURL: "https://rp.example/ssf",
            eventsAllowed: [.sessionRevoked],
            receiverClientID: "rp-1")
    }

    private static func decode(_ object: [String: Any]) throws -> SsfStream {
        try JSONDecoder().decode(SsfStream.self, from: Data(json(object).utf8))
    }

    // MARK: - 1. Replacement

    func testUpdateStreamPutsEveryMemberItModels() async throws {
        let id = UUID().uuidString.lowercased()
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 200, body: Self.json(Self.streamObject())),
        ])
        var body = Self.input(header: nil)
        body.eventsRequested = [.sessionRevoked]
        body.subjectFormat = .issSub
        body.status = .enabled
        body.statusReason = "ok"
        body.clearAuthorizationHeader = false

        let stream = try await client.ssf.updateStream(streamID: id, body: body)
        XCTAssertTrue(stream.transmitterActive)

        XCTAssertEqual(transport.last?.method, "PUT")
        XCTAssertEqual(transport.last?.path, "\(Self.streamsPath)/\(id)")
        let sent = try XCTUnwrap(transport.last?.jsonBody)
        for member in [
            "receiver_client_id", "audience", "delivery_method", "events_allowed",
            "description", "endpoint_url", "events_requested", "subject_format", "status",
            "status_reason", "clear_authorization_header",
        ] {
            XCTAssertNotNil(sent[member], "\(member) not sent")
        }
        XCTAssertEqual(sent["events_allowed"] as? [String], [Self.revoked])
        XCTAssertNil(sent["authorization_header"], "absent keeps the stored header")
        // The four required members are non-optional initializer parameters.
    }

    // MARK: - 2. The header is Sensitive

    func testThePushHeaderIsSentAndNeverRenderedOrDecoded() async throws {
        let header = Self.headerValue()
        let body = Self.input(header: header)
        for rendering in SecretKit.renderings(body) {
            XCTAssertFalse(SecretKit.leaks(rendering, header), "the header leaked")
        }
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 201, body: Self.json(Self.streamObject(["authorization_header": header]))),
        ])

        let created = try await client.ssf.createStream(body: body)
        let sent = try XCTUnwrap(transport.last?.jsonBody)
        XCTAssertEqual(sent["authorization_header"] as? String, header, "on the wire")
        let reencoded = String(decoding: try JSONEncoder().encode(created), as: UTF8.self)
        for rendering in SecretKit.renderings(created) + [reencoded] {
            XCTAssertFalse(SecretKit.leaks(rendering, header), "a response header was surfaced")
        }
        XCTAssertTrue(created.authorizationHeaderSet)
        // `SsfStream` declares only `authorizationHeaderSet`: no accessor for the value.
    }

    // MARK: - 3. Open decoding

    func testUnknownValuesAndBothTransmitterStatesDecode() throws {
        let odd = try Self.decode(Self.streamObject([
            "status": "quarantined", "delivery_method": "websocket",
            "subject_format": "opaque", "status_actor": "policy",
            "events_allowed": ["https://example.test/event-type/new"],
        ]))
        XCTAssertEqual(odd.status, .unknown)
        XCTAssertEqual(odd.deliveryMethod, .unknown)
        XCTAssertEqual(odd.subjectFormat, .unknown)
        XCTAssertEqual(odd.statusActor, .unknown)
        XCTAssertEqual(odd.eventsAllowed.map(\.rawValue), ["https://example.test/event-type/new"])
        XCTAssertFalse(odd.eventsAllowed[0].isKnown, "kept as itself, and known to be unknown")

        let inactive = try Self.decode(Self.streamObject([
            "transmitter_active": false,
            "transmitter_inactive_reason": "per-tenant issuers are off in a multi-tenant deployment",
        ]))
        XCTAssertFalse(inactive.transmitterActive)
        XCTAssertNotNil(inactive.transmitterInactiveReason)
        let active = try Self.decode(Self.streamObject())
        XCTAssertTrue(active.transmitterActive)
        XCTAssertNil(active.transmitterInactiveReason)
        XCTAssertEqual(active.eventsAllowed, [.sessionRevoked])
    }

    /// §32.2 (R-22, SW-10; contract 1.60 B4, §34.2 P12.2 (b)): event types are strings with the
    /// six URIs as named constants. An URI this SDK has never seen decodes AS ITSELF — not as a
    /// placeholder that loses it — renders without failing, and is sent back UNCHANGED on
    /// `update_stream`, the server judging it: this SDK keeps no list of URIs to refuse.
    func testAnUnseenEventTypeURIIsKeptAndSentBackUnchanged() async throws {
        let unseen = "https://example.test/event-type/\(UUID().uuidString.lowercased())"
        let odd = try Self.decode(Self.streamObject([
            "events_allowed": [Self.revoked, unseen],
            "events_requested": [unseen],
            "events_delivered": [unseen],
        ]))
        XCTAssertEqual(odd.eventsAllowed.map(\.rawValue), [Self.revoked, unseen])
        XCTAssertEqual(odd.eventsRequested.map(\.rawValue), [unseen])
        XCTAssertEqual(odd.eventsDelivered.map(\.rawValue), [unseen])
        XCTAssertEqual(odd.eventsAllowed.first, .sessionRevoked, "the constants still match")
        XCTAssertTrue(String(describing: odd).contains(unseen), "rendering never fails")

        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 200, body: Self.json(Self.streamObject())),
            (status: 200, body: Self.json(Self.streamObject())),
        ])
        let before = transport.count
        _ = try await client.ssf.updateStream(streamID: odd.id, body: SsfStreamInput(copying: odd))
        XCTAssertEqual(transport.count, before + 1, "the request was made")
        let sent = try XCTUnwrap(transport.last?.jsonBody)
        XCTAssertEqual(sent["events_allowed"] as? [String], [Self.revoked, unseen])
        XCTAssertEqual(sent["events_requested"] as? [String], [unseen])

        // A URI the caller typed is sent as held as well.
        var typed = Self.input(header: nil)
        typed.eventsAllowed = [SsfEventType(rawValue: unseen)]
        _ = try await client.ssf.updateStream(streamID: odd.id, body: typed)
        let typedSent = try XCTUnwrap(transport.last?.jsonBody)
        XCTAssertEqual(typedSent["events_allowed"] as? [String], [unseen])
    }

    /// Contract 1.60 A4 (R-22, §34.2 P12.2): `.unknown` is never sent. A read-modify-write of a
    /// stream carrying a `status`, `delivery_method` or `subject_format` this SDK does not
    /// know raises the validation failure before any request — and never sends `""`.
    func testAStreamCarryingAnUnknownEnumValueIsRefusedBeforeAnyRequest() async throws {
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 200, body: Self.json(Self.streamObject())),
        ])
        let before = transport.count
        for (member, value) in [
            ("status", "quarantined"), ("delivery_method", "websocket"),
            ("subject_format", "opaque"),
        ] {
            let odd = try Self.decode(Self.streamObject([member: value]))
            do {
                _ = try await client.ssf.updateStream(
                    streamID: odd.id, body: SsfStreamInput(copying: odd))
                XCTFail("\(member): an unknown value must not be sent")
            } catch AxiamError.network(let error) {
                XCTAssertTrue(error.isValidation, "\(member): refused locally, as a validation failure")
            }
            XCTAssertEqual(transport.count, before, "\(member): nothing was sent")
        }
    }

    // MARK: - 4. Pagination

    func testListStreamsPagesAndTheWalkCarriesSearch() async throws {
        let page1 = Self.json(["items": [Self.streamObject()], "total": 2, "offset": 0, "limit": 1])
        let page2 = Self.json(["items": [Self.streamObject()], "total": 2, "offset": 1, "limit": 1])
        let empty = Self.json(["items": [Any](), "total": 2, "offset": 2, "limit": 1])
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 200, body: page1),
            (status: 200, body: page1), (status: 200, body: page2), (status: 200, body: empty),
        ])

        let request = PageRequest(offset: 0, limit: 1, search: "rp.example")
        let first = try await client.ssf.listStreams(page: request)
        XCTAssertEqual(first.total, 2)
        XCTAssertEqual(first.count, 1)
        // §27.4 rule 4's auto-paging form.
        var all: [SsfStream] = []
        for try await stream in client.ssf.listStreamsAll(page: request) {
            all.append(stream)
        }
        XCTAssertEqual(all.count, 2)
        XCTAssertEqual(transport.count, 4)
        XCTAssertEqual(transport.requests.dropFirst().map(\.query), [
            "offset=0&limit=1&search=rp.example",
            "offset=1&limit=1&search=rp.example",
            "offset=2&limit=1&search=rp.example",
        ], "every page of the walk carries the search")
    }

    // MARK: - 5. No retry

    func testNoneOfTheThreeWritesIsRetriedOn503() async throws {
        let id = UUID().uuidString.lowercased()
        let (client, transport) = try await ManagementFixture.signedIn(
            Array(repeating: (status: 503, body: ""), count: 3), retryEnabled: true)

        var failures: [Error] = []
        var counts: [Int] = []
        do {
            _ = try await client.ssf.createStream(body: Self.input(header: Self.headerValue()))
        } catch { failures.append(error) }
        counts.append(transport.count)
        do {
            _ = try await client.ssf.updateStream(streamID: id, body: Self.input(header: nil))
        } catch { failures.append(error) }
        counts.append(transport.count)
        do { try await client.ssf.deleteStream(streamID: id) } catch { failures.append(error) }
        counts.append(transport.count)

        XCTAssertEqual(counts, [1, 2, 3], "exactly one request per write")
        XCTAssertEqual(failures.count, 3)
        for failure in failures {
            guard case AxiamError.network(let network) = failure else {
                return XCTFail("a 503 is a NetworkError")
            }
            XCTAssertEqual(network.statusCode, 503)
        }
    }

    // MARK: - 6. Errors

    func testStatusesMapPerSection2() async throws {
        let id = UUID().uuidString.lowercased()
        let (client, _) = try await ManagementFixture.signedIn([
            (status: 400, body: #"{"error": "validation_error", "message": "endpoint_url: must be https"}"#),
            (status: 409, body: #"{"error": "conflict", "message": "audience"}"#),
            (status: 404, body: #"{"error": "not_found", "message": "no"}"#),
            // The 401, then the §9 refresh it triggers, which fails too.
            (status: 401, body: #"{"error": "unauthorized", "message": "human only"}"#),
            (status: 401, body: #"{"error": "unauthorized"}"#),
        ])

        do {
            _ = try await client.ssf.createStream(body: Self.input(header: nil))
            XCTFail("expected a 400")
        } catch AxiamError.network(let error) {
            XCTAssertTrue(error.isValidation)
            XCTAssertTrue(error.message.contains("must be https"))
        }
        do {
            _ = try await client.ssf.createStream(body: Self.input(header: nil))
            XCTFail("expected a 409")
        } catch AxiamError.authz(let error) {
            XCTAssertEqual(error.managementFailure, .conflict)
        }
        do {
            _ = try await client.ssf.getStream(streamID: id)
            XCTFail("expected a 404")
        } catch AxiamError.authz(let error) {
            XCTAssertEqual(error.managementFailure, .notFound)
        }
        do {
            _ = try await client.ssf.getStream(streamID: id)
            XCTFail("expected a 401")
        } catch AxiamError.auth(_) {
            // expected: the §9 refresh failed too, so the 401 surfaces as AuthError
        }
    }

    func testAReadConvertsIntoTheReplacementBodyWithoutTheHeader() throws {
        let stream = try Self.decode(Self.streamObject())
        var body = SsfStreamInput(copying: stream)
        XCTAssertNil(body.authorizationHeader, "absent keeps the stored header")
        XCTAssertNil(body.clearAuthorizationHeader)
        XCTAssertEqual(body.audience, stream.audience)
        XCTAssertEqual(body.eventsRequested ?? [], [.sessionRevoked])
        body.statusReason = "maintenance"
        let sent = try XCTUnwrap(
            JSONSerialization.jsonObject(with: try JSONEncoder().encode(body)) as? [String: Any])
        XCTAssertNil(sent["authorization_header"])
        XCTAssertEqual(sent["status_reason"] as? String, "maintenance")
    }
}
