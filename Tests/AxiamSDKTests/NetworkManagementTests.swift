import XCTest
@testable import AxiamSDK

/// The `network` management namespace — CONTRACT.md §36.8's five required tests (contract 1.62),
/// against a recording transport that sits at the bottom of a real `AxiamClient`.
///
/// 1. the surface (twelve operations, the paths and methods of §36.1, and no way to
///    `POST /api/v1/network/decide`);
/// 2. versions (each exactly as given; a `409` is one request, a `ConflictError`, and exposes its
///    `reason_code`);
/// 3. closed bodies (the exact key sets of §36.2, an unset optional absent and never `null`);
/// 4. open decoding and pagination;
/// 5. errors.
final class NetworkManagementTests: XCTestCase {

    // MARK: - Fixtures

    private static let segmentID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    private static let tenant = ManagementFixture.tenantID
    private static let actor = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"

    static func json(_ object: [String: Any]) -> String {
        String(decoding: try! JSONSerialization.data(withJSONObject: object), as: UTF8.self)
    }

    static func segmentObject(_ extra: [String: Any] = [:]) -> [String: Any] {
        var body: [String: Any] = [
            "id": segmentID,
            "tenant_id": tenant,
            "path": "/network/zones/default/lab",
            "name": "lab",
            "site_key": "default",
            "kind": "access",
            "vlan_id": 20,
            "filter_ids": ["corp"],
            "rank": 1,
            "enabled": true,
            "version": 3,
            "created_by": actor,
            "updated_by": actor,
            "created_at": "2026-10-16T00:00:00Z",
            "updated_at": "2026-10-16T00:00:00Z",
        ]
        for (key, value) in extra { body[key] = value }
        return body
    }

    static func profileObject(_ extra: [String: Any] = [:]) -> [String: Any] {
        var body: [String: Any] = [
            "segment_id": segmentID,
            "tenant_id": tenant,
            "dictionary": "axiam-radius-reply/1",
            "session_timeout_secs": 3600,
            "session_timeout_clamped": false,
            "termination_action": "radius_request",
            "idle_timeout_secs": NSNull(),
            "filter_id": "corp",
            "service_type": "framed_user",
            "version": 5,
            "created_by": actor,
            "updated_by": actor,
            "created_at": "2026-10-16T00:00:00Z",
            "updated_at": "2026-10-16T00:00:00Z",
        ]
        for (key, value) in extra { body[key] = value }
        return body
    }

    static func policyObject(_ extra: [String: Any] = [:]) -> [String: Any] {
        var body: [String: Any] = [
            "tenant_id": tenant,
            "session_timeout_max_secs": 3600,
            "version": 0,
        ]
        for (key, value) in extra { body[key] = value }
        return body
    }

    private static func page(_ items: [[String: Any]], total: Int, offset: Int = 0, limit: Int = 50) -> String {
        json(["items": items, "total": total, "offset": offset, "limit": limit])
    }

    private static func profileInput() -> NetworkReplyProfileInput {
        NetworkReplyProfileInput(sessionTimeoutSecs: 3600)
    }

    /// The key set of a value as it is serialized.
    private static func keys<T: Encodable>(_ value: T) throws -> Set<String> {
        let data = try JSONEncoder().encode(value)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        return Set(object.keys)
    }

    // MARK: - 1. The surface

    func testTheTwelveOperationsReachTheRoutesOfSection36_1() async throws {
        let id = Self.segmentID
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 200, body: Self.page([Self.segmentObject()], total: 1)),
            (status: 201, body: Self.json(Self.segmentObject())),
            (status: 200, body: Self.json(Self.segmentObject())),
            (status: 200, body: Self.json(Self.segmentObject())),
            (status: 204, body: ""),
            (status: 200, body: Self.page([Self.profileObject()], total: 1)),
            (status: 201, body: Self.json(Self.profileObject())),
            (status: 200, body: Self.json(Self.profileObject())),
            (status: 200, body: Self.json(Self.profileObject())),
            (status: 204, body: ""),
            (status: 200, body: Self.json(Self.policyObject())),
            (status: 200, body: Self.json(Self.policyObject(["version": 1]))),
        ])
        let network = client.network

        _ = try await network.listSegments()
        _ = try await network.createSegment(body: CreateNetworkSegmentRequest(
            kind: .access, name: "lab", rank: 1, siteKey: "default", vlanID: 20))
        _ = try await network.getSegment(id: id)
        _ = try await network.replaceSegment(id: id, body: ReplaceNetworkSegmentRequest(
            enabled: true, filterIds: ["corp"], version: 3, vlanID: 20))
        try await network.deleteSegment(id: id, version: "3")
        _ = try await network.listProfiles()
        _ = try await network.createProfile(body: CreateNetworkReplyProfileRequest(
            profile: Self.profileInput(), segmentID: id, segmentVersion: 3))
        _ = try await network.getProfile(segmentID: id)
        _ = try await network.replaceProfile(segmentID: id, body: ReplaceNetworkReplyProfileRequest(
            profile: Self.profileInput(), segmentVersion: 3, version: 5))
        try await network.deleteProfile(segmentID: id, version: "5")
        _ = try await network.getPolicy()
        _ = try await network.replacePolicy(body: ReplaceNetworkPolicyRequest(
            sessionTimeoutMaxSecs: 1800, version: 0))

        let expected: [(String, String)] = [
            ("GET", "/api/v1/network/segments"),
            ("POST", "/api/v1/network/segments"),
            ("GET", "/api/v1/network/segments/\(id)"),
            ("PUT", "/api/v1/network/segments/\(id)"),
            ("DELETE", "/api/v1/network/segments/\(id)"),
            ("GET", "/api/v1/network/profiles"),
            ("POST", "/api/v1/network/profiles"),
            ("GET", "/api/v1/network/profiles/\(id)"),
            ("PUT", "/api/v1/network/profiles/\(id)"),
            ("DELETE", "/api/v1/network/profiles/\(id)"),
            ("GET", "/api/v1/network/policy"),
            ("PUT", "/api/v1/network/policy"),
        ]
        XCTAssertEqual(transport.count, 12)
        for (index, route) in expected.enumerated() {
            XCTAssertEqual(transport.requests[index].method, route.0, "request \(index)")
            XCTAssertEqual(transport.requests[index].path, route.1, "request \(index)")
        }
    }

    /// The registry lists twelve operations in `network` and excludes the decision route by name,
    /// and the generated surface has no method that reaches it. §27.8's regeneration check is
    /// what keeps it that way; this reads the two files it compares.
    func testNoMethodReachesTheDecisionRoute() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()  // AxiamSDKTests
            .deletingLastPathComponent()  // Tests
            .deletingLastPathComponent()  // repository root
        let registryData = try Data(contentsOf: root.appendingPathComponent("management-registry.json"))
        let registry = try XCTUnwrap(JSONSerialization.jsonObject(with: registryData) as? [String: Any])

        let excluded = try XCTUnwrap(registry["excluded_operations"] as? [String: Any])
        XCTAssertNotNil(excluded["POST /api/v1/network/decide"], "the registry excludes the decision route")

        let namespaces = try XCTUnwrap(registry["namespaces"] as? [String: Any])
        let network = try XCTUnwrap(namespaces["network"] as? [String: Any])
        let operations = try XCTUnwrap(network["operations"] as? [String: Any])
        XCTAssertEqual(operations.count, 12)
        XCTAssertEqual(
            Set(operations.keys),
            [
                "list_segments", "create_segment", "get_segment", "replace_segment", "delete_segment",
                "list_profiles", "create_profile", "get_profile", "replace_profile", "delete_profile",
                "get_policy", "replace_policy",
            ])
        for (name, value) in operations {
            let operation = try XCTUnwrap(value as? [String: Any])
            let path = try XCTUnwrap(operation["path"] as? String)
            XCTAssertFalse(path.hasSuffix("/decide"), "\(name) must not be the decision route")
        }
        XCTAssertEqual(registry["operation_count"] as? Int, 202)
        XCTAssertEqual(registry["namespace_count"] as? Int, 29)

        let generated = try String(
            contentsOf: root.appendingPathComponent(
                "Sources/AxiamSDK/Management/Generated/ManagementNamespaces.swift"),
            encoding: .utf8)
        XCTAssertFalse(generated.contains("/api/v1/network/decide"), "no method reaches the decision route")
    }

    // MARK: - 2. Versions

    func testEachWriteSendsTheVersionsItWasGivenExactly() async throws {
        let id = Self.segmentID
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 200, body: Self.json(Self.segmentObject())),
            (status: 204, body: ""),
            (status: 201, body: Self.json(Self.profileObject())),
            (status: 200, body: Self.json(Self.profileObject())),
            (status: 204, body: ""),
            (status: 200, body: Self.json(Self.policyObject())),
        ])
        let network = client.network

        _ = try await network.replaceSegment(id: id, body: ReplaceNetworkSegmentRequest(
            enabled: true, filterIds: [], version: 7, vlanID: 20))
        XCTAssertEqual(transport.last?.jsonBody?["version"] as? Int, 7)

        try await network.deleteSegment(id: id, version: "9")
        XCTAssertEqual(transport.last?.query, "version=9")

        _ = try await network.createProfile(body: CreateNetworkReplyProfileRequest(
            profile: Self.profileInput(), segmentID: id, segmentVersion: 11))
        var sent = try XCTUnwrap(transport.last?.jsonBody)
        XCTAssertEqual(sent["segment_version"] as? Int, 11)
        XCTAssertEqual(sent["segment_id"] as? String, id)

        _ = try await network.replaceProfile(segmentID: id, body: ReplaceNetworkReplyProfileRequest(
            profile: Self.profileInput(), segmentVersion: 13, version: 17))
        sent = try XCTUnwrap(transport.last?.jsonBody)
        XCTAssertEqual(sent["version"] as? Int, 17)
        XCTAssertEqual(sent["segment_version"] as? Int, 13)

        try await network.deleteProfile(segmentID: id, version: "19")
        XCTAssertEqual(transport.last?.query, "version=19")

        _ = try await network.replacePolicy(body: ReplaceNetworkPolicyRequest(
            sessionTimeoutMaxSecs: 1800, version: 0))
        XCTAssertEqual(transport.last?.jsonBody?["version"] as? Int, 0, "a tenant's first write sends version 0")
    }

    func testAStaleVersionIsOneRequestAndAConflictThatExposesItsReasonCode() async throws {
        let stale = #"{"error": "conflict", "message": "the row changed", "reason_code": "stale_version"}"#
        let operations: [(String, @Sendable (AxiamClient) async throws -> Void)] = [
            ("replace_segment", { client in
                _ = try await client.network.replaceSegment(id: Self.segmentID, body: ReplaceNetworkSegmentRequest(
                    enabled: true, filterIds: [], version: 1, vlanID: 20))
            }),
            ("delete_segment", { client in
                try await client.network.deleteSegment(id: Self.segmentID, version: "1")
            }),
            ("create_profile", { client in
                _ = try await client.network.createProfile(body: CreateNetworkReplyProfileRequest(
                    profile: NetworkReplyProfileInput(sessionTimeoutSecs: 3600),
                    segmentID: Self.segmentID, segmentVersion: 1))
            }),
            ("replace_profile", { client in
                _ = try await client.network.replaceProfile(
                    segmentID: Self.segmentID, body: ReplaceNetworkReplyProfileRequest(
                        profile: NetworkReplyProfileInput(sessionTimeoutSecs: 3600),
                        segmentVersion: 1, version: 1))
            }),
            ("delete_profile", { client in
                try await client.network.deleteProfile(segmentID: Self.segmentID, version: "1")
            }),
            ("replace_policy", { client in
                _ = try await client.network.replacePolicy(body: ReplaceNetworkPolicyRequest(
                    sessionTimeoutMaxSecs: 1800, version: 1))
            }),
        ]
        for (name, call) in operations {
            let (client, transport) = try await ManagementFixture.signedIn([
                (status: 409, body: stale),
                // A retry would be answered by this; the assertion on the count is what notices.
                (status: 200, body: Self.json(Self.segmentObject())),
            ])
            do {
                try await call(client)
                XCTFail("\(name): expected a 409")
            } catch AxiamError.authz(let error) {
                XCTAssertEqual(error.managementFailure, .conflict, name)
                XCTAssertEqual(error.reasonCode, "stale_version", name)
            }
            XCTAssertEqual(transport.count, 1, "\(name): a 409 is never retried")
        }
    }

    func testADuplicateVlanIsAConflictToo() async throws {
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 409, body: #"{"error": "already_exists", "message": "vlan 20", "reason_code": "duplicate_vlan"}"#),
        ])
        do {
            _ = try await client.network.createSegment(body: CreateNetworkSegmentRequest(
                kind: .access, name: "lab", rank: 1, siteKey: "default", vlanID: 20))
            XCTFail("expected a 409")
        } catch AxiamError.authz(let error) {
            XCTAssertEqual(error.managementFailure, .conflict)
            XCTAssertEqual(error.reasonCode, "duplicate_vlan")
        }
        XCTAssertEqual(transport.count, 1)
    }

    /// The vocabulary is open (§36.3 rule 2): a value this SDK does not name is surfaced verbatim
    /// and is still a conflict; a server that predates the member has none to surface.
    func testAnUnknownReasonCodeIsSurfacedVerbatimAndAnAbsentOneIsNil() async throws {
        let (client, _) = try await ManagementFixture.signedIn([
            (status: 409, body: #"{"error": "conflict", "message": "x", "reason_code": "a_value_from_the_future"}"#),
            (status: 409, body: #"{"error": "conflict", "message": "x"}"#),
        ])
        for expected in [Optional("a_value_from_the_future"), nil] {
            do {
                try await client.network.deleteSegment(id: Self.segmentID, version: "1")
                XCTFail("expected a 409")
            } catch AxiamError.authz(let error) {
                XCTAssertEqual(error.managementFailure, .conflict)
                XCTAssertEqual(error.reasonCode, expected)
            }
        }
    }

    // MARK: - 3. Closed bodies

    func testTheBodiesCarryExactlyTheKeysOfSection36_2() throws {
        // Only the members set: an unset `rank`, `idle_timeout_secs`, `filter_id` or `service_type`
        // is absent, never `null`.
        XCTAssertEqual(
            try Self.keys(CreateNetworkSegmentRequest(kind: .quarantine, name: "q", siteKey: "default", vlanID: 99)),
            ["kind", "name", "site_key", "vlan_id"])
        XCTAssertEqual(
            try Self.keys(CreateNetworkSegmentRequest(
                enabled: false, filterIds: ["corp"], kind: .access, name: "lab", rank: 1,
                siteKey: "default", vlanID: 20)),
            ["enabled", "filter_ids", "kind", "name", "rank", "site_key", "vlan_id"])

        // A replacement has no `kind`, `site_key` or `name`: a segment's kind and place do not change.
        XCTAssertEqual(
            try Self.keys(ReplaceNetworkSegmentRequest(enabled: true, filterIds: [], version: 1, vlanID: 20)),
            ["enabled", "filter_ids", "version", "vlan_id"])

        let created = CreateNetworkReplyProfileRequest(
            profile: NetworkReplyProfileInput(sessionTimeoutSecs: 3600),
            segmentID: Self.segmentID, segmentVersion: 1)
        XCTAssertEqual(try Self.keys(created), ["profile", "segment_id", "segment_version"])

        // The profile as written has no VLAN member: the VLAN is the segment's.
        XCTAssertEqual(try Self.keys(created.profile), ["session_timeout_secs"])
        XCTAssertFalse(try Self.keys(created.profile).contains("vlan_id"))
        XCTAssertEqual(
            try Self.keys(NetworkReplyProfileInput(
                dictionary: "axiam-radius-reply/1", filterID: "corp", idleTimeoutSecs: 600,
                serviceType: .framedUser, sessionTimeoutSecs: 3600, terminationAction: .radiusRequest)),
            ["dictionary", "filter_id", "idle_timeout_secs", "service_type", "session_timeout_secs", "termination_action"])

        XCTAssertEqual(
            try Self.keys(ReplaceNetworkReplyProfileRequest(
                profile: NetworkReplyProfileInput(sessionTimeoutSecs: 3600), segmentVersion: 1, version: 1)),
            ["profile", "segment_version", "version"])
        XCTAssertEqual(
            try Self.keys(ReplaceNetworkPolicyRequest(sessionTimeoutMaxSecs: 1800, version: 0)),
            ["session_timeout_max_secs", "version"])
    }

    /// The replace types cannot be built without their required members: that is a compile-time
    /// fact in Swift (the memberwise initializers have no default for them), so what this pins is
    /// the decoded side — a replacement body missing a required member does not decode.
    func testAReplaceBodyMissingARequiredMemberDoesNotDecode() {
        let decoder = JSONDecoder()
        XCTAssertThrowsError(try decoder.decode(
            ReplaceNetworkSegmentRequest.self, from: Data(#"{"enabled": true, "vlan_id": 20}"#.utf8)))
        XCTAssertThrowsError(try decoder.decode(
            ReplaceNetworkReplyProfileRequest.self, from: Data(#"{"version": 1}"#.utf8)))
        XCTAssertThrowsError(try decoder.decode(
            ReplaceNetworkPolicyRequest.self, from: Data(#"{"version": 1}"#.utf8)))
    }

    // MARK: - 4. Open decoding and pagination

    func testAnUnknownKindAndAnUnknownProfileEnumerationDecode() throws {
        let segment = try JSONDecoder().decode(
            NetworkSegmentResponse.self,
            from: Data(Self.json(Self.segmentObject(["kind": "a_future_kind"])).utf8))
        XCTAssertEqual(segment.kind, .unknown)

        let profile = try JSONDecoder().decode(
            NetworkReplyProfile.self,
            from: Data(Self.json(Self.profileObject([
                "termination_action": "a_future_action",
                "service_type": "a_future_service",
            ])).utf8))
        XCTAssertEqual(profile.terminationAction, .unknown)
        XCTAssertEqual(profile.serviceType, .unknown)

        // A value this SDK does not know is never sent back.
        XCTAssertThrowsError(try JSONEncoder().encode(profile.terminationAction))
    }

    func testAClampedProfileDecodesWithBothMembers() throws {
        let profile = try JSONDecoder().decode(
            NetworkReplyProfile.self,
            from: Data(Self.json(Self.profileObject([
                "session_timeout_secs": 900, "session_timeout_clamped": true,
            ])).utf8))
        XCTAssertEqual(profile.sessionTimeoutSecs, 900)
        XCTAssertTrue(profile.sessionTimeoutClamped)
    }

    func testTheListsReturnPagesAndTheWalkCarriesSearchAndSiteOnEveryRequest() async throws {
        let first = Self.page([Self.segmentObject()], total: 2, offset: 0, limit: 1)
        let second = Self.page([Self.segmentObject()], total: 2, offset: 1, limit: 1)
        let empty = Self.page([], total: 2, offset: 2, limit: 1)
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 200, body: first),
            (status: 200, body: first), (status: 200, body: second), (status: 200, body: empty),
            (status: 200, body: Self.page([Self.profileObject()], total: 1, offset: 0, limit: 1)),
            (status: 200, body: Self.page([Self.profileObject()], total: 1, offset: 0, limit: 1)),
            (status: 200, body: Self.page([], total: 1, offset: 1, limit: 1)),
        ])

        let request = PageRequest(offset: 0, limit: 1, search: "lab")
        let page = try await client.network.listSegments(page: request, site: "default")
        XCTAssertEqual(page.total, 2, "total is the server's count, not the page's")
        XCTAssertEqual(page.count, 1)

        var all: [NetworkSegmentResponse] = []
        for try await item in client.network.listSegmentsAll(page: request, site: "default") {
            all.append(item)
        }
        XCTAssertEqual(all.count, 2)
        XCTAssertEqual(transport.requests.dropFirst().map(\.query), [
            "offset=0&limit=1&search=lab&site=default",
            "offset=1&limit=1&search=lab&site=default",
            "offset=2&limit=1&search=lab&site=default",
        ], "every page of the walk carries the search and the site")

        let profiles = try await client.network.listProfiles(page: PageRequest(offset: 0, limit: 1, search: "corp"))
        XCTAssertEqual(profiles.total, 1)
        var walked: [NetworkReplyProfile] = []
        for try await item in client.network.listProfilesAll(page: PageRequest(offset: 0, limit: 1, search: "corp")) {
            walked.append(item)
        }
        XCTAssertEqual(walked.count, 1)
        XCTAssertEqual(transport.requests.suffix(3).map(\.query), [
            "offset=0&limit=1&search=corp",
            "offset=0&limit=1&search=corp",
            "offset=1&limit=1&search=corp",
        ])
    }

    // MARK: - 5. Errors

    func testStatusesMapPerSection36_4() async throws {
        let (client, _) = try await ManagementFixture.signedIn([
            (status: 403, body: #"{"error": "authorization_denied", "message": "no", "action": "network:grant", "resource_id": "\#(Self.segmentID)"}"#),
            (status: 400, body: #"{"error": "validation_error", "message": "vlan_id: out of range"}"#),
            (status: 404, body: #"{"error": "not_found", "message": "no profile"}"#),
            // The 401 a service-account token gets, then the §9 refresh it triggers, which fails too.
            (status: 401, body: #"{"error": "unauthorized", "message": "human only"}"#),
            (status: 401, body: #"{"error": "unauthorized"}"#),
        ])

        do {
            _ = try await client.network.replaceProfile(
                segmentID: Self.segmentID, body: ReplaceNetworkReplyProfileRequest(
                    profile: NetworkReplyProfileInput(sessionTimeoutSecs: 3600), segmentVersion: 1, version: 1))
            XCTFail("expected a 403")
        } catch AxiamError.authz(let error) {
            XCTAssertNil(error.managementFailure, "a 403 is the plain AuthzError")
            XCTAssertEqual(error.action, "network:grant")
            XCTAssertEqual(error.resourceID, Self.segmentID)
        }
        do {
            _ = try await client.network.createSegment(body: CreateNetworkSegmentRequest(
                kind: .access, name: "lab", rank: 1, siteKey: "default", vlanID: 5000))
            XCTFail("expected a 400")
        } catch AxiamError.network(let error) {
            XCTAssertTrue(error.isValidation)
            XCTAssertTrue(error.message.contains("out of range"))
        }
        do {
            _ = try await client.network.getProfile(segmentID: Self.segmentID)
            XCTFail("expected a 404")
        } catch AxiamError.authz(let error) {
            XCTAssertEqual(error.managementFailure, .notFound)
        }
        do {
            _ = try await client.network.getPolicy()
            XCTFail("expected a 401")
        } catch AxiamError.auth(_) {
            // expected: the §9 refresh failed too, so the 401 surfaces as AuthError
        }
    }

    func testA429AndA503OnEachWriteIsANetworkErrorAfterExactlyOneRequest() async throws {
        let writes: [(String, @Sendable (AxiamClient) async throws -> Void)] = [
            ("create_segment", { client in
                _ = try await client.network.createSegment(body: CreateNetworkSegmentRequest(
                    kind: .access, name: "lab", rank: 1, siteKey: "default", vlanID: 20))
            }),
            ("replace_segment", { client in
                _ = try await client.network.replaceSegment(id: Self.segmentID, body: ReplaceNetworkSegmentRequest(
                    enabled: true, filterIds: [], version: 1, vlanID: 20))
            }),
            ("delete_segment", { client in
                try await client.network.deleteSegment(id: Self.segmentID, version: "1")
            }),
            ("create_profile", { client in
                _ = try await client.network.createProfile(body: CreateNetworkReplyProfileRequest(
                    profile: NetworkReplyProfileInput(sessionTimeoutSecs: 3600),
                    segmentID: Self.segmentID, segmentVersion: 1))
            }),
            ("replace_profile", { client in
                _ = try await client.network.replaceProfile(
                    segmentID: Self.segmentID, body: ReplaceNetworkReplyProfileRequest(
                        profile: NetworkReplyProfileInput(sessionTimeoutSecs: 3600),
                        segmentVersion: 1, version: 1))
            }),
            ("delete_profile", { client in
                try await client.network.deleteProfile(segmentID: Self.segmentID, version: "1")
            }),
            ("replace_policy", { client in
                _ = try await client.network.replacePolicy(body: ReplaceNetworkPolicyRequest(
                    sessionTimeoutMaxSecs: 1800, version: 1))
            }),
        ]
        for status in [429, 503] {
            for (name, call) in writes {
                let (client, transport) = try await ManagementFixture.signedIn(
                    [(status: status, body: ""), (status: 200, body: "{}")], retryEnabled: true)
                do {
                    try await call(client)
                    XCTFail("\(name): expected a \(status)")
                } catch AxiamError.network(let error) {
                    XCTAssertEqual(error.statusCode, status, name)
                }
                XCTAssertEqual(transport.count, 1, "\(name) on \(status): a write is never retried")
            }
        }
    }
}
