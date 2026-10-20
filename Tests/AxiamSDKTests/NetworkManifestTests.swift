import XCTest
@testable import AxiamSDK

/// CONTRACT.md §27.6.2 — the `network` namespace in a manifest (contract 1.62), and the tests
/// §27.9 lists under "Manifest, `network`". Each test names the rule it works through.
///
/// The reads of one `plan` are `get_policy` (when the manifest states a policy), then
/// `list_segments` and `list_profiles` walked to exhaustion: a list with items is two requests
/// (the page, then the empty page that ends the walk) and an empty list is one.
final class NetworkManifestTests: XCTestCase {

    // MARK: - Fixtures

    private static let segA = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    private static let segB = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"

    private typealias Reply = (status: Int, body: String)

    private static func json(_ object: [String: Any]) -> String { NetworkManagementTests.json(object) }

    private static func segment(
        _ id: String = segA, name: String = "lab", kind: String = "access", vlan: Int = 20,
        rank: Any = 1, filters: [String] = ["corp"], enabled: Bool = true, version: Int = 3
    ) -> [String: Any] {
        NetworkManagementTests.segmentObject([
            "id": id, "name": name, "kind": kind, "vlan_id": vlan, "rank": rank,
            "filter_ids": filters, "enabled": enabled, "version": version,
        ])
    }

    private static func profile(
        _ segmentID: String = segA, timeout: Int = 3600, clamped: Bool = false,
        filter: Any = "corp", idle: Any = NSNull(), version: Int = 5
    ) -> [String: Any] {
        NetworkManagementTests.profileObject([
            "segment_id": segmentID, "session_timeout_secs": timeout,
            "session_timeout_clamped": clamped, "filter_id": filter,
            "idle_timeout_secs": idle, "version": version,
        ])
    }

    private static func policy(secs: Int = 3600, version: Int = 0) -> [String: Any] {
        NetworkManagementTests.policyObject(["session_timeout_max_secs": secs, "version": version])
    }

    /// A list read: the page, then the empty page that ends the walk; just the one when empty.
    private static func list(_ items: [[String: Any]]) -> [Reply] {
        let total = items.count
        let first: Reply = (status: 200, body: json(["items": items, "total": total, "offset": 0, "limit": 200]))
        guard !items.isEmpty else { return [first] }
        let end: Reply = (status: 200, body: json(["items": [Any](), "total": total, "offset": 200, "limit": 200]))
        return [first, end]
    }

    /// The reads of one `plan`, in the order it makes them.
    private static func reads(
        policy: [String: Any]? = nil, segments: [[String: Any]]? = nil, profiles: [[String: Any]]? = nil
    ) -> [Reply] {
        var out: [Reply] = []
        if let policy { out.append((status: 200, body: json(policy))) }
        if let segments { out.append(contentsOf: list(segments)) }
        if let profiles { out.append(contentsOf: list(profiles)) }
        return out
    }

    private static func lab(
        vlan: Int = 20, rank: NetworkMember<Int> = .value(1), filters: [String]? = ["corp"],
        enabled: Bool? = nil
    ) -> NetworkSegmentSpec {
        NetworkSegmentSpec(
            key: "lab", site: "default", kind: .access, name: "lab", vlanID: vlan, rank: rank,
            filterIds: filters, enabled: enabled)
    }

    private static func manifest(
        segments: [NetworkSegmentSpec] = [], profiles: [NetworkProfileSpec] = [],
        policy: NetworkPolicySpec? = nil
    ) -> Manifest {
        Manifest(
            entities: [],
            network: NetworkManifest(segments: segments, profiles: profiles, policy: policy))
    }

    private static func requestKeys(_ body: [String: Any]?) -> Set<String> {
        Set((body ?? [:]).keys)
    }

    // MARK: - plan writes nothing

    func testPlanIssuesGetsOnlyAndNothingElse() async throws {
        let (client, transport) = try await ManagementFixture.signedIn(
            Self.reads(policy: Self.policy(), segments: [], profiles: []))
        let plan = try await client.manifest.plan(Self.manifest(
            segments: [Self.lab()],
            profiles: [NetworkProfileSpec(segment: "lab", sessionTimeoutSecs: 1800)],
            policy: NetworkPolicySpec(sessionTimeoutMaxSecs: 1800)))

        XCTAssertEqual(transport.requests.map(\.method), ["GET", "GET", "GET"])
        XCTAssertEqual(transport.requests.map(\.path), [
            "/api/v1/network/policy", "/api/v1/network/segments", "/api/v1/network/profiles",
        ])
        // The order of the actions: the policy, then the segments, then the profiles.
        XCTAssertEqual(plan.networkChanges.map(\.kind), [.policy, .segment, .profile])
        XCTAssertEqual(plan.networkChanges.map(\.action), [.update, .create, .create])
        XCTAssertFalse(plan.isConverged)
    }

    func testAManifestWithoutANetworkSectionPlansExactlyAsItDidBefore() async throws {
        let (client, transport) = try await ManagementFixture.signedIn([])
        let plan = try await client.manifest.plan(Manifest(entities: []))
        XCTAssertEqual(transport.count, 0, "no network section: not one request")
        XCTAssertTrue(plan.networkChanges.isEmpty)
        XCTAssertTrue(plan.isConverged)
    }

    // MARK: - An empty tenant: create the segment, then its profile; then converged

    func testApplyOnAnEmptyTenantCreatesTheSegmentThenItsProfileWithTheNewIdAndVersion() async throws {
        let created = Self.segment(Self.segA, version: 7)
        let (client, transport) = try await ManagementFixture.signedIn(
            Self.reads(policy: Self.policy(), segments: [], profiles: [])
                + [
                    (status: 200, body: Self.json(Self.policy(secs: 1800, version: 1))),
                    (status: 201, body: Self.json(created)),
                    (status: 201, body: Self.json(Self.profile(timeout: 1800, version: 1))),
                ])
        let manifest = Self.manifest(
            segments: [Self.lab()],
            profiles: [NetworkProfileSpec(
                segment: "lab", sessionTimeoutSecs: 1800, filterID: .value("corp"))],
            policy: NetworkPolicySpec(sessionTimeoutMaxSecs: 1800))

        let report = try await client.manifest.apply(manifest)
        XCTAssertTrue(report.isComplete, report.describe.joined(separator: "\n"))
        XCTAssertEqual(report.appliedNetwork.map(\.kind), [.policy, .segment, .profile])

        XCTAssertEqual(transport.requests.map(\.method), ["GET", "GET", "GET", "PUT", "POST", "POST"])
        XCTAssertEqual(transport.requests.map(\.path), [
            "/api/v1/network/policy", "/api/v1/network/segments", "/api/v1/network/profiles",
            "/api/v1/network/policy", "/api/v1/network/segments", "/api/v1/network/profiles",
        ])

        // The policy is first, and a tenant that never wrote one sends version 0.
        let policyBody = try XCTUnwrap(transport.requests[3].jsonBody)
        XCTAssertEqual(policyBody["version"] as? Int, 0)
        XCTAssertEqual(policyBody["session_timeout_max_secs"] as? Int, 1800)

        // The segment's body: the wire spelling of the kind, the members stated, nothing else.
        let segmentBody = try XCTUnwrap(transport.requests[4].jsonBody)
        XCTAssertEqual(segmentBody["kind"] as? String, "access")
        XCTAssertEqual(Self.requestKeys(segmentBody), ["filter_ids", "kind", "name", "rank", "site_key", "vlan_id"])
        XCTAssertEqual(segmentBody["site_key"] as? String, "default")
        XCTAssertEqual(segmentBody["vlan_id"] as? Int, 20)

        // The profile's: the NEW segment's id and the version of the create response.
        let profileBody = try XCTUnwrap(transport.requests[5].jsonBody)
        XCTAssertEqual(profileBody["segment_id"] as? String, Self.segA)
        XCTAssertEqual(profileBody["segment_version"] as? Int, 7)
        let input = try XCTUnwrap(profileBody["profile"] as? [String: Any])
        XCTAssertEqual(Self.requestKeys(input), ["filter_id", "session_timeout_secs"])
        XCTAssertEqual(report.appliedNetwork[2].writtenVersion, 1)

        // And the plan afterwards is all NoChange (§27.6 rule 6).
        transport.script(Self.reads(
            policy: Self.policy(secs: 1800, version: 1), segments: [created],
            profiles: [Self.profile(timeout: 1800, version: 1)]))
        let converged = try await client.manifest.plan(manifest)
        XCTAssertTrue(converged.isConverged, converged.networkChanges.map(\.describe).joined(separator: "\n"))
        XCTAssertEqual(converged.networkChanges.map(\.action), [.unchanged, .unchanged, .unchanged])
    }

    // MARK: - A segment Update is the full replacement body, built from the read

    func testASegmentUpdateSendsTheFullReplacementBodyCarriedFromTheRead() async throws {
        let read = Self.segment(vlan: 20, rank: 1, filters: ["corp", "guest"], enabled: false, version: 3)
        let (client, transport) = try await ManagementFixture.signedIn(
            Self.reads(segments: [read]) + [(status: 200, body: Self.json(Self.segment(vlan: 30, version: 4)))])

        // Only the VLAN is stated: every other member is carried from the read.
        let report = try await client.manifest.apply(Self.manifest(
            segments: [NetworkSegmentSpec(
                key: "lab", site: "default", kind: .access, name: "lab", vlanID: 30)]))
        XCTAssertTrue(report.isComplete, report.describe.joined(separator: "\n"))

        let put = try XCTUnwrap(transport.last)
        XCTAssertEqual(put.method, "PUT")
        XCTAssertEqual(put.path, "/api/v1/network/segments/\(Self.segA)")
        let body = try XCTUnwrap(put.jsonBody)
        // The exact key set: `version` as read, the stated member, the carried ones — and no
        // `kind`, `site_key` or `name`, which a replacement does not have.
        XCTAssertEqual(Self.requestKeys(body), ["enabled", "filter_ids", "rank", "version", "vlan_id"])
        XCTAssertEqual(body["version"] as? Int, 3)
        XCTAssertEqual(body["vlan_id"] as? Int, 30)
        XCTAssertEqual(body["rank"] as? Int, 1)
        XCTAssertEqual(body["filter_ids"] as? [String], ["corp", "guest"])
        XCTAssertEqual(body["enabled"] as? Bool, false)
    }

    func testAStatedNullOnAnOptionalProfileMemberLeavesTheKeyOutAndTheRestIsCarried() async throws {
        let (client, transport) = try await ManagementFixture.signedIn(
            Self.reads(segments: [Self.segment()], profiles: [Self.profile(filter: "corp", idle: 600)])
                + [(status: 200, body: Self.json(Self.profile(filter: NSNull(), idle: 600, version: 6)))])

        // `filter_id` is stated as none: the replacement leaves the key out, which is how it clears.
        let report = try await client.manifest.apply(Self.manifest(
            segments: [Self.lab()],
            profiles: [NetworkProfileSpec(segment: "lab", sessionTimeoutSecs: 3600, filterID: .null)]))
        XCTAssertTrue(report.isComplete, report.describe.joined(separator: "\n"))
        XCTAssertEqual(report.appliedNetwork.map(\.kind), [.profile])

        let put = try XCTUnwrap(transport.last)
        XCTAssertEqual(put.method, "PUT")
        XCTAssertEqual(put.path, "/api/v1/network/profiles/\(Self.segA)")
        let body = try XCTUnwrap(put.jsonBody)
        XCTAssertEqual(Self.requestKeys(body), ["profile", "segment_version", "version"])
        XCTAssertEqual(body["version"] as? Int, 5)
        XCTAssertEqual(body["segment_version"] as? Int, 3, "the segment's version as read: it was not written")
        let input = try XCTUnwrap(body["profile"] as? [String: Any])
        XCTAssertFalse(input.keys.contains("filter_id"), "a stated none is left out, never null")
        XCTAssertEqual(input["idle_timeout_secs"] as? Int, 600, "unstated: carried from the read")
        XCTAssertEqual(input["service_type"] as? String, "framed_user")
        XCTAssertEqual(input["termination_action"] as? String, "radius_request")
        XCTAssertEqual(input["dictionary"] as? String, "axiam-radius-reply/1")
        XCTAssertEqual(input["session_timeout_secs"] as? Int, 3600)
    }

    func testASegmentAndItsProfileChangedTogetherSendTheSegmentWritesVersionAsSegmentVersion() async throws {
        let (client, transport) = try await ManagementFixture.signedIn(
            Self.reads(
                segments: [Self.segment(vlan: 20, version: 3)],
                profiles: [Self.profile(timeout: 3600, version: 5)])
                + [
                    (status: 200, body: Self.json(Self.segment(vlan: 30, version: 4))),
                    (status: 200, body: Self.json(Self.profile(timeout: 1800, version: 6))),
                ])

        let report = try await client.manifest.apply(Self.manifest(
            segments: [Self.lab(vlan: 30)],
            profiles: [NetworkProfileSpec(segment: "lab", sessionTimeoutSecs: 1800)]))
        XCTAssertTrue(report.isComplete, report.describe.joined(separator: "\n"))

        let writes = transport.requests.filter { $0.method == "PUT" }
        XCTAssertEqual(writes.map(\.path), [
            "/api/v1/network/segments/\(Self.segA)", "/api/v1/network/profiles/\(Self.segA)",
        ], "replace_segment, then replace_profile")
        XCTAssertEqual(writes[0].jsonBody?["version"] as? Int, 3, "the version plan read")
        let profileBody = try XCTUnwrap(writes[1].jsonBody)
        XCTAssertEqual(profileBody["version"] as? Int, 5, "the profile's own version, as read")
        XCTAssertEqual(
            profileBody["segment_version"] as? Int, 4,
            "the replace_segment response's version, not the 3 that plan read")
    }

    // MARK: - A 409 is that action's failure

    func testA409OnAnyNetworkWriteIsOneRequestStopsTheApplyAndExposesTheReasonCode() async throws {
        let bodies: [(String, String, String)] = [
            ("stale_version", "conflict", "the row changed since it was read"),
            ("duplicate_vlan", "already_exists", "the site already has that VLAN"),
        ]
        for (code, slug, message) in bodies {
            let (client, transport) = try await ManagementFixture.signedIn(
                Self.reads(
                    segments: [Self.segment(vlan: 20, version: 3)],
                    profiles: [Self.profile(timeout: 3600, version: 5)])
                    + [
                        (status: 409, body: Self.json(["error": slug, "message": message, "reason_code": code])),
                        // Reached only if the SDK went on after the failure.
                        (status: 200, body: Self.json(Self.profile(timeout: 1800, version: 6))),
                    ])

            let report = try await client.manifest.apply(Self.manifest(
                segments: [Self.lab(vlan: 30)],
                profiles: [NetworkProfileSpec(segment: "lab", sessionTimeoutSecs: 1800)]))

            XCTAssertFalse(report.isComplete, code)
            XCTAssertEqual(report.failedNetwork?.kind, .segment, code)
            XCTAssertEqual(report.networkFailureReasonCode, code)
            XCTAssertTrue(report.networkFailure.contains(message), "the server's message, as given")
            if case .authz(let error)? = report.networkFailureError {
                XCTAssertEqual(error.managementFailure, .conflict)
            } else {
                XCTFail("\(code): a 409 is an AuthzError carrying the conflict sub-type")
            }
            // The profile that followed was not attempted, and nothing was retried.
            XCTAssertEqual(report.remainingNetwork.map(\.kind), [.profile], code)
            XCTAssertEqual(transport.requests.filter { $0.method != "GET" }.count, 1, "\(code): exactly one write")
            XCTAssertEqual(transport.count, 5, "\(code): four reads and the one write")
            XCTAssertTrue(
                report.describe.contains { $0.contains("reason_code: \(code)") }, "\(code): the report says it")
        }
    }

    // MARK: - Pruning is off, and this SDK has none to turn on

    func testASegmentTheManifestDoesNotStateIsLeftAloneAndNeverDeleted() async throws {
        let other = Self.segment(Self.segB, name: "other", vlan: 99, rank: 2)
        let (client, transport) = try await ManagementFixture.signedIn(
            Self.reads(segments: [Self.segment(), other]))
        let report = try await client.manifest.apply(Self.manifest(segments: [Self.lab()]))
        XCTAssertTrue(report.isComplete)
        XCTAssertTrue(report.appliedNetwork.isEmpty, "the one segment stated is already as stated")
        XCTAssertEqual(transport.requests.map(\.method).filter { $0 != "GET" }, [], "omission is never deletion")
    }

    // MARK: - Refused with zero wire calls

    func testTwoSegmentsWithOneNaturalKeyAndADanglingProfileAreRefusedBeforeAnyRequest() async throws {
        let (client, transport) = try await ManagementFixture.signedIn([])

        let twin = NetworkSegmentSpec(
            key: "twin", site: "default", kind: .access, name: "lab", vlanID: 21, rank: .value(2))
        for manifest in [
            // Two segments with one site, kind and name.
            Self.manifest(segments: [Self.lab(), twin]),
            // The same manifest-local key twice.
            Self.manifest(segments: [Self.lab(), Self.lab(vlan: 22)]),
            // A profile whose segment names no segment spec of the manifest.
            Self.manifest(
                segments: [Self.lab()],
                profiles: [NetworkProfileSpec(segment: "nowhere", sessionTimeoutSecs: 1800)]),
            // Two profiles for one segment.
            Self.manifest(
                segments: [Self.lab()],
                profiles: [
                    NetworkProfileSpec(segment: "lab", sessionTimeoutSecs: 1800),
                    NetworkProfileSpec(segment: "lab", sessionTimeoutSecs: 900),
                ]),
        ] {
            do {
                _ = try await client.manifest.plan(manifest)
                XCTFail("expected a refusal")
            } catch is ManifestError {
                // expected
            }
            do {
                _ = try await client.manifest.apply(manifest)
                XCTFail("expected a refusal")
            } catch is ManifestError {
                // expected
            }
        }
        XCTAssertEqual(transport.count, 0, "refused client-side: zero wire calls")
    }

    func testASegmentListingOneFilterIdTwiceIsRefusedAtPlanAndAtApplyWithZeroWireCalls() async throws {
        let (client, transport) = try await ManagementFixture.signedIn([])
        let manifest = Self.manifest(segments: [Self.lab(filters: ["corp", "guest", "corp"])])
        do {
            _ = try await client.manifest.plan(manifest)
            XCTFail("expected a refusal at plan")
        } catch let error as ManifestError {
            XCTAssertTrue(error.message.contains("Filter-Id"))
        }
        do {
            _ = try await client.manifest.apply(manifest)
            XCTFail("expected a refusal at apply")
        } catch is ManifestError {
            // expected
        }
        XCTAssertEqual(transport.count, 0)
    }

    // MARK: - The kind is the wire spelling

    func testAnAccessSegmentIsNoChangeAgainstTheReadAndItsCreateBodyCarriesTheWireString() async throws {
        // Read says "access": the manifest's `.access` matches, so the segment is NoChange.
        let (client, _) = try await ManagementFixture.signedIn(Self.reads(segments: [Self.segment(kind: "access")]))
        let plan = try await client.manifest.plan(Self.manifest(segments: [Self.lab()]))
        XCTAssertEqual(plan.networkChanges.map(\.action), [.unchanged])

        // A quarantine segment is its own natural key, `quarantine` on the wire.
        let (second, transport) = try await ManagementFixture.signedIn(
            Self.reads(segments: [Self.segment(kind: "access")])
                + [(status: 201, body: Self.json(Self.segment(Self.segB, name: "lab", kind: "quarantine", vlan: 99, rank: NSNull())))])
        let quarantine = NetworkSegmentSpec(
            key: "q", site: "default", kind: .quarantine, name: "lab", vlanID: 99, rank: .null)
        let report = try await second.manifest.apply(Self.manifest(segments: [quarantine]))
        XCTAssertTrue(report.isComplete, report.describe.joined(separator: "\n"))
        let body = try XCTUnwrap(transport.last?.jsonBody)
        XCTAssertEqual(body["kind"] as? String, "quarantine")
        XCTAssertFalse(body.keys.contains("rank"), "a quarantine segment has no rank, and none is never null")
    }

    // MARK: - filter_ids is a set

    func testFilterIdsAreComparedAsASetAndWrittenInTheOrderStated() async throws {
        let read = Self.segment(filters: ["corp", "guest"])

        // The same names in another order: NoChange, and apply writes nothing.
        let (same, sameTransport) = try await ManagementFixture.signedIn(Self.reads(segments: [read]))
        let reorder = try await same.manifest.apply(Self.manifest(segments: [Self.lab(filters: ["guest", "corp"])]))
        XCTAssertTrue(reorder.isComplete)
        XCTAssertTrue(reorder.appliedNetwork.isEmpty, "a reorder alone is never an Update")
        XCTAssertEqual(sameTransport.requests.map(\.method).filter { $0 != "GET" }, [])

        // An Update caused by another member sends the filter_ids in the order the manifest states.
        let (update, updateTransport) = try await ManagementFixture.signedIn(
            Self.reads(segments: [read]) + [(status: 200, body: Self.json(Self.segment(vlan: 30, version: 4)))])
        let changed = try await update.manifest.apply(
            Self.manifest(segments: [Self.lab(vlan: 30, filters: ["guest", "corp"])]))
        XCTAssertTrue(changed.isComplete)
        XCTAssertEqual(updateTransport.last?.jsonBody?["filter_ids"] as? [String], ["guest", "corp"])

        // A Create does the same.
        let (create, createTransport) = try await ManagementFixture.signedIn(
            Self.reads(segments: []) + [(status: 201, body: Self.json(Self.segment(version: 1)))])
        let created = try await create.manifest.apply(
            Self.manifest(segments: [Self.lab(filters: ["guest", "corp"])]))
        XCTAssertTrue(created.isComplete)
        XCTAssertEqual(createTransport.last?.jsonBody?["filter_ids"] as? [String], ["guest", "corp"])
    }

    // MARK: - A clamped profile is judged on the read

    func testAClampedProfileIsNoChangeAtTheCapAndAnUpdateAboveItAndTheServersRefusalStopsTheApply() async throws {
        // The read is the effective profile: stored 7200, lowered to the cap of 1800.
        let clamped = Self.profile(timeout: 1800, clamped: true, version: 5)

        // States the cap: NoChange. The stored value is neither restored nor rewritten.
        let (atCap, atCapTransport) = try await ManagementFixture.signedIn(
            Self.reads(segments: [Self.segment()], profiles: [clamped]))
        let quiet = try await atCap.manifest.apply(Self.manifest(
            segments: [Self.lab()],
            profiles: [NetworkProfileSpec(segment: "lab", sessionTimeoutSecs: 1800)]))
        XCTAssertTrue(quiet.isComplete)
        XCTAssertEqual(quiet.appliedNetwork.count, 0)
        XCTAssertEqual(atCapTransport.requests.map(\.method).filter { $0 != "GET" }, [])

        // States a value above the cap: differs from the read, so plan shows an Update ...
        let refusal = #"{"error": "authorization_denied", "message": "session_timeout_secs is above the tenant's cap of 1800"}"#
        let other = Self.segment(Self.segB, name: "other", vlan: 21, rank: 2)
        let otherProfile = Self.profile(Self.segB, timeout: 3600, version: 8)
        let (above, aboveTransport) = try await ManagementFixture.signedIn(
            Self.reads(segments: [Self.segment(), other], profiles: [clamped, otherProfile]))
        let manifest = Manifest(entities: [], network: NetworkManifest(
            segments: [
                Self.lab(),
                NetworkSegmentSpec(
                    key: "other", site: "default", kind: .access, name: "other", vlanID: 21, rank: .value(2),
                    filterIds: ["corp"]),
            ],
            profiles: [
                NetworkProfileSpec(segment: "lab", sessionTimeoutSecs: 7200),
                NetworkProfileSpec(segment: "other", sessionTimeoutSecs: 900),
            ]))
        let plan = try await above.manifest.plan(manifest)
        XCTAssertEqual(plan.networkChanges.map(\.action), [.unchanged, .unchanged, .update, .update])

        // ... and apply sends exactly one replace_profile, which the server refuses with 403.
        aboveTransport.script(
            Self.reads(segments: [Self.segment(), other], profiles: [clamped, otherProfile])
                + [
                    (status: 403, body: refusal),
                    // Reached only if the SDK went on after the refusal.
                    (status: 200, body: Self.json(Self.profile(Self.segB, timeout: 900, version: 9))),
                ])
        let report = try await above.manifest.apply(manifest)
        XCTAssertFalse(report.isComplete)
        XCTAssertEqual(report.failedNetwork?.kind, .profile)
        XCTAssertEqual(report.failedNetwork?.key, "lab")
        XCTAssertTrue(report.networkFailure.contains("above the tenant's cap of 1800"), "the server's message")
        if case .authz(let error)? = report.networkFailureError {
            XCTAssertNil(error.managementFailure, "a 403 is the plain AuthzError")
        } else {
            XCTFail("a 403 is an AuthzError")
        }
        XCTAssertNil(report.networkFailureReasonCode, "only a 409 carries a reason_code")
        XCTAssertEqual(report.remainingNetwork.map(\.key), ["other"], "later actions are not attempted")
        // Exactly one write across the plan and the apply, and the apply never lowered the value.
        let writes = aboveTransport.requests.filter { $0.method == "PUT" }
        XCTAssertEqual(writes.count, 1)
        XCTAssertEqual(
            (writes[0].jsonBody?["profile"] as? [String: Any])?["session_timeout_secs"] as? Int, 7200,
            "reported as given: the SDK did not adjust the value to the cap")
    }

    // MARK: - An open-enum value the SDK cannot name (C162-07, §27.6.2 item 4)

    /// A profile whose two open-enum members carry values this SDK does not list.
    private static func futureProfile() -> [String: Any] {
        NetworkManagementTests.profileObject([
            "segment_id": segA, "session_timeout_secs": 3600, "filter_id": "corp",
            "termination_action": "future", "service_type": "future_service", "version": 5,
        ])
    }

    private func assertRefusal(
        _ error: Error, member: String, value: String, file: StaticString = #filePath, line: UInt = #line
    ) {
        guard case AxiamError.network(let failure) = error else {
            return XCTFail("expected AxiamError.network, got \(error)", file: file, line: line)
        }
        XCTAssertTrue(failure.isValidation, file: file, line: line)
        XCTAssertEqual(failure.statusCode, 400, file: file, line: line)
        XCTAssertTrue(failure.message.contains(member), "names the member", file: file, line: line)
        XCTAssertTrue(failure.message.contains("\"\(value)\""), "names the value", file: file, line: line)
    }

    func testAnUpdateThatWouldCarryAnUnknownEnumValueIsRefusedAtPlanAndApplyBeforeAnyWrite() async throws {
        let manifest = Self.manifest(
            segments: [Self.lab()],
            profiles: [NetworkProfileSpec(segment: "lab", sessionTimeoutSecs: 1800)])

        let (planClient, planTransport) = try await ManagementFixture.signedIn(
            Self.reads(segments: [Self.segment()], profiles: [Self.futureProfile()]))
        do {
            _ = try await planClient.manifest.plan(manifest)
            XCTFail("plan must refuse")
        } catch {
            assertRefusal(error, member: "termination_action", value: "future")
        }
        XCTAssertEqual(planTransport.requests.map(\.method).filter { $0 != "GET" }, [])

        let (applyClient, applyTransport) = try await ManagementFixture.signedIn(
            Self.reads(segments: [Self.segment()], profiles: [Self.futureProfile()]))
        do {
            _ = try await applyClient.manifest.apply(manifest)
            XCTFail("apply must refuse")
        } catch {
            assertRefusal(error, member: "termination_action", value: "future")
        }
        XCTAssertEqual(applyTransport.requests.map(\.method).filter { $0 != "GET" }, [], "zero writes")

        // service_type alone, with termination_action stated, is refused the same way.
        let (serviceClient, _) = try await ManagementFixture.signedIn(
            Self.reads(segments: [Self.segment()], profiles: [Self.futureProfile()]))
        do {
            _ = try await serviceClient.manifest.plan(Self.manifest(
                segments: [Self.lab()],
                profiles: [NetworkProfileSpec(
                    segment: "lab", sessionTimeoutSecs: 1800, terminationAction: .radiusRequest)]))
            XCTFail("plan must refuse")
        } catch {
            assertRefusal(error, member: "service_type", value: "future_service")
        }
    }

    func testStatingTheUnknownMembersGivesAnUpdateWhoseWriteNeverCarriesTheUnknownValue() async throws {
        let (client, transport) = try await ManagementFixture.signedIn(
            Self.reads(segments: [Self.segment()], profiles: [Self.futureProfile()])
                + [(status: 200, body: Self.json(Self.profile(timeout: 1800, version: 6)))])
        let report = try await client.manifest.apply(Self.manifest(
            segments: [Self.lab()],
            profiles: [NetworkProfileSpec(
                segment: "lab", sessionTimeoutSecs: 1800, terminationAction: .radiusRequest,
                serviceType: .value(.framedUser))]))
        XCTAssertTrue(report.isComplete)
        let writes = transport.requests.filter { $0.method == "PUT" }
        XCTAssertEqual(writes.count, 1)
        let profile = writes[0].jsonBody?["profile"] as? [String: Any]
        XCTAssertEqual(profile?["termination_action"] as? String, "radius_request")
        XCTAssertEqual(profile?["service_type"] as? String, "framed_user")
        XCTAssertFalse(String(describing: writes[0].jsonBody ?? [:]).contains("future"))
    }

    func testNothingDifferingIsNoChangeAndWritesNothingWhateverTheUnknownValues() async throws {
        let (client, transport) = try await ManagementFixture.signedIn(
            Self.reads(segments: [Self.segment()], profiles: [Self.futureProfile()]))
        let report = try await client.manifest.apply(Self.manifest(
            segments: [Self.lab()],
            profiles: [NetworkProfileSpec(segment: "lab", sessionTimeoutSecs: 3600)]))
        XCTAssertTrue(report.isComplete)
        XCTAssertEqual(report.appliedNetwork.count, 0)
        XCTAssertEqual(transport.requests.map(\.method).filter { $0 != "GET" }, [])
    }

    // MARK: - The policy

    func testThePolicyIsNeverACreateAndIsNoChangeAtTheStatedCap() async throws {
        let (client, transport) = try await ManagementFixture.signedIn(
            Self.reads(policy: Self.policy(secs: 3600, version: 0)))
        let plan = try await client.manifest.plan(Self.manifest(
            policy: NetworkPolicySpec(sessionTimeoutMaxSecs: 3600)))
        XCTAssertEqual(plan.networkChanges.map(\.action), [.unchanged])
        XCTAssertEqual(transport.requests.map(\.path), ["/api/v1/network/policy"], "no list is read")
    }
}
