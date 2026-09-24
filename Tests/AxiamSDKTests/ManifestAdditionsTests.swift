import XCTest
@testable import AxiamSDK

/// CONTRACT.md §27.6.1 — the three manifest additions contract 1.51 makes explicit:
/// `resources[].metadata`, the resource-scoped role binding (`{role, resource, inherit}`),
/// and `service_accounts`. §8 rule 7 requires every port ship these three round-trips;
/// §27.9's "Manifest additions" block is the required-test list this file works through.
final class ManifestAdditionsTests: XCTestCase {

    private static let uuid = ManagementFixture.tenantID

    private static func resourcePage(id: String, name: String, metadata: String) -> String {
        """
        {"items": [{"created_at": "2026-08-26T00:00:00Z", "id": "\(id)", "metadata": \(metadata), \
        "name": "\(name)", "resource_type": "folder", "tenant_id": "\(uuid)", \
        "updated_at": "2026-08-26T00:00:00Z"}], "total": 1}
        """
    }

    private static func resourceObject(id: String, name: String, metadata: String) -> String {
        """
        {"created_at": "2026-08-26T00:00:00Z", "id": "\(id)", "metadata": \(metadata), \
        "name": "\(name)", "resource_type": "folder", "tenant_id": "\(uuid)", \
        "updated_at": "2026-08-26T00:00:00Z"}
        """
    }

    private static func rolePage(id: String, name: String, isGlobal: Bool = false) -> String {
        """
        {"items": [{"created_at": "2026-08-26T00:00:00Z", "description": "", "id": "\(id)", \
        "is_global": \(isGlobal), "name": "\(name)", "tenant_id": "\(uuid)", \
        "updated_at": "2026-08-26T00:00:00Z"}], "total": 1}
        """
    }

    private static func groupPage(id: String, name: String, description: String = "") -> String {
        """
        {"items": [{"created_at": "2026-08-26T00:00:00Z", "description": "\(description)", \
        "id": "\(id)", "metadata": {}, "name": "\(name)", "tenant_id": "\(uuid)", \
        "updated_at": "2026-08-26T00:00:00Z"}], "total": 1}
        """
    }

    private static let emptyArray = "[]"

    private static func roleAssignment(
        groupID: String, groupName: String, resourceID: String?, inherit: Bool?, tenantScope: [String]? = nil
    ) -> String {
        var fields = [
            #""role": {"created_at": "2026-08-26T00:00:00Z", "description": "", "id": "\#(groupID)", "is_global": false, "name": "editor", "tenant_id": "\#(uuid)", "updated_at": "2026-08-26T00:00:00Z"}"#,
        ]
        if let resourceID { fields.append(#""resource_id": "\#(resourceID)""#) }
        if let inherit { fields.append(#""inherit": \#(inherit)"#) }
        if let tenantScope {
            fields.append(#""tenant_scope": [\#(tenantScope.map { "\"\($0)\"" }.joined(separator: ","))]"#)
        }
        return "[{\(fields.joined(separator: ","))}]"
    }

    // MARK: - `resources[].metadata` round-trips

    func testMetadataRoundTripsAndAChangeUpdatesTheWholeObject() async throws {
        let resourceID = Self.uuid
        // 1st plan: nothing exists.
        let (client, transport) = try await ManagementFixture.signedIn([
            (200, #"{"items": [], "total": 0}"#),
            (201, Self.resourceObject(id: resourceID, name: "documents", metadata: #"{"team":"docs"}"#)),
        ])
        let manifest = Manifest(entities: [
            ManifestEntity(
                kind: .resource, key: "root", name: "documents", resourceType: "folder",
                metadata: .object(["team": .string("docs")])),
        ])
        let report = try await client.manifest.apply(manifest)
        XCTAssertTrue(report.isComplete, report.describe.joined(separator: "\n"))
        let createBody = try XCTUnwrap(transport.last?.jsonBody)
        XCTAssertEqual((createBody["metadata"] as? [String: Any])?["team"] as? String, "docs")

        // apply -> plan is NoChange (idempotence, §27.6 rule 6).
        transport.script([
            (200, Self.resourcePage(id: resourceID, name: "documents", metadata: #"{"team":"docs"}"#)),
        ])
        let converged = try await client.manifest.plan(manifest)
        XCTAssertTrue(converged.isConverged, converged.changes.map { $0.describe }.joined(separator: "\n"))

        // A changed key -> Update whose body carries the WHOLE object (never a merge).
        let changedManifest = Manifest(entities: [
            ManifestEntity(
                kind: .resource, key: "root", name: "documents", resourceType: "folder",
                metadata: .object(["team": .string("eng"), "extra": .bool(true)])),
        ])
        transport.script([
            (200, Self.resourcePage(id: resourceID, name: "documents", metadata: #"{"team":"docs"}"#)),
            (200, Self.resourceObject(id: resourceID, name: "documents", metadata: #"{"team":"eng","extra":true}"#)),
        ])
        let updateReport = try await client.manifest.apply(changedManifest)
        XCTAssertTrue(updateReport.isComplete, updateReport.describe.joined(separator: "\n"))
        XCTAssertEqual(updateReport.applied.first?.action, .update)
        let updateBody = try XCTUnwrap(transport.last?.jsonBody)
        let sentMetadata = try XCTUnwrap(updateBody["metadata"] as? [String: Any])
        XCTAssertEqual(sentMetadata["team"] as? String, "eng")
        XCTAssertEqual(sentMetadata["extra"] as? Bool, true)
    }

    // MARK: - Resource-scoped binding, `inherit`

    /// A resource-scoped binding with `inherit: false` sends `resource_id` AND
    /// `inherit: false`. The same binding with `inherit` OMITTED (the default, `true`)
    /// sends NEITHER key extra — `resource_id` still goes (it is a scoped binding), but
    /// no `inherit` key at all, so an inheritable assignment's body stays byte-for-byte
    /// a pre-1.51 body (§27.13 S-10 rule 1).
    func testResourceScopedBindingSendsInheritOnlyWhenFalse() async throws {
        let resourceID = "r1"
        let roleID = "role1"
        let groupID = "group1"

        // inherit: false case.
        let (falseClient, falseTransport) = try await ManagementFixture.signedIn([
            (200, Self.resourcePage(id: resourceID, name: "documents", metadata: "{}")),
            (200, Self.rolePage(id: roleID, name: "editor")),
            (200, Self.groupPage(id: groupID, name: "editors")),
            (200, Self.emptyArray), // groups.listRoles: no existing assignment
            (204, ""), // roles.assignToGroup
        ])
        let falseManifest = Manifest(entities: [
            ManifestEntity(kind: .resource, key: "root", name: "documents", resourceType: "folder"),
            ManifestEntity(kind: .role, key: "editor", name: "editor"),
            ManifestEntity(
                kind: .group, key: "editors", name: "editors",
                roleBindings: [RoleBindingSpec(role: "editor", resource: "root", inherit: false)]),
        ])
        let falseReport = try await falseClient.manifest.apply(falseManifest)
        XCTAssertTrue(falseReport.isComplete, falseReport.describe.joined(separator: "\n"))
        XCTAssertEqual(falseReport.appliedBindings.count, 1)
        let falseBody = try XCTUnwrap(falseTransport.last?.jsonBody)
        XCTAssertEqual(falseBody["resource_id"] as? String, resourceID)
        XCTAssertEqual(falseBody["inherit"] as? Bool, false)

        // inherit omitted (default true) case — same shape, no `inherit` key at all.
        let (trueClient, trueTransport) = try await ManagementFixture.signedIn([
            (200, Self.resourcePage(id: resourceID, name: "documents", metadata: "{}")),
            (200, Self.rolePage(id: roleID, name: "editor")),
            (200, Self.groupPage(id: groupID, name: "editors")),
            (200, Self.emptyArray),
            (204, ""),
        ])
        let trueManifest = Manifest(entities: [
            ManifestEntity(kind: .resource, key: "root", name: "documents", resourceType: "folder"),
            ManifestEntity(kind: .role, key: "editor", name: "editor"),
            ManifestEntity(
                kind: .group, key: "editors", name: "editors",
                roleBindings: [RoleBindingSpec(role: "editor", resource: "root")]),
        ])
        _ = try await trueClient.manifest.apply(trueManifest)
        let trueBody = try XCTUnwrap(trueTransport.last?.jsonBody)
        XCTAssertEqual(trueBody["resource_id"] as? String, resourceID)
        XCTAssertNil(trueBody["inherit"], "an inheritable (default) binding must send NO inherit key")
    }

    /// Changing a binding's resource is an UNASSIGN followed by an ASSIGN, in that order.
    /// `tenant_scope` on the server binding survives the change (§27.13 S-10 rule 4 /
    /// §27.6.1: a manifest binding says nothing about `tenant_scope`, so the re-assign
    /// carries the server's value across unchanged rather than silently widening it).
    func testChangingABindingsResourceIsUnassignThenAssignAndTenantScopeSurvives() async throws {
        let oldResourceID = "r-old"
        let newResourceID = "r-new"
        let roleID = "role1"
        let groupID = "group1"

        let (client, transport) = try await ManagementFixture.signedIn([
            (200, """
                {"items": [\(Self.resourceObject(id: oldResourceID, name: "old", metadata: "{}")), \
                \(Self.resourceObject(id: newResourceID, name: "new", metadata: "{}"))], "total": 2}
                """),
            (200, Self.rolePage(id: roleID, name: "editor")),
            (200, Self.groupPage(id: groupID, name: "editors")),
            (200, Self.roleAssignment(
                groupID: groupID, groupName: "editors", resourceID: oldResourceID, inherit: nil,
                tenantScope: ["tenant-a"])),
            (204, ""), // unassign (old resource)
            (204, ""), // assign (new resource)
        ])
        let manifest = Manifest(entities: [
            ManifestEntity(kind: .resource, key: "old", name: "old", resourceType: "folder"),
            ManifestEntity(kind: .resource, key: "new", name: "new", resourceType: "folder"),
            ManifestEntity(kind: .role, key: "editor", name: "editor"),
            ManifestEntity(
                kind: .group, key: "editors", name: "editors",
                roleBindings: [RoleBindingSpec(role: "editor", resource: "new")]),
        ])
        let report = try await client.manifest.apply(manifest)
        XCTAssertTrue(report.isComplete, report.describe.joined(separator: "\n"))
        XCTAssertEqual(report.appliedBindings.first?.change.action, .rebind)

        // The two requests, in ORDER: DELETE (unassign the OLD resource) then POST (assign the NEW one).
        let last2 = transport.requests.suffix(2)
        XCTAssertEqual(last2.map(\.method), ["DELETE", "POST"])
        XCTAssertTrue(last2.first!.path.contains(oldResourceID) || (last2.first!.query.contains(oldResourceID)))
        let assignBody = try XCTUnwrap(last2.last?.jsonBody)
        XCTAssertEqual(assignBody["resource_id"] as? String, newResourceID)
        XCTAssertEqual(assignBody["tenant_scope"] as? [String], ["tenant-a"])
    }

    /// When the re-assign FAILS, the previous binding is assigned again and BOTH
    /// outcomes are reported — the admin console's T22.11b behaviour, and §27.6.1's own
    /// words: "a manifest must not be less careful than a form."
    func testAFailedRebindRestoresThePreviousBindingAndReportsBothOutcomes() async throws {
        let oldResourceID = "r-old"
        let newResourceID = "r-new"
        let roleID = "role1"
        let groupID = "group1"

        let (client, transport) = try await ManagementFixture.signedIn([
            (200, """
                {"items": [\(Self.resourceObject(id: oldResourceID, name: "old", metadata: "{}")), \
                \(Self.resourceObject(id: newResourceID, name: "new", metadata: "{}"))], "total": 2}
                """),
            (200, Self.rolePage(id: roleID, name: "editor")),
            (200, Self.groupPage(id: groupID, name: "editors")),
            (200, Self.roleAssignment(groupID: groupID, groupName: "editors", resourceID: oldResourceID, inherit: nil)),
            (204, ""),  // unassign (old) succeeds
            (409, #"{"error":"conflict","message":"already assigned"}"#), // assign (new) FAILS
            (204, ""),  // restore: assign (old) again succeeds
        ])
        let manifest = Manifest(entities: [
            ManifestEntity(kind: .resource, key: "old", name: "old", resourceType: "folder"),
            ManifestEntity(kind: .resource, key: "new", name: "new", resourceType: "folder"),
            ManifestEntity(kind: .role, key: "editor", name: "editor"),
            ManifestEntity(
                kind: .group, key: "editors", name: "editors",
                roleBindings: [RoleBindingSpec(role: "editor", resource: "new")]),
        ])
        let report = try await client.manifest.apply(manifest)
        XCTAssertFalse(report.isComplete)
        XCTAssertNotNil(report.failedBinding)
        XCTAssertEqual(report.failedBinding?.restored, true)
        // Exactly 3 write requests after the 4 reads: unassign, failed assign, restore assign.
        XCTAssertEqual(transport.count, 7)
    }

    // MARK: - One role bound twice / a global role with `inherit: false`

    /// A manifest binding one role to one subject twice is rejected with ZERO wire calls
    /// — `Manifest.validate()` runs before the first read.
    func testOneRoleBoundTwiceIsRejectedWithZeroWireCalls() async throws {
        let (client, transport) = try await ManagementFixture.signedIn([])
        let manifest = Manifest(entities: [
            ManifestEntity(kind: .role, key: "editor", name: "editor"),
            ManifestEntity(kind: .resource, key: "root", name: "documents", resourceType: "folder"),
            ManifestEntity(
                kind: .group, key: "editors", name: "editors",
                roleBindings: [
                    RoleBindingSpec(role: "editor"),
                    RoleBindingSpec(role: "editor", resource: "root"),
                ]),
        ])
        do {
            _ = try await client.manifest.plan(manifest)
            XCTFail("expected a ManifestError")
        } catch is ManifestError {
            // ok
        }
        XCTAssertEqual(transport.count, 0)
    }

    /// A global role bound with `inherit: false` is refused (§27.13 S-10 rule 2: the
    /// server would answer 400 — "a global role ignores resource scope" — and §27.6.1
    /// says an SDK MAY check it client-side; this one does), with ZERO wire calls.
    func testAGlobalRoleWithInheritFalseIsRejectedWithZeroWireCalls() async throws {
        let (client, transport) = try await ManagementFixture.signedIn([])
        let manifest = Manifest(entities: [
            ManifestEntity(kind: .role, key: "admin", name: "admin", isGlobal: true),
            ManifestEntity(kind: .resource, key: "root", name: "documents", resourceType: "folder"),
            ManifestEntity(
                kind: .group, key: "admins", name: "admins",
                roleBindings: [RoleBindingSpec(role: "admin", resource: "root", inherit: false)]),
        ])
        do {
            _ = try await client.manifest.plan(manifest)
            XCTFail("expected a ManifestError")
        } catch is ManifestError {
            // ok
        }
        XCTAssertEqual(transport.count, 0)
    }

    // MARK: - `service_accounts`

    /// A `Create` outcome carries `client_secret` as `Sensitive<T>`. A second `apply` is
    /// `NoChange` and issues NO `rotate-secret` request (§27.5 rule 5: `apply` never
    /// rotates to reconcile).
    func testServiceAccountCreateReturnsTheSecretAndASecondApplyNeverRotates() async throws {
        let saID = "sa-1"
        let (client, transport) = try await ManagementFixture.signedIn([
            (200, #"{"items": [], "total": 0}"#),
            (201, """
                {"client_id": "cid-1", "client_secret": "s3cr3t-once", "created_at": "2026-08-26T00:00:00Z", \
                "description": "", "id": "\(saID)", "name": "device-fleet", "status": "Active", \
                "tenant_id": "\(Self.uuid)", "updated_at": "2026-08-26T00:00:00Z"}
                """),
        ])
        let manifest = Manifest(entities: [
            ManifestEntity(kind: .serviceAccount, key: "fleet", name: "device-fleet"),
        ])
        let report = try await client.manifest.apply(manifest)
        XCTAssertTrue(report.isComplete, report.describe.joined(separator: "\n"))
        let secret = try XCTUnwrap(report.applied.first?.serviceAccountSecret)
        XCTAssertEqual(secret.expose(), "s3cr3t-once")

        // A second apply, against the server state the create just produced, is NoChange
        // and issues no `rotate-secret` request — only the ONE read.
        transport.script([
            (200, """
                {"items": [{"client_id": "cid-1", "created_at": "2026-08-26T00:00:00Z", \
                "description": "", "id": "\(saID)", "name": "device-fleet", "status": "Active", \
                "tenant_id": "\(Self.uuid)", "updated_at": "2026-08-26T00:00:00Z"}], "total": 1}
                """),
        ])
        let secondReport = try await client.manifest.apply(manifest)
        XCTAssertTrue(secondReport.isComplete)
        XCTAssertTrue(secondReport.applied.isEmpty, "a converged manifest applies nothing")
        XCTAssertNil(transport.requests.last(where: { $0.path.contains("rotate") }))
    }

    /// Two existing service accounts matching a stated name make `plan` fail BEFORE any
    /// write — picking one would reconcile an arbitrary account.
    func testTwoExistingServiceAccountsWithTheStatedNameFailsPlanBeforeAnyWrite() async throws {
        let (client, transport) = try await ManagementFixture.signedIn([
            (200, """
                {"items": [\
                {"client_id": "cid-1", "created_at": "2026-08-26T00:00:00Z", "description": "", \
                "id": "sa-1", "name": "device-fleet", "status": "Active", "tenant_id": "\(Self.uuid)", \
                "updated_at": "2026-08-26T00:00:00Z"}, \
                {"client_id": "cid-2", "created_at": "2026-08-26T00:00:00Z", "description": "", \
                "id": "sa-2", "name": "device-fleet", "status": "Active", "tenant_id": "\(Self.uuid)", \
                "updated_at": "2026-08-26T00:00:00Z"}\
                ], "total": 2}
                """),
        ])
        let manifest = Manifest(entities: [
            ManifestEntity(kind: .serviceAccount, key: "fleet", name: "device-fleet"),
        ])
        do {
            _ = try await client.manifest.plan(manifest)
            XCTFail("expected a ManifestError")
        } catch is ManifestError {
            // ok
        }
        // The read already happened (plan sends only reads); no write was ever sent.
        XCTAssertEqual(transport.count, 1)
    }
}
