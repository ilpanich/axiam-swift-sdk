import XCTest
@testable import AxiamSDK

/// CONTRACT.md §27.6/§27.7 — the declarative layer.
///
/// Everything here is about the properties that make a manifest safe to run more than once
/// against a live tenant: plan writes nothing, ordering is derived and stable, incoherence is
/// refused before the first request, apply stops at the first failure without rolling back,
/// and omission is never deletion.
final class ManagementManifestTests: XCTestCase {

    private static let uuid = ManagementFixture.tenantID

    private static let emptyPage = #"{"items": [], "total": 0}"#

    private static let permissionPage = """
        {"items": [{"action": "documents:read", "created_at": "2026-08-26T00:00:00Z", \
        "description": "Read documents", "id": "\(ManagementFixture.tenantID)", "tenant_id": "\(ManagementFixture.tenantID)", \
        "updated_at": "2026-08-26T00:00:00Z"}], "total": 1}
        """

    private static let permissionPageStale = """
        {"items": [{"action": "documents:read", "created_at": "2026-08-26T00:00:00Z", \
        "description": "stale", "id": "\(ManagementFixture.tenantID)", "tenant_id": "\(ManagementFixture.tenantID)", \
        "updated_at": "2026-08-26T00:00:00Z"}], "total": 1}
        """

    private static let permissionObject = """
        {"action": "documents:read", "created_at": "2026-08-26T00:00:00Z", \
        "description": "Read documents", "id": "\(ManagementFixture.tenantID)", "tenant_id": "\(ManagementFixture.tenantID)", \
        "updated_at": "2026-08-26T00:00:00Z"}
        """

    private static let resourcePage = """
        {"items": [{"created_at": "2026-08-26T00:00:00Z", "id": "\(ManagementFixture.tenantID)", "metadata": {}, \
        "name": "documents", "resource_type": "folder", "tenant_id": "\(ManagementFixture.tenantID)", \
        "updated_at": "2026-08-26T00:00:00Z"}], "total": 1}
        """

    private static let resourceObject = """
        {"created_at": "2026-08-26T00:00:00Z", "id": "\(ManagementFixture.tenantID)", "metadata": {}, \
        "name": "documents", "resource_type": "folder", "tenant_id": "\(ManagementFixture.tenantID)", \
        "updated_at": "2026-08-26T00:00:00Z"}
        """

    private static let rolePage = """
        {"items": [{"created_at": "2026-08-26T00:00:00Z", "description": "Edits documents", \
        "id": "\(ManagementFixture.tenantID)", "is_global": false, "name": "editor", "tenant_id": "\(ManagementFixture.tenantID)", \
        "updated_at": "2026-08-26T00:00:00Z"}], "total": 1}
        """

    private static let roleObject = """
        {"created_at": "2026-08-26T00:00:00Z", "description": "Edits documents", \
        "id": "\(ManagementFixture.tenantID)", "is_global": false, "name": "editor", "tenant_id": "\(ManagementFixture.tenantID)", \
        "updated_at": "2026-08-26T00:00:00Z"}
        """

    private static let groupPage = """
        {"items": [{"created_at": "2026-08-26T00:00:00Z", "description": "The editors", \
        "id": "\(ManagementFixture.tenantID)", "metadata": {}, "name": "editors", "tenant_id": "\(ManagementFixture.tenantID)", \
        "updated_at": "2026-08-26T00:00:00Z"}], "total": 1}
        """

    private static let groupObject = """
        {"created_at": "2026-08-26T00:00:00Z", "description": "The editors", "id": "\(ManagementFixture.tenantID)", \
        "metadata": {}, "name": "editors", "tenant_id": "\(ManagementFixture.tenantID)", \
        "updated_at": "2026-08-26T00:00:00Z"}
        """

    /// One permission, the smallest manifest that can drift.
    private func onePermission() -> Manifest {
        Manifest {
            Declare.permission(
                "read", name: "documents:read", description: "Read documents",
                action: "documents:read")
        }
    }

    /// One of every kind, DECLARED in reverse apply order so ordering has to be derived.
    private func fourKinds() -> Manifest {
        Manifest {
            Declare.group("editors", description: "The editors", dependsOn: "editor")
            Declare.role("editor", description: "Edits documents")
            Declare.permission(
                "read", name: "documents:read", description: "Read documents",
                action: "documents:read")
            Declare.resource("root", name: "documents", type: "folder")
        }
    }

    // MARK: - plan writes nothing

    func testPlanIssuesOnlyReads() async throws {
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 200, body: Self.emptyPage),
        ])

        let plan = try await client.manifest.plan(onePermission())

        XCTAssertEqual(transport.count, 1)
        XCTAssertEqual(transport.last?.method, "GET")
        XCTAssertEqual(plan.pending.count, 1)
        XCTAssertEqual(plan.changes.first?.action, .create)
    }

    func testAConvergedTenantPlansAndAppliesNothing() async throws {
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 200, body: Self.permissionPage),
            (status: 200, body: Self.permissionPage),
        ])

        let plan = try await client.manifest.plan(onePermission())
        XCTAssertTrue(plan.isConverged)
        XCTAssertEqual(plan.changes.first?.id, Self.uuid)

        let report = try await client.manifest.apply(onePermission())
        XCTAssertTrue(report.isComplete)
        XCTAssertTrue(report.applied.isEmpty)
        // Two reads, one per call. No writes.
        XCTAssertEqual(transport.count, 2)
        XCTAssertTrue(transport.requests.allSatisfy { $0.method == "GET" })
    }

    func testApplyThenPlanYieldsAnAllUnchangedPlan() async throws {
        // §27.6 rule 6, the property that makes a manifest re-runnable at all.
        let (client, _) = try await ManagementFixture.signedIn([
            (status: 200, body: Self.emptyPage),      // apply: re-plan, nothing there
            (status: 201, body: Self.permissionObject),  // apply: create
            (status: 200, body: Self.permissionPage),  // plan: now it exists and matches
        ])

        let first = try await client.manifest.apply(onePermission())
        XCTAssertTrue(first.isComplete)
        XCTAssertEqual(first.applied.count, 1)

        let second = try await client.manifest.plan(onePermission())
        XCTAssertTrue(second.isConverged)
        XCTAssertTrue(second.changes.allSatisfy { $0.action == .unchanged })
    }

    func testDriftIsUpdatedInPlaceWithASparseBody() async throws {
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 200, body: Self.permissionPageStale),
            (status: 200, body: Self.permissionObject),
        ])

        let report = try await client.manifest.apply(onePermission())

        XCTAssertTrue(report.isComplete)
        XCTAssertEqual(report.applied.count, 1)
        XCTAssertEqual(report.applied.first?.action, .update)
        // In place against the existing id, never a delete-then-create.
        XCTAssertNotEqual(transport.last?.method, "POST")
        XCTAssertEqual(transport.last?.path, "/api/v1/permissions/\(Self.uuid)")
        // Sparse (§27.4 rule 5): only the field that drifted.
        let body = try XCTUnwrap(transport.last?.jsonBody)
        XCTAssertEqual(Set(body.keys), ["description"])
    }

    // MARK: - ordering is derived, and stable

    func testOrderIsDerivedFromKindNotFromDeclarationOrder() throws {
        let ordered = try ManifestApi.ordered(fourKinds())

        XCTAssertEqual(ordered.map(\.kind), [.resource, .permission, .role, .group])
        XCTAssertEqual(ordered.map(\.key), ["root", "read", "editor", "editors"])
    }

    func testAParentResourceIsOrderedBeforeItsChild() throws {
        let manifest = Manifest {
            Declare.resource("root", name: "documents", type: "folder") {
                Declare.resource("drafts", name: "drafts", type: "folder")
            }
        }

        let ordered = try ManifestApi.ordered(manifest)

        XCTAssertEqual(ordered.map(\.key), ["root", "drafts"])
        // The nesting DSL derives the parent link, which is the one thing nesting is for.
        XCTAssertEqual(ordered.last?.dependsOn, "root")
    }

    func testOrderingIsStableAcrossRuns() throws {
        // Two entities of the same kind with no dependency between them have no natural
        // order. Without a deterministic tie-break they come out however the caller declared
        // them, which makes every plan diff unreadable.
        let forwards = Manifest {
            Declare.permission("alpha", name: "a", action: "a")
            Declare.permission("beta", name: "b", action: "b")
            Declare.permission("gamma", name: "c", action: "c")
        }
        let backwards = Manifest {
            Declare.permission("gamma", name: "c", action: "c")
            Declare.permission("beta", name: "b", action: "b")
            Declare.permission("alpha", name: "a", action: "a")
        }

        XCTAssertEqual(
            try ManifestApi.ordered(forwards).map(\.key),
            try ManifestApi.ordered(backwards).map(\.key))
        XCTAssertEqual(try ManifestApi.ordered(forwards).map(\.key), ["alpha", "beta", "gamma"])
    }

    func testTwoPlansAgainstUnchangedStateAreEqual() async throws {
        let (client, _) = try await ManagementFixture.signedIn([
            (status: 200, body: Self.permissionPage),
            (status: 200, body: Self.permissionPage),
        ])

        let first = try await client.manifest.plan(onePermission())
        let second = try await client.manifest.plan(onePermission())

        XCTAssertEqual(first, second)
    }

    // MARK: - incoherence is refused before the first request

    func testADanglingReferenceIsRefusedBeforeAnyRequest() async throws {
        let (client, transport) = try await ManagementFixture.signedIn()
        let manifest = Manifest {
            Declare.role("editor", dependsOn: "a-permission-nobody-declared")
        }

        do {
            _ = try await client.manifest.plan(manifest)
            XCTFail("a dangling reference must be refused")
        } catch let error as ManifestError {
            XCTAssertTrue(error.message.contains("a-permission-nobody-declared"), error.message)
        }
        XCTAssertEqual(transport.count, 0)
    }

    func testACycleIsRefusedBeforeAnyRequest() async throws {
        let (client, transport) = try await ManagementFixture.signedIn()
        let manifest = Manifest {
            Declare.resource("a", dependsOn: "b")
            Declare.resource("b", dependsOn: "a")
        }

        do {
            _ = try await client.manifest.plan(manifest)
            XCTFail("a cycle must be refused")
        } catch let error as ManifestError {
            XCTAssertTrue(error.message.contains("cycle"), error.message)
        }
        XCTAssertEqual(transport.count, 0)
    }

    func testADuplicateKeyIsRefused() {
        let manifest = Manifest {
            Declare.permission("read", name: "a", action: "a")
            Declare.permission("read", name: "b", action: "b")
        }

        XCTAssertThrowsError(try ManifestApi.validate(manifest)) { error in
            XCTAssertTrue("\(error)".contains("twice"), "\(error)")
        }
    }

    func testAnEntityWithoutAKeyIsRefused() {
        let manifest = Manifest(entities: [
            ManifestEntity(kind: .role, key: "", name: "editor"),
        ])

        XCTAssertThrowsError(try ManifestApi.validate(manifest))
    }

    // MARK: - §27.7 apply stops at the first failure and does not roll back

    func testApplyStopsAtTheFirstFailureAndDoesNotRollBack() async throws {
        let manifest = Manifest {
            Declare.permission("a", name: "a", description: "A", action: "a")
            Declare.permission("b", name: "b", description: "B", action: "b")
            Declare.permission("c", name: "c", description: "C", action: "c")
        }
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 200, body: Self.emptyPage),          // re-plan: nothing exists
            (status: 201, body: Self.permissionObject),   // a: created
            // b fails. 403 rather than 5xx: a 5xx on a POST is not retried, but a 403 also
            // cannot be mistaken for a transport blip in the assertion below.
            (status: 403, body: #"{"message": "forbidden"}"#),
        ])

        let report = try await client.manifest.apply(manifest)

        XCTAssertFalse(report.isComplete)
        XCTAssertEqual(report.applied.count, 1)
        XCTAssertEqual(report.applied.first?.entity.key, "a")
        XCTAssertEqual(report.failed?.entity.key, "b")
        XCTAssertEqual(report.remaining.map(\.entity.key), ["c"])

        // No rollback: `a` is not deleted. One read plus two writes, and nothing else — an
        // automatic rollback would fire a second wave of writes at exactly the moment the
        // server is saying something is wrong.
        XCTAssertEqual(transport.count, 3)
        XCTAssertFalse(transport.requests.contains { $0.method == "DELETE" })
    }

    func testTheReportReadsAsARecoveryInstruction() async throws {
        let manifest = Manifest {
            Declare.permission("a", name: "a", description: "A", action: "a")
            Declare.permission("b", name: "b", description: "B", action: "b")
        }
        let (client, _) = try await ManagementFixture.signedIn([
            (status: 200, body: Self.emptyPage),
            (status: 201, body: Self.permissionObject),
            (status: 403, body: #"{"message": "forbidden"}"#),
        ])

        let report = try await client.manifest.apply(manifest)
        let lines = report.describe

        XCTAssertEqual(lines.count, 2)
        XCTAssertEqual(lines[0], "applied  create permission:a")
        XCTAssertTrue(lines[1].hasPrefix("FAILED   create permission:b: "), lines[1])
    }

    // MARK: - omission is never deletion

    func testOmissionIsNeverDeletion() async throws {
        // The tenant holds a permission the manifest does not mention. Pruning is off by
        // default — and `ChangeAction` has no `delete` case at all, so it is structural
        // rather than a default somebody could flip.
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 200, body: Self.permissionPage),
        ])
        let manifest = Manifest {
            Declare.permission(
                "read", name: "documents:read", description: "Read documents",
                action: "documents:read")
        }

        let plan = try await client.manifest.plan(manifest)

        XCTAssertEqual(plan.changes.count, 1)
        XCTAssertTrue(plan.isConverged)
        XCTAssertFalse(ChangeAction.allCases.contains { $0.rawValue == "delete" })
        XCTAssertFalse(transport.requests.contains { $0.method == "DELETE" })
    }

    // MARK: - every kind, read and written

    func testAManifestSpanningEveryKindReadsEachKindExactlyOnce() async throws {
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 200, body: Self.emptyPage), (status: 200, body: Self.emptyPage),
            (status: 200, body: Self.emptyPage), (status: 200, body: Self.emptyPage),
        ])

        let plan = try await client.manifest.plan(fourKinds())

        XCTAssertEqual(plan.changes.count, 4)
        XCTAssertEqual(plan.pending.count, 4)
        // One read per KIND, not one per entity: ten roles must still be one list call.
        XCTAssertEqual(transport.count, 4)
        XCTAssertTrue(transport.requests.allSatisfy { $0.method == "GET" })
    }

    func testAManifestSpanningEveryKindCreatesEachInDerivedOrder() async throws {
        let (client, _) = try await ManagementFixture.signedIn([
            (status: 200, body: Self.emptyPage), (status: 200, body: Self.emptyPage),
            (status: 200, body: Self.emptyPage), (status: 200, body: Self.emptyPage),
            (status: 201, body: Self.resourceObject),
            (status: 201, body: Self.permissionObject),
            (status: 201, body: Self.roleObject),
            (status: 201, body: Self.groupObject),
        ])

        let report = try await client.manifest.apply(fourKinds())

        XCTAssertTrue(report.isComplete, report.failure)
        XCTAssertEqual(report.applied.map(\.entity.kind), [.resource, .permission, .role, .group])
    }

    func testAManifestSpanningEveryKindConvergesAgainstAMatchingTenant() async throws {
        let (client, _) = try await ManagementFixture.signedIn([
            (status: 200, body: Self.resourcePage),
            (status: 200, body: Self.permissionPage),
            (status: 200, body: Self.rolePage),
            (status: 200, body: Self.groupPage),
        ])

        let plan = try await client.manifest.plan(fourKinds())

        // A resource carries a description in the manifest and none on the server — the
        // model has no such property. Comparing the two would mark it drifted forever, and
        // §27.6 rule 6 says apply-then-plan is all-unchanged.
        XCTAssertTrue(plan.isConverged, "\(plan.changes.map(\.describe))")
        XCTAssertTrue(plan.changes.allSatisfy { $0.id != nil })
    }

    func testADescribedResourceStillConverges() async throws {
        let (client, _) = try await ManagementFixture.signedIn([
            (status: 200, body: Self.resourcePage),
        ])
        let manifest = Manifest {
            Declare.resource(
                "root", name: "documents", description: "The document tree", type: "folder")
        }

        let plan = try await client.manifest.plan(manifest)

        XCTAssertTrue(plan.isConverged, "\(plan.changes.map(\.describe))")
    }

    // MARK: - §27.7 the declarative form lowers to the same value

    func testTheDslLowersToTheSameValueAsPlainConstruction() {
        let declarative = Manifest {
            Declare.role("editor", description: "Edits documents")
        }
        let plain = Manifest(entities: [
            ManifestEntity(kind: .role, key: "editor", name: "editor",
                           description: "Edits documents"),
        ])

        // §27.7: "whatever the surface syntax, it MUST lower to the same ManagementManifest
        // value and go through the same plan/apply."
        XCTAssertEqual(declarative, plain)
    }

    func testTheDslSupportsConditionalsAndLoops() {
        let includeDrafts = true
        let manifest = Manifest {
            Declare.resource("root", name: "documents", type: "folder")
            if includeDrafts {
                Declare.resource("drafts", name: "drafts", type: "folder", dependsOn: "root")
            }
            for name in ["read", "write"] {
                Declare.permission(name, name: "documents:\(name)", action: "documents:\(name)")
            }
        }

        XCTAssertEqual(
            manifest.entities.map(\.key), ["root", "drafts", "read", "write"])
    }

    func testEveryKindAndActionRendersInDescribe() {
        // A report a caller pastes into a ticket is only useful if it says which object it is
        // about, so no combination may render as a placeholder.
        for kind in ManifestKind.allCases {
            for action in ChangeAction.allCases {
                let change = PlannedChange(
                    entity: ManifestEntity(kind: kind, key: "thing", name: "thing"),
                    action: action)
                XCTAssertFalse(change.describe.contains("?"), change.describe)
                XCTAssertTrue(change.describe.contains("thing"), change.describe)
            }
        }
    }
    // MARK: - drift on every kind, so every update branch is exercised

    /// A resource, role and group all present but with a drifted description.
    ///
    /// The resource is the interesting one: it has NO description on the server, so it must
    /// come back `unchanged` while the other two update. A per-kind switch that compared
    /// them all the same way would produce a manifest that never converges.
    func testDriftIsRepairedPerKindAndTheResourceIsLeftAlone() async throws {
        let manifest = Manifest {
            Declare.resource("root", name: "documents",
                             description: "described only in the manifest", type: "folder")
            Declare.role("editor", description: "Edits documents")
            Declare.group("editors", description: "The editors")
        }
        let staleRolePage = """
            {"items": [{"created_at": "2026-08-26T00:00:00Z", "description": "stale", \
            "id": "\(ManagementFixture.tenantID)", "is_global": false, "name": "editor", \
            "tenant_id": "\(ManagementFixture.tenantID)", \
            "updated_at": "2026-08-26T00:00:00Z"}], "total": 1}
            """
        let staleGroupPage = """
            {"items": [{"created_at": "2026-08-26T00:00:00Z", "description": "stale", \
            "id": "\(ManagementFixture.tenantID)", "metadata": {}, "name": "editors", \
            "tenant_id": "\(ManagementFixture.tenantID)", \
            "updated_at": "2026-08-26T00:00:00Z"}], "total": 1}
            """
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 200, body: Self.resourcePage),
            (status: 200, body: staleRolePage),
            (status: 200, body: staleGroupPage),
            (status: 200, body: Self.roleObject),
            (status: 200, body: Self.groupObject),
        ])

        let report = try await client.manifest.apply(manifest)

        XCTAssertTrue(report.isComplete, report.failure)
        XCTAssertEqual(report.applied.map(\.entity.kind), [.role, .group])
        XCTAssertTrue(report.applied.allSatisfy { $0.action == .update })

        // Two updates, both sparse and both in place.
        let writes = transport.requests.filter { $0.method != "GET" }
        XCTAssertEqual(writes.count, 2)
        for write in writes {
            XCTAssertEqual(Set(try XCTUnwrap(write.jsonBody).keys), ["description"])
            XCTAssertTrue(
                write.path.hasSuffix("/\(ManagementFixture.tenantID)"), write.path)
        }
    }

    /// A resource the tenant does not have is created with its declared type.
    func testAResourceIsCreatedWithItsDeclaredType() async throws {
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 200, body: Self.emptyPage),
            (status: 201, body: Self.resourceObject),
        ])
        let manifest = Manifest {
            Declare.resource("root", name: "documents", type: "workspace")
        }

        let report = try await client.manifest.apply(manifest)

        XCTAssertTrue(report.isComplete, report.failure)
        let body = try XCTUnwrap(transport.last?.jsonBody)
        XCTAssertEqual(body["name"] as? String, "documents")
        XCTAssertEqual(body["resource_type"] as? String, "workspace")
    }

    /// A resource declared with no type gets the default rather than an empty string.
    func testAResourceWithNoDeclaredTypeGetsTheDefault() async throws {
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 200, body: Self.emptyPage),
            (status: 201, body: Self.resourceObject),
        ])
        let manifest = Manifest(entities: [
            // Built by hand rather than through `Declare.resource`, whose own default would
            // hide the one this test is about.
            ManifestEntity(kind: .resource, key: "root", name: "documents"),
        ])

        _ = try await client.manifest.apply(manifest)

        // An empty `resource_type` is a 422 from the server, and a manifest that omitted the
        // field is a manifest that did not care — "folder" is what it means.
        XCTAssertEqual(
            try XCTUnwrap(transport.last?.jsonBody)["resource_type"] as? String, "folder")
    }

    /// A role's `isGlobal` reaches the create body.
    func testARoleCarriesItsGlobalFlag() async throws {
        let (client, transport) = try await ManagementFixture.signedIn([
            (status: 200, body: Self.emptyPage),
            (status: 201, body: Self.roleObject),
        ])
        let manifest = Manifest {
            Declare.role("admin", description: "Everything", isGlobal: true)
        }

        _ = try await client.manifest.apply(manifest)

        let body = try XCTUnwrap(transport.last?.jsonBody)
        XCTAssertEqual(body["is_global"] as? Bool, true)
        XCTAssertEqual(Set(body.keys), ["description", "is_global", "name"])
    }

    /// A permission is matched by its ACTION, everything else by name.
    func testAPermissionIsMatchedByActionNotByName() async throws {
        let (client, _) = try await ManagementFixture.signedIn([
            (status: 200, body: Self.permissionPage),
        ])
        // The manifest's `name` deliberately differs from the server object's; only the
        // action matches. A matcher keyed on `name` would plan a create and then collide.
        let manifest = Manifest {
            Declare.permission(
                "read", name: "a name the server does not use",
                description: "Read documents", action: "documents:read")
        }

        let plan = try await client.manifest.plan(manifest)

        XCTAssertTrue(plan.isConverged, "\(plan.changes.map(\.describe))")
    }

}
