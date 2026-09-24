import XCTest
@testable import AxiamSDK

/// §13 row 17's two Swift defects (CONTRACT.md §27.10's "PHP, Swift, C and C++" table),
/// fixed in this port:
///
/// - **defect a**: a resource's `parent_id` was never sent on `Create`, although the
///   model always carried the field — so a NESTED manifest was created FLAT.
/// - **defect b**: an unstated `resource_type` was silently defaulted to `"folder"` — a
///   default the contract never stated.
///
/// Each gets its own idempotence test over a NESTED manifest, asserting on the wire
/// exactly what §13 row 17 names: the create body carries the created parent's
/// `parent_id`; the `resource_type` sent is the stated one, never a silent `"folder"`;
/// and `apply` followed by `plan` is empty.
final class ManifestNestedResourceTests: XCTestCase {

    private static let emptyResourcePage = #"{"items": [], "total": 0}"#

    private static func resourceObject(
        id: String, name: String, parentID: String?, resourceType: String
    ) -> String {
        let parent = parentID.map { "\"\($0)\"" } ?? "null"
        return """
            {"created_at": "2026-08-26T00:00:00Z", "id": "\(id)", "metadata": {}, \
            "name": "\(name)", "parent_id": \(parent), "resource_type": "\(resourceType)", \
            "tenant_id": "\(ManagementFixture.tenantID)", "updated_at": "2026-08-26T00:00:00Z"}
            """
    }

    private static let rootID = "44444444-4444-4444-8444-444444444444"
    private static let childID = "55555555-5555-4555-8555-555555555555"

    /// A NESTED manifest: one root resource, one child naming it as `dependsOn` — a
    /// stated `resource_type` on each, deliberately not `"folder"` on either, so this
    /// test cannot pass by accident of Swift's own DSL default matching the wire value.
    private func nestedManifest() -> Manifest {
        Manifest {
            Declare.resource("root", name: "documents", type: "collection") {
                Declare.resource("child", name: "drafts", type: "leaf")
            }
        }
    }

    /// **Defect a, the fix.** The child's `Create` body carries `parent_id` naming the
    /// PARENT's server id — the one `perform` just received back from creating it, not
    /// a manifest-local key and not omitted.
    ///
    /// Mutated once: dropping the `parentID:` argument from the child's
    /// `CreateResourceRequest` (reverting to the pre-fix flat-tree body) turns this red,
    /// confirmed, then restored.
    func testCreateBodyCarriesTheCreatedParentsParentID() async throws {
        let (client, transport) = try await ManagementFixture.signedIn([
            (200, Self.emptyResourcePage), // plan's resources.list (inside apply)
            (201, Self.resourceObject(id: Self.rootID, name: "documents", parentID: nil, resourceType: "collection")),
            (201, Self.resourceObject(id: Self.childID, name: "drafts", parentID: Self.rootID, resourceType: "leaf")),
        ])

        let report = try await client.manifest.apply(nestedManifest())
        XCTAssertTrue(report.isComplete, report.describe.joined(separator: "\n"))
        XCTAssertEqual(transport.count, 3)

        let childCreate = transport.requests[2]
        XCTAssertEqual(childCreate.method, "POST")
        let body = try XCTUnwrap(childCreate.jsonBody)
        XCTAssertEqual(body["parent_id"] as? String, Self.rootID)
        XCTAssertEqual(body["name"] as? String, "drafts")
    }

    /// **Defect a's I4 twin.** The ROOT — which has no parent — sends NO `parent_id` key
    /// at all, not `null`. `CreateResourceRequest.parentID` is `String?` and encoded with
    /// `encodeIfPresent`, so a `nil` never reaches the wire as an explicit key.
    func testRootResourceCreateBodySendsNoParentIDKey() async throws {
        let (client, transport) = try await ManagementFixture.signedIn([
            (200, Self.emptyResourcePage),
            (201, Self.resourceObject(id: Self.rootID, name: "documents", parentID: nil, resourceType: "collection")),
            (201, Self.resourceObject(id: Self.childID, name: "drafts", parentID: Self.rootID, resourceType: "leaf")),
        ])

        _ = try await client.manifest.apply(nestedManifest())
        let rootCreate = transport.requests[1]
        let body = try XCTUnwrap(rootCreate.jsonBody)
        XCTAssertNil(body["parent_id"], "a root resource's Create body must carry no parent_id key at all")
    }

    /// **Defect b, the fix.** The `resource_type` sent on the wire is the STATED one
    /// (`"collection"` / `"leaf"`) — never `"folder"`, even though every entity in this
    /// manifest happens to use AXIAM's own conventional default elsewhere. A silent
    /// `"folder"` substitution would pass an idempotence test that only checked
    /// "converges to something"; this asserts the exact string sent.
    ///
    /// Mutated once: reverting `perform`'s `resourceType: entity.resourceType` to
    /// `entity.resourceType.isEmpty ? "folder" : entity.resourceType` does not turn this
    /// test red BY ITSELF (both entities here state a non-empty type) — see
    /// `testEntityWithNoStatedResourceTypeIsRejected` for the mutation this one catches
    /// on its own: it is the one that would still pass with the silent default restored,
    /// which is exactly why both tests exist.
    func testResourceTypeSentIsTheStatedOneNeverFolder() async throws {
        let (client, transport) = try await ManagementFixture.signedIn([
            (200, Self.emptyResourcePage),
            (201, Self.resourceObject(id: Self.rootID, name: "documents", parentID: nil, resourceType: "collection")),
            (201, Self.resourceObject(id: Self.childID, name: "drafts", parentID: Self.rootID, resourceType: "leaf")),
        ])

        _ = try await client.manifest.apply(nestedManifest())

        let rootBody = try XCTUnwrap(transport.requests[1].jsonBody)
        XCTAssertEqual(rootBody["resource_type"] as? String, "collection")
        let childBody = try XCTUnwrap(transport.requests[2].jsonBody)
        XCTAssertEqual(childBody["resource_type"] as? String, "leaf")
    }

    /// The defect's other half: an entity that states NO `resourceType` at all (built by
    /// hand, bypassing `Declare.resource`'s own visible default) is refused rather than
    /// silently sent as `"folder"`.
    ///
    /// Mutated once: restoring `entity.resourceType.isEmpty ? "folder" : entity.resourceType`
    /// in `perform` turns this red (the create SUCCEEDS with `"folder"` on the wire
    /// instead of throwing) — confirmed, then reverted.
    func testEntityWithNoStatedResourceTypeIsRejected() async throws {
        let manifest = Manifest(entities: [
            ManifestEntity(kind: .resource, key: "root", name: "documents"),
        ])
        let (client, transport) = try await ManagementFixture.signedIn([
            (200, Self.emptyResourcePage),
        ])

        // `apply` never THROWS per-action failures (§27.7: no rollback, no exception —
        // the report is the recovery tool); it reports the action as failed.
        let report = try await client.manifest.apply(manifest)
        XCTAssertFalse(report.isComplete)
        XCTAssertTrue(report.failure.contains("resourceType"), report.failure)
        // The read already happened (plan sends only reads); no CREATE was ever sent —
        // the failure is caught before the wire, inside `perform`.
        XCTAssertEqual(transport.count, 1)
    }

    /// **The idempotence test §27.6 rule 6 calls "worth more than any other in this
    /// section," over the NESTED manifest both defects above touch.** `apply` followed
    /// by `plan` reports every action `unchanged` — which is only true once the parent
    /// tree the server now holds actually matches what this manifest describes: had the
    /// child been created FLAT (defect a) or with a substituted `resource_type` (defect
    /// b), the second `plan`'s read of the server's real tree would disagree with the
    /// manifest and report `update`s or a second, duplicate `create`, not `unchanged`.
    func testApplyThenPlanIsEmptyOverTheNestedManifest() async throws {
        let manifest = nestedManifest()
        let (client, transport) = try await ManagementFixture.signedIn([
            (200, Self.emptyResourcePage), // apply's own plan: nothing exists yet
            (201, Self.resourceObject(id: Self.rootID, name: "documents", parentID: nil, resourceType: "collection")),
            (201, Self.resourceObject(id: Self.childID, name: "drafts", parentID: Self.rootID, resourceType: "leaf")),
            // The SECOND plan reads back exactly the tree just created — nested, with the
            // stated types — which is what makes convergence possible at all.
            (200, """
                {"items": [\
                \(Self.resourceObject(id: Self.rootID, name: "documents", parentID: nil, resourceType: "collection")), \
                \(Self.resourceObject(id: Self.childID, name: "drafts", parentID: Self.rootID, resourceType: "leaf"))\
                ], "total": 2}
                """),
        ])

        let report = try await client.manifest.apply(manifest)
        XCTAssertTrue(report.isComplete, report.describe.joined(separator: "\n"))
        XCTAssertEqual(transport.count, 3)

        let second = try await client.manifest.plan(manifest)
        let summary = second.changes.map { $0.describe }.joined(separator: "\n")
        XCTAssertTrue(second.isConverged, summary)
        for change in second.changes {
            let action: ChangeAction = change.action
            XCTAssertEqual(action, ChangeAction.unchanged, change.describe)
        }
        XCTAssertEqual(transport.count, 4, "plan must issue exactly one more (GET) request")
    }
}
