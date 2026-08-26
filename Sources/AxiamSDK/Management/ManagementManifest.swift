import Foundation

// CONTRACT.md §27.6/§27.7 — describe a tenant, plan, apply.
//
// The imperative surface is fine for one change. It is a poor way to describe a TENANT,
// because re-running it either fails on the second run or makes the caller hand-write
// "does this exist already?" for every object. A manifest is re-runnable by construction:
// apply it twice and the second run sends nothing.
//
// Four properties constrain everything here, and are worth knowing before running one
// against production:
//
//   * `plan` writes nothing. It reads the tenant and reports the difference — safe in CI,
//     safe on a schedule, safe against a live tenant.
//   * `apply` stops at the first failure and does NOT roll back (§27.7). The report says
//     what landed, what failed and what was never attempted; a partial apply is a state an
//     operator resumes from, and an automatic rollback would fire a second wave of writes
//     at exactly the moment the server is saying something is wrong.
//   * Ordering is derived, not declared — kind, then dependency, then key. The tie-break on
//     key is what makes a plan stable across runs, and therefore readable as a diff.
//   * Omission is never deletion. `ChangeAction` has no delete case at all, so an
//     incomplete manifest cannot become a destructive one.
//
// Entities are addressed by a manifest-local `key`, never by a server-assigned UUID — that
// is what lets the same manifest mean the same thing against a fresh tenant and an existing
// one, since a UUID does not exist until the first apply.

/// The entity kinds a manifest can declare.
///
/// The order of these cases IS the order an apply runs them in — the dependency order §27.6
/// requires be derived rather than written down by the caller. A role cannot be granted a
/// permission that does not exist yet, and a group cannot be assigned a role that does not.
public enum ManifestKind: Int, Sendable, Comparable, CaseIterable {
    /// Hierarchical resource; parents before children.
    case resource = 0
    /// A permission (an action). Depends on nothing.
    case permission = 1
    /// A role. Depends on permissions.
    case role = 2
    /// A group. Depends on roles.
    case group = 3

    public static func < (lhs: ManifestKind, rhs: ManifestKind) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    /// A one-word rendering, for `PlannedChange.describe`.
    var label: String {
        switch self {
        case .resource: return "resource"
        case .permission: return "permission"
        case .role: return "role"
        case .group: return "group"
        }
    }

    /// Whether the SERVER stores a description for this kind.
    ///
    /// Three of the four do. A resource does not: `Resource` has no description property, so
    /// reading current state can only ever report an empty one — and comparing a manifest's
    /// resource description against that would mark the resource drifted, update it, and
    /// mark it drifted again on the next run. §27.6 rule 6 requires apply-then-plan to be
    /// all-`unchanged`, and a manifest that never converges is the exact failure it rules out.
    var hasDescription: Bool { self != .resource }
}

/// What a plan intends to do to one declared entity.
///
/// There is deliberately no `delete`. §27.6 is explicit that omission is never deletion: a
/// manifest describes what must exist, not everything that may exist, and a tenant almost
/// always holds objects no manifest mentions. Leaving the case out of the enum makes that
/// structural rather than a matter of discipline.
public enum ChangeAction: String, Sendable, CaseIterable {
    /// Already matches; nothing will be sent.
    case unchanged
    /// Does not exist; will be created.
    case create
    /// Exists but differs; updated in place with a sparse body (§27.4 rule 5).
    case update
}

/// One entity a manifest declares must exist.
public struct ManifestEntity: Sendable, Equatable {
    /// What sort of object this is.
    public var kind: ManifestKind
    /// Manifest-local identity, unique within its kind.
    public var key: String
    /// The name the server knows it by; also the match key.
    public var name: String
    /// Human-readable description.
    public var description: String
    /// For a resource: its `resource_type`.
    public var resourceType: String
    /// For a permission: the action it names.
    public var action: String
    /// For a role: whether it applies tenant-wide.
    public var isGlobal: Bool
    /// Key of the entity this one must be applied after, beyond what `kind` already orders —
    /// a parent resource, or a permission a role grants.
    ///
    /// A KEY, never a UUID: a manifest describes a tenant that may not exist yet.
    public var dependsOn: String?

    public init(
        kind: ManifestKind,
        key: String,
        name: String,
        description: String = "",
        resourceType: String = "",
        action: String = "",
        isGlobal: Bool = false,
        dependsOn: String? = nil
    ) {
        self.kind = kind
        self.key = key
        self.name = name
        self.description = description
        self.resourceType = resourceType
        self.action = action
        self.isGlobal = isGlobal
        self.dependsOn = dependsOn
    }

    /// The name this declaration is matched against on the server: a permission is known by
    /// its action, everything else by its name.
    var matchName: String { kind == .permission ? action : name }
}

/// A declarative description of the state a tenant must be in.
public struct Manifest: Sendable, Equatable {
    public let entities: [ManifestEntity]

    public init(entities: [ManifestEntity]) {
        self.entities = entities
    }
}

/// One entry in a plan: what would happen to one entity, and why.
public struct PlannedChange: Sendable, Equatable {
    /// The declaration this is for.
    public let entity: ManifestEntity
    /// What would be done.
    public let action: ChangeAction
    /// Server id, when the object already exists.
    public let id: String?

    public init(entity: ManifestEntity, action: ChangeAction, id: String? = nil) {
        self.entity = entity
        self.action = action
        self.id = id
    }

    /// A one-line rendering, e.g. `create permission:read`.
    public var describe: String {
        "\(action.rawValue) \(entity.kind.label):\(entity.key)"
    }
}

/// What `plan` produced: the ordered changes an apply would make.
///
/// Includes the `unchanged` entries too, so a reader sees what was considered and not only
/// what moved.
public struct ManagementPlan: Sendable, Equatable {
    public let changes: [PlannedChange]

    public init(changes: [PlannedChange]) {
        self.changes = changes
    }

    /// Only the changes that would actually send a request.
    public var pending: [PlannedChange] {
        changes.filter { $0.action != .unchanged }
    }

    /// True when the tenant already matches and an apply would send nothing.
    public var isConverged: Bool { pending.isEmpty }
}

/// What `apply` actually did — including, when it stopped early, what it had already done.
///
/// This is the recovery tool. Fix the cause and re-run: the changes that already landed plan
/// as `unchanged` next time, so a resumed apply picks up where this one stopped.
public struct ApplyReport: Sendable {
    /// Changes that succeeded, in order.
    public let applied: [PlannedChange]
    /// The change that failed, if any.
    public let failed: PlannedChange?
    /// Why it failed.
    public let failure: String
    /// Never attempted, because of the failure.
    public let remaining: [PlannedChange]

    public init(
        applied: [PlannedChange],
        failed: PlannedChange? = nil,
        failure: String = "",
        remaining: [PlannedChange] = []
    ) {
        self.applied = applied
        self.failed = failed
        self.failure = failure
        self.remaining = remaining
    }

    /// True when every planned change landed.
    public var isComplete: Bool { failed == nil }

    /// A human-readable account of the run, for a log line or a CI summary.
    public var describe: [String] {
        var lines = applied.map { "applied  \($0.describe)" }
        if let failed {
            lines.append("FAILED   \(failed.describe): \(failure)")
            lines.append(contentsOf: remaining.map { "skipped  \($0.describe)" })
        }
        return lines
    }
}

/// Raised when a manifest is rejected BEFORE any request is sent.
///
/// Every use of this type is a refusal to START. A manifest with a dangling reference or a
/// dependency cycle cannot be applied coherently, and discovering that halfway through —
/// with no rollback (§27.7) — is strictly worse than refusing up front.
public struct ManifestError: Error, Sendable, Equatable, CustomStringConvertible {
    public let message: String

    public init(_ message: String) {
        self.message = message
    }

    public var description: String { "ManifestError: \(message)" }
}

// MARK: - §27.7's Swift declarative form

/// The result builder behind `Manifest { … }`.
@resultBuilder
public enum ManifestBuilder {
    public static func buildBlock(_ components: [ManifestEntity]...) -> [ManifestEntity] {
        components.flatMap { $0 }
    }

    public static func buildExpression(_ entity: ManifestEntity) -> [ManifestEntity] {
        [entity]
    }

    public static func buildExpression(_ entities: [ManifestEntity]) -> [ManifestEntity] {
        entities
    }

    public static func buildOptional(_ component: [ManifestEntity]?) -> [ManifestEntity] {
        component ?? []
    }

    public static func buildEither(first component: [ManifestEntity]) -> [ManifestEntity] {
        component
    }

    public static func buildEither(second component: [ManifestEntity]) -> [ManifestEntity] {
        component
    }

    public static func buildArray(_ components: [[ManifestEntity]]) -> [ManifestEntity] {
        components.flatMap { $0 }
    }
}

extension Manifest {
    /// Build a manifest with §27.7's result-builder DSL.
    ///
    /// ```swift
    /// let manifest = Manifest {
    ///     Declare.resource("root", name: "documents", type: "folder") {
    ///         Declare.resource("drafts", name: "drafts", type: "folder")
    ///     }
    ///     Declare.permission("read", name: "documents:read", action: "documents:read")
    ///     Declare.role("editor", description: "Edits documents", dependsOn: "read")
    ///     Declare.group("editors", description: "The editors", dependsOn: "editor")
    /// }
    /// ```
    ///
    /// The factories live under `Declare` rather than being bare `Role(…)` / `Resource(…)`
    /// functions, which is the one place this diverges from the shape §27.7's table
    /// sketches. `Role`, `Permission`, `Resource` and `Group` are all names of GENERATED
    /// model types in this module, and a free function sharing a name with a type is a
    /// resolution puzzle at every call site rather than a DSL. The namespace costs seven
    /// characters and the lowering is identical — which is what §27.7 actually requires:
    /// whatever the surface syntax, it lowers to the same `Manifest` value and goes through
    /// the same `plan`/`apply`.
    public init(@ManifestBuilder _ content: () -> [ManifestEntity]) {
        self.init(entities: content())
    }
}

/// The §27.7 entity factories.
///
/// Each returns a plain `ManifestEntity` (or, for a nested resource tree, an array of them),
/// so a manifest written with this DSL and one deserialized from configuration are the same
/// value.
public enum Declare {
    /// A hierarchical resource, optionally with child resources.
    ///
    /// Children get `dependsOn` set to this resource's key automatically, which is the one
    /// thing nesting is for here: a parent must be applied before its children, and writing
    /// that link by hand is exactly the bookkeeping a DSL should remove.
    public static func resource(
        _ key: String,
        name: String? = nil,
        description: String = "",
        type resourceType: String = "folder",
        dependsOn: String? = nil,
        @ManifestBuilder children: () -> [ManifestEntity] = { [] }
    ) -> [ManifestEntity] {
        let parent = ManifestEntity(
            kind: .resource, key: key, name: name ?? key, description: description,
            resourceType: resourceType, dependsOn: dependsOn)
        let nested = children().map { child -> ManifestEntity in
            guard child.kind == .resource, child.dependsOn == nil else { return child }
            var linked = child
            linked.dependsOn = key
            return linked
        }
        return [parent] + nested
    }

    /// A permission — an action on a resource.
    public static func permission(
        _ key: String,
        name: String? = nil,
        description: String = "",
        action: String? = nil,
        dependsOn: String? = nil
    ) -> ManifestEntity {
        ManifestEntity(
            kind: .permission, key: key, name: name ?? key, description: description,
            action: action ?? name ?? key, dependsOn: dependsOn)
    }

    /// A role — a collection of permissions.
    public static func role(
        _ key: String,
        name: String? = nil,
        description: String = "",
        isGlobal: Bool = false,
        dependsOn: String? = nil
    ) -> ManifestEntity {
        ManifestEntity(
            kind: .role, key: key, name: name ?? key, description: description,
            isGlobal: isGlobal, dependsOn: dependsOn)
    }

    /// A group — a named collection of users.
    public static func group(
        _ key: String,
        name: String? = nil,
        description: String = "",
        dependsOn: String? = nil
    ) -> ManifestEntity {
        ManifestEntity(
            kind: .group, key: key, name: name ?? key, description: description,
            dependsOn: dependsOn)
    }
}

// MARK: - Plan and apply

/// Plans and applies a §27.6 manifest.
public struct ManifestApi: Sendable {
    private let client: AxiamClient
    private let scope: CallScope

    init(client: AxiamClient, scope: CallScope) {
        self.client = client
        self.scope = scope
    }

    /// Page size used when reading existing state; large enough to make one call usual.
    private static let scanLimit = 200

    /// Compute what an apply would do. Sends only reads (§27.6).
    ///
    /// Validates the manifest before the first read, so an incoherent one is refused up front
    /// rather than halfway through.
    public func plan(_ manifest: Manifest) async throws -> ManagementPlan {
        let entities = try Self.ordered(manifest)
        var cache: [ManifestKind: [String: Existing]] = [:]
        var changes: [PlannedChange] = []

        for entity in entities {
            let existing: [String: Existing]
            if let cached = cache[entity.kind] {
                existing = cached
            } else {
                existing = try await readExisting(entity.kind)
                cache[entity.kind] = existing
            }

            guard let found = existing[entity.matchName] else {
                changes.append(PlannedChange(entity: entity, action: .create))
                continue
            }
            // Compare ONLY what the manifest names, and only what the SERVER carries. A
            // server object holds plenty a manifest says nothing about, and treating that
            // as drift would make every plan report a change and every apply overwrite work
            // nobody claimed.
            let drifted = entity.kind.hasDescription
                && !entity.description.isEmpty
                && entity.description != found.description
            changes.append(PlannedChange(
                entity: entity, action: drifted ? .update : .unchanged, id: found.id))
        }

        return ManagementPlan(changes: changes)
    }

    /// Apply a manifest, stopping at the first failure and NOT rolling back (§27.7).
    ///
    /// Re-plans internally rather than taking a `ManagementPlan`, so what is applied is
    /// computed against the tenant's state NOW. A plan from an earlier run describes a tenant
    /// that may have moved since, and applying it would either duplicate work or fail on a
    /// conflict — either way acting on a world that no longer exists.
    public func apply(_ manifest: Manifest) async throws -> ApplyReport {
        // `self.` and a distinct local name on purpose: `let plan = try await plan(...)`
        // reads as a shadowing puzzle even where the compiler accepts it.
        let computed = try await self.plan(manifest)
        let pending = computed.pending
        var applied: [PlannedChange] = []

        for (index, change) in pending.enumerated() {
            do {
                try await perform(change)
                applied.append(change)
            } catch {
                return ApplyReport(
                    applied: applied,
                    failed: change,
                    failure: String(describing: error),
                    remaining: Array(pending[(index + 1)...]))
            }
        }
        return ApplyReport(applied: applied)
    }

    /// Validate a manifest without contacting the server.
    ///
    /// Every check is one that can be made from the manifest alone: a duplicate key, a
    /// `dependsOn` naming an entity nobody declares, or a dependency cycle. Exposed
    /// separately so a caller can check at start-up rather than at apply time.
    public static func validate(_ manifest: Manifest) throws {
        // A duplicate key does not merge — one silently wins, and which one is an accident of
        // ordering. Since the key is also how an entity is referenced, the loser takes every
        // reference to it along.
        var seen = Set<String>()
        for entity in manifest.entities {
            guard !entity.key.isEmpty else {
                throw ManifestError("manifest: every entity needs a key")
            }
            let identity = "\(entity.kind.rawValue):\(entity.key)"
            guard seen.insert(identity).inserted else {
                throw ManifestError(
                    "manifest declares \"\(entity.key)\" twice — a key must be unique "
                    + "within its kind")
            }
        }

        // A dangling reference is invisible until apply reaches the entity that needs it, by
        // which point the objects before it are already created.
        let byKey = Dictionary(
            manifest.entities.map { ($0.key, $0) }, uniquingKeysWith: { first, _ in first })
        for entity in manifest.entities {
            if let dependency = entity.dependsOn, byKey[dependency] == nil {
                throw ManifestError(
                    "\"\(entity.key)\" depends on \"\(dependency)\", which this manifest "
                    + "does not declare")
            }
        }

        // Resources are the realistic source of a cycle: a parent link makes them a tree, and
        // a manifest can describe a shape that is not one. No ordering satisfies a cycle, so
        // the only correct response is to refuse.
        for start in manifest.entities {
            var at: ManifestEntity? = start
            var steps = 0
            while let current = at, let dependency = current.dependsOn {
                steps += 1
                if steps > manifest.entities.count {
                    throw ManifestError(
                        "manifest has a dependency cycle reachable from \"\(start.key)\"")
                }
                at = byKey[dependency]
            }
        }
    }

    /// The entities in apply order: by kind, then by dependency, then by key.
    ///
    /// The final tie-break on key is what makes a plan STABLE ACROSS RUNS. Two entities of the
    /// same kind with no dependency between them have no natural order, and without a
    /// deterministic tie-break they would come out in whatever order the caller happened to
    /// declare them — making every plan diff unreadable.
    public static func ordered(_ manifest: Manifest) throws -> [ManifestEntity] {
        try validate(manifest)
        let byKey = Dictionary(
            manifest.entities.map { ($0.key, $0) }, uniquingKeysWith: { first, _ in first })

        // Depth of an entity's dependency chain WITHIN its kind — a parent sorts before its
        // child. Across kinds the case order already decides.
        func depth(of entity: ManifestEntity) -> Int {
            var result = 0
            var at: ManifestEntity? = entity
            var guardCount = 0
            while let current = at, let dependency = current.dependsOn,
                  guardCount <= manifest.entities.count {
                guardCount += 1
                guard let parent = byKey[dependency], parent.kind == current.kind else { break }
                result += 1
                at = parent
            }
            return result
        }

        return manifest.entities.enumerated().sorted { left, right in
            let (leftIndex, a) = left
            let (rightIndex, b) = right
            if a.kind != b.kind { return a.kind < b.kind }
            let da = depth(of: a)
            let db = depth(of: b)
            if da != db { return da < db }
            if a.key != b.key { return a.key < b.key }
            return leftIndex < rightIndex
        }.map { $0.element }
    }

    // MARK: - Reading and writing

    /// One existing object: the id an update needs, and the one field manifests compare.
    private struct Existing {
        let id: String
        let description: String
    }

    /// Read the tenant's current state for one kind.
    ///
    /// Only the kinds a manifest mentions are scanned: a manifest declaring two permissions
    /// has no business listing every group in the tenant, and on a large tenant that is one
    /// request instead of dozens.
    private func readExisting(_ kind: ManifestKind) async throws -> [String: Existing] {
        let page = PageRequest(offset: 0, limit: Self.scanLimit)
        var out: [String: Existing] = [:]

        switch kind {
        case .resource:
            for item in try await ResourcesApi(client: client, scope: scope).list(page: page) {
                out[item.name] = Existing(id: item.id, description: "")
            }
        case .permission:
            for item in try await PermissionsApi(client: client, scope: scope).list(page: page) {
                out[item.action] = Existing(id: item.id, description: item.description)
            }
        case .role:
            for item in try await RolesApi(client: client, scope: scope).list(page: page) {
                out[item.name] = Existing(id: item.id, description: item.description)
            }
        case .group:
            for item in try await GroupsApi(client: client, scope: scope).list(page: page) {
                out[item.name] = Existing(id: item.id, description: item.description)
            }
        }
        return out
    }

    /// Send one planned change.
    ///
    /// An update carries a SPARSE body (§27.4 rule 5): only the fields the manifest names,
    /// absent rather than null, so a field nobody declared keeps whatever the server holds.
    private func perform(_ change: PlannedChange) async throws {
        let entity = change.entity
        let isCreate = change.action == .create
        let id = change.id ?? ""

        switch entity.kind {
        case .resource:
            let handle = ResourcesApi(client: client, scope: scope)
            if isCreate {
                _ = try await handle.create(body: CreateResourceRequest(
                    name: entity.name,
                    resourceType: entity.resourceType.isEmpty ? "folder" : entity.resourceType))
            } else {
                _ = try await handle.update(
                    resourceID: id, body: UpdateResourceRequest(name: entity.name))
            }
        case .permission:
            let handle = PermissionsApi(client: client, scope: scope)
            if isCreate {
                _ = try await handle.create(body: CreatePermissionRequest(
                    action: entity.action, description: entity.description))
            } else {
                _ = try await handle.update(
                    permissionID: id,
                    body: UpdatePermissionRequest(description: entity.description))
            }
        case .role:
            let handle = RolesApi(client: client, scope: scope)
            if isCreate {
                _ = try await handle.create(body: CreateRoleRequest(
                    description: entity.description,
                    isGlobal: entity.isGlobal,
                    name: entity.name))
            } else {
                _ = try await handle.update(
                    roleID: id, body: UpdateRole(description: entity.description))
            }
        case .group:
            let handle = GroupsApi(client: client, scope: scope)
            if isCreate {
                _ = try await handle.create(body: CreateGroupRequest(
                    description: entity.description, name: entity.name))
            } else {
                _ = try await handle.update(
                    groupID: id, body: UpdateGroup(description: entity.description))
            }
        }
    }
}
