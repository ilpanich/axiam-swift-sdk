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
    /// A service account (§27.6.1, contract 1.51). Depends on roles, like a group.
    case serviceAccount = 4

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
        case .serviceAccount: return "service_account"
        }
    }

    /// Whether the SERVER stores a description for this kind.
    ///
    /// Four of the five do. A resource does not: `Resource` has no description property, so
    /// reading current state can only ever report an empty one — and comparing a manifest's
    /// resource description against that would mark the resource drifted, update it, and
    /// mark it drifted again on the next run. §27.6 rule 6 requires apply-then-plan to be
    /// all-`unchanged`, and a manifest that never converges is the exact failure it rules out.
    var hasDescription: Bool { self != .resource }
}

/// One §27.6.1 role binding, in either shape.
///
/// - a **role key alone** (`resource == nil`) — the binding every manifest has always
///   had: no resource, and so no inheritance question;
/// - **resource-scoped** (`resource` set) — `inherit` defaults to `true` and is sent on
///   the wire ONLY when `false` (§27.13 S-10 rule 1), so an inheritable binding's body
///   stays byte-for-byte a pre-1.51 body.
public struct RoleBindingSpec: Sendable, Equatable {
    /// The bound role's manifest-local key.
    public let role: String
    /// The resource's manifest-local key this binding is scoped to, or `nil` for a
    /// plain (unscoped) binding.
    public let resource: String?
    /// Whether the binding reaches the resource's descendants. Only meaningful with
    /// `resource` set; `true` (the default) is never sent explicitly.
    public let inherit: Bool

    public init(role: String, resource: String? = nil, inherit: Bool = true) {
        self.role = role
        self.resource = resource
        self.inherit = inherit
    }
}

/// What `plan` would do to reconcile one declared binding against the server.
public enum BindingAction: Sendable, Equatable {
    /// The subject holds no assignment of this role yet: `assign`.
    case bind
    /// The subject already holds this role, but at a different resource or a different
    /// `inherit` — no update endpoint exists (§27.13 S-10 rule 4), so this is
    /// **unassign, then assign** (§27.6.1).
    case rebind
    /// Matches the server exactly: nothing sent.
    case unchanged
}

/// One binding-level entry of a plan, for a `.group` or `.serviceAccount` entity's
/// `roleBindings` (§27.6.1).
public struct BindingChange: Sendable, Equatable {
    /// `.group` or `.serviceAccount`.
    public let subjectKind: ManifestKind
    /// The owning entity's manifest key.
    public let subjectKey: String
    /// The declared binding this change reconciles.
    public let binding: RoleBindingSpec
    public let action: BindingAction

    /// The SERVER's current assignment for this role/subject pair — populated only for
    /// `.rebind`, where `perform` needs it to unassign the RIGHT existing binding (which
    /// may be scoped differently than what is being assigned) and to restore it exactly
    /// if the new assign fails.
    public let serverResourceID: String?
    /// The SERVER's current `inherit` for this role/subject pair (already resolved:
    /// absent reads as `true`, §27.13 S-10 rule 3). Only meaningful for `.rebind`.
    public let serverInherit: Bool
    /// The SERVER's current `tenant_scope` for this role/subject pair, carried across
    /// unchanged on a `rebind`'s re-assign (§27.13 S-10 rule 4) — a manifest binding
    /// says nothing about `tenant_scope` (rule 3), and dropping it would silently widen
    /// an organization-level account's reach (§5.2.3).
    public let serverTenantScope: [String]?

    public init(
        subjectKind: ManifestKind, subjectKey: String, binding: RoleBindingSpec,
        action: BindingAction, serverResourceID: String? = nil, serverInherit: Bool = true,
        serverTenantScope: [String]? = nil
    ) {
        self.subjectKind = subjectKind
        self.subjectKey = subjectKey
        self.binding = binding
        self.action = action
        self.serverResourceID = serverResourceID
        self.serverInherit = serverInherit
        self.serverTenantScope = serverTenantScope
    }

    /// A one-line rendering, matching `PlannedChange.describe`'s shape.
    public var describe: String {
        let scope = binding.resource.map { "@\($0)" + (binding.inherit ? "" : "(inherit:false)") } ?? ""
        switch action {
        case .bind: return "bind \(subjectKind.label):\(subjectKey) -> \(binding.role)\(scope)"
        case .rebind: return "rebind \(subjectKind.label):\(subjectKey) -> \(binding.role)\(scope)"
        case .unchanged: return "unchanged \(subjectKind.label):\(subjectKey) -> \(binding.role)\(scope)"
        }
    }
}

/// The outcome of one `BindingChange` actually applied — mirrors `PlannedChange`'s role
/// but for a binding rather than an entity.
public struct BindingOutcome: Sendable, Equatable {
    public let change: BindingChange
    /// For a `rebind` whose assign failed: `true` once the PREVIOUS binding was
    /// successfully re-assigned (§27.6.1's restore), `false` if that restore itself
    /// failed too — the subject then holds NEITHER binding, and is left for the
    /// caller to fix by hand.
    public let restored: Bool?

    public init(change: BindingChange, restored: Bool? = nil) {
        self.change = change
        self.restored = restored
    }
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
    /// For a resource (§27.6.1 addition 1): its `metadata`, compared by JSON value
    /// equality of the WHOLE object (never a key-by-key merge — §27.6.1 says a merge
    /// would make `apply` unable to remove a key). `nil` means "the manifest says
    /// nothing about metadata" (rule 3: silent, not "clear it"); `.object([:])`
    /// explicitly asserts the empty object, which is also what the server returns for
    /// a resource created with none.
    public var metadata: ManagementJSON?
    /// For a `.group` or `.serviceAccount` (§27.6.1 addition 2 and 3): the roles this
    /// subject must hold, in either binding shape.
    public var roleBindings: [RoleBindingSpec]

    public init(
        kind: ManifestKind,
        key: String,
        name: String,
        description: String = "",
        resourceType: String = "",
        action: String = "",
        isGlobal: Bool = false,
        dependsOn: String? = nil,
        metadata: ManagementJSON? = nil,
        roleBindings: [RoleBindingSpec] = []
    ) {
        self.kind = kind
        self.key = key
        self.name = name
        self.description = description
        self.resourceType = resourceType
        self.action = action
        self.isGlobal = isGlobal
        self.dependsOn = dependsOn
        self.metadata = metadata
        self.roleBindings = roleBindings
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
    /// A newly created service account's one-time secret (§27.5 rule 5). `nil` for
    /// every action but a `.serviceAccount`'s `Create` — and even then only once
    /// `apply` has actually performed it; `plan` never populates this.
    public let serviceAccountSecret: Sensitive<String>?

    public init(
        entity: ManifestEntity, action: ChangeAction, id: String? = nil,
        serviceAccountSecret: Sensitive<String>? = nil
    ) {
        self.entity = entity
        self.action = action
        self.id = id
        self.serviceAccountSecret = serviceAccountSecret
    }

    /// A one-line rendering, e.g. `create permission:read`.
    public var describe: String {
        "\(action.rawValue) \(entity.kind.label):\(entity.key)"
    }

    /// This change with `serviceAccountSecret` filled in — `apply`'s way of attaching the
    /// one-time secret to the outcome it just performed, without a mutable var anywhere
    /// a caller could accidentally share.
    func withSecret(_ secret: Sensitive<String>) -> PlannedChange {
        PlannedChange(entity: entity, action: action, id: id, serviceAccountSecret: secret)
    }

    /// This change with `id` filled in from a `Create`'s response, so `apply` can thread
    /// the new server id to anything ordered after it (a child resource's `parent_id`, a
    /// role/group/service-account binding).
    func resolvedAs(id: String) -> PlannedChange {
        PlannedChange(entity: entity, action: action, id: id, serviceAccountSecret: serviceAccountSecret)
    }
}

/// What `plan` produced: the ordered changes an apply would make.
///
/// Includes the `unchanged` entries too, so a reader sees what was considered and not only
/// what moved.
public struct ManagementPlan: Sendable, Equatable {
    public let changes: [PlannedChange]
    /// §27.6.1's role-binding reconciliation for every `.group`/`.serviceAccount` entity,
    /// in manifest order. Kept separate from `changes` rather than folded into it: a
    /// binding can drift while its OWNING entity does not (a group whose description
    /// still matches but whose roles do not), so an entity's own `action` cannot carry
    /// both.
    public let bindingChanges: [BindingChange]

    public init(changes: [PlannedChange], bindingChanges: [BindingChange] = []) {
        self.changes = changes
        self.bindingChanges = bindingChanges
    }

    /// Only the entity changes that would actually send a request.
    public var pending: [PlannedChange] {
        changes.filter { $0.action != .unchanged }
    }

    /// Only the binding changes that would actually send a request.
    public var pendingBindings: [BindingChange] {
        bindingChanges.filter { $0.action != .unchanged }
    }

    /// True when the tenant already matches and an apply would send nothing — entities
    /// AND bindings both (§27.6 rule 6's idempotence test covers all three §27.6.1
    /// additions at once).
    public var isConverged: Bool { pending.isEmpty && pendingBindings.isEmpty }
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
    /// §27.6.1 binding changes that succeeded, in order — run only once every entity
    /// change above has (rule 5: bindings depend on the roles/groups/service accounts
    /// they name, which entity changes just created).
    public let appliedBindings: [BindingOutcome]
    /// The binding change that failed, if any. Entity changes always run to completion
    /// (or fail) before any binding is attempted, so this and `failed` are never both
    /// set.
    public let failedBinding: BindingOutcome?
    /// Why the binding failed.
    public let bindingFailure: String
    /// Binding changes never attempted, because of `failedBinding`.
    public let remainingBindings: [BindingChange]

    public init(
        applied: [PlannedChange],
        failed: PlannedChange? = nil,
        failure: String = "",
        remaining: [PlannedChange] = [],
        appliedBindings: [BindingOutcome] = [],
        failedBinding: BindingOutcome? = nil,
        bindingFailure: String = "",
        remainingBindings: [BindingChange] = []
    ) {
        self.applied = applied
        self.failed = failed
        self.failure = failure
        self.remaining = remaining
        self.appliedBindings = appliedBindings
        self.failedBinding = failedBinding
        self.bindingFailure = bindingFailure
        self.remainingBindings = remainingBindings
    }

    /// True when every planned change landed — entities AND bindings.
    public var isComplete: Bool { failed == nil && failedBinding == nil }

    /// A human-readable account of the run, for a log line or a CI summary.
    public var describe: [String] {
        var lines = applied.map { "applied  \($0.describe)" }
        if let failed {
            lines.append("FAILED   \(failed.describe): \(failure)")
            lines.append(contentsOf: remaining.map { "skipped  \($0.describe)" })
            return lines
        }
        lines.append(contentsOf: appliedBindings.map { "applied  \($0.change.describe)" })
        if let failedBinding {
            lines.append("FAILED   \(failedBinding.change.describe): \(bindingFailure)"
                + (failedBinding.restored == true ? " (previous binding restored)"
                    : failedBinding.restored == false ? " (RESTORE ALSO FAILED — subject holds neither binding)"
                    : ""))
            lines.append(contentsOf: remainingBindings.map { "skipped  \($0.describe)" })
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
        metadata: ManagementJSON? = nil,
        @ManifestBuilder children: () -> [ManifestEntity] = { [] }
    ) -> [ManifestEntity] {
        let parent = ManifestEntity(
            kind: .resource, key: key, name: name ?? key, description: description,
            resourceType: resourceType, dependsOn: dependsOn, metadata: metadata)
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
        dependsOn: String? = nil,
        roles: [RoleBindingSpec] = []
    ) -> ManifestEntity {
        ManifestEntity(
            kind: .group, key: key, name: name ?? key, description: description,
            dependsOn: dependsOn, roleBindings: roles)
    }

    /// A service account (§27.6.1 addition 3).
    public static func serviceAccount(
        _ key: String,
        name: String? = nil,
        description: String = "",
        roles: [RoleBindingSpec] = []
    ) -> ManifestEntity {
        ManifestEntity(
            kind: .serviceAccount, key: key, name: name ?? key, description: description,
            roleBindings: roles)
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
        let byKey = Dictionary(
            manifest.entities.map { ($0.key, $0) }, uniquingKeysWith: { first, _ in first })
        var cache: [ManifestKind: [String: Existing]] = [:]
        var changes: [PlannedChange] = []
        // Manifest key -> server id, RESOURCES only. Seeded as each resource is planned,
        // so a child resource created later in this same loop can resolve its parent's id
        // (rule 5: resources are topologically sorted, parent before child) and so a
        // `.group`/`.serviceAccount`'s resource-scoped binding can resolve an EXISTING
        // resource's id below. A resource still being CREATED in this apply has no id
        // yet — `nil` here, which is exactly right: no pre-existing binding could be
        // scoped to a resource that does not exist yet either.
        var resourceIDs: [String: String] = [:]
        var serviceAccountsRead = false
        var serviceAccountMatches: [String: [Existing]] = [:]
        var bindingChanges: [BindingChange] = []

        for entity in entities {
            switch entity.kind {
            case .resource:
                let existing = try await cachedExisting(.resource, cache: &cache)
                guard let found = existing[entity.matchName] else {
                    changes.append(PlannedChange(entity: entity, action: .create))
                    continue
                }
                resourceIDs[entity.key] = found.id
                // §27.6.1 addition 1: JSON value equality of the WHOLE object. `nil` on
                // the manifest side is rule 3's silence, never "clear it" — a manifest
                // that says nothing about metadata reports no drift regardless of what
                // the server holds.
                let drifted = entity.metadata.map { $0 != (found.metadata ?? .object([:])) } ?? false
                changes.append(PlannedChange(
                    entity: entity, action: drifted ? .update : .unchanged, id: found.id))

            case .permission, .role:
                let existing = try await cachedExisting(entity.kind, cache: &cache)
                guard let found = existing[entity.matchName] else {
                    changes.append(PlannedChange(entity: entity, action: .create))
                    continue
                }
                let drifted = !entity.description.isEmpty && entity.description != found.description
                changes.append(PlannedChange(
                    entity: entity, action: drifted ? .update : .unchanged, id: found.id))

            case .group:
                let existing = try await cachedExisting(.group, cache: &cache)
                let found = existing[entity.matchName]
                let drifted = found.map { !entity.description.isEmpty && entity.description != $0.description } ?? false
                changes.append(PlannedChange(
                    entity: entity, action: found == nil ? .create : (drifted ? .update : .unchanged),
                    id: found?.id))
                bindingChanges.append(contentsOf: try await computeBindingChanges(
                    subjectKind: .group, subjectKey: entity.key, subjectID: found?.id,
                    roleBindings: entity.roleBindings, byKey: byKey, resourceIDs: resourceIDs))

            case .serviceAccount:
                // §27.6.1 addition 3: the natural key is `name`, and the server does NOT
                // enforce it — only `client_id` is indexed. `plan` MUST fail, before
                // `apply` writes anything, when more than one existing account matches a
                // stated name; picking one would reconcile an arbitrary account.
                if !serviceAccountsRead {
                    serviceAccountMatches = try await readExistingServiceAccounts()
                    serviceAccountsRead = true
                }
                let matches = serviceAccountMatches[entity.matchName] ?? []
                guard matches.count <= 1 else {
                    throw ManifestError(
                        "\"\(entity.key)\" names service account \"\(entity.name)\", which "
                        + "matches \(matches.count) existing accounts — service-account names "
                        + "are not unique (only client_id is), so plan cannot tell which one "
                        + "this manifest means. No request was sent.")
                }
                let found = matches.first
                let drifted = found.map { !entity.description.isEmpty && entity.description != $0.description } ?? false
                changes.append(PlannedChange(
                    entity: entity, action: found == nil ? .create : (drifted ? .update : .unchanged),
                    id: found?.id))
                bindingChanges.append(contentsOf: try await computeBindingChanges(
                    subjectKind: .serviceAccount, subjectKey: entity.key, subjectID: found?.id,
                    roleBindings: entity.roleBindings, byKey: byKey, resourceIDs: resourceIDs))
            }
        }

        return ManagementPlan(changes: changes, bindingChanges: bindingChanges)
    }

    /// `readExisting`, memoized across the one `plan` call it serves.
    private func cachedExisting(
        _ kind: ManifestKind, cache: inout [ManifestKind: [String: Existing]]
    ) async throws -> [String: Existing] {
        if let cached = cache[kind] { return cached }
        let existing = try await readExisting(kind)
        cache[kind] = existing
        return existing
    }

    /// §27.6.1: reconcile one subject's declared `roleBindings` against what it currently
    /// holds. `subjectID == nil` means the subject does not exist yet (it will be CREATED
    /// by this same apply), so it holds nothing today and every declared binding is a
    /// `.bind` — there is no existing assignment a not-yet-created subject could hold.
    private func computeBindingChanges(
        subjectKind: ManifestKind,
        subjectKey: String,
        subjectID: String?,
        roleBindings: [RoleBindingSpec],
        byKey: [String: ManifestEntity],
        resourceIDs: [String: String]
    ) async throws -> [BindingChange] {
        guard !roleBindings.isEmpty else { return [] }

        let existingAssignments: [RoleAssignment]
        if let subjectID {
            switch subjectKind {
            case .group:
                existingAssignments = try await GroupsApi(client: client, scope: scope).listRoles(groupID: subjectID)
            case .serviceAccount:
                existingAssignments = try await ServiceAccountsApi(client: client, scope: scope)
                    .listRoles(serviceAccountID: subjectID)
            default:
                existingAssignments = []
            }
        } else {
            existingAssignments = []
        }

        var changes: [BindingChange] = []
        for binding in roleBindings {
            // Validated in `Manifest.validate()`: `byKey[binding.role]` always resolves to
            // a `.role` entity here.
            let roleName = byKey[binding.role]?.name ?? binding.role
            let desiredResourceID = binding.resource.flatMap { resourceIDs[$0] }

            guard let match = existingAssignments.first(where: { $0.role.name == roleName }) else {
                changes.append(BindingChange(
                    subjectKind: subjectKind, subjectKey: subjectKey, binding: binding, action: .bind))
                continue
            }
            // §27.6.1: "the binding's natural key is (subject, role), and its resource
            // and inherit are fields" — `NoChange` only when BOTH match. A resource still
            // being created this run has no id yet (`desiredResourceID == nil`), so it
            // can never equal an existing assignment's real resource id, which is exactly
            // right: no pre-existing binding could already be scoped to it.
            let matches = match.resourceID == desiredResourceID && match.inherits == binding.inherit
            changes.append(BindingChange(
                subjectKind: subjectKind, subjectKey: subjectKey, binding: binding,
                action: matches ? .unchanged : .rebind,
                serverResourceID: match.resourceID, serverInherit: match.inherits,
                serverTenantScope: match.tenantScope))
        }
        return changes
    }

    /// Apply a manifest, stopping at the first failure and NOT rolling back (§27.7).
    ///
    /// Re-plans internally rather than taking a `ManagementPlan`, so what is applied is
    /// computed against the tenant's state NOW. A plan from an earlier run describes a tenant
    /// that may have moved since, and applying it would either duplicate work or fail on a
    /// conflict — either way acting on a world that no longer exists.
    ///
    /// Ordering (§27.6 rule 5): every entity change (resources, permissions, roles,
    /// groups, service accounts, in that order) runs to completion FIRST; role bindings
    /// run only afterward, because a binding names a role and a subject that this same
    /// apply may just have created.
    public func apply(_ manifest: Manifest) async throws -> ApplyReport {
        // `self.` and a distinct local name on purpose: `let plan = try await plan(...)`
        // reads as a shadowing puzzle even where the compiler accepts it.
        let computed = try await self.plan(manifest)

        // Manifest key -> server id, EVERY kind. Seeded from every entity `plan` already
        // resolved (existing or about-to-be-updated); filled in as each `Create` lands.
        var entityIDs: [String: String] = [:]
        for change in computed.changes {
            if let id = change.id { entityIDs[change.entity.key] = id }
        }

        let pending = computed.pending
        var applied: [PlannedChange] = []

        for (index, change) in pending.enumerated() {
            do {
                let outcome = try await perform(change, entityIDs: entityIDs)
                if let id = outcome.id { entityIDs[change.entity.key] = id }
                applied.append(outcome)
            } catch {
                return ApplyReport(
                    applied: applied,
                    failed: change,
                    failure: String(describing: error),
                    remaining: Array(pending[(index + 1)...]))
            }
        }

        let pendingBindings = computed.pendingBindings
        var appliedBindings: [BindingOutcome] = []
        for (index, change) in pendingBindings.enumerated() {
            do {
                appliedBindings.append(try await performBinding(change, entityIDs: entityIDs))
            } catch let error as BindingApplyFailure {
                return ApplyReport(
                    applied: applied, appliedBindings: appliedBindings,
                    failedBinding: BindingOutcome(change: change, restored: error.restored),
                    bindingFailure: String(describing: error.underlying),
                    remainingBindings: Array(pendingBindings[(index + 1)...]))
            } catch {
                return ApplyReport(
                    applied: applied, appliedBindings: appliedBindings,
                    failedBinding: BindingOutcome(change: change),
                    bindingFailure: String(describing: error),
                    remainingBindings: Array(pendingBindings[(index + 1)...]))
            }
        }
        return ApplyReport(applied: applied, appliedBindings: appliedBindings)
    }

    /// Thrown by `performBinding` for a `.rebind` whose new assign failed, carrying
    /// whether the PREVIOUS binding was successfully re-assigned (§27.6.1's restore).
    private struct BindingApplyFailure: Error {
        let restored: Bool
        let underlying: Error
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

        // §27.6.1: every `roleBindings` entry, on every `.group`/`.serviceAccount`, checked
        // BEFORE any request — all three of these describe a manifest that cannot be applied
        // coherently, exactly like a dangling `dependsOn` or a resource cycle above.
        for entity in manifest.entities where entity.kind == .group || entity.kind == .serviceAccount {
            var seenRoles = Set<String>()
            for binding in entity.roleBindings {
                // A dangling reference. Discovering this mid-apply, after the objects before
                // it already landed, is strictly worse than refusing up front.
                guard let role = byKey[binding.role], role.kind == .role else {
                    throw ManifestError(
                        "\"\(entity.key)\" binds role \"\(binding.role)\", which this manifest "
                        + "does not declare as a role")
                }
                if let resourceKey = binding.resource {
                    guard let resource = byKey[resourceKey], resource.kind == .resource else {
                        throw ManifestError(
                            "\"\(entity.key)\"'s binding to \"\(binding.role)\" names resource "
                            + "\"\(resourceKey)\", which this manifest does not declare as a "
                            + "resource")
                    }
                }
                // §27.6.1: "a subject holds a role at most once" — `has_role` is
                // `UNIQUE(in, out)` with no resource component, so a manifest binding one
                // role to one subject twice (at two resources, or once plain and once
                // scoped) describes a state the server cannot hold.
                guard seenRoles.insert(binding.role).inserted else {
                    throw ManifestError(
                        "\"\(entity.key)\" binds role \"\(binding.role)\" twice — the server "
                        + "keys a role assignment on (subject, role) alone, with no resource "
                        + "component, so one subject cannot hold one role at two resources or "
                        + "once plain and once scoped (CONTRACT.md §27.6.1)")
                }
                // §27.13 S-10 rule 2: the server refuses `inherit: false` on a global role
                // with 400 ("a global role ignores resource scope"). §27.6.1 says an SDK
                // MAY check it client-side when the role is in the manifest; this one does,
                // so the ambiguous-account-style zero-wire-calls refusal applies here too.
                if !binding.inherit, binding.resource != nil, role.isGlobal {
                    throw ManifestError(
                        "\"\(entity.key)\" binds the GLOBAL role \"\(binding.role)\" with "
                        + "inherit: false, which the server refuses with 400 — a global role "
                        + "ignores resource scope (CONTRACT.md §27.13 S-10 rule 2)")
                }
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

    /// One existing object: the id an update needs, and the fields manifests compare.
    private struct Existing {
        let id: String
        let description: String
        /// Resources only (§27.6.1 addition 1); `nil` for every other kind.
        let metadata: ManagementJSON?
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
                out[item.name] = Existing(id: item.id, description: "", metadata: item.metadata)
            }
        case .permission:
            for item in try await PermissionsApi(client: client, scope: scope).list(page: page) {
                out[item.action] = Existing(id: item.id, description: item.description, metadata: nil)
            }
        case .role:
            for item in try await RolesApi(client: client, scope: scope).list(page: page) {
                out[item.name] = Existing(id: item.id, description: item.description, metadata: nil)
            }
        case .group:
            for item in try await GroupsApi(client: client, scope: scope).list(page: page) {
                out[item.name] = Existing(id: item.id, description: item.description, metadata: nil)
            }
        case .serviceAccount:
            // Service accounts are read through `readExistingServiceAccounts()`, which
            // preserves EVERY match rather than collapsing to one — see its doc comment.
            break
        }
        return out
    }

    /// Every existing service account, grouped by `name` (§27.6.1 addition 3: the natural
    /// key is `name`, and the server does NOT enforce it — only `client_id` is indexed, so
    /// more than one account can share a name). `plan` fails when a manifest's stated name
    /// matches more than one entry here, rather than picking one.
    private func readExistingServiceAccounts() async throws -> [String: [Existing]] {
        let page = PageRequest(offset: 0, limit: Self.scanLimit)
        var out: [String: [Existing]] = [:]
        for item in try await ServiceAccountsApi(client: client, scope: scope).list(page: page) {
            out[item.name, default: []].append(
                Existing(id: item.id, description: item.description ?? "", metadata: nil))
        }
        return out
    }

    /// Send one planned change and return it with `id` (and, for a service-account
    /// `Create`, `serviceAccountSecret`) filled in from the server's response.
    ///
    /// An update carries a SPARSE body (§27.4 rule 5): only the fields the manifest names,
    /// absent rather than null, so a field nobody declared keeps whatever the server holds.
    private func perform(_ change: PlannedChange, entityIDs: [String: String]) async throws -> PlannedChange {
        let entity = change.entity
        let isCreate = change.action == .create
        let id = change.id ?? ""

        switch entity.kind {
        case .resource:
            let handle = ResourcesApi(client: client, scope: scope)
            if isCreate {
                // §13 row 17 defect b: this generator/port used to default an unstated
                // `resourceType` to `"folder"` — a default the contract never stated.
                // The fix is to require the manifest state one, not to pick a quieter
                // default; a manifest built through `Declare.resource` always has one
                // (its OWN default is explicit and visible in that call's signature), so
                // this only rejects a `ManifestEntity` built by hand with none.
                guard !entity.resourceType.isEmpty else {
                    throw ManifestError(
                        "resource \"\(entity.key)\" has no resourceType — a manifest MUST "
                        + "state one (CONTRACT.md §27.6.1); this generator no longer "
                        + "defaults an unstated one to \"folder\"")
                }
                // §13 row 17 defect a: this port used to never send a resource's
                // `parent_id` on Create, although the model always carried the field —
                // so a nested manifest was created FLAT. `dependsOn`, for a `.resource`
                // entity, names its parent (rule 5's topological sort guarantees the
                // parent was created, or already existed, before this runs).
                let parentID = entity.dependsOn.flatMap { entityIDs[$0] }
                let created = try await handle.create(body: CreateResourceRequest(
                    metadata: entity.metadata,
                    name: entity.name,
                    parentID: parentID,
                    resourceType: entity.resourceType))
                return change.resolvedAs(id: created.id)
            } else {
                _ = try await handle.update(resourceID: id, body: UpdateResourceRequest(
                    metadata: entity.metadata, name: entity.name))
                return change
            }
        case .permission:
            let handle = PermissionsApi(client: client, scope: scope)
            if isCreate {
                let created = try await handle.create(body: CreatePermissionRequest(
                    action: entity.action, description: entity.description))
                return change.resolvedAs(id: created.id)
            } else {
                _ = try await handle.update(
                    permissionID: id,
                    body: UpdatePermissionRequest(description: entity.description))
                return change
            }
        case .role:
            let handle = RolesApi(client: client, scope: scope)
            if isCreate {
                let created = try await handle.create(body: CreateRoleRequest(
                    description: entity.description,
                    isGlobal: entity.isGlobal,
                    name: entity.name))
                return change.resolvedAs(id: created.id)
            } else {
                _ = try await handle.update(
                    roleID: id, body: UpdateRole(description: entity.description))
                return change
            }
        case .group:
            let handle = GroupsApi(client: client, scope: scope)
            if isCreate {
                let created = try await handle.create(body: CreateGroupRequest(
                    description: entity.description, name: entity.name))
                return change.resolvedAs(id: created.id)
            } else {
                _ = try await handle.update(
                    groupID: id, body: UpdateGroup(description: entity.description))
                return change
            }
        case .serviceAccount:
            let handle = ServiceAccountsApi(client: client, scope: scope)
            if isCreate {
                // §27.5 rule 5: the ONE moment the plaintext `client_secret` exists.
                // `apply` never rotates to reconcile — the outcome carries it here, on
                // THIS action, and nowhere else.
                let created = try await handle.create(body: CreateServiceAccountRequest(
                    description: entity.description.isEmpty ? nil : entity.description,
                    name: entity.name))
                return change.resolvedAs(id: created.id).withSecret(created.clientSecret)
            } else {
                _ = try await handle.update(
                    saID: id, body: UpdateServiceAccount(description: entity.description))
                return change
            }
        }
    }

    /// Send one §27.6.1 binding change. `entityIDs` MUST already carry a server id for
    /// the subject, the role, and (when the binding is scoped) the resource — `apply`
    /// guarantees this by running every entity change to completion before any binding.
    private func performBinding(_ change: BindingChange, entityIDs: [String: String]) async throws -> BindingOutcome {
        guard let subjectID = entityIDs[change.subjectKey] else {
            throw ManifestError(
                "binding for \"\(change.subjectKey)\" has no resolved server id (internal error)")
        }
        guard let roleID = entityIDs[change.binding.role] else {
            throw ManifestError(
                "role \"\(change.binding.role)\" has no resolved server id (internal error)")
        }

        switch change.action {
        case .unchanged:
            return BindingOutcome(change: change)

        case .bind:
            let resourceID = try change.binding.resource.map { try resolvedOrThrow($0, entityIDs: entityIDs) }
            try await assign(
                subjectKind: change.subjectKind, subjectID: subjectID, roleID: roleID,
                resourceID: resourceID, inherit: change.binding.inherit, tenantScope: nil)
            return BindingOutcome(change: change)

        case .rebind:
            // §27.6.1: "there is no update endpoint, so apply performs an Update as
            // unassign, then assign, and the subject holds no such role between the two
            // calls. If the assign fails, the SDK MUST attempt to assign the previous
            // binding again... and report both outcomes."
            try await unassign(
                subjectKind: change.subjectKind, subjectID: subjectID, roleID: roleID,
                resourceID: change.serverResourceID)
            do {
                let resourceID = try change.binding.resource.map { try resolvedOrThrow($0, entityIDs: entityIDs) }
                try await assign(
                    subjectKind: change.subjectKind, subjectID: subjectID, roleID: roleID,
                    resourceID: resourceID, inherit: change.binding.inherit,
                    // §27.13 S-10 rule 4 / §27.6.1: `tenant_scope` is not a manifest
                    // field — the re-assign carries the SERVER's existing value across
                    // unchanged, so a rebind can never silently widen an
                    // organization-level account's reach.
                    tenantScope: change.serverTenantScope)
                return BindingOutcome(change: change)
            } catch {
                // Restore the previous binding exactly as it was. A failure restoring
                // it too is reported (`restored: false`) rather than thrown again: the
                // ORIGINAL assign failure is the one the caller needs to see and fix.
                do {
                    try await assign(
                        subjectKind: change.subjectKind, subjectID: subjectID, roleID: roleID,
                        resourceID: change.serverResourceID,
                        inherit: change.serverInherit, tenantScope: change.serverTenantScope)
                    throw BindingApplyFailure(restored: true, underlying: error)
                } catch let failure as BindingApplyFailure {
                    throw failure
                } catch {
                    throw BindingApplyFailure(restored: false, underlying: error)
                }
            }
        }
    }

    /// `entityIDs[key]`, or a `ManifestError` naming the missing resource — used only for
    /// a binding's `resource`, which `Manifest.validate()` already guarantees names a
    /// declared `.resource` entity; a missing id here means that resource's OWN change
    /// has not run yet, which `apply`'s ordering (entities before bindings) rules out.
    private func resolvedOrThrow(_ key: String, entityIDs: [String: String]) throws -> String {
        guard let id = entityIDs[key] else {
            throw ManifestError("resource \"\(key)\" has no resolved server id (internal error)")
        }
        return id
    }

    private func assign(
        subjectKind: ManifestKind, subjectID: String, roleID: String,
        resourceID: String?, inherit: Bool, tenantScope: [String]?
    ) async throws {
        let roles = RolesApi(client: client, scope: scope)
        // §27.13 S-10 rule 1: sent only when `false`, so an inheritable assignment's
        // body stays byte-for-byte a pre-1.51 body.
        let inheritField: Bool? = inherit ? nil : false
        switch subjectKind {
        case .group:
            try await roles.assignToGroup(roleID: roleID, body: AssignRoleToGroupRequest(
                groupID: subjectID, inherit: inheritField, resourceID: resourceID, tenantScope: tenantScope))
        case .serviceAccount:
            try await roles.assignToServiceAccount(roleID: roleID, body: AssignRoleToServiceAccountRequest(
                inherit: inheritField, resourceID: resourceID, serviceAccountID: subjectID,
                tenantScope: tenantScope))
        default:
            throw ManifestError("performBinding: unsupported subject kind \(subjectKind)")
        }
    }

    private func unassign(
        subjectKind: ManifestKind, subjectID: String, roleID: String, resourceID: String?
    ) async throws {
        let roles = RolesApi(client: client, scope: scope)
        switch subjectKind {
        case .group:
            try await roles.unassignFromGroup(roleID: roleID, groupID: subjectID, resourceID: resourceID)
        case .serviceAccount:
            try await roles.unassignFromServiceAccount(
                roleID: roleID, serviceAccountID: subjectID, resourceID: resourceID)
        default:
            throw ManifestError("performBinding: unsupported subject kind \(subjectKind)")
        }
    }
}
