import Foundation

// CONTRACT.md §27.6.2 — the `network` namespace in a manifest (contract 1.62).
//
// A site's segments and their reply profiles are exactly the *shape* §27.6 exists for: a
// migration or a fixture that has to assert them otherwise writes the exists-checks and the
// version bookkeeping by hand. This file is the part of the manifest that knows about them. It
// extends `ManifestApi` (`plan`, `apply`, `validate`) rather than the flat `ManifestEntity` list,
// because none of the three kinds below is a name-keyed, description-bearing entity:
//
//   * a **segment** is keyed by site + kind + name, where `kind` is the WIRE spelling (`access`
//     or `quarantine`) — the value `create_segment` writes and every read returns. There is no
//     `zones` spelling here, in either direction;
//   * a **profile** is keyed by its segment: it has no name or id of its own;
//   * the **policy** is a singleton. A manifest carries at most one, and an optional property
//     cannot hold two, so "two policies" is not a state this type can be put in.
//
// What the contract fixes, and where it is enforced:
//
//   * order — the policy, then the segments, then the profiles, each in key order, so a plan is
//     stable (`planNetwork`). The policy goes first because a profile's `session_timeout_secs`
//     is checked against the cap at the write;
//   * judged on the read — every STATED member is compared with the value as the read returns
//     it, the effective (clamped) one for a profile. `filter_ids` compare as a SET. Nothing
//     hidden and nothing stored is compared, and nothing is kept between calls;
//   * a version-conditional, full-body `replace_*` built from the read — a stated member
//     replaces the read's, an unstated one is carried from it, a member stated as none is left
//     out of the body. The `version` is the one `plan` read, sent exactly; a profile's
//     `segment_version` is the segment write's response `version` when this `apply` wrote the
//     segment, never the stale one (`performNetwork`);
//   * never retried — a `409` and its `reason_code`, a `403`, any other refusal is THAT action's
//     failure: `apply` stops, reports it as given, and tries nothing again.
//
// This SDK's manifest has no pruning at all (omission is never deletion: `ChangeAction` has no
// delete case), so §27.6.2 item 6 — the opt-in `Delete` of a segment or profile the manifest
// does not state — is not offered, and a segment or a profile absent from a manifest is left
// alone, as every other kind is.

// MARK: - The members

/// One optional member of a `network` spec that can be left unsaid, said to be none, or given a
/// value (§27.6.2 item 4).
///
/// The three states are different things, and a plain `Optional` cannot hold them: **unstated**
/// is silence — rule 3 says silence is not an assertion, so the member is not compared and is
/// carried from the read; **null** is "none" — it is compared (a read that has a value differs)
/// and the key is left OUT of the replacement body, which is how a replacement clears an
/// optional member, and `null` is never sent; **value** is asserted.
public enum NetworkMember<Value: Sendable & Equatable>: Sendable, Equatable {
    /// The manifest says nothing: no drift, and the replacement carries what the read had.
    case unstated
    /// The manifest says "none": the key is omitted from the body.
    case null
    /// The manifest states this value.
    case value(Value)

    /// The value of a stated member, `nil` for silence and for none.
    var statedValue: Value? {
        if case .value(let value) = self { return value }
        return nil
    }

    /// Whether this member, as STATED, differs from what the read returned. Silence never does.
    func differs(from read: Value?) -> Bool {
        switch self {
        case .unstated: return false
        case .null: return read != nil
        case .value(let stated): return read != stated
        }
    }

    /// What goes in the replacement body: the stated value, nothing for none, the read's for
    /// silence.
    func resolved(carrying read: Value?) -> Value? {
        switch self {
        case .unstated: return read
        case .null: return nil
        case .value(let stated): return stated
        }
    }
}

/// One segment a manifest declares (§27.6.2 item 1, `network.segments[]`).
///
/// The natural key is **site + kind + name**, `kind` being the wire spelling; `key` is the
/// manifest-local handle a ``NetworkProfileSpec`` names. `site`, `kind` and `name` never drift
/// (§36.3 rule 4: they do not change); every other member is a field.
public struct NetworkSegmentSpec: Sendable, Equatable {
    /// The manifest-local key a profile's `segment` names. Unique within the manifest.
    public var key: String
    /// The wire `site_key`.
    public var site: String
    /// `.access` or `.quarantine`: the value `create_segment` writes and every read returns. An
    /// `.unknown` is refused at `plan`.
    public var kind: NetworkSegmentKind
    /// The segment's name within its site.
    public var name: String
    /// The VLAN, 1–4094 and unique within the site (the server judges both).
    public var vlanID: Int
    /// Placement order among the site's access segments; required by the server for `access` and
    /// absent for `quarantine`. `.null` states "none".
    public var rank: NetworkMember<Int>
    /// The segment's envelope: the `Filter-Id` names its profile may choose from. Compared as a
    /// **set** — a reorder is `NoChange` — and a list that names one Filter-Id twice is refused
    /// at `plan` with no request sent. When the SDK writes the segment it sends the order given.
    /// `nil` is silence: omitted on create, carried from the read on a replacement.
    public var filterIds: [String]?
    /// Whether the segment is a placement candidate. `nil` is silence.
    public var enabled: Bool?

    public init(
        key: String,
        site: String,
        kind: NetworkSegmentKind,
        name: String,
        vlanID: Int,
        rank: NetworkMember<Int> = .unstated,
        filterIds: [String]? = nil,
        enabled: Bool? = nil
    ) {
        self.key = key
        self.site = site
        self.kind = kind
        self.name = name
        self.vlanID = vlanID
        self.rank = rank
        self.filterIds = filterIds
        self.enabled = enabled
    }
}

/// One reply profile a manifest declares (§27.6.2 item 1, `network.profiles[]`).
///
/// Its natural key is **its segment**: it has no name or id of its own and is addressed by the
/// segment's id. `termination_action` has no `.null`: the server always returns a concrete value
/// for it, so a manifest stating "none" could never converge.
public struct NetworkProfileSpec: Sendable, Equatable {
    /// The ``NetworkSegmentSpec/key`` of a segment spec of the **same manifest**. A key that
    /// names none is refused at `plan` with no request sent.
    public var segment: String
    /// Compared with the **effective** (clamped) value the read returns (§36.3 rule 6). A value
    /// above the tenant's cap is an `Update` in `plan`, and `apply`'s replace is refused by the
    /// server with `403 authorization_denied` — reported as given, `apply` stops, nothing is
    /// retried or lowered by the SDK.
    public var sessionTimeoutSecs: Int
    /// `nil` is silence.
    public var terminationAction: RadiusTerminationAction?
    /// Never above `sessionTimeoutSecs`. `.null` states "none".
    public var idleTimeoutSecs: NetworkMember<Int>
    /// One of the segment's `filter_ids`. `.null` states "none".
    public var filterID: NetworkMember<String>
    /// `framed_user` or none. `.null` states "none".
    public var serviceType: NetworkMember<RadiusServiceType>

    public init(
        segment: String,
        sessionTimeoutSecs: Int,
        terminationAction: RadiusTerminationAction? = nil,
        idleTimeoutSecs: NetworkMember<Int> = .unstated,
        filterID: NetworkMember<String> = .unstated,
        serviceType: NetworkMember<RadiusServiceType> = .unstated
    ) {
        self.segment = segment
        self.sessionTimeoutSecs = sessionTimeoutSecs
        self.terminationAction = terminationAction
        self.idleTimeoutSecs = idleTimeoutSecs
        self.filterID = filterID
        self.serviceType = serviceType
    }
}

/// The tenant's `Session-Timeout` cap (§27.6.2 item 1, `network.policy`): a **singleton**, so it
/// has no key and a manifest carries at most one. It always exists on the server (the default,
/// `version` 0, until the tenant first writes one), so it is never a `Create`; it is `NoChange`
/// or `Update`, and it is never deleted or pruned.
public struct NetworkPolicySpec: Sendable, Equatable {
    /// 300–86 400 (the server judges the range).
    public var sessionTimeoutMaxSecs: Int

    public init(sessionTimeoutMaxSecs: Int) {
        self.sessionTimeoutMaxSecs = sessionTimeoutMaxSecs
    }
}

/// The `network` section of a ``Manifest`` (§27.6.2).
public struct NetworkManifest: Sendable, Equatable {
    public var segments: [NetworkSegmentSpec]
    public var profiles: [NetworkProfileSpec]
    /// At most one: the cap is the tenant's, and an optional cannot hold two.
    public var policy: NetworkPolicySpec?

    public init(
        segments: [NetworkSegmentSpec] = [],
        profiles: [NetworkProfileSpec] = [],
        policy: NetworkPolicySpec? = nil
    ) {
        self.segments = segments
        self.profiles = profiles
        self.policy = policy
    }

    /// Whether the section declares nothing — a manifest then plans as it did before 1.62.
    public var isEmpty: Bool { segments.isEmpty && profiles.isEmpty && policy == nil }
}

extension Declare {
    /// A network segment (§27.6.2). See ``NetworkSegmentSpec``.
    public static func networkSegment(
        _ key: String,
        site: String,
        kind: NetworkSegmentKind,
        name: String,
        vlanID: Int,
        rank: NetworkMember<Int> = .unstated,
        filterIds: [String]? = nil,
        enabled: Bool? = nil
    ) -> NetworkSegmentSpec {
        NetworkSegmentSpec(
            key: key, site: site, kind: kind, name: name, vlanID: vlanID, rank: rank,
            filterIds: filterIds, enabled: enabled)
    }

    /// The reply profile of a segment of the same manifest (§27.6.2). See ``NetworkProfileSpec``.
    public static func networkProfile(
        segment: String,
        sessionTimeoutSecs: Int,
        terminationAction: RadiusTerminationAction? = nil,
        idleTimeoutSecs: NetworkMember<Int> = .unstated,
        filterID: NetworkMember<String> = .unstated,
        serviceType: NetworkMember<RadiusServiceType> = .unstated
    ) -> NetworkProfileSpec {
        NetworkProfileSpec(
            segment: segment, sessionTimeoutSecs: sessionTimeoutSecs,
            terminationAction: terminationAction, idleTimeoutSecs: idleTimeoutSecs,
            filterID: filterID, serviceType: serviceType)
    }

    /// The tenant's `Session-Timeout` cap (§27.6.2). See ``NetworkPolicySpec``.
    public static func networkPolicy(sessionTimeoutMaxSecs: Int) -> NetworkPolicySpec {
        NetworkPolicySpec(sessionTimeoutMaxSecs: sessionTimeoutMaxSecs)
    }
}

// MARK: - The plan's entries

/// Which `network` object a ``NetworkChange`` is for.
public enum NetworkChangeKind: String, Sendable, CaseIterable {
    case policy
    case segment
    case profile
}

/// What a plan intends to do to one `network` object, and what `apply` did.
///
/// Carries what `plan` READ — the ids and versions a replacement must send exactly — and, in an
/// `apply`'s outcome, what the write's response returned.
public struct NetworkChange: Sendable, Equatable {
    /// The `key` of a policy change.
    public static let policyKey = "policy"

    public let kind: NetworkChangeKind
    /// `"policy"` for the policy; a segment spec's `key` for a segment; for a profile, the `key`
    /// of its segment (a profile has no key of its own).
    public let key: String
    /// `create`, `update` or `unchanged`. There is no delete (this SDK does not prune).
    public let action: ChangeAction
    /// The segment's server id — the segment's own, or its profile's owner — when it exists.
    /// In an outcome of `create_segment`, the new id.
    public let segmentID: String?
    /// The version `plan` read (the policy's, the segment's or the profile's own), which the
    /// replacement sends exactly. `nil` for a `Create`.
    public let version: Int?
    /// A profile's owning segment's version as `plan` read it. `nil` when this apply creates the
    /// segment. `apply` sends the segment write's response version instead when it wrote one.
    public let segmentVersion: Int?
    /// The `version` the write's response carried; `nil` in a plan.
    public let writtenVersion: Int?
    public let policy: NetworkPolicySpec?
    public let segment: NetworkSegmentSpec?
    public let profile: NetworkProfileSpec?

    // What the read held, for the members a replacement carries over.
    let readSegment: NetworkSegmentRead?
    let readProfile: NetworkProfileRead?

    init(
        kind: NetworkChangeKind,
        key: String,
        action: ChangeAction,
        segmentID: String? = nil,
        version: Int? = nil,
        segmentVersion: Int? = nil,
        writtenVersion: Int? = nil,
        policy: NetworkPolicySpec? = nil,
        segment: NetworkSegmentSpec? = nil,
        profile: NetworkProfileSpec? = nil,
        readSegment: NetworkSegmentRead? = nil,
        readProfile: NetworkProfileRead? = nil
    ) {
        self.kind = kind
        self.key = key
        self.action = action
        self.segmentID = segmentID
        self.version = version
        self.segmentVersion = segmentVersion
        self.writtenVersion = writtenVersion
        self.policy = policy
        self.segment = segment
        self.profile = profile
        self.readSegment = readSegment
        self.readProfile = readProfile
    }

    /// A one-line rendering, e.g. `update network_segment:site-a-access`.
    public var describe: String {
        "\(action.rawValue) network_\(kind.rawValue):\(key)"
    }

    /// This change as an outcome: the id a `Create` returned, and the version the response carried.
    func written(segmentID newID: String? = nil, version newVersion: Int?) -> NetworkChange {
        NetworkChange(
            kind: kind, key: key, action: action, segmentID: newID ?? segmentID, version: version,
            segmentVersion: segmentVersion, writtenVersion: newVersion, policy: policy,
            segment: segment, profile: profile, readSegment: readSegment, readProfile: readProfile)
    }

    /// The natural key of a segment, as one string. The separator is a control character no site,
    /// kind or name (each `^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`) can contain.
    static func naturalKey(site: String, kind: String, name: String) -> String {
        [site, kind, name].joined(separator: "\u{1F}")
    }
}

/// A segment as `plan` read it: only the members a replacement carries over.
struct NetworkSegmentRead: Sendable, Equatable {
    let vlanID: Int
    let rank: Int?
    let filterIds: [String]
    let enabled: Bool
}

/// A profile as `plan` read it — the effective profile — for the members a replacement carries.
struct NetworkProfileRead: Sendable, Equatable {
    let dictionary: String
    let terminationAction: RadiusTerminationAction
    let idleTimeoutSecs: Int?
    let filterID: String?
    let serviceType: RadiusServiceType?
}

/// What `apply` knows about each segment while it runs: the id and the CURRENT version, which a
/// profile write must send as `segment_version`. Seeded from the plan, then moved by each
/// segment write's own response (§27.6.2 item 4).
struct NetworkApplyState {
    var ids: [String: String] = [:]
    var versions: [String: Int] = [:]

    init(changes: [NetworkChange]) {
        for change in changes where change.kind == .segment {
            if let id = change.segmentID { ids[change.key] = id }
            if let version = change.version { versions[change.key] = version }
        }
    }
}

// MARK: - Validate, plan, apply

extension ManifestApi {

    /// §27.6.2 item 1's refusals, every one made from the manifest alone, before any request.
    static func validateNetwork(_ network: NetworkManifest) throws {
        var keys = Set<String>()
        var naturals = Set<String>()
        for segment in network.segments {
            guard !segment.key.isEmpty else {
                throw ManifestError("manifest: every network segment needs a key")
            }
            guard keys.insert(segment.key).inserted else {
                throw ManifestError(
                    "manifest declares network segment \"\(segment.key)\" twice — a key must be "
                    + "unique within the manifest")
            }
            // The kind is the wire spelling. `.unknown` is what a value this SDK has no name for
            // decodes to, and it is never sent (§36.2).
            guard segment.kind != .unknown else {
                throw ManifestError(
                    "network segment \"\(segment.key)\" has no kind this SDK can send — a "
                    + "segment's kind is `access` or `quarantine`, the wire spelling "
                    + "(CONTRACT.md §27.6.2 item 1)")
            }
            let natural = NetworkChange.naturalKey(
                site: segment.site, kind: segment.kind.rawValue, name: segment.name)
            guard naturals.insert(natural).inserted else {
                throw ManifestError(
                    "network segment \"\(segment.key)\" repeats the natural key (site "
                    + "\"\(segment.site)\", kind \"\(segment.kind.rawValue)\", name "
                    + "\"\(segment.name)\") of another — one server row cannot satisfy both "
                    + "(CONTRACT.md §27.6.2 item 1). No request was sent.")
            }
            // `filter_ids` are compared as a set, and a set has no repeated member.
            if let ids = segment.filterIds, Set(ids).count != ids.count {
                throw ManifestError(
                    "network segment \"\(segment.key)\" lists a Filter-Id more than once in its "
                    + "filter_ids, which are compared as a set (CONTRACT.md §27.6.2 item 1). "
                    + "No request was sent.")
            }
        }

        var profiled = Set<String>()
        for profile in network.profiles {
            // A dangling reference: the manifest does not reach for a segment it does not declare.
            guard keys.contains(profile.segment) else {
                throw ManifestError(
                    "a network profile names segment \"\(profile.segment)\", which this manifest "
                    + "does not declare (CONTRACT.md §27.6.2 item 1). No request was sent.")
            }
            guard profiled.insert(profile.segment).inserted else {
                throw ManifestError(
                    "network segment \"\(profile.segment)\" has two profiles in this manifest — a "
                    + "profile is keyed by its segment, so one server row cannot satisfy both "
                    + "(CONTRACT.md §27.6.2 item 1). No request was sent.")
            }
        }
    }

    /// The `network` half of `plan` (§27.6.2 item 3): `GET`s only, each list walked to exhaustion,
    /// every stated member judged on the read.
    func planNetwork(_ network: NetworkManifest) async throws -> [NetworkChange] {
        guard !network.isEmpty else { return [] }
        let api = NetworkApi(client: client, scope: scope)
        let page = PageRequest(offset: 0, limit: Self.scanLimit)
        var changes: [NetworkChange] = []

        // 1. The policy: it exists on the server from the start, so it is never a Create.
        if let policy = network.policy {
            let read = try await api.getPolicy()
            let drifted = read.sessionTimeoutMaxSecs != policy.sessionTimeoutMaxSecs
            changes.append(NetworkChange(
                kind: .policy, key: NetworkChange.policyKey,
                action: drifted ? .update : .unchanged,
                version: read.version, policy: policy))
        }
        guard !network.segments.isEmpty else { return changes }

        // 2. The segments, in key order, so a plan is stable.
        let readSegments = try await api.listSegmentsAll(page: page).collect()
        var readByNaturalKey: [String: NetworkSegmentResponse] = [:]
        for item in readSegments {
            let natural = NetworkChange.naturalKey(
                site: item.siteKey, kind: item.kind.rawValue, name: item.name)
            if readByNaturalKey[natural] == nil { readByNaturalKey[natural] = item }
        }
        var readByManifestKey: [String: NetworkSegmentResponse] = [:]
        for spec in network.segments.sorted(by: { $0.key < $1.key }) {
            let natural = NetworkChange.naturalKey(
                site: spec.site, kind: spec.kind.rawValue, name: spec.name)
            guard let found = readByNaturalKey[natural] else {
                changes.append(NetworkChange(
                    kind: .segment, key: spec.key, action: .create, segment: spec))
                continue
            }
            readByManifestKey[spec.key] = found
            changes.append(NetworkChange(
                kind: .segment, key: spec.key,
                action: Self.segmentDrifted(spec, read: found) ? .update : .unchanged,
                segmentID: found.id, version: found.version, segment: spec,
                readSegment: NetworkSegmentRead(
                    vlanID: found.vlanID, rank: found.rank, filterIds: found.filterIds,
                    enabled: found.enabled)))
        }
        guard !network.profiles.isEmpty else { return changes }

        // 3. The profiles, in the segments' order, each matched to its segment by `segment_id`.
        let readProfiles = try await api.listProfilesAll(page: page).collect()
        var readBySegmentID: [String: NetworkReplyProfile] = [:]
        for item in readProfiles where readBySegmentID[item.segmentID] == nil {
            readBySegmentID[item.segmentID] = item
        }
        for spec in network.profiles.sorted(by: { $0.segment < $1.segment }) {
            // A segment this apply creates has no profile yet, and no id.
            guard let segment = readByManifestKey[spec.segment] else {
                changes.append(NetworkChange(
                    kind: .profile, key: spec.segment, action: .create, profile: spec))
                continue
            }
            guard let found = readBySegmentID[segment.id] else {
                changes.append(NetworkChange(
                    kind: .profile, key: spec.segment, action: .create,
                    segmentID: segment.id, segmentVersion: segment.version, profile: spec))
                continue
            }
            changes.append(NetworkChange(
                kind: .profile, key: spec.segment,
                action: Self.profileDrifted(spec, read: found) ? .update : .unchanged,
                segmentID: segment.id, version: found.version, segmentVersion: segment.version,
                profile: spec,
                readProfile: NetworkProfileRead(
                    dictionary: found.dictionary, terminationAction: found.terminationAction,
                    idleTimeoutSecs: found.idleTimeoutSecs, filterID: found.filterID,
                    serviceType: found.serviceType)))
        }
        return changes
    }

    /// Whether a STATED member of a segment differs from the read. `site`, `kind` and `name` are
    /// the key and never drift; `filter_ids` compare as a set.
    static func segmentDrifted(_ spec: NetworkSegmentSpec, read: NetworkSegmentResponse) -> Bool {
        if spec.vlanID != read.vlanID { return true }
        if spec.rank.differs(from: read.rank) { return true }
        if let ids = spec.filterIds, Set(ids) != Set(read.filterIds) { return true }
        if let enabled = spec.enabled, enabled != read.enabled { return true }
        return false
    }

    /// Whether a STATED member of a profile differs from the read — the EFFECTIVE profile, so a
    /// stated timeout above a lowered cap differs from the clamped value the read returns.
    static func profileDrifted(_ spec: NetworkProfileSpec, read: NetworkReplyProfile) -> Bool {
        if spec.sessionTimeoutSecs != read.sessionTimeoutSecs { return true }
        if let action = spec.terminationAction, action != read.terminationAction { return true }
        if spec.idleTimeoutSecs.differs(from: read.idleTimeoutSecs) { return true }
        if spec.filterID.differs(from: read.filterID) { return true }
        if spec.serviceType.differs(from: read.serviceType) { return true }
        return false
    }

    /// Send one `network` action, once, and return it as an outcome (§27.6.2 item 4).
    ///
    /// A replacement's body is built from the read: stated members replace the read's, unstated
    /// ones are carried from it, a member stated as none is left out. The version is the one
    /// `plan` read. A profile's `segment_version` is the CURRENT version of its segment in
    /// `state` — the response of this apply's own write of that segment when there was one —
    /// because the segment write moved it, and the one `plan` read would be `409
    /// stale_version` on every profile that follows a changed segment. There is no retry and no
    /// re-read: a stale version means another administrator wrote (§36.9).
    func performNetwork(_ change: NetworkChange, state: inout NetworkApplyState) async throws -> NetworkChange {
        let api = NetworkApi(client: client, scope: scope)

        switch change.kind {
        case .policy:
            guard let policy = change.policy else {
                throw ManifestError("network policy change carries no spec (internal error)")
            }
            let written = try await api.replacePolicy(body: ReplaceNetworkPolicyRequest(
                sessionTimeoutMaxSecs: policy.sessionTimeoutMaxSecs, version: change.version ?? 0))
            return change.written(version: written.version)

        case .segment:
            guard let spec = change.segment else {
                throw ManifestError("network segment change carries no spec (internal error)")
            }
            if change.action == .create {
                // `filter_ids` and `enabled` take the server's defaults when unstated; `rank`
                // is sent only when stated with a value, and none is omitted.
                let created = try await api.createSegment(body: CreateNetworkSegmentRequest(
                    enabled: spec.enabled,
                    filterIds: spec.filterIds,
                    kind: spec.kind,
                    name: spec.name,
                    rank: spec.rank.statedValue,
                    siteKey: spec.site,
                    vlanID: spec.vlanID))
                state.ids[change.key] = created.id
                state.versions[change.key] = created.version
                return change.written(segmentID: created.id, version: created.version)
            }
            guard let id = change.segmentID, let version = change.version,
                  let read = change.readSegment
            else {
                throw ManifestError("network segment \"\(change.key)\" has no read to replace from (internal error)")
            }
            // `kind`, `site_key` and `name` are not in the replacement body (§36.2).
            let replaced = try await api.replaceSegment(id: id, body: ReplaceNetworkSegmentRequest(
                enabled: spec.enabled ?? read.enabled,
                filterIds: spec.filterIds ?? read.filterIds,
                rank: spec.rank.resolved(carrying: read.rank),
                version: version,
                vlanID: spec.vlanID))
            state.versions[change.key] = replaced.version
            return change.written(version: replaced.version)

        case .profile:
            guard let spec = change.profile else {
                throw ManifestError("network profile change carries no spec (internal error)")
            }
            guard let segmentID = state.ids[change.key],
                  let segmentVersion = state.versions[change.key]
            else {
                throw ManifestError(
                    "the profile of network segment \"\(change.key)\" has no segment id and "
                    + "version to write against (internal error)")
            }
            if change.action == .create {
                // The dictionary is not a manifest member: omitted, so the server's default holds.
                let created = try await api.createProfile(body: CreateNetworkReplyProfileRequest(
                    profile: NetworkReplyProfileInput(
                        dictionary: nil,
                        filterID: spec.filterID.statedValue,
                        idleTimeoutSecs: spec.idleTimeoutSecs.statedValue,
                        serviceType: spec.serviceType.statedValue,
                        sessionTimeoutSecs: spec.sessionTimeoutSecs,
                        terminationAction: spec.terminationAction),
                    segmentID: segmentID,
                    segmentVersion: segmentVersion))
                return change.written(segmentID: segmentID, version: created.version)
            }
            guard let version = change.version, let read = change.readProfile else {
                throw ManifestError(
                    "the profile of network segment \"\(change.key)\" has no read to replace "
                    + "from (internal error)")
            }
            // A carried `session_timeout_secs` would be the read's EFFECTIVE value, but it is a
            // stated member here, so it is the manifest's; the profile's `dictionary` is carried
            // from the read so a replacement never silently resets it.
            let replaced = try await api.replaceProfile(
                segmentID: segmentID,
                body: ReplaceNetworkReplyProfileRequest(
                    profile: NetworkReplyProfileInput(
                        dictionary: read.dictionary,
                        filterID: spec.filterID.resolved(carrying: read.filterID),
                        idleTimeoutSecs: spec.idleTimeoutSecs.resolved(carrying: read.idleTimeoutSecs),
                        serviceType: spec.serviceType.resolved(carrying: read.serviceType),
                        sessionTimeoutSecs: spec.sessionTimeoutSecs,
                        terminationAction: spec.terminationAction ?? read.terminationAction),
                    segmentVersion: segmentVersion,
                    version: version))
            return change.written(version: replaced.version)
        }
    }

    /// The text of a failed `network` action: the server's own message where the error carries
    /// one, so a refusal is reported as given.
    static func networkFailureText(_ error: Error) -> String {
        if let axiam = error as? AxiamError {
            switch axiam {
            case .auth(let failure): return failure.message
            case .authz(let failure): return failure.message
            case .network(let failure): return failure.message
            }
        }
        return String(describing: error)
    }
}
