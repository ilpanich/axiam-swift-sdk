import Foundation

// CONTRACT.md §27 — the hand-written half of the management API.
//
// §27.8 divides this section in two. The 146 operations and their model types are
// GENERATED from `management-registry.json` (see `Scripts/gen_management.py`, and the
// files under `Generated/`). Everything in this file is the part that is written once:
// paging, per-call scope, the error sub-types, and the JSON value the spec's free-form
// objects need.

// MARK: - Paging (§27.4 rule 4)

/// One page's worth of `?offset=`/`?limit=`.
///
/// Default-constructed means the first page at the server's default size, which is what a
/// caller who does not care about paging gets by passing nothing.
public struct PageRequest: Sendable, Equatable {
    /// How many items to skip. Clamped at 0.
    public let offset: Int
    /// How many to ask for. Clamped to at least 1.
    public let limit: Int

    public init(offset: Int = 0, limit: Int = 50) {
        self.offset = max(offset, 0)
        self.limit = max(limit, 1)
    }

    /// The page after this one — same size, advanced by exactly `limit`.
    ///
    /// By the REQUESTED limit, not by how many items came back: rule 4 stops auto-paging on
    /// an EMPTY page, not a short one, and advancing by a short count would re-request rows
    /// the caller has already seen.
    public func next() -> PageRequest {
        PageRequest(offset: offset + limit, limit: limit)
    }

    /// This request as `(name, value)` query pairs, for the URL builder.
    ///
    /// Pairs rather than `URLQueryItem`: these cross an actor boundary on every call, and a
    /// tuple of `String`s is `Sendable` on every platform without depending on which
    /// Foundation build annotated `URLQueryItem`. CI compiles one leg in Swift 6 language
    /// mode, where getting that wrong is an error rather than a warning.
    var queryPairs: [(String, String)] {
        [("offset", String(offset)), ("limit", String(limit))]
    }
}

/// One page of a paginated response.
///
/// `total` is the SERVER's count across every page. It is NOT `items.count`, and deriving
/// one from the other is how a management tool silently processes the first fifty of four
/// hundred rows — so they are separate properties and neither is computed from the other.
///
/// A bare JSON array response is NOT a page and is never modelled as one; those operations
/// return a plain `Array`.
public struct Page<Item: Sendable>: Sendable {
    /// The items on THIS page.
    public let items: [Item]
    /// The server's total across all pages. Deliberately not `items.count`.
    public let total: Int
    /// The request that produced this page.
    public let request: PageRequest

    public init(items: [Item], total: Int, request: PageRequest) {
        self.items = items
        self.total = total
        self.request = request
    }

    /// True when this page carried nothing — rule 4's stop condition.
    public var isEmpty: Bool { items.isEmpty }

    /// How many items are on THIS page.
    public var count: Int { items.count }

    /// The request that would fetch the page after this one.
    public var nextRequest: PageRequest { request.next() }
}

extension Page: Sequence {
    public func makeIterator() -> Array<Item>.Iterator { items.makeIterator() }
}

// MARK: - Per-call scope (§27.4 rule 3)

/// Overrides for the `{org_id}` / `{tenant_id}` a route substitutes.
///
/// Applied with a handle's `inOrg(_:)` / `forTenant(_:)`, which return a NEW handle rather
/// than mutating the one you called them on. An administrator holding a handle to their own
/// tenant should not find it repointed at someone else's because an unrelated code path
/// re-scoped a shared object — and on a management surface that failure mode WRITES to the
/// wrong tenant.
public struct CallScope: Sendable, Equatable {
    /// Overrides `{org_id}`.
    public let orgID: String?
    /// Overrides `{tenant_id}`.
    public let tenantID: String?

    public init(orgID: String? = nil, tenantID: String? = nil) {
        self.orgID = orgID
        self.tenantID = tenantID
    }

    func withOrg(_ id: String) -> CallScope { CallScope(orgID: id, tenantID: tenantID) }
    func withTenant(_ id: String) -> CallScope { CallScope(orgID: orgID, tenantID: id) }
}

// MARK: - The §27.4 rule 7 classification

/// Why a management call failed, beyond the §2 taxonomy's three cases.
///
/// §27.4 rule 7 describes `NotFoundError` and `ConflictError` as SUB-TYPES of `AuthzError`,
/// and `ValidationError` as a sub-type of `NetworkError`. Swift's error taxonomy here is an
/// enum with exactly three cases over three *structs*, and a struct cannot be subclassed —
/// so this SDK renders the sub-type as a discriminator ON the existing struct, exactly as it
/// already renders `OAuthProtocolError` as an `AuthError` carrying `oauthError`.
///
/// The property rule 7 actually asks for is preserved either way: a
/// `catch AxiamError.authz` written before §27 existed still catches a 404 and a 409, and a
/// `catch AxiamError.network` still catches a 422.
public enum ManagementFailure: String, Sendable, Equatable {
    /// `404`. Under `AuthzError`, which is the surprising part and the deliberate part:
    /// AXIAM answers `404` for an object in another tenant PRECISELY SO a probing caller
    /// cannot tell "does not exist" from "exists, not yours". Classifying it as an
    /// authorization outcome keeps the SDK from re-drawing a line the server deliberately
    /// refused to draw.
    case notFound
    /// `409`. Also under `AuthzError` — §2 already mapped `409` there as a resource-level
    /// refusal, and rule 7 KEEPS that mapping rather than moving it.
    case conflict
}

// MARK: - The JSON value the spec's free-form objects need

/// A JSON value, for the schema properties the spec leaves free-form (`metadata`, and the
/// payload of a discriminated union).
///
/// The alternative was inventing a Swift type per free-form field, which would silently drop
/// every key this SDK did not know to declare — and the server round-trips those. This
/// round-trips them too.
///
/// `int` is a separate case from `number` on purpose: routing every JSON number through
/// `Double` would re-encode `1` as `1` only by luck of `JSONEncoder`'s formatting, and
/// `9007199254740993` not at all.
public enum ManagementJSON: Codable, Sendable, Equatable {
    case null
    case bool(Bool)
    case int(Int)
    case number(Double)
    case string(String)
    case array([ManagementJSON])
    case object([String: ManagementJSON])

    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let value = try? container.decode(Bool.self) {
            self = .bool(value)
        } else if let value = try? container.decode(Int.self) {
            self = .int(value)
        } else if let value = try? container.decode(Double.self) {
            self = .number(value)
        } else if let value = try? container.decode(String.self) {
            self = .string(value)
        } else if let value = try? container.decode([ManagementJSON].self) {
            self = .array(value)
        } else if let value = try? container.decode([String: ManagementJSON].self) {
            self = .object(value)
        } else {
            throw DecodingError.dataCorruptedError(
                in: container, debugDescription: "not a JSON value")
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .null: try container.encodeNil()
        case .bool(let value): try container.encode(value)
        case .int(let value): try container.encode(value)
        case .number(let value): try container.encode(value)
        case .string(let value): try container.encode(value)
        case .array(let value): try container.encode(value)
        case .object(let value): try container.encode(value)
        }
    }

    /// This value's members, when it is an object; `nil` otherwise.
    public var objectValue: [String: ManagementJSON]? {
        if case .object(let members) = self { return members }
        return nil
    }

    /// One member of this object, when it is one.
    public subscript(key: String) -> ManagementJSON? { objectValue?[key] }

    /// This value as a `String`, when it is one.
    public var stringValue: String? {
        if case .string(let value) = self { return value }
        return nil
    }

    /// An empty JSON object — what a `metadata` nobody set looks like.
    public static var emptyObject: ManagementJSON { .object([:]) }
}

// MARK: - Encoding and decoding

/// The one JSON codec the §27 surface uses.
///
/// Its whole job is to keep a `DecodingError` or an `EncodingError` from escaping as itself:
/// §2 fixes the error taxonomy at three cases, and a caller catching `AxiamError` must not
/// have a `Foundation` error type reach them from underneath it.
enum ManagementCodec {
    static func encode<T: Encodable>(_ value: T) throws -> Data {
        do {
            return try JSONEncoder().encode(value)
        } catch {
            throw AxiamError.network(
                NetworkError("Failed to encode a management request body", cause: error))
        }
    }

    static func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        do {
            return try JSONDecoder().decode(type, from: data)
        } catch {
            throw AxiamError.network(
                NetworkError("Failed to decode a management response body", cause: error))
        }
    }

    /// A `{"items": [...], "total": n}` envelope (§27.4 rule 4).
    static func decodePage<T: Decodable & Sendable>(
        _ type: T.Type,
        from data: Data,
        request: PageRequest
    ) throws -> Page<T> {
        let envelope = try decode(PageEnvelope<T>.self, from: data)
        // `total` comes from the SERVER. Falling back to the page length when the field is
        // missing would manufacture a plausible wrong answer; 0 is the honest one, and the
        // page's own `count` is right there for anyone who wanted the other number.
        return Page(items: envelope.items, total: envelope.total ?? 0, request: request)
    }

    private struct PageEnvelope<T: Decodable>: Decodable {
        let items: [T]
        let total: Int?
    }
}
