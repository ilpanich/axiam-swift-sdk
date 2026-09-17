import Foundation

// CONTRACT.md §28 — MCP resource-server helpers (RFC 9728 + RFC 6750).
//
// This is the *resource-server* half of the Model Context Protocol authorization handshake:
// publishing the RFC 9728 protected-resource metadata document that tells a client which
// authorization server guards this resource, and emitting the `WWW-Authenticate` challenge that
// starts the client's discovery. It is additive to §10/§11 and changes neither (§28.0).
//
// **Nothing here performs network I/O.** All three canonical operations —
// `protected_resource_metadata`, `serve_protected_resource_metadata` (this SDK: the
// `AxiamRequestAuthenticator`/`AxiamGuards` integration plus the Vapor route the README shows),
// and `bearer_challenge` — are pure local computation, like `oidcBegin` and `umaParseChallenge`.
// So neither §16 (retry) nor §9 (single-flight refresh) applies, and nothing here touches an
// `AxiamClient`'s own session.
//
// **Nothing here is a source of truth about a token.** The document is a claim a resource server
// publishes about itself; the challenge is a hint it gives a caller that already failed. Whether a
// request is authorized stays §10.1's and §11's decision, unchanged and unreachable from here.

// MARK: - §28.1 / §28.4 error vocabulary

/// RFC 6750 §3.1's three error codes — the complete vocabulary a challenge may name (§28.4).
///
/// A caseless enum of `String` constants rather than a `String`-backed `enum` with cases — the
/// same choice ``ReasonCode`` makes and for a related reason: ``AxiamClient/bearerChallenge(resourceMetadataUrl:error:errorDescription:scope:)``
/// validates `error` against exactly these three values and refuses anything else (§28.9 test 2
/// requires refusing a well-formed-looking code such as `invalid_grant`), which a plain `String`
/// parameter lets a test exercise directly.
public enum BearerChallengeError {
    public static let invalidRequest = "invalid_request"
    public static let invalidToken = "invalid_token"
    public static let insufficientScope = "insufficient_scope"
}

// MARK: - §28.2 the document

/// The RFC 9728 §2 document, carrying **at most** the five members §28.2 permits, in that order,
/// and no others.
///
/// `scopesSupported` and `resourceDocumentation` are **omitted rather than emitted empty or
/// `null`** when the caller passed none — `Codable`'s synthesized conformance already does this
/// for a `nil` `Optional`, which is why both are declared optional here rather than defaulted to
/// an empty value.
public struct ProtectedResourceMetadataDocument: Sendable, Equatable, Codable {
    /// The resource identifier this server publishes for itself — the string an RFC 8707
    /// `resource` parameter carries and the `aud` the guard checks.
    public let resource: String
    /// The issuer identifiers of the authorization servers that guard this resource. At least
    /// one, each verbatim.
    public let authorizationServers: [String]
    /// The scope tokens this resource server understands, in the caller's order. Omitted when the
    /// caller passed none.
    public let scopesSupported: [String]?
    /// Always `["header"]` in this contract version — §10's guard reads a bearer credential from
    /// the `Authorization` header alone.
    public let bearerMethodsSupported: [String]
    /// A human-readable documentation page. Omitted when the caller passed none; never `null`.
    public let resourceDocumentation: String?

    enum CodingKeys: String, CodingKey {
        case resource
        case authorizationServers = "authorization_servers"
        case scopesSupported = "scopes_supported"
        case bearerMethodsSupported = "bearer_methods_supported"
        case resourceDocumentation = "resource_documentation"
    }
}

/// What ``AxiamClient/protectedResourceMetadata(resource:authorizationServers:scopesSupported:bearerMethodsSupported:resourceDocumentation:)``
/// returns: the document, the path it is served at, and the URL that path resolves to.
///
/// `metadataUrl` exists so that ``AxiamConfig/resourceMetadataUrl`` is fed from the value this
/// produced rather than retyped — retyping is how the two come to disagree, and a challenge
/// pointing at a document that is not this resource server's is worse than no challenge at all.
public struct ProtectedResourceMetadata: Sendable, Equatable {
    /// The RFC 9728 §2 document, ready to serialize.
    public let document: ProtectedResourceMetadataDocument
    /// The absolute path the document is served at, derived from `resource` per §28.3 — never
    /// chosen.
    public let metadataPath: String
    /// `metadataPath` resolved against the resource's scheme and authority. Feed this to
    /// ``AxiamConfig/resourceMetadataUrl``.
    public let metadataUrl: String
    /// The document serialized once, so a route that serves it returns the identical bytes to
    /// every caller (§28.3 rule 4) rather than a fresh — though value-identical — encoding per
    /// request.
    public let jsonBody: Data
}

// MARK: - §28 internals shared by the public operations and the guard integration

enum McpResourceServer {
    /// RFC 9728 §3.1's well-known prefix — the segment inserted between a resource's authority and
    /// its path to reach the document that describes it.
    static let metadataPrefix = "/.well-known/oauth-protected-resource"

    /// The three hosts §28.2 rule 2 lets an `http` URL use, and the only ones — AXIAM's RFC 8252
    /// §7.3 loopback hosts, reused verbatim. There is deliberately no flag, environment variable or
    /// debug build that widens this.
    static let loopbackHosts: Set<String> = ["127.0.0.1", "[::1]", "localhost"]

    /// Build §28's refusal: always `NetworkError(isValidation: true)`, per §27.4 rule 7's
    /// precedent for rendering the contract's `ValidationError` in a taxonomy with no dedicated
    /// type for it (§28.6: "§28's refusals are ValidationError; no new type").
    static func refuse(_ operation: String, _ field: String, _ message: String) -> NetworkError {
        NetworkError("\(operation): \(field): \(message) (CONTRACT.md §28)", statusCode: 400, isValidation: true)
    }

    // MARK: Character classes (RFC 6749 Appendix A) — §28.2 rule 5, §28.4

    /// `NQCHAR`: `%x21` / `%x23`–`%x5B` / `%x5D`–`%x7E`. No space, no `"`, no `\`, no control, no
    /// non-ASCII.
    static func isNqchar(_ scalar: Unicode.Scalar) -> Bool {
        let value = scalar.value
        return value == 0x21 || (value >= 0x23 && value <= 0x5B) || (value >= 0x5D && value <= 0x7E)
    }

    /// `NQSCHAR`: `NQCHAR` plus the space (`%x20`).
    static func isNqschar(_ scalar: Unicode.Scalar) -> Bool {
        scalar.value == 0x20 || isNqchar(scalar)
    }

    /// `true` when `value` is non-empty and every scalar satisfies `predicate`. A validator MUST
    /// require "one or more characters" (§28.2 rule 5, §28.4): an empty string trivially satisfies
    /// `allSatisfy` on its own, which is why this is not spelled `value.unicodeScalars.allSatisfy`.
    static func isAll(_ value: String, _ predicate: (Unicode.Scalar) -> Bool) -> Bool {
        !value.unicodeScalars.isEmpty && value.unicodeScalars.allSatisfy(predicate)
    }

    // MARK: Absolute-URI parsing (§28.2 rules 1, 2, 3, 7)

    /// The pieces of an absolute URI, sliced out of the caller's string without normalisation.
    struct ParsedUri {
        /// The scheme, verbatim (compared case-insensitively, stored as written).
        let scheme: String
        /// The authority, verbatim — `userinfo@host:port` included.
        let authority: String
        /// The path component: empty, or starting with `/`. A trailing slash is preserved.
        let path: String
        /// `true` when the string carried a `?`, even an empty one.
        let hasQuery: Bool
        /// `true` when the string carried a `#`, even an empty one.
        let hasFragment: Bool
    }

    /// `scheme://authority[path][?query][#fragment]`, matched against the caller's string exactly
    /// as given.
    ///
    /// Deliberately not `URLComponents` or `URL`: both *normalise* — resolving `..` segments,
    /// percent-decoding, appending a path to an authority-only URL. §28.2 forbids adjusting a
    /// value to make it pass, and §28.3 derives the document's own path from this string, so what
    /// is validated must be exactly what was written.
    static func parseAbsoluteUri(_ raw: String) -> ParsedUri? {
        guard let schemeEnd = raw.range(of: "://") else { return nil }
        let scheme = String(raw[raw.startIndex..<schemeEnd.lowerBound])
        guard isValidScheme(scheme) else { return nil }

        var rest = raw[schemeEnd.upperBound...]
        var authorityEnd = rest.startIndex
        while authorityEnd < rest.endIndex, !"/?#".contains(rest[authorityEnd]) {
            authorityEnd = rest.index(after: authorityEnd)
        }
        let authority = String(rest[rest.startIndex..<authorityEnd])
        guard !authority.isEmpty else { return nil }
        rest = rest[authorityEnd...]

        var pathEnd = rest.startIndex
        while pathEnd < rest.endIndex, !"?#".contains(rest[pathEnd]) {
            pathEnd = rest.index(after: pathEnd)
        }
        let path = String(rest[rest.startIndex..<pathEnd])
        rest = rest[pathEnd...]

        var hasQuery = false
        if rest.first == "?" {
            hasQuery = true
            if let fragmentStart = rest.firstIndex(of: "#") {
                rest = rest[fragmentStart...]
            } else {
                rest = rest[rest.endIndex...]
            }
        }
        let hasFragment = rest.first == "#"

        return ParsedUri(scheme: scheme, authority: authority, path: path, hasQuery: hasQuery, hasFragment: hasFragment)
    }

    /// `[A-Za-z][A-Za-z0-9+.-]*` — RFC 3986 §3.1's scheme grammar. Checked against ASCII ranges
    /// directly rather than `CharacterSet.letters`/`.decimalDigits`, which admit every Unicode
    /// letter and digit, not only the ASCII ones the grammar names.
    private static func isValidScheme(_ scheme: String) -> Bool {
        func isAsciiLetter(_ v: UInt32) -> Bool { (0x41...0x5A).contains(v) || (0x61...0x7A).contains(v) }
        func isAsciiDigit(_ v: UInt32) -> Bool { (0x30...0x39).contains(v) }
        guard let first = scheme.unicodeScalars.first, isAsciiLetter(first.value) else { return false }
        return scheme.unicodeScalars.allSatisfy {
            isAsciiLetter($0.value) || isAsciiDigit($0.value) || $0 == "+" || $0 == "." || $0 == "-"
        }
    }

    /// The host inside an authority: `userinfo@` stripped, port stripped, an IPv6 literal's
    /// brackets kept (so `[::1]` compares as §28.2 rule 2 spells it).
    static func hostOf(_ authority: String) -> String {
        var hostport = Substring(authority)
        if let at = hostport.lastIndex(of: "@") {
            hostport = hostport[hostport.index(after: at)...]
        }
        if hostport.first == "[" {
            if let close = hostport.firstIndex(of: "]") {
                return String(hostport[hostport.startIndex...close])
            }
            return String(hostport)
        }
        if let colon = hostport.firstIndex(of: ":") {
            return String(hostport[hostport.startIndex..<colon])
        }
        return String(hostport)
    }

    /// How much of §28.2 rule 1 a particular member is held to — rule 7 and §28.4's
    /// `resource_metadata` relax two parts of it.
    enum UriPolicy {
        /// `resource`, `authorization_servers` entries: no query, no fragment.
        case identifier
        /// `resource_documentation` (§28.2 rule 7), `resource_metadata` (§28.4): a page for a
        /// human, or a URL a client dereferences, may carry both.
        case locator
    }

    /// §28.2 rules 1 and 2, applied to one member.
    static func requireAbsoluteUri(
        _ operation: String, _ field: String, _ raw: String, _ policy: UriPolicy
    ) throws -> ParsedUri {
        guard !raw.isEmpty else {
            throw refuse(operation, field, "must be a non-empty absolute URI")
        }
        guard let parsed = parseAbsoluteUri(raw) else {
            throw refuse(operation, field, "must be an absolute URI with a scheme and an authority, not \"\(raw)\"")
        }
        if parsed.hasQuery, case .identifier = policy {
            throw refuse(operation, field, "must carry no query — §28.3 derives the metadata path from it")
        }
        if parsed.hasFragment, case .identifier = policy {
            throw refuse(operation, field, "must carry no fragment")
        }
        let scheme = parsed.scheme.lowercased()
        if scheme == "https" { return parsed }
        if scheme == "http", loopbackHosts.contains(hostOf(parsed.authority).lowercased()) {
            return parsed
        }
        throw refuse(
            operation, field,
            "must use https — http is accepted only on 127.0.0.1, [::1] or localhost, and \"\(raw)\" is neither")
    }

    /// §28.3's derivation: RFC 9728 §3.1 inserts the well-known segment between the authority and
    /// the path. An empty path and a bare `/` both reach the root form; anything else is appended,
    /// **trailing slash included** — it is part of the identifier a client compares, and two
    /// resources that differ only by it are two resources.
    static func deriveMetadataPath(_ resourcePath: String) -> String {
        resourcePath.isEmpty || resourcePath == "/" ? metadataPrefix : metadataPrefix + resourcePath
    }

    // MARK: §28.4 raw formatting — used by the validating public API and by the guard
    // integration's precomputed challenges, whose inputs are already known-valid.

    /// Assemble a `WWW-Authenticate` value from already-validated parts. Never validates and never
    /// escapes — callers that have not validated their inputs must go through
    /// ``AxiamClient/bearerChallenge(resourceMetadataUrl:error:errorDescription:scope:)``.
    static func formatChallenge(
        resourceMetadataUrl: String, error: String?, errorDescription: String?, scope: String?
    ) -> String {
        var params: [String] = []
        if let error { params.append("error=\"\(error)\"") }
        if let errorDescription { params.append("error_description=\"\(errorDescription)\"") }
        if let scope { params.append("scope=\"\(scope)\"") }
        params.append("resource_metadata=\"\(resourceMetadataUrl)\"")
        return "Bearer " + params.joined(separator: ", ")
    }
}

// MARK: - §28.1 / §28.2 — `protectedResourceMetadata`

extension AxiamClient {
    /// `protectedResourceMetadata(...)` (CONTRACT.md §28.1) — build and validate the RFC 9728
    /// protected-resource metadata document this server publishes about itself, and derive the
    /// path and URL it is served at.
    ///
    /// **Validation happens here and it refuses; it never repairs** (§28.2). Every rule is checked
    /// before any request is served, and a violation throws ``NetworkError`` with
    /// ``NetworkError/isValidation`` set — this SDK's rendering of the contract's `ValidationError`
    /// (§28.6: no new error type). Nothing is normalised, trimmed, lowercased or re-encoded to make
    /// a value pass.
    ///
    /// **Nothing in the document may come from a request** (§28.2 rule 8). Both `resource` and
    /// `authorizationServers` are configuration; there is no overload that builds either from a
    /// `Host` header or a request URL.
    ///
    /// - Parameters:
    ///   - resource: Absolute, `https` (or `http` on a loopback host), with no query and no
    ///     fragment. A trailing slash is significant.
    ///   - authorizationServers: At least one issuer identifier, no duplicates, no query, no
    ///     fragment.
    ///   - scopesSupported: The scope tokens this resource server understands. Order is preserved,
    ///     duplicates are refused, and an empty list omits the member from the document.
    ///   - bearerMethodsSupported: Defaults to `["header"]`, the only accepted value in this
    ///     contract version.
    ///   - resourceDocumentation: Optional documentation page for a human. May carry a query and a
    ///     fragment; omitted from the document when absent.
    /// - Throws: ``NetworkError`` (`isValidation == true`) when any §28.2 rule is violated.
    ///
    /// ```swift
    /// let metadata = try AxiamClient.protectedResourceMetadata(
    ///     resource: "https://mcp.example.com/mcp",
    ///     authorizationServers: ["https://axiam.example.com"],
    ///     scopesSupported: ["mcp:read", "mcp:tools"]
    /// )
    /// metadata.metadataPath  // "/.well-known/oauth-protected-resource/mcp"
    /// metadata.metadataUrl   // "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
    /// ```
    public nonisolated static func protectedResourceMetadata(
        resource: String,
        authorizationServers: [String],
        scopesSupported: [String] = [],
        bearerMethodsSupported: [String] = ["header"],
        resourceDocumentation: String? = nil
    ) throws -> ProtectedResourceMetadata {
        let op = "protectedResourceMetadata"

        // Rules 1 + 2.
        let parsedResource = try McpResourceServer.requireAbsoluteUri(op, "resource", resource, .identifier)

        // Rules 3 + 4: at least one entry, each an issuer verbatim, no duplicates.
        guard !authorizationServers.isEmpty else {
            throw McpResourceServer.refuse(
                op, "authorization_servers",
                "must name at least one authorization server — a document that names none answers none of the question the client asked")
        }
        var seenServers = Set<String>()
        var validatedServers: [String] = []
        for entry in authorizationServers {
            _ = try McpResourceServer.requireAbsoluteUri(op, "authorization_servers", entry, .identifier)
            guard !seenServers.contains(entry) else {
                throw McpResourceServer.refuse(op, "authorization_servers", "duplicate entry \"\(entry)\"")
            }
            seenServers.insert(entry)
            validatedServers.append(entry)
        }

        // Rule 5: NQCHAR tokens, order preserved, duplicates refused, empty list omits the member.
        var seenScopes = Set<String>()
        var validatedScopes: [String] = []
        for scope in scopesSupported {
            guard McpResourceServer.isAll(scope, McpResourceServer.isNqchar) else {
                throw McpResourceServer.refuse(
                    op, "scopes_supported",
                    "\"\(scope)\" is not a scope token — one or more NQCHAR (no space, no '\"', no '\\', no control character, no non-ASCII)")
            }
            guard !seenScopes.contains(scope) else {
                throw McpResourceServer.refuse(op, "scopes_supported", "duplicate scope \"\(scope)\"")
            }
            seenScopes.insert(scope)
            validatedScopes.append(scope)
        }

        // Rule 6: exactly ["header"].
        guard bearerMethodsSupported == ["header"] else {
            throw McpResourceServer.refuse(
                op, "bearer_methods_supported",
                "must be exactly [\"header\"] in this contract version — §10's guard reads a bearer credential from the Authorization header alone, so \(bearerMethodsSupported) would describe behaviour this SDK does not have")
        }

        // Rule 7: absolute URL, query and fragment permitted, omitted from the document when absent.
        if let resourceDocumentation {
            _ = try McpResourceServer.requireAbsoluteUri(op, "resource_documentation", resourceDocumentation, .locator)
        }

        let document = ProtectedResourceMetadataDocument(
            resource: resource,
            authorizationServers: validatedServers,
            scopesSupported: validatedScopes.isEmpty ? nil : validatedScopes,
            bearerMethodsSupported: ["header"],
            resourceDocumentation: resourceDocumentation
        )
        let metadataPath = McpResourceServer.deriveMetadataPath(parsedResource.path)
        let metadataUrl = "\(parsedResource.scheme)://\(parsedResource.authority)\(metadataPath)"
        // Encoding a value built entirely from validated `String`/`[String]`/`Optional` members
        // cannot fail; `JSONEncoder.encode` is `throws` only because `Encodable` is general.
        let jsonBody = (try? JSONEncoder().encode(document)) ?? Data()

        return ProtectedResourceMetadata(
            document: document, metadataPath: metadataPath, metadataUrl: metadataUrl, jsonBody: jsonBody)
    }

    // MARK: - §28.4 — `bearerChallenge`

    /// `bearerChallenge(...)` (CONTRACT.md §28.4) — build the **value** of a `WWW-Authenticate`
    /// header, never the whole header line. The caller sets the header.
    ///
    /// Parameters appear in a fixed order — `error`, `error_description`, `scope`,
    /// `resource_metadata` — separated by exactly `, `. `resourceMetadataUrl` is always present;
    /// the other three are omitted when not given.
    ///
    /// **Every value is quoted and no value is ever escaped.** RFC 6750 §3 restricts each
    /// parameter to a character set that cannot contain `"` or `\`, so a value needing an escape is
    /// a value that does not belong in a challenge: this function refuses it rather than escaping,
    /// truncating or stripping it.
    ///
    /// - Parameters:
    ///   - resourceMetadataUrl: the document's URL. May carry a query and a fragment.
    ///   - error: one of ``BearerChallengeError``'s three values, or `nil` when the request carried
    ///     no authentication information at all.
    ///   - errorDescription: for an application building **its own** challenge for its own `400`.
    ///     This SDK's own guards never set it — every distinction a 401 draws for an
    ///     unauthenticated stranger is an oracle (§28.4, §28.8).
    ///   - scope: the scope the route asked for, verbatim — one or more tokens joined by a single
    ///     space.
    /// - Throws: ``NetworkError`` (`isValidation == true`) when any parameter is outside RFC 6750's
    ///   syntax.
    ///
    /// ```swift
    /// try AxiamClient.bearerChallenge(resourceMetadataUrl: metadata.metadataUrl)
    /// // Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
    ///
    /// try AxiamClient.bearerChallenge(
    ///     resourceMetadataUrl: metadata.metadataUrl,
    ///     error: BearerChallengeError.insufficientScope, scope: "mcp:tools")
    /// // Bearer error="insufficient_scope", scope="mcp:tools", resource_metadata="https://…/mcp"
    /// ```
    public nonisolated static func bearerChallenge(
        resourceMetadataUrl: String,
        error: String? = nil,
        errorDescription: String? = nil,
        scope: String? = nil
    ) throws -> String {
        let op = "bearerChallenge"

        if let error {
            guard error == BearerChallengeError.invalidRequest
                || error == BearerChallengeError.invalidToken
                || error == BearerChallengeError.insufficientScope
            else {
                throw McpResourceServer.refuse(
                    op, "error",
                    "must be one of invalid_request, invalid_token, insufficient_scope — RFC 6750 §3.1 defines no others, and \"\(error)\" is not among them")
            }
        }

        if let errorDescription {
            guard McpResourceServer.isAll(errorDescription, McpResourceServer.isNqschar) else {
                throw McpResourceServer.refuse(
                    op, "error_description",
                    "must be one or more NQSCHAR (no '\"', no '\\', no control character, no non-ASCII) — a value needing an escape does not belong in a challenge")
            }
        }

        if let scope {
            guard !scope.isEmpty else {
                throw McpResourceServer.refuse(op, "scope", "must be one or more scope tokens joined by a single space")
            }
            for token in scope.split(separator: " ", omittingEmptySubsequences: false) {
                guard McpResourceServer.isAll(String(token), McpResourceServer.isNqchar) else {
                    throw McpResourceServer.refuse(
                        op, "scope",
                        "\"\(scope)\" is not a space-joined list of scope tokens — no leading, trailing or doubled space, and no empty token")
                }
            }
        }

        _ = try McpResourceServer.requireAbsoluteUri(op, "resource_metadata", resourceMetadataUrl, .locator)
        guard McpResourceServer.isAll(resourceMetadataUrl, McpResourceServer.isNqchar) else {
            throw McpResourceServer.refuse(
                op, "resource_metadata",
                "must carry no '\"', no '\\', no space and no control character — a correctly encoded URL cannot, so one that does has not been encoded")
        }

        return McpResourceServer.formatChallenge(
            resourceMetadataUrl: resourceMetadataUrl, error: error, errorDescription: errorDescription, scope: scope)
    }
}

// MARK: - §28.5 — the guard integration

/// The §28 challenge values a guard emits, precomputed once at
/// ``AxiamRequestAuthenticator`` construction time so that an invalid ``AxiamConfig/resourceMetadataUrl``
/// is a startup failure rather than a surprise on the 401 path.
///
/// `AxiamRequestAuthenticator.mcpChallenges` is `nil` when ``AxiamConfig/resourceMetadataUrl`` is
/// unset, which is how "§28 is off" stays byte-for-byte indistinguishable from "§28 is absent"
/// (§28.5 rule 1).
struct McpChallenges: Sendable {
    /// §28.4 vector 1 — the request carried **no** authentication information, so RFC 6750 §3 says
    /// not to name an error.
    let noCredential: String
    /// §28.4 vector 2 — a credential was presented and rejected. The only thing a 401 ever says
    /// about why (§28.4, §28.8).
    let invalidToken: String
    /// The document's path, exempted from authentication (§28.3 rule 2) — see
    /// ``AxiamRequestAuthenticator/isProtectedResourceMetadataRequest(method:path:)``.
    let metadataPath: String
    /// The validated URL every challenge this type builds is stamped with.
    private let resourceMetadataUrl: String

    /// - Precondition: `resourceMetadataUrl` has already passed
    ///   ``AxiamClient/bearerChallenge(resourceMetadataUrl:error:errorDescription:scope:)``'s
    ///   validation — ``AxiamConfig`` enforces this at construction, so this initializer cannot
    ///   fail and is not `throws`.
    init(resourceMetadataUrl: String) {
        self.resourceMetadataUrl = resourceMetadataUrl
        self.noCredential = McpResourceServer.formatChallenge(
            resourceMetadataUrl: resourceMetadataUrl, error: nil, errorDescription: nil, scope: nil)
        self.invalidToken = McpResourceServer.formatChallenge(
            resourceMetadataUrl: resourceMetadataUrl, error: BearerChallengeError.invalidToken,
            errorDescription: nil, scope: nil)
        let path = McpResourceServer.parseAbsoluteUri(resourceMetadataUrl)?.path ?? ""
        self.metadataPath = path.isEmpty ? "/" : path
    }

    /// §28.5 rule 5 — the `insufficient_scope` challenge for one route's own `scope` argument, or
    /// `nil` when `scope` is outside RFC 6750's syntax.
    ///
    /// A malformed `scope` is a caller configuration error, and CONTRACT.md §28.5 rule 5 has
    /// `AxiamGuards.requireAccess` build this "at route setup … rather than on the first denial".
    /// This SDK's `requireAccess` predates §28 and returns its handler without `throws` — adding it
    /// would be a source-breaking signature change no other §28 rule requires — so an invalid
    /// `scope` fails open on the *header* (no challenge attached; the 403 itself is unaffected)
    /// rather than failing the route registration. Nothing security-relevant depends on this
    /// header: §28's own rule is that neither the document nor the challenge is ever a source of
    /// truth about a token (§28 preamble).
    func insufficientScope(forScope scope: String) -> String? {
        try? AxiamClient.bearerChallenge(
            resourceMetadataUrl: resourceMetadataUrl, error: BearerChallengeError.insufficientScope, scope: scope)
    }
}
