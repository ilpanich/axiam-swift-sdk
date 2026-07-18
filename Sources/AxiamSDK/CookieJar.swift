import Foundation

/// A single stored cookie with the attributes the jar honours when matching outgoing requests.
struct StoredCookie: Sendable, Equatable {
    var name: String
    var value: String
    var domain: String
    var path: String
    var secure: Bool
}

/// An in-memory, per-client cookie store (§4 of CONTRACT.md).
///
/// AsyncHTTPClient does not manage cookies, so the SDK parses `Set-Cookie` response headers,
/// persists them for the lifetime of the client, and re-sends matching cookies (honouring
/// domain / path / secure) on subsequent requests. This is what lets the `httpOnly`
/// access/refresh cookies survive across calls (§4 rationale).
///
/// Not thread-safe on its own; it is always mutated under the `AxiamClient` actor's isolation.
struct CookieJar: Sendable {
    private var cookies: [StoredCookie] = []

    init() {}

    /// Number of stored cookies — used by tests to assert persistence.
    var count: Int { cookies.count }

    func value(named name: String) -> String? {
        cookies.first(where: { $0.name == name })?.value
    }

    /// Parse and store all `Set-Cookie` header lines returned for a request to `requestURL`.
    mutating func store(setCookieLines: [String], requestURL: URL) {
        for line in setCookieLines {
            if let cookie = Self.parse(setCookie: line, requestURL: requestURL) {
                upsert(cookie)
            }
        }
    }

    private mutating func upsert(_ cookie: StoredCookie) {
        if let idx = cookies.firstIndex(where: {
            $0.name == cookie.name && $0.domain == cookie.domain && $0.path == cookie.path
        }) {
            cookies[idx] = cookie
        } else {
            cookies.append(cookie)
        }
    }

    /// Build the `Cookie` request-header value for `requestURL`, or `nil` when nothing matches.
    func cookieHeader(for requestURL: URL) -> String? {
        guard let host = requestURL.host else { return nil }
        let path = requestURL.path.isEmpty ? "/" : requestURL.path
        let isSecure = (requestURL.scheme?.lowercased() == "https")

        let matches = cookies.filter { cookie in
            guard Self.domainMatches(host: host, domain: cookie.domain) else { return false }
            guard Self.pathMatches(requestPath: path, cookiePath: cookie.path) else { return false }
            if cookie.secure && !isSecure { return false }
            return true
        }
        guard !matches.isEmpty else { return nil }
        return matches.map { "\($0.name)=\($0.value)" }.joined(separator: "; ")
    }

    // MARK: - Parsing

    static func parse(setCookie: String, requestURL: URL) -> StoredCookie? {
        let parts = setCookie.split(separator: ";").map { $0.trimmingCharacters(in: .whitespaces) }
        guard let first = parts.first, let eq = first.firstIndex(of: "=") else { return nil }
        let name = String(first[first.startIndex..<eq])
        let value = String(first[first.index(after: eq)...])
        guard !name.isEmpty else { return nil }

        var domain = requestURL.host ?? ""
        var path = "/"
        var secure = false

        for attr in parts.dropFirst() {
            let lower = attr.lowercased()
            if lower == "secure" {
                secure = true
            } else if lower.hasPrefix("domain=") {
                var d = String(attr[attr.index(attr.startIndex, offsetBy: 7)...])
                if d.hasPrefix(".") { d.removeFirst() }
                if !d.isEmpty { domain = d.lowercased() }
            } else if lower.hasPrefix("path=") {
                let p = String(attr[attr.index(attr.startIndex, offsetBy: 5)...])
                if !p.isEmpty { path = p }
            }
        }
        return StoredCookie(name: name, value: value, domain: domain.lowercased(), path: path, secure: secure)
    }

    static func domainMatches(host: String, domain: String) -> Bool {
        let host = host.lowercased()
        let domain = domain.lowercased()
        if host == domain { return true }
        // Domain cookie: host must be a subdomain of `domain`.
        return host.hasSuffix("." + domain)
    }

    static func pathMatches(requestPath: String, cookiePath: String) -> Bool {
        if cookiePath == "/" { return true }
        if requestPath == cookiePath { return true }
        if requestPath.hasPrefix(cookiePath) {
            // e.g. cookiePath "/api" matches "/api/x" but not "/apixyz".
            let idx = requestPath.index(requestPath.startIndex, offsetBy: cookiePath.count)
            return requestPath[idx] == "/" || cookiePath.hasSuffix("/")
        }
        return false
    }
}
