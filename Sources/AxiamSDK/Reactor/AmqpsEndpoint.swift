import Foundation

/// A validated broker endpoint: everything a caller needs to open an `amqps://`
/// connection, and nothing that could open a plaintext one.
public struct AmqpsEndpoint: Sendable, Equatable {
    /// The validated `amqps://` URL, unchanged.
    public let url: String
    public let host: String
    /// The broker TLS port, defaulted when the URL omits it.
    public let port: Int
    /// `/` when the URL carries no path.
    public let virtualHost: String
    /// A privately-issued broker certificate's CA.
    public let caPEM: String?
    public let clientCertificatePEM: String?
    public let clientKeyPEM: String?
}

/// A broker URL or its TLS material that §8b refuses.
public enum AmqpsEndpointError: Error, Sendable, Equatable, CustomStringConvertible {
    /// Every scheme but `amqps://`, `amqp://` included. There is **no loopback
    /// exception** (§8b rule 8).
    case schemeRefused(String)
    /// A URL this could not read is not a URL it can vouch for.
    case unparseable(String)
    /// Half a client identity (§8b rule 3).
    case incompleteClientIdentity

    public var description: String {
        switch self {
        case .schemeRefused(let scheme):
            return """
                scheme '\(scheme)' is refused; the broker URL must be amqps:// and there is no \
                plaintext fallback and no loopback exception (CONTRACT.md §8b rules 1, 5 and 8)
                """
        case .unparseable(let url):
            return "'\(url)' is not a usable broker URL (CONTRACT.md §8b)"
        case .incompleteClientIdentity:
            return """
                a client certificate and its key must be supplied together — half a client \
                identity fails closed rather than connecting without the mutual half \
                (CONTRACT.md §8b rule 3)
                """
        }
    }
}

/// Validate a broker URL and its TLS material against §8b rules 1–5.
///
/// **§22.11 rule 3 is why this is a public, tested function rather than a
/// paragraph.** §8b rule 7 cannot be satisfied by a runtime that never sees a URL
/// — this SDK bundles no AMQP client — so the SDK hands the integrator the check
/// instead. Documenting the requirement is precisely the failure contract 1.23
/// was written to stop: three SDKs asserting `amqps://` in a doc comment above a
/// call that accepted anything.
///
/// What it enforces:
///
/// 1. The scheme MUST be `amqps://`. Every other scheme is refused, `amqp://`
///    included, and there is **no loopback exception** (§8b rule 8): this applies
///    to `localhost`, `127.0.0.1` and `::1` exactly as to any other host. §6's
///    `http://localhost` dev carve-out does not extend here, and the server has
///    no plaintext listener for such an exception to reach.
/// 2. A custom CA bundle is supported, because an in-cluster broker's certificate
///    is not issued by a public CA — the common case, and it exists so nobody has
///    a legitimate reason to want rule 4 relaxed.
/// 3. A client certificate and its key are required TOGETHER. Half a client
///    identity fails closed rather than connecting without the mutual half.
/// 4. There is no verification-skip option, under any name. It is the most
///    reliably misused option in TLS: it appears in a dev compose file, it works,
///    and it travels unchanged into production, where it turns TLS into an
///    expensive no-op against precisely the attacker TLS exists to stop.
/// 5. There is no plaintext fallback. A failed `amqps://` connection is an error
///    to surface, not a condition to work around — and this call offers no way to
///    express one.
public func amqpsEndpoint(
    _ url: String,
    caPEM: String? = nil,
    clientCertificatePEM: String? = nil,
    clientKeyPEM: String? = nil
) throws -> AmqpsEndpoint {
    // Rule 3, checked first because it is about the caller's arguments rather
    // than about the URL.
    let hasCert = !(clientCertificatePEM ?? "").isEmpty
    let hasKey = !(clientKeyPEM ?? "").isEmpty
    guard hasCert == hasKey else { throw AmqpsEndpointError.incompleteClientIdentity }

    guard let separator = url.range(of: "://") else {
        // Rule 5's posture applied to parsing: a URL this cannot read is not a
        // URL it can vouch for, so it fails closed rather than being passed on
        // for a socket to interpret.
        throw AmqpsEndpointError.unparseable(url)
    }
    let scheme = String(url[url.startIndex..<separator.lowerBound]).lowercased()
    guard scheme == "amqps" else { throw AmqpsEndpointError.schemeRefused(scheme) }

    var rest = String(url[separator.upperBound...])
    // Strip any userinfo — credentials belong to the connection, not to this
    // check, and leaving them in `host` would put them wherever host is logged.
    if let at = rest.range(of: "@", options: .backwards) {
        rest = String(rest[at.upperBound...])
    }

    var authority = rest
    var virtualHost = "/"
    if let slash = rest.firstIndex(of: "/") {
        authority = String(rest[rest.startIndex..<slash])
        let path = String(rest[rest.index(after: slash)...])
        if !path.isEmpty { virtualHost = path }
    }
    guard !authority.isEmpty else { throw AmqpsEndpointError.unparseable(url) }

    var host = authority
    var port = 5671  // the broker TLS port
    if authority.hasPrefix("[") {
        // An IPv6 literal is bracketed; its colons are not a port separator.
        guard let close = authority.firstIndex(of: "]") else {
            throw AmqpsEndpointError.unparseable(url)
        }
        host = String(authority[authority.index(after: authority.startIndex)..<close])
        let after = authority.index(after: close)
        if after < authority.endIndex, authority[after] == ":" {
            guard let parsed = Int(authority[authority.index(after: after)...]) else {
                throw AmqpsEndpointError.unparseable(url)
            }
            port = parsed
        }
    } else if let colon = authority.range(of: ":", options: .backwards) {
        host = String(authority[authority.startIndex..<colon.lowerBound])
        guard let parsed = Int(authority[colon.upperBound...]) else {
            throw AmqpsEndpointError.unparseable(url)
        }
        port = parsed
    }
    guard !host.isEmpty, port > 0, port <= 65535 else {
        throw AmqpsEndpointError.unparseable(url)
    }

    // Rule 2 carries the CA through; rule 4 needs no code at all, because there
    // is no parameter for it under any name and none may be added.
    return AmqpsEndpoint(
        url: url,
        host: host,
        port: port,
        virtualHost: virtualHost,
        caPEM: (caPEM ?? "").isEmpty ? nil : caPEM,
        clientCertificatePEM: hasCert ? clientCertificatePEM : nil,
        clientKeyPEM: hasKey ? clientKeyPEM : nil)
}
