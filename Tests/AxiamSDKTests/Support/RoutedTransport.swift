import Foundation
@testable import AxiamSDK

/// A recording, route-scripted `HTTPTransport` for the contract 1.53–1.58 suites (§28.12,
/// §32.7, §33).
///
/// Like every harness here it sits at the BOTTOM of a real `AxiamClient`, so what it records
/// is exactly what reached the wire — headers, query and body included. Each route answers
/// from its own script, one entry per request, the last entry repeating; a `nil` entry is a
/// dropped connection (the transport throws, as `AsyncHTTPClientTransport` does when no
/// response arrives). A request no route matches is recorded and answered `404`.
final class RoutedTransport: HTTPTransport, @unchecked Sendable {

    /// One request as it reached the wire.
    struct Recorded: Sendable {
        let method: String
        let url: URL
        let headers: [(String, String)]
        let body: Data?

        var path: String { url.path }

        /// The raw query string, or `nil` when the URL carried none.
        var query: String? { URLComponents(url: url, resolvingAgainstBaseURL: false)?.query }

        /// One query parameter's value.
        func queryValue(_ name: String) -> String? {
            URLComponents(url: url, resolvingAgainstBaseURL: false)?
                .queryItems?.first { $0.name == name }?.value
        }

        /// Every value of the header `name`, case-insensitively.
        func headerValues(_ name: String) -> [String] {
            headers.filter { $0.0.lowercased() == name.lowercased() }.map { $0.1 }
        }

        func header(_ name: String) -> String? { headerValues(name).first }

        /// The body as an `application/x-www-form-urlencoded` form.
        var form: [String: String] {
            guard let body, let text = String(data: body, encoding: .utf8), !text.isEmpty else {
                return [:]
            }
            var out: [String: String] = [:]
            for pair in text.split(separator: "&") {
                let parts = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
                let key = String(parts[0]).removingPercentEncoding ?? String(parts[0])
                let value = parts.count > 1
                    ? (String(parts[1]).removingPercentEncoding ?? String(parts[1]))
                    : ""
                out[key] = value
            }
            return out
        }

        /// The body as a JSON object.
        var jsonBody: [String: Any]? {
            guard let body else { return nil }
            return (try? JSONSerialization.jsonObject(with: body)) as? [String: Any]
        }
    }

    /// One scripted answer.
    struct Reply: Sendable {
        let status: Int
        let headers: [(String, String)]
        let body: Data

        static func json(_ status: Int, _ text: String, headers: [(String, String)] = []) -> Reply {
            Reply(
                status: status,
                headers: [("Content-Type", "application/json")] + headers,
                body: Data(text.utf8))
        }

        static func json(_ status: Int, object: [String: Any], headers: [(String, String)] = []) -> Reply {
            let data = (try? JSONSerialization.data(withJSONObject: object)) ?? Data()
            return Reply(
                status: status, headers: [("Content-Type", "application/json")] + headers,
                body: data)
        }

        static func empty(_ status: Int) -> Reply {
            Reply(status: status, headers: [], body: Data())
        }
    }

    private struct Route {
        let method: String?
        let pathSuffix: String
        let replies: [Reply?]
        var served: Int
    }

    private let lock = NSLock()
    private var routes: [Route] = []
    private var recorded: [Recorded] = []

    /// Answer `method pathSuffix` (any method when `nil`) from `replies`, in order; the last
    /// repeats. A `nil` reply drops the connection. Later routes shadow earlier ones.
    func route(_ method: String?, _ pathSuffix: String, _ replies: [Reply?]) {
        lock.locked {
            routes.insert(
                Route(method: method, pathSuffix: pathSuffix, replies: replies, served: 0), at: 0)
        }
    }

    /// Every request, in order.
    var requests: [Recorded] { lock.locked { recorded } }

    /// The requests whose path ends with `suffix`.
    func requests(_ suffix: String) -> [Recorded] {
        requests.filter { $0.path.hasSuffix(suffix) }
    }

    func execute(_ spec: HTTPRequestSpec, timeout: TimeInterval) async throws -> HTTPResponseData {
        let reply = lock.locked { () -> Reply?? in
            recorded.append(Recorded(
                method: spec.method.rawValue, url: spec.url, headers: spec.headers,
                body: spec.body))
            guard let index = routes.firstIndex(where: {
                ($0.method == nil || $0.method == spec.method.rawValue)
                    && spec.url.path.hasSuffix($0.pathSuffix)
            }) else {
                return .none
            }
            let route = routes[index]
            let next = route.replies.isEmpty
                ? Reply.empty(204)
                : route.replies[min(route.served, route.replies.count - 1)]
            routes[index].served += 1
            return .some(next)
        }
        guard let scripted = reply else {
            return HTTPResponseData(
                status: 404, headers: [("Content-Type", "application/json")],
                body: Data("{}".utf8))
        }
        guard let answer = scripted else {
            throw AxiamError.network(NetworkError("connection reset by peer"))
        }
        return HTTPResponseData(status: answer.status, headers: answer.headers, body: answer.body)
    }

    func shutdown() async throws {}
}

/// Run-time secrets and the redaction assertion the §28.12 / §29–§33 suites share.
enum SecretKit {
    /// A fresh 64-character lower-case hex value: random per run, so no test carries a
    /// credential literal and a redaction check cannot pass by coincidence.
    static func random() -> String {
        let digits = Array("0123456789abcdef")
        return String((0..<64).map { _ in digits[Int.random(in: 0..<16)] })
    }

    /// Whether any 8-character substring of `secret` occurs in `haystack`.
    ///
    /// Returns a Bool rather than asserting, so a FAILING redaction test reports a fixed text
    /// at the call site and never prints the secret, the fragment or the rendering it caught
    /// (CodeQL's "cleartext logging of sensitive information" — the lesson from the Rust port).
    static func leaks(_ haystack: String, _ secret: String) -> Bool {
        let characters = Array(secret)
        guard characters.count >= 8 else { return haystack.contains(secret) }
        for start in 0...(characters.count - 8) {
            if haystack.contains(String(characters[start..<(start + 8)])) { return true }
        }
        return false
    }
}
