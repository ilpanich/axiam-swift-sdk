import Foundation
import NIOCore
import NIOHTTP1
import NIOSSL
import AsyncHTTPClient

enum HTTPRequestMethod: String, Sendable {
    case get = "GET"
    case post = "POST"
    case put = "PUT"
    case patch = "PATCH"
    case delete = "DELETE"

    /// State-changing methods must carry the CSRF token (§3) when one is known.
    var isStateChanging: Bool {
        switch self {
        case .get: return false
        default: return true
        }
    }
}

struct HTTPRequestSpec: Sendable {
    var method: HTTPRequestMethod
    var url: URL
    var headers: [(String, String)]
    var body: Data?
}

struct HTTPResponseData: Sendable {
    var status: Int
    /// All header pairs, preserving duplicates such as multiple `Set-Cookie` lines.
    var headers: [(String, String)]
    var body: Data

    func firstHeader(_ name: String) -> String? {
        headers.first(where: { $0.0.lowercased() == name.lowercased() })?.1
    }

    func allHeaders(_ name: String) -> [String] {
        headers.filter { $0.0.lowercased() == name.lowercased() }.map { $0.1 }
    }
}

/// Abstraction over the HTTP layer so the client's session/CSRF/refresh logic can be exercised
/// against a real server (integration tests) or a counting mock (single-flight unit test).
protocol HTTPTransport: Sendable {
    func execute(_ spec: HTTPRequestSpec, timeout: TimeInterval) async throws -> HTTPResponseData
    func shutdown() async throws
}

/// Production transport built on `AsyncHTTPClient`.
///
/// Chosen over `URLSession` because client-certificate mTLS (§6.1) requires NIOSSL, which
/// works on Linux CI; `URLSession` client certs depend on Apple's Security.framework.
final class AsyncHTTPClientTransport: HTTPTransport {
    private let client: HTTPClient

    init(tls: TLSConfiguration) {
        var configuration = HTTPClient.Configuration()
        configuration.tlsConfiguration = tls
        // Follow no redirects automatically — auth flows are sensitive to them.
        configuration.redirectConfiguration = .disallow
        self.client = HTTPClient(eventLoopGroupProvider: .singleton, configuration: configuration)
    }

    func execute(_ spec: HTTPRequestSpec, timeout: TimeInterval) async throws -> HTTPResponseData {
        var request = HTTPClientRequest(url: spec.url.absoluteString)
        request.method = Self.niaMethod(spec.method)
        for (name, value) in spec.headers {
            request.headers.add(name: name, value: value)
        }
        if let body = spec.body {
            request.body = .bytes([UInt8](body))
        }

        let response: HTTPClientResponse
        do {
            response = try await client.execute(request, timeout: .seconds(Int64(timeout.rounded())))
        } catch {
            // Connection refused / timeout / TLS / DNS all surface here → NetworkError (§2).
            throw AxiamError.network(NetworkError("Transport failure calling \(spec.url.path)", cause: error))
        }

        var buffer: ByteBuffer
        do {
            buffer = try await response.body.collect(upTo: 32 * 1024 * 1024)
        } catch {
            throw AxiamError.network(NetworkError("Failed to read response body", cause: error))
        }

        var headerPairs: [(String, String)] = []
        for header in response.headers {
            headerPairs.append((header.name, header.value))
        }

        // Avoid NIOFoundationCompat's `Data(buffer:)` — read raw bytes into Data directly.
        let bytes = buffer.readBytes(length: buffer.readableBytes) ?? []
        return HTTPResponseData(
            status: Int(response.status.code),
            headers: headerPairs,
            body: Data(bytes)
        )
    }

    func shutdown() async throws {
        try await client.shutdown()
    }

    /// Map the SDK's method enum to NIO's `HTTPMethod` explicitly (NIO's `HTTPMethod` is not a
    /// reliable `RawRepresentable` across versions).
    private static func niaMethod(_ method: HTTPRequestMethod) -> HTTPMethod {
        switch method {
        case .get: return .GET
        case .post: return .POST
        case .put: return .PUT
        case .patch: return .PATCH
        case .delete: return .DELETE
        }
    }
}
