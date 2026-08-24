import Foundation
import NIOCore
import NIOPosix
import NIOHTTP1

struct TestRequest: Sendable {
    let method: String
    let uri: String
    let headers: [(String, String)]
    let body: Data

    func header(_ name: String) -> String? {
        headers.first(where: { $0.0.lowercased() == name.lowercased() })?.1
    }

    func headers(_ name: String) -> [String] {
        headers.filter { $0.0.lowercased() == name.lowercased() }.map { $0.1 }
    }
}

struct TestResponse: Sendable {
    var status: Int
    var headers: [(String, String)]
    var body: Data

    init(status: Int, headers: [(String, String)] = [], body: Data = Data()) {
        self.status = status
        self.headers = headers
        self.body = body
    }

    static func json(_ status: Int, _ object: [String: Any], headers: [(String, String)] = []) -> TestResponse {
        TestResponse(status: status, headers: headers, body: jsonBody(object))
    }

    /// Serialize a JSON fixture ahead of time.
    ///
    /// `TestRouter` is `@Sendable`, so a router closure cannot capture a `[String: Any]`
    /// fixture — `Any` defeats `Sendable` checking. Serializing at the point the fixture is
    /// built turns it into `Data`, which *is* `Sendable`, and the closure captures that.
    /// The bytes are what the response was always going to carry, so nothing is lost.
    static func jsonBody(_ object: [String: Any]) -> Data {
        (try? JSONSerialization.data(withJSONObject: object)) ?? Data()
    }
}

/// Shared, lock-protected state recording requests and per-key counters.
final class TestServerState: @unchecked Sendable {
    private let lock = NSLock()
    private var _requests: [TestRequest] = []
    private var _counts: [String: Int] = [:]

    func record(_ request: TestRequest) {
        lock.lock(); defer { lock.unlock() }
        _requests.append(request)
    }

    var requests: [TestRequest] {
        lock.lock(); defer { lock.unlock() }
        return _requests
    }

    func requests(pathContaining fragment: String) -> [TestRequest] {
        requests.filter { $0.uri.contains(fragment) }
    }

    @discardableResult
    func increment(_ key: String) -> Int {
        lock.lock(); defer { lock.unlock() }
        _counts[key, default: 0] += 1
        return _counts[key]!
    }

    func count(_ key: String) -> Int {
        lock.lock(); defer { lock.unlock() }
        return _counts[key, default: 0]
    }
}

typealias TestRouter = @Sendable (TestRequest, TestServerState) -> TestResponse

/// A minimal NIO HTTP/1.1 server for exercising the SDK over real sockets on Linux CI.
final class TestHTTPServer: @unchecked Sendable {
    private let group: MultiThreadedEventLoopGroup
    private var channel: Channel?
    private let router: TestRouter
    let state = TestServerState()

    init(router: @escaping TestRouter) {
        self.group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        self.router = router
    }

    /// Bind to an ephemeral localhost port and return it.
    func start() throws -> Int {
        let router = self.router
        let state = self.state
        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.backlog, value: 256)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                channel.pipeline.configureHTTPServerPipeline().flatMap {
                    channel.pipeline.addHandler(TestServerHandler(router: router, state: state))
                }
            }
            .childChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)

        let bound = try bootstrap.bind(host: "127.0.0.1", port: 0).wait()
        self.channel = bound
        return bound.localAddress?.port ?? 0
    }

    func stop() {
        try? channel?.close().wait()
        try? group.syncShutdownGracefully()
    }
}

/// `@unchecked Sendable` with a stated invariant, which is the standard NIO one: the only
/// mutable state here is `head`/`bodyData`, and both are touched exclusively from
/// `channelRead(context:data:)`, which NIO guarantees to call on this channel's event loop
/// and never concurrently with itself. `router` is `@Sendable` and `state` is internally
/// locked, so neither adds a race. There is nothing here to make *checked* `Sendable`:
/// a `ChannelInboundHandler` accumulating a request body is mutable by definition.
private final class TestServerHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    private let router: TestRouter
    private let state: TestServerState

    private var head: HTTPRequestHead?
    private var bodyData = Data()

    init(router: @escaping TestRouter, state: TestServerState) {
        self.router = router
        self.state = state
    }

    static func methodString(_ method: HTTPMethod) -> String {
        switch method {
        case .GET: return "GET"
        case .POST: return "POST"
        case .PUT: return "PUT"
        case .PATCH: return "PATCH"
        case .DELETE: return "DELETE"
        case .HEAD: return "HEAD"
        case .OPTIONS: return "OPTIONS"
        default: return "\(method)"
        }
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case .head(let requestHead):
            self.head = requestHead
            self.bodyData = Data()
        case .body(var buffer):
            if let bytes = buffer.readBytes(length: buffer.readableBytes) {
                bodyData.append(contentsOf: bytes)
            }
        case .end:
            guard let head = self.head else { return }
            let headerPairs = head.headers.map { ($0.name, $0.value) }
            let request = TestRequest(
                method: Self.methodString(head.method),
                uri: head.uri,
                headers: headerPairs,
                body: bodyData
            )
            state.record(request)
            let response = router(request, state)
            write(response, to: context)
        }
    }

    private func write(_ response: TestResponse, to context: ChannelHandlerContext) {
        var headers = HTTPHeaders()
        for (name, value) in response.headers {
            headers.add(name: name, value: value)
        }
        headers.replaceOrAdd(name: "Content-Length", value: String(response.body.count))
        headers.replaceOrAdd(name: "Connection", value: "close")

        let status = HTTPResponseStatus(statusCode: response.status)
        let responseHead = HTTPResponseHead(version: .http1_1, status: status, headers: headers)
        context.write(wrapOutboundOut(.head(responseHead)), promise: nil)

        var buffer = context.channel.allocator.buffer(capacity: response.body.count)
        buffer.writeBytes(response.body)
        context.write(wrapOutboundOut(.body(.byteBuffer(buffer))), promise: nil)

        // Capture the `Channel`, not the `ChannelHandlerContext`: a context is valid only
        // on the event loop and inside the pipeline, and is not `Sendable`. `Channel` is,
        // and closing it is what this callback wanted — the connection, not the handler's
        // position in the pipeline.
        let channel = context.channel
        context.writeAndFlush(wrapOutboundOut(.end(nil))).whenComplete { _ in
            channel.close(promise: nil)
        }
    }
}
