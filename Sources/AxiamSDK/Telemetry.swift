import Foundation

/// A telemetry event (CONTRACT.md §19).
///
/// An `enum` rather than a protocol hierarchy, which is what makes §19.2 rule 3's "no event
/// payload may carry a secret" checkable rather than aspirational: the case list is closed, each
/// case has a fixed associated-value list, and none of them is a dictionary. There is nowhere to
/// put a token in a payload bound for a metrics backend — the type, not a review comment, is what
/// keeps them out.
///
/// Hooks are invoked on the calling task, so a sink must not block: §19.2 rule 4 makes buffering
/// the caller's job so they can pick the policy. Every mature metrics library already buffers.
public enum TelemetryEvent: Sendable, Equatable {

    /// Why a request finished.
    public enum Outcome: String, Sendable {
        /// The call returned a usable response.
        case success
        /// The call failed, at any layer.
        case failure
    }

    /// Whether this caller performed a §9 refresh or waited on another task's.
    public enum RefreshRole: String, Sendable {
        /// This caller performed the refresh.
        case leader
        /// This caller waited on another task's refresh.
        case follower
    }

    /// Emitted before an outbound call leaves the SDK.
    ///
    /// - Parameters:
    ///   - operation: canonical operation name, e.g. `checkAccess`.
    ///   - method: HTTP method.
    ///   - pathTemplate: the route constant — `/api/v1/authz/check`, never a URL with ids
    ///     substituted in. A metric label carrying a UUID is a cardinality bomb.
    ///   - attempt: 1 for the first try, incrementing per §16 retry.
    case requestStart(operation: String, method: String, pathTemplate: String, attempt: Int)

    /// Emitted after a call completes, success or failure.
    ///
    /// - Parameters:
    ///   - operation: canonical operation name.
    ///   - method: HTTP method.
    ///   - pathTemplate: the route constant; see ``requestStart(operation:method:pathTemplate:attempt:)``.
    ///   - attempt: the attempt this event closes.
    ///   - status: HTTP status, or `nil` when no response arrived.
    ///   - duration: wall-clock time this attempt took.
    ///   - outcome: success or failure.
    case requestEnd(
        operation: String,
        method: String,
        pathTemplate: String,
        attempt: Int,
        status: Int?,
        duration: TimeInterval,
        outcome: Outcome
    )

    /// Emitted before each §16 retry wait.
    ///
    /// §16.5 requires this: a retried-then-succeeded operation is otherwise invisible — the
    /// caller sees a slow success and no signal at all that the server is failing. That silence
    /// is the standing objection to automatic retry, and this event is what answers it.
    ///
    /// - Parameters:
    ///   - operation: canonical operation name.
    ///   - attempt: the attempt that just failed.
    ///   - delay: the wait about to be taken, after jitter and any `Retry-After`.
    ///   - reason: a redacted failure description; never carries a token.
    case retry(operation: String, attempt: Int, delay: TimeInterval, reason: String)

    /// Emitted around a §9 single-flight refresh.
    ///
    /// - Parameters:
    ///   - role: whether this caller led or followed.
    ///   - duration: how long the refresh, or the wait for one, took.
    case refresh(role: RefreshRole, duration: TimeInterval)

    /// Emitted at client construction, once per caller-supplied setting the SDK clamped
    /// (§19.1, §19.2 rule 6).
    ///
    /// Clamping rather than rejecting is the right call — rejecting would fail construction for a
    /// caller whose configuration was merely optimistic, and honoring would let one client become
    /// the herd §16 exists to prevent. Doing it **silently** is the part that is wrong: an
    /// operator who set a 60-second memo TTL believes their staleness bound is 60 seconds. It is
    /// five, and their revocation reasoning is off by a factor of twelve with nothing anywhere to
    /// say so.
    ///
    /// Not emitted for a value already within its limit: an event that fires when nothing
    /// happened trains its reader to ignore it.
    ///
    /// - Parameters:
    ///   - setting: the configuration property's name, e.g. `decisionMemoTtl`.
    ///   - requested: the value the caller asked for, rendered.
    ///   - effective: the value actually in force, rendered.
    ///   - contractReference: the §-reference for the limit, e.g. `§17.1 rule 2`.
    case configClamped(setting: String, requested: String, effective: String, contractReference: String)
}

/// A caller-supplied telemetry sink (CONTRACT.md §19).
///
/// Install one with ``AxiamConfig/telemetryHook``. It receives request start/end, §16 retry, §9
/// refresh and §19.2 rule 6 clamp events, so metrics can be wired without this package taking a
/// dependency on any metrics library.
///
/// The closure is `@Sendable` because an `AxiamClient` is an actor and the hook is invoked from
/// inside it. It must not block (§19.2 rule 4).
public typealias TelemetryHook = @Sendable (TelemetryEvent) -> Void

/// Internal §19 dispatcher. A `nil` hook is the overwhelmingly common case and costs one optional
/// check per request.
struct TelemetryDispatcher: Sendable {
    private let hook: TelemetryHook?

    init(_ hook: TelemetryHook?) {
        self.hook = hook
    }

    /// Whether a hook is installed. The whole cost of §19 when one is not.
    var installed: Bool { hook != nil }

    /// Deliver `event`.
    ///
    /// §19.2 rule 2 says telemetry is not permitted to fail an authorization check. Swift's
    /// typed-throws boundary does most of the work here: ``TelemetryHook`` is non-throwing, so a
    /// sink cannot propagate an error into the SDK by construction. A hook that traps takes the
    /// process down, which no library can defend against and which this dispatcher does not
    /// pretend to.
    func emit(_ event: TelemetryEvent) {
        hook?(event)
    }
}
