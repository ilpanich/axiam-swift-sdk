import Foundation

/// A configured `WWW-Authenticate: UMA` challenge emitter (CONTRACT.md §20.3, emit half).
///
/// Hand one to ``AxiamGuards/requireAccess(_:resource:scope:umaChallenge:)`` and a denial stops
/// being a bare 403: the guard mints a fresh permission ticket for the pair the caller lacked and
/// attaches it to the thrown ``AuthzError``, so the framework adapter can return it as a header and
/// a UMA-aware client knows where to go for authority instead of only being told "no".
///
/// **Opt-in, and deliberately so.** Emitting a challenge means minting a credential — a wire call
/// to the Protection API, and a live ticket, produced on a path the caller did not explicitly
/// request. A guard that did that on every denial by default would turn each unauthorized request
/// into a Protection API call, which is a denial-of-service amplifier pointed at your own
/// authorization server. So it happens only where an application asked for it.
///
/// **Failure is not escalation.** If minting fails — the PAT expired, the Protection API is down,
/// the resource declares none of the requested scopes — the denial still surfaces as an ordinary
/// ``AuthzError`` without a challenge. A caller who was going to be refused is refused either way;
/// letting a Protection API outage turn a deny into a 503 would hand the outage a second
/// consequence, and letting it turn into an allow would be a security bug.
public struct UmaChallenger: Sendable {
    /// The protection realm named in the header.
    public let realm: String
    /// The authorization server the caller should redeem the ticket at — normally this
    /// deployment's issuer, read from ``AxiamClient/umaDiscover()`` rather than concatenated by
    /// hand, for the same reason §12.3 rule 6 gives.
    public let asURI: String
    /// A Protection API Token: a *client-credentials* token carrying the `uma_protection` scope
    /// (§20.2 rule 1). A user token cannot stand in — a minted ticket is bound to the `client_id`
    /// that minted it.
    public let pat: Sensitive<String>

    public init(realm: String, asURI: String, pat: Sensitive<String>) {
        self.realm = realm
        self.asURI = asURI
        self.pat = pat
    }
}
