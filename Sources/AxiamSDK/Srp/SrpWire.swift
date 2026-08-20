import Foundation

/// Wire shapes for the §23.5 SRP endpoints.
struct SrpChallengeRequest: Encodable {
    let username_or_email: String
    /// `A`, lowercase hex. There is deliberately **no** `password` field: not
    /// sending it is the entire point of the exchange.
    let client_public: String
    let tenant_id: String?
    let tenant_slug: String?
    let org_id: String?
    let org_slug: String?
}

struct SrpChallengeResponse: Decodable {
    let srp_session: String
    /// The canonical identity to feed into the KDF — the server's answer, not the
    /// user's input. A user may sign in with a username or an email while only one
    /// of the two is bound into `x` (§23.3 rule 2).
    let identity: String
    let salt: String
    let group: String
    let kdf: String
    let memory_kib: Int?
    let iterations: Int
    let parallelism: Int?
    let b_pub: String
}

struct SrpVerifyRequest: Encodable {
    let srp_session: String
    let client_proof: String
}

/// The `server_proof` §23.5 adds to each response of the §3 login union.
struct SrpServerProof: Decodable {
    let server_proof: String?
}
