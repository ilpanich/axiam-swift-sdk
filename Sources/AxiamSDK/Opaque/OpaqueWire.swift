import Foundation

/// Wire shapes for the §23 OPAQUE endpoints.
///
/// Note what is absent from every request here: `password`. Not sending it is the entire point of
/// the exchange, and a field that does not exist cannot be added back by accident.
struct OpaqueLoginStartRequest: Encodable {
    let username_or_email: String
    /// Hex `KE1` — a blinded group element, useless without the tenant's OPRF seed.
    let ke1: String
    let tenant_id: String?
    let tenant_slug: String?
    let org_id: String?
    let org_slug: String?
}

/// The `register/start` body.
///
/// It names no account at all — not even a username. A record binds to a credential identifier the
/// server chooses, which is why a later rename cannot invalidate a credential, and why the SRP
/// enrolment's `identity` argument has no successor.
struct OpaqueRegisterStartRequest: Encodable {
    let registration_request: String
    let tenant_id: String?
    let tenant_slug: String?
    let org_id: String?
    let org_slug: String?
}

/// The `*/start` response: a session handle, one protocol message, and the key-stretching function
/// the server names for *this* exchange.
///
/// The cost fields are flat and optional because that is how they arrive, and a field that does
/// not apply to the named function is absent rather than zero (§23.4 rule 5).
struct OpaqueStartResponse: Decodable {
    let opaque_session: String
    /// Present on `login/start`.
    let ke2: String?
    /// Present on `register/start`.
    let registration_response: String?
    let ksf: String
    let memory_kib: Int?
    let iterations: Int?
    let parallelism: Int?
    let log_n: Int?
    let r: Int?
    let p: Int?

    var ksfParams: KsfParams {
        KsfParams(
            ksf: ksf,
            memoryKib: memory_kib,
            iterations: iterations,
            parallelism: parallelism,
            logN: log_n,
            r: r,
            p: p
        )
    }
}

struct OpaqueLoginFinishRequest: Encodable {
    let opaque_session: String
    let ke3: String
}

/// The `opaque` object CONTRACT.md §23 defines: a registration record and the server-issued
/// session handle that identifies the exchange it came from.
///
/// The server cannot build this — it never sees the plaintext — so any request that **sets** a
/// password has to carry it: `POST /api/v1/users`, `/auth/password/change`,
/// `/auth/reset/confirm` and `/admin/bootstrap`.
///
/// Note what is *not* here. The SRP enrolment this replaces carried a salt, a group and a full set
/// of KDF costs, and required the account's canonical username — passing an email produced a
/// verifier no login could ever satisfy, and renaming a user invalidated their verifier outright.
/// A record binds to a credential identifier the server chooses, and the key-stretching parameters
/// are the server's, so there is nothing here a caller can get wrong.
public struct OpaqueEnrollment: Sendable, Encodable, Equatable {
    /// The handle `register/start` issued.
    public let opaque_session: String

    /// The hex `RegistrationRecord`.
    public let registration_record: String

    public init(opaque_session: String, registration_record: String) {
        self.opaque_session = opaque_session
        self.registration_record = registration_record
    }
}
