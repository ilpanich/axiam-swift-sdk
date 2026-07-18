import Foundation
import NIOSSL

/// A client-identity certificate for mutual TLS (§6.1 of CONTRACT.md).
///
/// The mandatory baseline is a PEM certificate chain plus a PEM private key (PKCS#8 or
/// PKCS#1). The private key is held behind ``Sensitive`` so it never appears in any
/// debug/log output (§7). A non-PEM value fails at construction time (§6.1 rule 1).
public enum ClientCertificate: Sendable {
    /// PEM certificate chain + PEM private key.
    case pem(certificate: Data, privateKey: Sensitive<Data>)

    /// Convenience initializer taking raw PEM bytes; wraps the key in ``Sensitive``.
    public static func pem(certificate: Data, privateKey: Data) -> ClientCertificate {
        .pem(certificate: certificate, privateKey: Sensitive(privateKey))
    }
}

/// Immutable configuration for an ``AxiamClient``.
///
/// Enforces the §5 tenant rule (a tenant identifier is mandatory) and the §6 "PEM only" TLS
/// rule at construction time. There is deliberately **no** insecure/skip-verify surface (§6).
public struct AxiamConfig: Sendable {
    public let baseURL: URL
    public let tenantID: String?
    public let tenantSlug: String?
    public let orgID: String?
    public let orgSlug: String?
    public let customCA: Data?
    public let clientCertificate: ClientCertificate?
    public let requestTimeout: TimeInterval

    /// Designated initializer.
    ///
    /// - Throws: ``AuthError`` if neither `tenantID` nor `tenantSlug` is supplied (§5), or if
    ///   both `orgID` and `orgSlug` are supplied (they are mutually exclusive).
    public init(
        baseURL: URL,
        tenantID: String? = nil,
        tenantSlug: String? = nil,
        orgID: String? = nil,
        orgSlug: String? = nil,
        customCA: Data? = nil,
        clientCertificate: ClientCertificate? = nil,
        requestTimeout: TimeInterval = 30
    ) throws {
        // §5: a tenant identifier is non-optional and cannot be deferred.
        let hasTenant = (tenantID?.isEmpty == false) || (tenantSlug?.isEmpty == false)
        guard hasTenant else {
            throw AuthError("AxiamConfig requires either tenantID or tenantSlug (§5: no default tenant).")
        }
        // org identifiers are optional but mutually exclusive.
        if (orgID?.isEmpty == false) && (orgSlug?.isEmpty == false) {
            throw AuthError("AxiamConfig accepts at most one of orgID or orgSlug, not both.")
        }

        self.baseURL = baseURL
        self.tenantID = tenantID
        self.tenantSlug = tenantSlug
        self.orgID = orgID
        self.orgSlug = orgSlug
        self.customCA = customCA
        self.clientCertificate = clientCertificate
        self.requestTimeout = requestTimeout
    }

    /// The value injected as the `X-Tenant-ID` header on every request (§5). Prefers the UUID
    /// form when both are present.
    var tenantHeaderValue: String {
        if let tenantID, !tenantID.isEmpty { return tenantID }
        return tenantSlug ?? ""
    }

    /// Build the NIOSSL `TLSConfiguration` for this config (§6 + §6.1).
    ///
    /// Strict server verification (`.fullVerification`) is **always** on. A `customCA` adds a
    /// trust root for development self-signed servers; a `clientCertificate` installs the mTLS
    /// client identity. There is no code path that weakens verification.
    ///
    /// - Throws: ``NetworkError`` if any PEM material fails to parse (§6/§6.1: PEM-only, clear
    ///   error at construction time).
    func makeTLSConfiguration() throws -> TLSConfiguration {
        var tls = TLSConfiguration.makeClientConfiguration()
        // Strict verification is mandatory and immutable (§6). Set explicitly for clarity.
        tls.certificateVerification = .fullVerification

        if let customCA {
            do {
                let caCerts = try NIOSSLCertificate.fromPEMBytes(Array(customCA))
                guard !caCerts.isEmpty else {
                    throw NetworkError("customCA did not contain any PEM certificate.")
                }
                tls.trustRoots = .certificates(caCerts)
            } catch let error as NetworkError {
                throw error
            } catch {
                throw NetworkError("customCA is not valid PEM (§6: PEM-only).", cause: error)
            }
        }

        if let clientCertificate {
            try Self.applyClientCertificate(clientCertificate, to: &tls)
        }

        return tls
    }

    /// Isolated so the client-cert path stays separate from server-verification code (§6.1 rule 2).
    static func applyClientCertificate(_ cert: ClientCertificate, to tls: inout TLSConfiguration) throws {
        switch cert {
        case let .pem(certificate, privateKey):
            do {
                let chain = try NIOSSLCertificate.fromPEMBytes(Array(certificate))
                    .map { NIOSSLCertificateSource.certificate($0) }
                guard !chain.isEmpty else {
                    throw NetworkError("clientCertificate chain contained no PEM certificate.")
                }
                let key = try NIOSSLPrivateKey(bytes: Array(privateKey.wrapped), format: .pem)
                tls.certificateChain = chain
                tls.privateKey = .privateKey(key)
            } catch let error as NetworkError {
                throw error
            } catch {
                throw NetworkError("clientCertificate is not valid PEM (§6.1: PEM cert + PEM key).", cause: error)
            }
        }
    }
}
