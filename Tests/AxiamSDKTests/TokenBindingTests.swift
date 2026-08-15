import Foundation
import XCTest

@testable import AxiamSDK

/// CONTRACT.md §10.1 rule 9 extended for DPoP (contract 1.16).
final class TokenBindingTests: XCTestCase {

    private let thumb = "bwcK0esC3yEWCTuAFrDPBqZ_hvIn0UbmJKlSjMbGZKM"
    private let jkt = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
    private let otherJkt = "sBjflhaR2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

    private func claims(cnf: String?) throws -> JwtClaims {
        let json = cnf.map { "{\"sub\":\"u\",\"cnf\":\($0)}" } ?? "{\"sub\":\"u\"}"
        return try JSONDecoder().decode(JwtClaims.self, from: Data(json.utf8))
    }

    /// THE POSITIVE REGRESSION TEST, and the one this change is most likely to break: an
    /// unbound token must still pass with no certificate and no proof. The likeliest wrong
    /// implementation of rule 9 is one that starts demanding evidence from every caller.
    func testUnboundTokenIsAcceptedWithNoProofsAtAll() throws {
        XCTAssertNoThrow(
            try AxiamRequestAuthenticator.verifyTokenBinding(try claims(cnf: nil), proofs: .none))
        // ...and proofs it never asked for do not make it invalid.
        XCTAssertNoThrow(
            try AxiamRequestAuthenticator.verifyTokenBinding(
                try claims(cnf: nil),
                proofs: PresentedProofs(certificateThumbprint: thumb, dpopThumbprint: jkt)))
    }

    func testDpopBoundTokenAcceptsTheMatchingKey() throws {
        XCTAssertNoThrow(
            try AxiamRequestAuthenticator.verifyTokenBinding(
                try claims(cnf: "{\"jkt\":\"\(jkt)\"}"), proofs: .dpop(jkt)))
    }

    func testDpopBoundTokenIsRejectedWithoutAProofOrWithTheWrongKey() throws {
        XCTAssertThrowsError(
            try AxiamRequestAuthenticator.verifyTokenBinding(
                try claims(cnf: "{\"jkt\":\"\(jkt)\"}"), proofs: .none)
        ) { XCTAssertTrue("\($0)".contains("no verified DPoP proof"), "\($0)") }

        XCTAssertThrowsError(
            try AxiamRequestAuthenticator.verifyTokenBinding(
                try claims(cnf: "{\"jkt\":\"\(jkt)\"}"), proofs: .dpop(otherJkt))
        ) { XCTAssertTrue("\($0)".contains("different DPoP key"), "\($0)") }
    }

    func testCertificateBoundTokenIsUnchanged() throws {
        let c = try claims(cnf: "{\"x5t#S256\":\"\(thumb)\"}")

        XCTAssertNoThrow(
            try AxiamRequestAuthenticator.verifyTokenBinding(c, proofs: .certificate(thumb)))
        XCTAssertThrowsError(try AxiamRequestAuthenticator.verifyTokenBinding(c, proofs: .none))
        XCTAssertThrowsError(
            try AxiamRequestAuthenticator.verifyTokenBinding(c, proofs: .certificate(otherJkt)))
    }

    /// BOTH NAMED IS A CONJUNCTION. An operator who turned on two constraints asked for
    /// two; satisfying the more convenient one is not compliance. Each half is asserted to
    /// fail alone, because "check whichever we can" is the likeliest wrong implementation.
    func testCnfNamingBothMethodsRequiresBoth() throws {
        let both = try claims(cnf: "{\"x5t#S256\":\"\(thumb)\",\"jkt\":\"\(jkt)\"}")

        XCTAssertNoThrow(
            try AxiamRequestAuthenticator.verifyTokenBinding(
                both, proofs: PresentedProofs(certificateThumbprint: thumb, dpopThumbprint: jkt)))

        XCTAssertThrowsError(
            try AxiamRequestAuthenticator.verifyTokenBinding(both, proofs: .certificate(thumb)))
        XCTAssertThrowsError(
            try AxiamRequestAuthenticator.verifyTokenBinding(both, proofs: .dpop(jkt)))
    }

    /// An empty `cnf` names nothing checkable and is refused, not read as unbound. Over
    /// gRPC this is also how proto3 delivers an empty `CnfClaim` message, which is why
    /// §10.3 rule 3 spells it out separately.
    func testEmptyCnfIsRefusedRatherThanReadAsUnbound() throws {
        XCTAssertThrowsError(
            try AxiamRequestAuthenticator.verifyTokenBinding(try claims(cnf: "{}"), proofs: .none)
        ) { XCTAssertTrue("\($0)".contains("no method this SDK can verify"), "\($0)") }
    }

    /// The narrow entry point refuses a DPoP-bound token rather than ignoring the `jkt` it
    /// cannot check. That refusal is what lets it stay in the API without becoming a
    /// downgrade path.
    func testCertificateOnlyEntryPointRefusesDpopAndBothBoundTokens() throws {
        for presented in [nil, thumb] {
            XCTAssertThrowsError(
                try AxiamRequestAuthenticator.verifyCertificateBinding(
                    try claims(cnf: "{\"jkt\":\"\(jkt)\"}"), presentedThumbprint: presented)
            ) { XCTAssertTrue("\($0)".contains("cannot verify"), "\($0)") }
        }

        XCTAssertThrowsError(
            try AxiamRequestAuthenticator.verifyCertificateBinding(
                try claims(cnf: "{\"x5t#S256\":\"\(thumb)\",\"jkt\":\"\(jkt)\"}"),
                presentedThumbprint: thumb)
        ) { XCTAssertTrue("\($0)".contains("both must hold"), "\($0)") }
    }
}
