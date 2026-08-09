import XCTest
import Foundation
@testable import AxiamSDK

/// Decision reason codes — CONTRACT.md §11 rule 9 (B1 deny-override).
///
/// The rule exists because the two refusals mean **opposite things to the person on the
/// other end**: `no_grant` says *ask an admin for access*, `denied_by_rule` says *an admin
/// has already decided*. An application that cannot tell them apart sends users to raise
/// tickets that will be refused.
final class ReasonCodeTests: XCTestCase {

    /// Runs `assertions` against a client whose `/authz/check` returns `body`.
    private func withCheck(
        returning body: [String: Any],
        _ assertions: (AccessResult) async throws -> Void
    ) async throws {
        try await withClient(router: { _, _ in
            .json(200, body)
        }) { client, _ in
            try await assertions(try await client.checkAccess("read", resource: "res-1"))
        }
    }

    func testAnAllowSurfacesTheAllowedReasonCode() async throws {
        try await withCheck(returning: ["allowed": true, "reason_code": "allowed"]) { decision in
            XCTAssertTrue(decision.allowed)
            XCTAssertEqual(decision.reasonCode, ReasonCode.allowed)
        }
    }

    func testNoGrantAndDeniedByRuleAreNotCollapsed() async throws {
        var noGrant: AccessResult?
        var byRule: AccessResult?

        try await withCheck(returning: ["allowed": false, "reason_code": "no_grant"]) { noGrant = $0 }
        try await withCheck(returning: ["allowed": false, "reason_code": "denied_by_rule"]) { byRule = $0 }

        // Both are refusals…
        XCTAssertEqual(noGrant?.allowed, false)
        XCTAssertEqual(byRule?.allowed, false)
        // …and the SDK must not reduce them to that shared `false`.
        XCTAssertEqual(noGrant?.reasonCode, ReasonCode.noGrant)
        XCTAssertEqual(byRule?.reasonCode, ReasonCode.deniedByRule)
        XCTAssertNotEqual(noGrant?.reasonCode, byRule?.reasonCode)
    }

    func testAnUnknownReasonCodeIsSurfacedVerbatimAndChangesNothing() async throws {
        // §11 rule 9: an SDK that does not recognise a code MUST surface it unchanged and
        // MUST NOT let it affect the outcome, which `allowed` carries alone. This is what
        // lets the server add a fourth code without breaking every deployed SDK.
        try await withCheck(
            returning: ["allowed": false, "reason_code": "denied_by_some_future_thing"]
        ) { decision in
            XCTAssertFalse(decision.allowed)
            XCTAssertEqual(decision.reasonCode, "denied_by_some_future_thing")
        }

        try await withCheck(
            returning: ["allowed": true, "reason_code": "something-unrecognised"]
        ) { decision in
            XCTAssertTrue(decision.allowed, "an unknown code must not flip an allow")
        }
    }

    func testAnOlderServerOmittingTheFieldIsNotAnError() async throws {
        // A newer SDK against an older server: the field is simply absent, and that MUST
        // degrade to today's behaviour rather than failing to decode.
        try await withCheck(returning: ["allowed": false]) { decision in
            XCTAssertFalse(decision.allowed)
            XCTAssertNil(decision.reasonCode)
        }

        try await withCheck(returning: ["allowed": true, "reason": "role grants it"]) { decision in
            XCTAssertTrue(decision.allowed)
            XCTAssertNil(decision.reasonCode)
            XCTAssertEqual(decision.reason, "role grants it")
        }
    }

    func testCanStillReturnsFalseForBothRefusals() async throws {
        // §11 rule 9 is about *reporting*, not enforcement: `can` is the "just tell me yes
        // or no" helper and both refusals answer `false` identically. An SDK must not start
        // varying enforcement on the code.
        for code in [ReasonCode.noGrant, ReasonCode.deniedByRule] {
            try await withClient(router: { _, _ in
                .json(200, ["allowed": false, "reason_code": code])
            }) { client, _ in
                let allowed = try await client.can("read", resource: "res-1")
                XCTAssertFalse(allowed, "can() must answer false for \(code)")
            }
        }
    }

    func testBatchCheckSurfacesAReasonCodePerDecision() async throws {
        try await withClient(router: { _, _ in
            .json(200, ["results": [
                ["allowed": true, "reason_code": "allowed"],
                ["allowed": false, "reason_code": "no_grant"],
                ["allowed": false, "reason_code": "denied_by_rule"],
            ]])
        }) { client, _ in
            let results = try await client.batchCheck([
                AccessCheck(action: "read", resource: "res-1"),
                AccessCheck(action: "write", resource: "res-1"),
                AccessCheck(action: "delete", resource: "res-1"),
            ])

            XCTAssertEqual(
                results.map(\.reasonCode),
                [ReasonCode.allowed, ReasonCode.noGrant, ReasonCode.deniedByRule]
            )
        }
    }
}
