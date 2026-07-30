import XCTest
import Foundation
@testable import AxiamSDK

/// CONTRACT.md §9 **rule 6** (contract 1.6) — the implementation invariants behind rule 2's
/// observable "exactly one wire call per burst, shared outcome" requirement, each of which a
/// production bug in a sibling SDK was built on top of:
///
/// * **6a** publish-before-vacate,
/// * **6b** occupancy is not liveness,
/// * **6c** only the current owner clears its own slot (identity-checked),
/// * **6d** a caller arriving after full settlement gets a fresh refresh.
///
/// Swift's prescribed mechanism (§9's per-language table) is an `actor` serializing refresh and
/// sharing one in-flight `Task`. Unlike a mutex held across the whole wire call, that shape has
/// real actor-reentrancy points, so these tests pin the two interesting windows open with the
/// ``AxiamClient/RefreshPhase`` hook — documented as never installed in production — and assert the
/// **wire-call count**, not just the returned value.
final class RefreshRule6Tests: XCTestCase {

    // MARK: 6a / 6b — the bookkeeping window

    /// The slot legitimately holds an already-settled `Task` between that task settling and the
    /// owner's continuation vacating the slot (6b). A caller landing in that window MUST join that
    /// outcome and MUST NOT start a second wire call (6a): a second `POST /auth/refresh` would
    /// replay an already-consumed, single-use refresh token.
    func testCallerInBookkeepingWindowJoinsAndTriggersNoSecondWireCall() async throws {
        let transport = RefreshProbeTransport()
        let client = AxiamClient(config: try TestKit.makeConfig(port: 0), transport: transport)
        _ = try await client.login(email: "a@b.c", password: "pw")

        let once = ProbeLatch()
        let occupiedInWindow = ProbeBox(false)
        let countInsideWindow = ProbeBox(-1)
        let lateCallerSucceeded = ProbeBox(false)

        await client._setRefreshTestHook { phase in
            guard phase == .ownerPublished, once.claimOnce() else { return }
            // We are inside the window: the refresh has settled, the slot is not yet vacated.
            occupiedInWindow.value = await client._refreshSlotOccupied()
            let late = Task { try await client.refresh() }
            do {
                try await late.value
                lateCallerSucceeded.value = true
            } catch {
                lateCallerSucceeded.value = false
            }
            countInsideWindow.value = transport.count("refresh")
        }

        try await client.refresh()

        XCTAssertTrue(occupiedInWindow.value,
                      "6b: the slot must still hold the settled task during the bookkeeping window")
        XCTAssertTrue(lateCallerSucceeded.value, "6a: the window arrival must receive the outcome")
        XCTAssertEqual(countInsideWindow.value, 1,
                       "6a: a caller landing in the bookkeeping window must join the settled outcome, "
                       + "never start a second wire call against the consumed refresh token")
        XCTAssertEqual(transport.count("refresh"), 1)
        let vacated = await client._refreshSlotOccupied()
        XCTAssertFalse(vacated, "6a/6c: the owner must vacate its slot")

        await client._setRefreshTestHook(nil)
        try await client.shutdown()
    }

    /// Same window, but on the failure path (§9.3): the one failure is handed to the window arrival
    /// as-is, with no second wire call and no retry.
    func testCallerInBookkeepingWindowJoinsAFailedRefreshWithoutRetrying() async throws {
        let transport = RefreshProbeTransport(failRefresh: true)
        let client = AxiamClient(config: try TestKit.makeConfig(port: 0), transport: transport)
        _ = try await client.login(email: "a@b.c", password: "pw")

        let once = ProbeLatch()
        let lateGotAuthError = ProbeBox(false)
        let countInsideWindow = ProbeBox(-1)

        await client._setRefreshTestHook { phase in
            guard phase == .ownerPublished, once.claimOnce() else { return }
            do {
                try await Task { try await client.refresh() }.value
            } catch AxiamError.auth {
                lateGotAuthError.value = true
            } catch {
                lateGotAuthError.value = false
            }
            countInsideWindow.value = transport.count("refresh")
        }

        do {
            try await client.refresh()
            XCTFail("expected the refresh 401 to surface as AuthError")
        } catch AxiamError.auth {
            // expected (§9.3)
        }

        XCTAssertTrue(lateGotAuthError.value, "the window arrival must get the same failure, as-is")
        XCTAssertEqual(countInsideWindow.value, 1, "§9.3 + 6a: no second refresh wire call")
        XCTAssertEqual(transport.count("refresh"), 1)

        await client._setRefreshTestHook(nil)
        try await client.shutdown()
    }

    // MARK: 6d — after full settlement

    /// Once the outcome is published and the slot fully vacated, a later-arriving caller MUST
    /// perform its own new wire call and receive *that* call's outcome — never the previous burst's
    /// result served from a settled task (the C++ SDK's `shared_future` bug).
    func testCallerArrivingAfterFullSettlementPerformsItsOwnRefresh() async throws {
        let transport = RefreshProbeTransport()
        let client = AxiamClient(config: try TestKit.makeConfig(port: 0), transport: transport)
        _ = try await client.login(email: "a@b.c", password: "pw")

        try await client.refresh()
        XCTAssertEqual(transport.count("refresh"), 1)
        let firstCookie = await client._cookieValue("axiam_access")
        XCTAssertEqual(firstCookie, "refresh-1")
        let vacated = await client._refreshSlotOccupied()
        XCTAssertFalse(vacated, "6a/6c: the slot must be fully vacated once the owner has finished")

        try await client.refresh()
        XCTAssertEqual(transport.count("refresh"), 2,
                       "6d: a caller arriving after full settlement must trigger its own wire call")
        let secondCookie = await client._cookieValue("axiam_access")
        XCTAssertEqual(secondCookie, "refresh-2",
                       "6d: its outcome must be the second call's, not the first burst's")

        try await client.shutdown()
    }

    // MARK: 6c — only the current owner clears its own slot

    /// A lagging attempt unwinding after a *newer* leader has taken the slot MUST NOT clear that
    /// newer leader's entry — doing so would let the next caller start a second concurrent wire
    /// call against an already-consumed refresh token.
    ///
    /// Through the public API the race is unreachable (ownership is taken and released with no
    /// intervening suspension point), so the newer leader is installed directly, from inside the
    /// lagging attempt's own bookkeeping window — exactly the instant at which an unconditional
    /// `refreshTask = nil` would wipe it.
    func testLaggingAttemptDoesNotClearNewerLeadersSlot() async throws {
        let transport = RefreshProbeTransport()
        let client = AxiamClient(config: try TestKit.makeConfig(port: 0), transport: transport)
        _ = try await client.login(email: "a@b.c", password: "pw")

        let once = ProbeLatch()
        let foreignBox = ProbeBox<Task<Void, Error>?>(nil)

        await client._setRefreshTestHook { phase in
            guard phase == .ownerPublished, once.claimOnce() else { return }
            // A newer leader is elected while this (already-settled) attempt is still unwinding.
            let foreign = Task<Void, Error> { try await Task.sleep(nanoseconds: 60_000_000_000) }
            foreignBox.value = foreign
            await client._installForeignRefreshTask(foreign)
        }

        try await client.refresh()

        let newerLeaderSurvived = await client._refreshSlotOccupied()
        XCTAssertTrue(newerLeaderSurvived,
                      "6c: the lagging attempt must clear only the entry it created — the newer "
                      + "leader's live slot must survive it")

        foreignBox.value?.cancel()
        await client._clearRefreshSlot()
        await client._setRefreshTestHook(nil)
        try await client.shutdown()
    }

    // MARK: Cancellation

    /// Swift `Task` cancellation is cooperative, and the shared refresh is an *unstructured* task.
    /// Cancelling the leading caller therefore must not (i) cancel the shared refresh and strand
    /// the callers that joined it, (ii) unblock the leader before its bookkeeping runs, (iii) leave
    /// the slot permanently occupied, or (iv) clear a slot whose refresh is still on the wire.
    func testCancellingTheLeaderStrandsNoWaiterAndLeavesTheSlotUsable() async throws {
        let transport = RefreshProbeTransport(parkFirstRefresh: true)
        let client = AxiamClient(config: try TestKit.makeConfig(port: 0), transport: transport)
        _ = try await client.login(email: "a@b.c", password: "pw")

        let leader = Task { try await client.refresh() }
        await transport.awaitRefreshStarted() // the slot is published and the refresh is on the wire

        let joined = ProbeLatch()
        await client._setRefreshTestHook { phase in
            if phase == .waiterJoining { joined.signal() }
        }
        let waiter = Task { try await client.refresh() }
        await joined.wait() // the waiter has committed to the live task

        leader.cancel()
        transport.release()

        try await waiter.value // (i) not stranded by the leader's cancellation
        try await leader.value // (ii) `await task.value` is not a cancellation point
        XCTAssertEqual(transport.count("refresh"), 1, "still exactly one wire call for the burst")
        let vacatedAfterCancel = await client._refreshSlotOccupied()
        XCTAssertFalse(vacatedAfterCancel, "(iii) a cancelled leader must still vacate its slot")

        await client._setRefreshTestHook(nil)
        try await client.refresh()
        XCTAssertEqual(transport.count("refresh"), 2, "the guard is usable after a cancellation")
        try await client.shutdown()
    }
}
