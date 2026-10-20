import Foundation
import Testing
@testable import WardenrunCore

struct ApprovalGateTests {
    /// A gate on a temp directory with a clock the test moves by hand.
    private struct Rig {
        let dir: String
        let clock: Box<Date>
        var gate: ApprovalGate { make() }

        init(dir: String) {
            self.dir = dir
            clock = Box(Date(timeIntervalSince1970: 1_800_000_000))
        }

        func make() -> ApprovalGate {
            let clock = self.clock
            return ApprovalGate(stateDirectory: dir + "/state", now: { clock.value })
        }

        func advance(_ seconds: TimeInterval) { clock.value = clock.value.addingTimeInterval(seconds) }
    }

    private func withRig(_ body: (Rig) throws -> Void) throws {
        try withTempDirectory { raw in try body(Rig(dir: realPath(raw))) }
    }

    private func fail(_ gate: ApprovalGate, _ decision: ApprovalDecision = .denied) throws {
        let result = try gate.guarded { decision }
        #expect(result == decision)
    }

    @Test func anApprovalPassesAndLeavesNoLockout() throws {
        try withRig { rig in
            let gate = rig.gate
            for _ in 0..<5 {
                let result = try gate.guarded { .approved }
                #expect(result == .approved)
            }
        }
    }

    @Test func aSecondGuardedCallWhileTheFirstRunsIsRefusedAtOnce() throws {
        try withRig { rig in
            let first = rig.gate
            let second = rig.make()
            let entered = DispatchSemaphore(value: 0)
            let release = DispatchSemaphore(value: 0)
            let outcome = Box<ApprovalDecision?>(nil)
            Thread.detachNewThread {
                outcome.value = try? first.guarded {
                    entered.signal()
                    _ = release.wait(timeout: .now() + 20)
                    return .approved
                }
                entered.signal()
            }
            #expect(entered.wait(timeout: .now() + 10) == .success)
            let start = Date()
            #expect(throws: GateRefusal.anotherApprovalPending) { _ = try second.guarded { .approved } }
            #expect(Date().timeIntervalSince(start) < 5)   // refused, not queued
            release.signal()
            #expect(entered.wait(timeout: .now() + 10) == .success)
            #expect(outcome.value == .approved)
            // and the lock is free again afterwards
            let again = try second.guarded { .approved }
            #expect(again == .approved)
        }
    }

    @Test func threeDenialsWithinTheWindowLockOutForSixtySeconds() throws {
        try withRig { rig in
            let gate = rig.gate
            try fail(gate); rig.advance(10)
            try fail(gate); rig.advance(10)
            try fail(gate)                       // the third is answered, then the door closes
            #expect(throws: GateRefusal.lockedOut(secondsLeft: 60)) { _ = try gate.guarded { .approved } }
            rig.advance(59)
            #expect(throws: GateRefusal.lockedOut(secondsLeft: 1)) { _ = try gate.guarded { .approved } }
            rig.advance(1)
            let result = try gate.guarded { .approved }
            #expect(result == .approved)
        }
    }

    @Test func aLockoutAppliesToEveryGateOnTheSameDirectoryLikeASecondProcess() throws {
        try withRig { rig in
            for _ in 0..<3 { try fail(rig.make()) }
            #expect(throws: GateRefusal.lockedOut(secondsLeft: 60)) { _ = try rig.make().guarded { .approved } }
        }
    }

    @Test func timeoutsCountLikeDenials() throws {
        try withRig { rig in
            let gate = rig.gate
            try fail(gate, .timedOut); try fail(gate, .denied); try fail(gate, .timedOut)
            #expect(throws: GateRefusal.lockedOut(secondsLeft: 60)) { _ = try gate.guarded { .approved } }
        }
    }

    @Test func failuresOlderThanTheWindowAreForgotten() throws {
        try withRig { rig in
            let gate = rig.gate
            try fail(gate); try fail(gate)
            rig.advance(301)
            try fail(gate)                                   // only one in the window now
            let still = try gate.guarded { .approved }
            #expect(still == .approved)
            try fail(gate); try fail(gate)                   // third within the window → locked
            #expect(throws: GateRefusal.lockedOut(secondsLeft: 60)) { _ = try gate.guarded { .approved } }
        }
    }

    @Test func afterALockoutTheCountStartsAgainFromZero() throws {
        try withRig { rig in
            let gate = rig.gate
            for _ in 0..<3 { try fail(gate) }
            rig.advance(61)
            try fail(gate); try fail(gate)                   // two: not locked
            let ok = try gate.guarded { .approved }
            #expect(ok == .approved)
            try fail(gate)                                   // three again → locked
            #expect(throws: GateRefusal.lockedOut(secondsLeft: 60)) { _ = try gate.guarded { .approved } }
        }
    }

    @Test func unavailableIsNeverCounted() throws {
        try withRig { rig in
            let gate = rig.gate
            for _ in 0..<10 { try fail(gate, .unavailable(reason: "no Touch ID")) }
            let ok = try gate.guarded { .approved }
            #expect(ok == .approved)
        }
    }

    @Test func anApprovalBetweenDenialsDoesNotClearThem() throws {
        try withRig { rig in
            let gate = rig.gate
            try fail(gate); try fail(gate)
            let ok = try gate.guarded { .approved }
            #expect(ok == .approved)
            try fail(gate)
            #expect(throws: GateRefusal.lockedOut(secondsLeft: 60)) { _ = try gate.guarded { .approved } }
        }
    }

    @Test func corruptOrUnreadableStateIsTreatedAsEmptyAndRewritten() throws {
        try withRig { rig in
            let gate = rig.gate
            try fail(gate)
            let statePath = rig.dir + "/state/approval-state.json"
            for garbage in ["not json", "[1,2]", "{\"failures\":\"x\"}", "{\"failures\":[1e999],\"locked_until\":\"soon\"}", ""] {
                try Data(garbage.utf8).write(to: URL(fileURLWithPath: statePath))
                try fail(gate)
                let text = try String(contentsOfFile: statePath, encoding: .utf8)
                let object = try #require(JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any])
                #expect((object["failures"] as? [Double])?.count == 1, "after \(garbage.debugDescription)")
            }
        }
    }

    @Test func theDirectoryIsPrivateAndTheStateFileIsMode0600() throws {
        try withRig { rig in
            try fail(rig.gate)
            #expect(permissionBits(of: rig.dir + "/state") == 0o700)
            #expect(permissionBits(of: rig.dir + "/state/approval-state.json") == 0o600)
            #expect(permissionBits(of: rig.dir + "/state/approval.lock") == 0o600)
        }
    }

    @Test func theStateHoldsTimesOnlyAndNothingAboutWhatWasAsked() throws {
        try withRig { rig in
            try fail(rig.gate)
            let text = try String(contentsOfFile: rig.dir + "/state/approval-state.json", encoding: .utf8)
            let object = try #require(JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any])
            #expect(Set(object.keys) == ["failures", "locked_until"])
        }
    }

    @Test func aStateDirectoryThatCannotBeCreatedMakesTheGateRefuseNotApprove() throws {
        try withRig { rig in
            let blocker = rig.dir + "/blocker"
            FileManager.default.createFile(atPath: blocker, contents: Data())
            let gate = ApprovalGate(stateDirectory: blocker + "/inside", now: { Date() })
            var asked = false
            #expect(throws: GateRefusal.stateUnavailable) { _ = try gate.guarded { asked = true; return .approved } }
            #expect(!asked)
        }
    }
}
