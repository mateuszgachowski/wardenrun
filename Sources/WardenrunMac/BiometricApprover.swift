#if canImport(Darwin)
import Foundation
import LocalAuthentication
import WardenrunCore

/// Asks the human with the system Touch ID sheet and nothing else (DESIGN 5.3): no button that
/// anything but a fingerprint can press, no password fallback, no way to approve from a script.
/// The sheet shows `reason` and is drawn by macOS, not by wardenrun.
public struct BiometricApprover: Approver {
    public init() {}

    public func approve(reason: String, timeout: TimeInterval) -> ApprovalDecision {
        let context = LAContext()
        context.localizedFallbackTitle = ""      // no "Enter Password" button
        context.localizedCancelTitle = "Deny"
        context.interactionNotAllowed = false

        var availability: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &availability) else {
            return Self.decision(forLAErrorCode: availability?.code ?? 0)
        }

        let finished = DispatchSemaphore(value: 0)
        let state = NSLock()
        var outcome: ApprovalDecision?
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, error in
            state.lock()
            outcome = success ? .approved : Self.decision(forLAErrorCode: (error as NSError?)?.code ?? 0)
            state.unlock()
            finished.signal()
        }

        var timedOut = false
        if finished.wait(timeout: .now() + max(timeout, 0)) == .timedOut {
            timedOut = true
            context.invalidate()                  // closes the sheet; the reply follows with "app cancel"
            _ = finished.wait(timeout: .now() + 5)
        }
        state.lock()
        defer { state.unlock() }
        // A decision that arrived before the timer fired stands; only an answer cut off by the
        // timer is a timeout. Nothing is ever approved here that the evaluation did not approve.
        if timedOut, outcome != .approved { return .timedOut }
        return outcome ?? .unavailable(reason: "Touch ID could not be used")
    }

    /// `LAError.Code` raw values to a decision. `.approved` is not reachable from here: it comes
    /// only from a successful evaluation.
    static func decision(forLAErrorCode code: Int) -> ApprovalDecision {
        switch code {
        case -1, -2, -3, -4, -9:        // failed, user cancel, fallback, system cancel, app cancel
            return .denied
        case -8:
            return .unavailable(reason: "Touch ID is locked out; unlock the Mac with its password first")
        case -7:
            return .unavailable(reason: "Touch ID has no enrolled fingerprint")
        case -6:
            return .unavailable(reason: "Touch ID is not available on this Mac")
        case -5:
            return .unavailable(reason: "this Mac has no passcode set")
        default:
            return .unavailable(reason: "Touch ID could not be used")
        }
    }
}
#endif
