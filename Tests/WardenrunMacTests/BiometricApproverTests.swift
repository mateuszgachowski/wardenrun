#if canImport(Darwin)
import Testing
import WardenrunCore
@testable import WardenrunMac

// The sheet itself is never shown from a test: only the mapping of LocalAuthentication error
// codes to decisions is. The real sheet is on the manual checklist (docs/RELEASING.md).
struct BiometricApproverTests {
    // LAError.Code raw values: authenticationFailed -1, userCancel -2, userFallback -3,
    // systemCancel -4, passcodeNotSet -5, biometryNotAvailable -6, biometryNotEnrolled -7,
    // biometryLockout -8, appCancel -9, invalidContext -10, notInteractive -1004.

    @Test(arguments: [-1, -2, -3, -4, -9])
    func userCancelAndAuthenticationFailedAreDenied(code: Int) {
        #expect(BiometricApprover.decision(forLAErrorCode: code) == .denied)
    }

    @Test func biometryLockoutNotEnrolledNotAvailableAreUnavailableWithFixedTexts() {
        #expect(BiometricApprover.decision(forLAErrorCode: -8)
            == .unavailable(reason: "Touch ID is locked out; unlock the Mac with its password first"))
        #expect(BiometricApprover.decision(forLAErrorCode: -7) == .unavailable(reason: "Touch ID has no enrolled fingerprint"))
        #expect(BiometricApprover.decision(forLAErrorCode: -6) == .unavailable(reason: "Touch ID is not available on this Mac"))
        #expect(BiometricApprover.decision(forLAErrorCode: -5) == .unavailable(reason: "this Mac has no passcode set"))
    }

    @Test(arguments: [0, 1, -10, -1004, -999, 12345, Int.max, Int.min])
    func anUnknownCodeIsUnavailableNotApproved(code: Int) {
        #expect(BiometricApprover.decision(forLAErrorCode: code) == .unavailable(reason: "Touch ID could not be used"))
    }

    @Test func onlySuccessCanApprove() {
        // `approved` is produced by the evaluation succeeding and by nothing else: no error code,
        // known or not, maps to it.
        for code in -3000...3000 {
            #expect(BiometricApprover.decision(forLAErrorCode: code) != .approved, "code \(code)")
        }
    }
}
#endif
