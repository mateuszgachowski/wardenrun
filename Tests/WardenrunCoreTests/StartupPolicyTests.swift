import Foundation
import Testing
@testable import WardenrunCore

struct StartupPolicyTests {
    private func ok(_ name: String) -> CheckResult { CheckResult(name: name, status: .ok, detail: "fine") }
    private let hardened = CheckResult(name: "hardened-runtime", status: .ok, detail: "the hardened runtime is on")
    private let unhardened = CheckResult(name: "hardened-runtime", status: .warn, detail: "ad-hoc without the runtime")

    @Test func aCleanSetOfChecksGoesOn() {
        #expect(StartupPolicy.refusal(checks: [ok("deny-attach"), ok("core-dumps"), hardened, ok("graphic-session")], allowUnhardened: false) == nil)
    }

    @Test func anyFailedCheckRefusesWithItsNameAndDetail() {
        let failed = CheckResult(name: "graphic-session", status: .fail, detail: "no window-server session")
        #expect(StartupPolicy.refusal(checks: [hardened, failed], allowUnhardened: true) == "refusing to run: graphic-session: no window-server session")
        let dyld = CheckResult(name: "dyld-environment", status: .fail, detail: "DYLD_ variables are set (DYLD_X)")
        #expect(StartupPolicy.refusal(checks: [dyld, hardened], allowUnhardened: true)?.contains("DYLD_X") == true)
    }

    @Test func aBuildWithoutTheHardenedRuntimeIsRefusedUnlessItIsADebugBuild() {
        let release = StartupPolicy.refusal(checks: [ok("deny-attach"), unhardened], allowUnhardened: false)
        #expect(release == "refusing to run: hardened-runtime: ad-hoc without the runtime")
        #expect(StartupPolicy.refusal(checks: [ok("deny-attach"), unhardened], allowUnhardened: true) == nil)
    }

    @Test func aMissingHardenedRuntimeCheckIsNotAnExcuse() {
        // The check list must contain the hardened-runtime line; when it is absent a release build
        // has not been checked at all and must not pass by default.
        #expect(StartupPolicy.refusal(checks: [ok("deny-attach")], allowUnhardened: false) == "refusing to run: no hardened-runtime check was made")
    }
}
