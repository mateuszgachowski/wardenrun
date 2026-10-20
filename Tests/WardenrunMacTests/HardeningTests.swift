#if canImport(Darwin)
import Darwin
import Testing
import WardenrunCore
@testable import WardenrunMac

struct HardeningTests {
    @Test func dyldVariablesAreFoundCaseSensitivelyAndSorted() {
        let environment = ["DYLD_INSERT_LIBRARIES": "/x.dylib", "PATH": "/usr/bin", "dyld_lower": "1",
                           "DYLD_FRAMEWORK_PATH": "/f", "MY_DYLD_X": "1", "DYLD": "1"]
        #expect(Hardening.dyldVariables(in: environment) == ["DYLD_FRAMEWORK_PATH", "DYLD_INSERT_LIBRARIES"])
    }

    @Test func anEnvironmentWithDyldFailsTheSelfCheckWithoutPrintingValues() throws {
        let results = Hardening.selfCheck(environment: ["DYLD_INSERT_LIBRARIES": "/secret/evil.dylib"])
        let dyld = try #require(results.first { $0.name == "dyld-environment" })
        #expect(dyld.status == .fail)
        #expect(dyld.detail.contains("DYLD_INSERT_LIBRARIES"))
        #expect(!dyld.detail.contains("evil"))
        #expect(!dyld.detail.contains("/secret"))
    }

    @Test func aCleanEnvironmentPassesTheDyldCheck() throws {
        let results = Hardening.selfCheck(environment: ["PATH": "/usr/bin", "HOME": "/Users/x"])
        let dyld = try #require(results.first { $0.name == "dyld-environment" })
        #expect(dyld.status == .ok)
    }

    @Test func rlimitCoreIsZeroAfterTheCoreLimitHelperRuns() {
        // The hard limit goes to zero too, and an unprivileged process cannot raise it again: this
        // lowers the test runner's limits for good, which is harmless (no core dumps).
        #expect(Hardening.disableCoreDumps())
        var limit = rlimit()
        #expect(getrlimit(RLIMIT_CORE, &limit) == 0)
        #expect(limit.rlim_cur == 0 && limit.rlim_max == 0)
    }

    @Test func selfCheckNamesAreStable() {
        // The names are part of the doctor output, which the README shows.
        #expect(Hardening.selfCheck(environment: [:]).map(\.name) == ["dyld-environment", "hardened-runtime", "graphic-session"])
    }

    @Test func anUnsignedBinaryIsReportedAsNotHardenedNeverAsHardened() throws {
        // The SwiftPM test runner is not signed with the hardened runtime.
        #expect(Hardening.hardenedRuntimeEnabled() != true)
        let results = Hardening.selfCheck(environment: [:])
        let runtime = try #require(results.first { $0.name == "hardened-runtime" })
        #expect(runtime.status != .ok)
    }
}
#endif
