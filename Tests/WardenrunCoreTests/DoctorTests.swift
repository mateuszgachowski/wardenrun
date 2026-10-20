import Foundation
import Testing
@testable import WardenrunCore

private struct FakeStore: SecretStore {
    var result: Result<ProtectedConfig?, StoreError>
    var tierDescription: String { "test tier" }
    func load() throws -> ProtectedConfig? { try result.get() }
    func save(_ config: ProtectedConfig) throws {}
    func erase() throws {}
}

private struct AcceptingChecker: BwSignatureChecker {
    func checkRunning(pid: Int32, teamID: String) throws {}
    var accept = true
    func check(path: String, teamID: String) throws { if !accept { throw BwError.signatureMismatch } }
}

private func sampleConfig(path: String = "/opt/wardenrun/bw") throws -> ProtectedConfig {
    try ProtectedConfig(serverURL: try #require(URL(string: "https://vault.example:8443")), accountEmail: "agent@example.org",
                        organizationID: "org-1", collectionIDs: ["col-1", "col-2"],
                        masterPassword: SecretBuffer(copying: Array("hunter2-hunter2-KNOWN".utf8)),
                        bwPin: .signedRelease(teamID: "LTZ2PFU5D6", path: path))
}

struct DoctorTests {
    @Test func reportRendersEveryCheckOnOneLineWithStatus() {
        let report = DoctorReport(tier: "B: something", checks: [
            CheckResult(name: "a", status: .ok, detail: "fine"),
            CheckResult(name: "b", status: .warn, detail: "hmm"),
            CheckResult(name: "c", status: .fail, detail: "broken\nsecond line\u{1B}[31m"),
            CheckResult(name: "d", status: .info, detail: "just so you know"),
        ])
        let lines = report.render().split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        #expect(lines.first == "wardenrun doctor")
        #expect(lines.contains("tier: B: something"))
        let body = lines.filter { $0.hasPrefix("ok ") || $0.hasPrefix("warn ") || $0.hasPrefix("FAIL ") || $0.hasPrefix("info ") }
        #expect(body.count == 4, "\(lines)")
        #expect(body[0] == "ok    a  fine")
        #expect(body[1] == "warn  b  hmm")
        #expect(body[2].hasPrefix("FAIL  c  broken second line"))
        #expect(!report.render().unicodeScalars.contains { $0.value == 0x1B }, "control characters are removed from details")
        #expect(body[3] == "info  d  just so you know")
    }

    @Test func exitCodeIsOneOnlyForFail() {
        func code(_ statuses: [CheckResult.Status]) -> Int32 {
            DoctorReport(tier: "t", checks: statuses.map { CheckResult(name: "x", status: $0, detail: "d") }).exitCode
        }
        #expect(code([]) == 0)
        #expect(code([.ok, .info, .warn]) == 0)
        #expect(code([.ok, .fail]) == 1)
        #expect(code([.fail, .fail]) == 1)
    }

    @Test func doctorWithoutAnItemExplainsRunSetup() {
        let result = DoctorChecks.protectedItem(store: FakeStore(result: .success(nil)))
        #expect(result.check.status == .info)
        #expect(result.check.detail.contains("wardenrun setup"))
        #expect(result.config == nil)
    }

    @Test func anUnreadableItemIsAFailWithTheStoresFixedReason() {
        let result = DoctorChecks.protectedItem(store: FakeStore(result: .failure(.unreadable(reason: "the item is not readable by this binary; run wardenrun setup again"))))
        #expect(result.check.status == .fail)
        #expect(result.check.detail == "the item is not readable by this binary; run wardenrun setup again")
        #expect(result.config == nil)
    }

    @Test func aReadableItemIsReportedByCountsOnly() throws {
        let result = DoctorChecks.protectedItem(store: FakeStore(result: .success(try sampleConfig())))
        #expect(result.check.status == .ok)
        #expect(result.check.detail == "readable: 1 organization, 2 collections")
        #expect(result.config != nil)
        for secret in ["hunter2", "vault.example", "agent@example.org", "org-1", "col-1"] {
            #expect(!result.check.detail.contains(secret), "\(secret)")
        }
    }

    @Test func renderNeverContainsAPasswordLookingValue() throws {
        let config = try sampleConfig()
        let item = DoctorChecks.protectedItem(store: FakeStore(result: .success(config)))
        let pin = DoctorChecks.bwPin(config: config, signature: AcceptingChecker())
        let report = DoctorReport(tier: "test tier", checks: [item.check, pin])
        #expect(!report.render().contains("hunter2"))
        #expect(!"\(config)".contains("hunter2"))
    }

    @Test func aPinThatPassesIsOkAndNamesOnlyTheTeamAndPath() throws {
        try withTempDirectory { raw in
            let dir = realPath(raw)
            let bw = writeFile(dir + "/bw")
            let check = DoctorChecks.bwPin(config: try sampleConfig(path: bw), signature: AcceptingChecker())
            #expect(check.status == .ok)
            #expect(check.detail.contains("LTZ2PFU5D6"))
            #expect(check.detail.contains(bw))
            #expect(!check.detail.contains("hunter2"))
        }
    }

    @Test func aMissingOrRefusedBwIsAFailWithAFixedText() throws {
        let missing = DoctorChecks.bwPin(config: try sampleConfig(path: "/nonexistent/bw"), signature: AcceptingChecker())
        #expect(missing.status == .fail)
        #expect(missing.detail == "the pinned bw is not usable: pinned bw is missing or not an executable file")
        try withTempDirectory { raw in
            let dir = realPath(raw)
            let bw = writeFile(dir + "/bw")
            let refused = DoctorChecks.bwPin(config: try sampleConfig(path: bw), signature: AcceptingChecker(accept: false))
            #expect(refused.status == .fail)
            #expect(refused.detail == "the pinned bw is not usable: its code signature does not match team LTZ2PFU5D6")
        }
    }

    @Test func theBwProfileCheckIsLocalOnly() throws {
        try withTempDirectory { dir in
            let absent = DoctorChecks.bwProfile(appDataDirectory: dir + "/bw")
            #expect(absent.status == .info)
            #expect(absent.detail.contains("wardenrun setup"))
            try FileManager.default.createDirectory(atPath: dir + "/bw", withIntermediateDirectories: true)
            _ = writeFile(dir + "/bw/data.json", "{}")
            let present = DoctorChecks.bwProfile(appDataDirectory: dir + "/bw")
            #expect(present.status == .ok)
        }
    }

    @Test func bwErrorsHaveFixedSummaries() {
        let errors: [BwError] = [.itemNotFound, .ambiguous(count: 2), .alreadyExists, .unsupportedField("x"),
                                 .binaryNotAllowed(reason: "r"), .signatureMismatch, .lockBusy, .stateUnavailable(reason: "r"),
                                 .cancelled, .outputTooLarge, .notLoggedIn, .spawnFailed(errno: 2), .timeout(phase: "p"),
                                 .protocolError("x"), .unlockFailed(message: "x"), .serverError(status: 500), .invalidUTF8(field: "f")]
        for error in errors { #expect(!error.summary.isEmpty && !error.summary.contains("\n")) }
        #expect(BwError.protocolError("SECRET-MARKER").summary.contains("SECRET-MARKER") == false)
        #expect(BwError.unlockFailed(message: "SECRET-MARKER").summary.contains("SECRET-MARKER") == false)
    }
}
