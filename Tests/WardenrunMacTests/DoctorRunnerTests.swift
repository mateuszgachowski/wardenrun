#if canImport(Darwin)
import Foundation
import Testing
import WardenrunCore
@testable import WardenrunMac

private struct FakeStore: SecretStore {
    var config: ProtectedConfig?
    var tierDescription: String { "B: test tier" }
    func load() throws -> ProtectedConfig? { config }
    func save(_ config: ProtectedConfig) throws {}
    func erase() throws {}
}

private struct AcceptingChecker: BwSignatureChecker {
    func checkRunning(pid: Int32, teamID: String) throws {}
    func check(path: String, teamID: String) throws {}
}

private func tempDirectory() -> String {
    let path = (NSTemporaryDirectory() as NSString).appendingPathComponent("wardenrun-doctor-" + UUID().uuidString)
    try? FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: true)
    return path
}

private func config(bw: String) throws -> ProtectedConfig {
    try ProtectedConfig(serverURL: try #require(URL(string: "https://vault.example")), accountEmail: "a@b.example",
                        organizationID: "o", collectionIDs: ["c"],
                        masterPassword: SecretBuffer(copying: Array("master-password-KNOWN".utf8)),
                        bwPin: .signedRelease(teamID: "LTZ2PFU5D6", path: bw))
}

/// Stand-ins for the checks that ask the Security framework, so that these tests do not depend on
/// the system's trust services (which can stall for as long as a keychain dialog is open).
private func fakeCertificate() -> CheckResult { CheckResult(name: "certificate", status: .info, detail: "fake") }
private func fakeHardening(_ environment: [String: String]) -> [CheckResult] {
    let dyld = Hardening.dyldVariables(in: environment)
    return [CheckResult(name: "dyld-environment", status: dyld.isEmpty ? .ok : .fail,
                        detail: dyld.isEmpty ? "none" : "DYLD_ variables are set (\(dyld.joined(separator: ", ")))"),
            CheckResult(name: "hardened-runtime", status: .ok, detail: "fake"),
            CheckResult(name: "graphic-session", status: .ok, detail: "fake")]
}

struct DoctorRunnerTests {
    private func names(_ report: DoctorReport) -> [String] { report.checks.map(\.name) }

    @Test func withoutAnItemTheReportExplainsSetupAndSkipsTheBwChecks() throws {
        let home = tempDirectory()
        defer { try? FileManager.default.removeItem(atPath: home) }
        let report = DoctorRunner.run(environment: [:], store: FakeStore(config: nil), paths: WardenrunPaths(home: home),
                                      signature: AcceptingChecker(), certificate: fakeCertificate, hardening: fakeHardening, touchID: { CheckResult(name: "touch-id", status: .ok, detail: "ready") })
        #expect(report.tier == "B: test tier")
        #expect(names(report) == ["certificate", "dyld-environment", "hardened-runtime", "graphic-session",
                                  "protected-item", "bw-profile", "touch-id"])
        #expect(report.render().contains("wardenrun setup"))
    }

    @Test func withAnItemThePinAndTheBwVersionAreChecked() throws {
        let home = tempDirectory()
        defer { try? FileManager.default.removeItem(atPath: home) }
        let bw = home + "/bw"
        try Data("#!/bin/sh\necho 2026.10.0\n".utf8).write(to: URL(fileURLWithPath: bw))
        chmod(bw, 0o755)
        let canonical = realpath(bw, nil).map { String(cString: $0) } ?? bw
        let report = DoctorRunner.run(environment: [:], store: FakeStore(config: try config(bw: canonical)),
                                      paths: WardenrunPaths(home: home), signature: AcceptingChecker(),
                                      certificate: fakeCertificate, hardening: fakeHardening, touchID: { CheckResult(name: "touch-id", status: .ok, detail: "ready") })
        #expect(names(report).contains("bw-pin"))
        let pin = try #require(report.checks.first { $0.name == "bw-pin" })
        #expect(pin.status == .ok)
        let version = try #require(report.checks.first { $0.name == "bw-version" })
        #expect(version.status == .info)
        #expect(version.detail.contains("2026.10.0"))
        #expect(!report.render().contains("KNOWN"), "the master password never appears")
    }

    @Test func aFailingPinSkipsTheVersionCheckAndFailsTheReport() throws {
        let home = tempDirectory()
        defer { try? FileManager.default.removeItem(atPath: home) }
        let report = DoctorRunner.run(environment: [:], store: FakeStore(config: try config(bw: "/nonexistent/bw")),
                                      paths: WardenrunPaths(home: home), signature: AcceptingChecker(),
                                      certificate: fakeCertificate, hardening: fakeHardening, touchID: { CheckResult(name: "touch-id", status: .ok, detail: "ready") })
        #expect(report.checks.first { $0.name == "bw-pin" }?.status == .fail)
        #expect(!names(report).contains("bw-version"))
        #expect(report.exitCode == 1)
    }

    @Test func dyldInTheEnvironmentFailsTheReportWithoutPrintingTheValue() throws {
        let home = tempDirectory()
        defer { try? FileManager.default.removeItem(atPath: home) }
        let report = DoctorRunner.run(environment: ["DYLD_INSERT_LIBRARIES": "/tmp/evil-VALUE.dylib"], store: FakeStore(config: nil),
                                      paths: WardenrunPaths(home: home), signature: AcceptingChecker(),
                                      certificate: fakeCertificate, hardening: fakeHardening, touchID: { CheckResult(name: "touch-id", status: .ok, detail: "ready") })
        #expect(report.exitCode == 1)
        #expect(report.render().contains("DYLD_INSERT_LIBRARIES"))
        #expect(!report.render().contains("evil-VALUE"))
    }

    /// Runs the doctor with a fake `bw` whose body is `script` and returns its `bw-version` line.
    private func versionLine(script: String) throws -> CheckResult {
        let home = tempDirectory()
        defer { try? FileManager.default.removeItem(atPath: home) }
        let bw = home + "/bw"
        try Data(("#!/bin/sh\n" + script + "\n").utf8).write(to: URL(fileURLWithPath: bw))
        chmod(bw, 0o755)
        let canonical = realpath(bw, nil).map { String(cString: $0) } ?? bw
        let report = DoctorRunner.run(environment: [:], store: FakeStore(config: try config(bw: canonical)),
                                      paths: WardenrunPaths(home: home), signature: AcceptingChecker(),
                                      certificate: fakeCertificate, hardening: fakeHardening,
                                      touchID: { CheckResult(name: "touch-id", status: .ok, detail: "ready") })
        return try #require(report.checks.first { $0.name == "bw-version" })
    }

    @Test func aBwVersionOtherThanTheTestedOneIsMarkedUntestedNotWrong() throws {
        let other = try versionLine(script: "echo 2025.1.0")
        #expect(other.status == .info)
        #expect(other.detail.contains("untested"))
        let tested = try versionLine(script: "echo 2026.10.3")
        #expect(!tested.detail.contains("untested"))
        #expect(tested.detail.contains("tested with 2026.10."))
    }

    @Test func aVersionInAnUnexpectedFormIsAWarningAndIsNotEchoed() throws {
        for output in ["echo 'v1; rm -rf /'", "echo 2026.10.0-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "printf '\\033[31mred'", "echo"] {
            let line = try versionLine(script: output)
            #expect(line.status == .warn, Comment(rawValue: output))
            #expect(line.detail == "bw reported a version in an unexpected form" || line.detail == "bw did not report its version")
            #expect(!line.detail.contains("rm -rf"))
        }
    }

    @Test func aBwThatFailsToReportItsVersionIsAWarning() throws {
        let line = try versionLine(script: "echo 2026.10.0; exit 3")
        #expect(line.status == .warn)
        #expect(line.detail == "bw did not report its version")
    }

    @Test func theCertificateLineNamesTheSigner() throws {
        let check = DoctorRunner.certificateCheck()
        #expect(check.name == "certificate")
        #expect(check.status == .info)
        #expect(!check.detail.isEmpty && !check.detail.contains("\n"))
    }

    @Test func touchIDCheckAnswersWithAStatusAndNeverShowsASheet() {
        // canEvaluatePolicy only asks whether biometrics could be used; it shows nothing.
        let check = DoctorRunner.touchIDCheck()
        #expect(check.name == "touch-id")
        #expect([CheckResult.Status.ok, .fail].contains(check.status))
    }
}
#endif
