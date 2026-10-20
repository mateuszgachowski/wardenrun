import Foundation
import Testing
@testable import WardenrunCore

final class RecordingChecker: BwSignatureChecker, @unchecked Sendable {
    let accept: Bool
    private let lock = NSLock()
    private var recorded: [String] = []

    init(accept: Bool = true) { self.accept = accept }

    var calls: [String] { lock.lock(); defer { lock.unlock() }; return recorded }
    private var running: [String] = []
    /// `team@pid` of every live check.
    var runningCalls: [String] { lock.lock(); defer { lock.unlock() }; return running }

    func checkRunning(pid: Int32, teamID: String) throws {
        lock.lock(); running.append("\(teamID)@\(pid)"); lock.unlock()
        if !accept { throw BwError.signatureMismatch }
    }

    func check(path: String, teamID: String) throws {
        lock.lock(); recorded.append(teamID + "@" + path); lock.unlock()
        if !accept { throw BwError.signatureMismatch }
    }
}

struct BwBinaryTests {
    private let team = "LTZ2PFU5D6"

    @Test func theSpecCarriesALiveCheckThatAsksTheCheckerAboutTheRunningProcess() throws {
        try withTempDirectory { raw in
            let dir = realPath(raw)
            let bw = writeFile(dir + "/bin/bw")
            let checker = RecordingChecker()
            let spec = try BwBinaryPolicy.launchSpec(for: .signedRelease(teamID: team, path: bw), signature: checker)
            let verify = try #require(spec.verifyStarted)
            try verify(4242)
            #expect(checker.runningCalls == ["\(team)@4242"])
            let refuse = RecordingChecker(accept: false)
            #expect(throws: BwError.signatureMismatch) {
                _ = try BwBinaryPolicy.launchSpec(for: .signedRelease(teamID: team, path: bw), signature: refuse)
            }
        }
    }

    @Test func theLiveCheckIsNotPartOfTheSpecsEquality() {
        let a = BwLaunchSpec(executable: "/x", leadingArguments: [], pinnedDirectories: ["/"])
        let b = BwLaunchSpec(executable: "/x", leadingArguments: [], pinnedDirectories: ["/"], verifyStarted: { _ in })
        #expect(a == b)
    }


    // MARK: signed release

    @Test func signedReleaseAcceptsAPinnedRegularFile() throws {
        try withTempDirectory { raw in
            let dir = realPath(raw)
            let bw = writeFile(dir + "/bin/bw")
            let checker = RecordingChecker()
            let spec = try BwBinaryPolicy.launchSpec(for: .signedRelease(teamID: team, path: bw), signature: checker)
            #expect(spec == BwLaunchSpec(executable: bw, leadingArguments: [], pinnedDirectories: [dir + "/bin"]))
            #expect(checker.calls == [team + "@" + bw])
        }
    }

    @Test func signedReleaseRefusesASymlinkedPath() throws {
        try withTempDirectory { raw in
            let dir = realPath(raw)
            let real = writeFile(dir + "/real/bw")
            try FileManager.default.createDirectory(atPath: dir + "/link", withIntermediateDirectories: true)
            try FileManager.default.createSymbolicLink(atPath: dir + "/link/bw", withDestinationPath: real)
            let checker = RecordingChecker()
            #expect(throws: BwError.binaryNotAllowed(reason: "pinned path is not canonical (a symlink?)")) {
                _ = try BwBinaryPolicy.launchSpec(for: .signedRelease(teamID: team, path: dir + "/link/bw"), signature: checker)
            }
            #expect(checker.calls.isEmpty)
        }
    }

    @Test func signedReleaseRefusesWhenTheCheckerRejects() {
        withTempDirectory { raw in
            let bw = writeFile(realPath(raw) + "/bw")
            #expect(throws: BwError.signatureMismatch) {
                _ = try BwBinaryPolicy.launchSpec(for: .signedRelease(teamID: team, path: bw), signature: RecordingChecker(accept: false))
            }
        }
    }

    @Test func missingOrNonExecutableFilesAreRefusedBeforeTheSignatureIsChecked() {
        withTempDirectory { raw in
            let dir = realPath(raw)
            let plain = writeFile(dir + "/plain", mode: 0o644)
            for path in [dir + "/missing", plain, dir] {
                let checker = RecordingChecker()
                #expect(throws: BwError.binaryNotAllowed(reason: "pinned bw is missing or not an executable file"), "\(path)") {
                    _ = try BwBinaryPolicy.launchSpec(for: .signedRelease(teamID: team, path: path), signature: checker)
                }
                #expect(checker.calls.isEmpty)
            }
        }
    }

    @Test func aBwDataEntryBesideTheBinaryIsRefused() throws {
        try withTempDirectory { raw in
            let dir = realPath(raw)
            let bw = writeFile(dir + "/bw")
            try FileManager.default.createDirectory(atPath: dir + "/bw-data", withIntermediateDirectories: true)
            #expect(throws: BwError.binaryNotAllowed(reason: "a bw-data directory sits beside the binary")) {
                _ = try BwBinaryPolicy.launchSpec(for: .signedRelease(teamID: team, path: bw), signature: RecordingChecker())
            }
        }
    }
}
