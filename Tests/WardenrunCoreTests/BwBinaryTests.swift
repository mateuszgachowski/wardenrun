import Foundation
import Testing
@testable import WardenrunCore

final class RecordingChecker: BwSignatureChecker, @unchecked Sendable {
    let accept: Bool
    private let lock = NSLock()
    private var recorded: [String] = []

    init(accept: Bool = true) { self.accept = accept }

    var calls: [String] { lock.lock(); defer { lock.unlock() }; return recorded }

    func check(path: String, teamID: String) throws {
        lock.lock(); recorded.append(teamID + "@" + path); lock.unlock()
        if !accept { throw BwError.signatureMismatch }
    }
}

struct BwBinaryTests {
    private let team = "LTZ2PFU5D6"

    private func hash(_ path: String) throws -> String { try FileHash.sha256(ofFileAt: path) }

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

    // MARK: node script

    private func nodePin(_ dir: String, scriptDir: String? = nil, mutate: (String, String) throws -> Void = { _, _ in }) throws -> (BwPin, node: String, script: String) {
        let node = writeFile(dir + "/node-bin/node", "#!/bin/sh\n")
        let script = writeFile((scriptDir ?? dir + "/bw-lib") + "/bw.js", "console.log(1)\n", mode: 0o644)
        let pin = BwPin.nodeScript(nodePath: node, nodeSHA256: try hash(node), scriptPath: script, scriptSHA256: try hash(script))
        try mutate(node, script)
        return (pin, node, script)
    }

    @Test func nodeScriptAcceptsMatchingHashesAndNeverAsksTheSignatureChecker() throws {
        try withTempDirectory { raw in
            let dir = realPath(raw)
            let (pin, node, script) = try nodePin(dir)
            let checker = RecordingChecker()
            let spec = try BwBinaryPolicy.launchSpec(for: pin, signature: checker)
            #expect(spec == BwLaunchSpec(executable: node, leadingArguments: [script], pinnedDirectories: [dir + "/node-bin"]))
            #expect(checker.calls.isEmpty)
        }
    }

    @Test func nodeScriptAcceptsUppercaseHashesInThePin() throws {
        try withTempDirectory { raw in
            let dir = realPath(raw)
            let (pin, node, script) = try nodePin(dir)
            guard case .nodeScript(_, let nodeHash, _, let scriptHash) = pin else { Issue.record("wrong pin kind"); return }
            let upper = BwPin.nodeScript(nodePath: node, nodeSHA256: nodeHash.uppercased(), scriptPath: script, scriptSHA256: scriptHash.uppercased())
            _ = try BwBinaryPolicy.launchSpec(for: upper, signature: RecordingChecker())
        }
    }

    @Test func nodeScriptRefusesAScriptChangedByOneByte() throws {
        try withTempDirectory { raw in
            let (pin, _, script) = try nodePin(realPath(raw))
            let handle = try #require(FileHandle(forWritingAtPath: script))
            try handle.seekToEnd()
            try handle.write(contentsOf: Data([0x20]))
            try handle.close()
            #expect(throws: BwError.binaryNotAllowed(reason: "script does not match its pinned hash")) {
                _ = try BwBinaryPolicy.launchSpec(for: pin, signature: RecordingChecker())
            }
        }
    }

    @Test func nodeScriptRefusesAChangedNode() throws {
        try withTempDirectory { raw in
            let (pin, node, _) = try nodePin(realPath(raw))
            writeFile(node, "#!/bin/sh\necho evil\n")
            #expect(throws: BwError.binaryNotAllowed(reason: "node does not match its pinned hash")) {
                _ = try BwBinaryPolicy.launchSpec(for: pin, signature: RecordingChecker())
            }
        }
    }

    @Test func nodeScriptRefusesMissingFiles() throws {
        try withTempDirectory { raw in
            let (pin, node, script) = try nodePin(realPath(raw))
            try FileManager.default.removeItem(atPath: script)
            #expect(throws: BwError.binaryNotAllowed(reason: "pinned node or script is missing")) {
                _ = try BwBinaryPolicy.launchSpec(for: pin, signature: RecordingChecker())
            }
            try FileManager.default.removeItem(atPath: node)
            #expect(throws: BwError.binaryNotAllowed(reason: "pinned node or script is missing")) {
                _ = try BwBinaryPolicy.launchSpec(for: pin, signature: RecordingChecker())
            }
        }
    }

    @Test func nodeScriptRefusesBwDataBesideTheNodeOrBesideTheScript() throws {
        for besideNode in [true, false] {
            try withTempDirectory { raw in
                let dir = realPath(raw)
                let (pin, _, _) = try nodePin(dir)
                try FileManager.default.createDirectory(atPath: dir + (besideNode ? "/node-bin" : "/bw-lib") + "/bw-data",
                                                        withIntermediateDirectories: true)
                #expect(throws: BwError.binaryNotAllowed(reason: "a bw-data directory sits beside the binary")) {
                    _ = try BwBinaryPolicy.launchSpec(for: pin, signature: RecordingChecker())
                }
            }
        }
    }

    @Test func nodeScriptRefusesASymlinkedNode() throws {
        try withTempDirectory { raw in
            let dir = realPath(raw)
            let (_, node, script) = try nodePin(dir)
            try FileManager.default.createDirectory(atPath: dir + "/alias", withIntermediateDirectories: true)
            try FileManager.default.createSymbolicLink(atPath: dir + "/alias/node", withDestinationPath: node)
            let pin = BwPin.nodeScript(nodePath: dir + "/alias/node", nodeSHA256: try hash(node), scriptPath: script, scriptSHA256: try hash(script))
            #expect(throws: BwError.binaryNotAllowed(reason: "pinned path is not canonical (a symlink?)")) {
                _ = try BwBinaryPolicy.launchSpec(for: pin, signature: RecordingChecker())
            }
        }
    }
}
