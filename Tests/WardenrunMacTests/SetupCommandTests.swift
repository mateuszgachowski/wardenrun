#if canImport(Darwin)
import Foundation
import Testing
import WardenrunCore
@testable import WardenrunMac

private func withTempDirectory(_ body: (String) throws -> Void) throws {
    let path = (NSTemporaryDirectory() as NSString).appendingPathComponent("wardenrun-setupcmd-" + UUID().uuidString)
    try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(atPath: path) }
    try body(path)
}

private func realPath(_ path: String) -> String { URL(fileURLWithPath: path).resolvingSymlinksInPath().path }

struct SetupCommandTests {
    private func makeBw(in dir: String, executable: Bool) throws {
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        let path = dir + "/bw"
        FileManager.default.createFile(atPath: path, contents: Data("#!/bin/sh\n".utf8))
        chmod(path, executable ? 0o755 : 0o644)
    }

    @Test func theTeamIsTheBitwardenDeveloperIdTeam() {
        #expect(SetupCommand.bitwardenTeamID == "LTZ2PFU5D6")
    }

    @Test func findBwTakesTheFirstExecutableOnThePath() throws {
        try withTempDirectory { raw in
            let dir = realPath(raw)
            try makeBw(in: dir + "/a", executable: false)
            try makeBw(in: dir + "/b", executable: true)
            try makeBw(in: dir + "/c", executable: true)
            #expect(SetupCommand.findBw(in: "\(dir)/a:\(dir)/b:\(dir)/c") == dir + "/b/bw")
        }
    }

    @Test func findBwIgnoresRelativeDirectoriesAndFindsNothingElse() throws {
        try withTempDirectory { raw in
            let dir = realPath(raw)
            try makeBw(in: dir + "/x", executable: true)
            // A relative entry that does lead to a real bw from the current directory is still refused.
            let up = String(repeating: "../", count: FileManager.default.currentDirectoryPath.split(separator: "/").count)
            let relative = up + dir.dropFirst() + "/x"
            #expect(access(relative + "/bw", X_OK) == 0, "the relative path must really reach the file")
            #expect(SetupCommand.findBw(in: relative) == nil)
            #expect(SetupCommand.findBw(in: "x:.:") == nil)
            #expect(SetupCommand.findBw(in: "") == nil)
            #expect(SetupCommand.findBw(in: dir + "/missing") == nil)
        }
    }
}
#endif
