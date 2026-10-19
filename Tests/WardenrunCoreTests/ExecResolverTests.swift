import Foundation
import Testing
@testable import WardenrunCore

struct ExecResolverTests {
    private func resolve(_ argv: [String], path: String, cwd: String) throws -> ResolvedExecutable {
        try ExecResolver.resolve(argv: argv, searchPath: path, cwd: cwd)
    }

    @Test func findsTheCommandOnThePathAndHashesIt() throws {
        try withTempDirectory { (dir: String) throws in
            let d1 = dir + "/d1", d2 = dir + "/d2"
            try FileManager.default.createDirectory(atPath: d1, withIntermediateDirectories: true)
            let script = "#!/bin/sh\necho second\n"
            writeFile(d2 + "/tool", script)
            let found = try resolve(["tool", "a"], path: "\(d1):\(d2)", cwd: dir)
            #expect(found.path == realPath(d2) + "/tool")
            #expect(found.argv == ["tool", "a"])
            #expect(found.sha256 == SHA256.hexHash(Array(script.utf8)))
        }
    }

    @Test func theFirstMatchOnThePathWins() throws {
        try withTempDirectory { (dir: String) throws in
            writeFile(dir + "/d1/tool", "one")
            writeFile(dir + "/d2/tool", "two")
            let found = try resolve(["tool"], path: "\(dir)/d1:\(dir)/d2", cwd: dir)
            #expect(found.path == realPath(dir) + "/d1/tool")
        }
    }

    @Test func adirectoryOrANonExecutableFileEarlierOnThePathIsSkipped() throws {
        try withTempDirectory { (dir: String) throws in
            try FileManager.default.createDirectory(atPath: dir + "/d1/tool", withIntermediateDirectories: true)
            writeFile(dir + "/d2/tool", "not executable", mode: 0o644)
            writeFile(dir + "/d3/tool", "real")
            let found = try resolve(["tool"], path: "\(dir)/d1:\(dir)/d2:\(dir)/d3", cwd: dir)
            #expect(found.path == realPath(dir) + "/d3/tool")
        }
    }

    @Test func anEmptyOrRelativePathEntryMeansTheWorkingDirectoryButTheResultIsAbsolute() throws {
        try withTempDirectory { (dir: String) throws in
            writeFile(dir + "/tool", "in cwd")
            writeFile(dir + "/bin/other", "in bin")
            let viaEmpty = try resolve(["tool"], path: ":/nonexistent", cwd: dir)
            #expect(viaEmpty.path == realPath(dir) + "/tool")
            let viaRelative = try resolve(["other"], path: "bin", cwd: dir)
            #expect(viaRelative.path == realPath(dir) + "/bin/other")
        }
    }

    @Test func aCommandWithASlashIsNotSearchedOnThePath() throws {
        try withTempDirectory { (dir: String) throws in
            writeFile(dir + "/tool", "in cwd")
            writeFile(dir + "/sub/tool", "in sub")
            writeFile(dir + "/path/tool", "on path")
            #expect(try resolve(["./tool"], path: dir + "/path", cwd: dir).path == realPath(dir) + "/tool")
            #expect(try resolve(["sub/tool"], path: dir + "/path", cwd: dir).path == realPath(dir) + "/sub/tool")
            #expect(try resolve([dir + "/sub/tool"], path: "", cwd: "/").path == realPath(dir) + "/sub/tool")
        }
    }

    @Test func aSymlinkIsResolvedForThePathButArgvZeroIsKept() throws {
        try withTempDirectory { (dir: String) throws in
            let content = "#!/bin/sh\nreal\n"
            writeFile(dir + "/real/tool-real", content)
            try FileManager.default.createDirectory(atPath: dir + "/bin", withIntermediateDirectories: true)
            try FileManager.default.createSymbolicLink(atPath: dir + "/bin/link", withDestinationPath: dir + "/real/tool-real")
            let found = try resolve(["link", "x"], path: dir + "/bin", cwd: dir)
            #expect(found.path == realPath(dir) + "/real/tool-real")
            #expect(found.argv == ["link", "x"])
            #expect(found.sha256 == SHA256.hexHash(Array(content.utf8)))
        }
    }

    @Test func theHashCoversLargeFilesReadInBlocks() throws {
        try withTempDirectory { (dir: String) throws in
            let content = String(repeating: "0123456789abcdef", count: 20_000)   // 320 kB, several 64 KiB blocks
            writeFile(dir + "/big", content)
            let found = try resolve(["./big"], path: "", cwd: dir)
            #expect(found.sha256 == SHA256.hexHash(Array(content.utf8)))
        }
    }

    @Test func stillMatchesIsTrueRightAfterResolvingAndFalseOnceTheFileChanges() throws {
        try withTempDirectory { (dir: String) throws in
            writeFile(dir + "/tool", "#!/bin/sh\necho one\n")
            let found = try resolve(["./tool"], path: "", cwd: dir)
            #expect(ExecResolver.stillMatches(found))
            writeFile(dir + "/tool", "#!/bin/sh\necho two\n")
            #expect(!ExecResolver.stillMatches(found))
        }
    }

    @Test func stillMatchesIsFalseWhenTheFileIsGoneReplacedByALinkOrNoLongerExecutable() throws {
        try withTempDirectory { (dir: String) throws in
            writeFile(dir + "/tool", "same bytes")
            writeFile(dir + "/other", "same bytes")
            let found = try resolve(["./tool"], path: "", cwd: dir)
            // swapped for a symlink to a file with identical content: the path no longer resolves to itself
            try FileManager.default.removeItem(atPath: dir + "/tool")
            try FileManager.default.createSymbolicLink(atPath: dir + "/tool", withDestinationPath: dir + "/other")
            #expect(!ExecResolver.stillMatches(found))
            try FileManager.default.removeItem(atPath: dir + "/tool")
            #expect(!ExecResolver.stillMatches(found))   // gone
            writeFile(dir + "/tool", "same bytes", mode: 0o644)
            #expect(!ExecResolver.stillMatches(found))   // same bytes, no execute bit
        }
    }

    @Test func rejectsAnEmptyCommand() throws {
        try withTempDirectory { (dir: String) throws in
            #expect(throws: ExecError.emptyCommand) { try resolve([], path: "/bin", cwd: dir) }
            #expect(throws: ExecError.emptyCommand) { try resolve(["", "x"], path: "/bin", cwd: dir) }
        }
    }

    @Test func rejectsAMissingCommand() throws {
        try withTempDirectory { (dir: String) throws in
            #expect(throws: ExecError.notFound("tool")) { try resolve(["tool"], path: dir, cwd: dir) }
            #expect(throws: ExecError.notFound("./nope")) { try resolve(["./nope"], path: dir, cwd: dir) }
        }
    }

    @Test func rejectsAFileThatIsNotExecutableAndADirectory() throws {
        try withTempDirectory { (dir: String) throws in
            writeFile(dir + "/notexec", "data", mode: 0o644)
            try FileManager.default.createDirectory(atPath: dir + "/adir", withIntermediateDirectories: true)
            #expect(throws: ExecError.notExecutable(dir + "/notexec")) { try resolve(["./notexec"], path: "", cwd: dir) }
            #expect(throws: ExecError.notRegularFile(dir + "/adir")) { try resolve(["./adir"], path: "", cwd: dir) }
        }
    }

    @Test func rejectsANulByteInAnyArgument() throws {
        try withTempDirectory { (dir: String) throws in
            writeFile(dir + "/tool", "x")
            #expect(throws: ExecError.nulInArgument(index: 1)) { try resolve(["tool", "a\u{0}b"], path: dir, cwd: dir) }
            #expect(throws: ExecError.nulInArgument(index: 0)) { try resolve(["to\u{0}ol"], path: dir, cwd: dir) }
        }
    }
}
