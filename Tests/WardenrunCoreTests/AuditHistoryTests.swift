import Foundation
import Testing
@testable import WardenrunCore

struct AuditHistoryTests {
    private func path(_ dir: String) -> String { dir + "/logs/audit.jsonl" }

    private func log(_ dir: String, redactor: @escaping @Sendable (String) -> String = { $0 }) -> AuditLog {
        AuditLog(path: path(dir), redactor: redactor, clock: { Date(timeIntervalSince1970: 0) })
    }

    private func event(_ kind: AuditEventKind, item: String = "alpha", exe: String = "/usr/bin/curl",
                       hash: String? = nil) -> AuditEvent {
        AuditEvent(event: kind, item: item, commandLine: ["curl"], executable: exe,
                   executableSHA256: hash ?? String(repeating: "ab", count: 32))
    }

    private let first = String(repeating: "11", count: 32)
    private let second = String(repeating: "22", count: 32)

    @Test func findsTheNewestApprovedHashForItemAndPath() throws {
        try withTempDirectory { dir in
            let audit = log(dir)
            try audit.append(event(.approved, hash: first))
            try audit.append(event(.approved, hash: second))
            #expect(AuditLog.lastApprovedHash(path: path(dir), item: "alpha", executable: "/usr/bin/curl") == second)
        }
    }

    @Test func ignoresDeniedAndOtherItemsAndOtherPaths() throws {
        try withTempDirectory { dir in
            let audit = log(dir)
            try audit.append(event(.approved, hash: first))
            try audit.append(event(.denied, hash: second))
            try audit.append(event(.timeout, hash: second))
            try audit.append(event(.finished, hash: second))
            try audit.append(event(.approved, item: "beta", hash: second))
            try audit.append(event(.approved, exe: "/usr/local/bin/curl", hash: second))
            #expect(AuditLog.lastApprovedHash(path: path(dir), item: "alpha", executable: "/usr/bin/curl") == first)
            #expect(AuditLog.lastApprovedHash(path: path(dir), item: "gamma", executable: "/usr/bin/curl") == nil)
            #expect(AuditLog.lastApprovedHash(path: path(dir), item: "alpha", executable: "/bin/ls") == nil)
        }
    }

    @Test func aMissingOrDamagedLogGivesNil() throws {
        try withTempDirectory { dir in
            #expect(AuditLog.lastApprovedHash(path: path(dir), item: "alpha", executable: "/usr/bin/curl") == nil)
            try FileManager.default.createDirectory(atPath: dir + "/logs", withIntermediateDirectories: true)
            try Data("not json\n{\"event\":\n[1,2]\n\u{0}\u{1}\n".utf8).write(to: URL(fileURLWithPath: path(dir)))
            #expect(AuditLog.lastApprovedHash(path: path(dir), item: "alpha", executable: "/usr/bin/curl") == nil)
            // a directory where the log should be is an error that is not allowed to escape
            try FileManager.default.removeItem(atPath: path(dir))
            try FileManager.default.createDirectory(atPath: path(dir), withIntermediateDirectories: true)
            #expect(AuditLog.lastApprovedHash(path: path(dir), item: "alpha", executable: "/usr/bin/curl") == nil)
        }
    }

    @Test func aDamagedLineBetweenGoodOnesIsSkipped() throws {
        try withTempDirectory { dir in
            let audit = log(dir)
            try audit.append(event(.approved, hash: first))
            let handle = try FileHandle(forWritingTo: URL(fileURLWithPath: path(dir)))
            try handle.seekToEnd()
            try handle.write(contentsOf: Data("garbage line\n".utf8))
            try handle.close()
            #expect(AuditLog.lastApprovedHash(path: path(dir), item: "alpha", executable: "/usr/bin/curl") == first)
        }
    }

    @Test func aHashThatIsNotSixtyFourLowercaseHexDigitsIsIgnored() throws {
        try withTempDirectory { dir in
            let audit = log(dir)
            try audit.append(event(.approved, hash: first))
            for bad in ["short", String(repeating: "G", count: 64), String(repeating: "AB", count: 32), String(repeating: "1", count: 65)] {
                try audit.append(event(.approved, hash: bad))
            }
            #expect(AuditLog.lastApprovedHash(path: path(dir), item: "alpha", executable: "/usr/bin/curl") == first)
        }
    }

    @Test func aSymbolicLinkInsteadOfTheLogIsNotFollowed() throws {
        try withTempDirectory { dir in
            try log(dir).append(event(.approved, hash: first))
            let link = dir + "/link.jsonl"
            try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: path(dir))
            #expect(AuditLog.lastApprovedHash(path: link, item: "alpha", executable: "/usr/bin/curl") == nil)
            #expect(AuditLog.lastApprovedHash(path: path(dir), item: "alpha", executable: "/usr/bin/curl") == first)
        }
    }

    @Test func onlyTheTailOfAHugeLogIsRead() throws {
        try withTempDirectory { dir in
            let audit = log(dir)
            try audit.append(event(.approved, hash: first))          // old: will fall off the tail
            let filler = Data((String(repeating: "x", count: 1023) + "\n").utf8)
            let handle = try FileHandle(forWritingTo: URL(fileURLWithPath: path(dir)))
            try handle.seekToEnd()
            for _ in 0..<(AuditLog.historyWindow / 1024 + 8) { try handle.write(contentsOf: filler) }
            try handle.close()
            #expect(AuditLog.lastApprovedHash(path: path(dir), item: "alpha", executable: "/usr/bin/curl") == nil)
            // a newer approval inside the window is found, although the file is far past the window
            let size = (try FileManager.default.attributesOfItem(atPath: path(dir))[.size] as? Int) ?? 0
            #expect(size > AuditLog.historyWindow)
            let handle2 = try FileHandle(forWritingTo: URL(fileURLWithPath: path(dir)))
            try handle2.seekToEnd()
            let newest = "{\"event\":\"approved\",\"executable\":\"/usr/bin/curl\",\"executable_sha256\":\"\(second)\",\"item\":\"alpha\"}\n"
            try handle2.write(contentsOf: Data(newest.utf8))
            try handle2.close()
            #expect(AuditLog.lastApprovedHash(path: path(dir), item: "alpha", executable: "/usr/bin/curl") == second)
        }
    }

    @Test func finishedEventsCarryExitStatusAndDurationAndNoValues() throws {
        try withTempDirectory { dir in
            let audit = log(dir, redactor: { $0.replacingOccurrences(of: "hunter2", with: "[masked]") })
            try audit.append(AuditEvent(event: .finished, item: "alpha hunter2", exitStatus: 3, durationMs: 4200))
            let text = try String(contentsOfFile: path(dir), encoding: .utf8)
            let object = try #require(JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any])
            #expect(object["event"] as? String == "finished")
            #expect(object["exit_status"] as? Int == 3)
            #expect(object["duration_ms"] as? Int == 4200)
            #expect(object["item"] as? String == "alpha [masked]")
            #expect(object["command_line"] == nil)
            #expect(!text.contains("hunter2"))
            #expect(try AuditLog.verify(path: path(dir)) == .ok(lines: 1))
        }
    }
}
