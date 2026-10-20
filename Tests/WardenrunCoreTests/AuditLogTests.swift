import Foundation
import Testing
@testable import WardenrunCore

struct AuditLogTests {
    private static let zeros = String(repeating: "0", count: 64)
    private static let epoch: @Sendable () -> Date = { Date(timeIntervalSince1970: 0) }

    private func log(_ dir: String, redactor: @escaping @Sendable (String) -> String = { $0 }) -> AuditLog {
        AuditLog(path: dir + "/logs/audit.jsonl", redactor: redactor, clock: Self.epoch)
    }

    private func path(_ dir: String) -> String { dir + "/logs/audit.jsonl" }

    private func fileLines(_ dir: String) throws -> [String] {
        try String(contentsOfFile: path(dir), encoding: .utf8)
            .split(separator: "\n", omittingEmptySubsequences: true).map(String.init)
    }

    private func object(_ line: String) throws -> [String: Any] {
        try #require(JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any])
    }

    private func sample(_ item: String = "alpha") -> AuditEvent {
        AuditEvent(event: .approved, item: item, commandLine: ["curl", "https://example.org/x"],
                   executable: "/usr/bin/curl", executableSHA256: String(repeating: "ab", count: 32),
                   cwd: "/work", parentChain: ["zsh", "Terminal"], tier: "B", exitStatus: 0, durationMs: 12)
    }

    @Test func theFirstAppendCreatesTheDirectoryAndFileWithPrivateModes() throws {
        try withTempDirectory { dir in
            try log(dir).append(sample())
            #expect(permissionBits(of: dir + "/logs") == 0o700)
            #expect(permissionBits(of: path(dir)) == 0o600)
            let raw = try String(contentsOfFile: path(dir), encoding: .utf8)
            #expect(raw.hasSuffix("\n"))
            let lines = try fileLines(dir)
            #expect(lines.count == 1)
            let line = try object(lines[0])
            #expect(line["prev"] as? String == Self.zeros)
            #expect(line["time"] as? String == "1970-01-01T00:00:00.000Z")
            #expect(line["event"] as? String == "approved")
            #expect(line["item"] as? String == "alpha")
            #expect(line["command_line"] as? [String] == ["curl", "https://example.org/x"])
            #expect(line["executable_sha256"] as? String == String(repeating: "ab", count: 32))
            #expect(line["parent_chain"] as? [String] == ["zsh", "Terminal"])
            #expect(line["exit_status"] as? Int == 0)
            #expect(line["duration_ms"] as? Int == 12)
            #expect(line["tier"] as? String == "B")
            #expect(raw.contains("https://example.org/x"))   // slashes are not escaped
        }
    }

    @Test func eachLineCarriesTheHashOfThePreviousLine() throws {
        try withTempDirectory { dir in
            let audit = log(dir)
            try audit.append(sample("one"))
            try audit.append(sample("two"))
            try audit.append(AuditEvent(event: .denied, item: "three"))
            let lines = try fileLines(dir)
            #expect(lines.count == 3)
            for index in 1..<3 {
                #expect(try object(lines[index])["prev"] as? String == SHA256.hexHash(Array(lines[index - 1].utf8)))
            }
            #expect(try AuditLog.verify(path: path(dir)) == .ok(lines: 3))
        }
    }

    @Test func editingAMiddleLineIsDetectedAtTheNextLine() throws {
        try withTempDirectory { dir in
            let audit = log(dir)
            for name in ["alpha", "bravo", "charlie", "delta"] { try audit.append(sample(name)) }
            let edited = try String(contentsOfFile: path(dir), encoding: .utf8).replacingOccurrences(of: "bravo", with: "bravx")
            try edited.write(toFile: path(dir), atomically: false, encoding: .utf8)
            guard case .broken(let line, _) = try AuditLog.verify(path: path(dir)) else {
                Issue.record("tampering was not detected"); return
            }
            #expect(line == 3)
        }
    }

    @Test func editingTheLastLineIsNotDetectableByDesign() throws {
        try withTempDirectory { dir in
            let audit = log(dir)
            for name in ["alpha", "bravo"] { try audit.append(sample(name)) }
            let edited = try String(contentsOfFile: path(dir), encoding: .utf8).replacingOccurrences(of: "bravo", with: "bravx")
            try edited.write(toFile: path(dir), atomically: false, encoding: .utf8)
            // A chain only protects what a later line vouches for; the tail has no later line.
            #expect(try AuditLog.verify(path: path(dir)) == .ok(lines: 2))
        }
    }

    @Test func deletingOrReorderingLinesIsDetected() throws {
        try withTempDirectory { dir in
            let audit = log(dir)
            for name in ["alpha", "bravo", "charlie"] { try audit.append(sample(name)) }
            let lines = try fileLines(dir)
            try ([lines[0], lines[2]].joined(separator: "\n") + "\n").write(toFile: path(dir), atomically: false, encoding: .utf8)
            guard case .broken(let afterDelete, _) = try AuditLog.verify(path: path(dir)) else {
                Issue.record("deletion was not detected"); return
            }
            #expect(afterDelete == 2)
            try ([lines[0], lines[2], lines[1]].joined(separator: "\n") + "\n").write(toFile: path(dir), atomically: false, encoding: .utf8)
            guard case .broken(let afterReorder, _) = try AuditLog.verify(path: path(dir)) else {
                Issue.record("reordering was not detected"); return
            }
            #expect(afterReorder == 2)
        }
    }

    @Test func theRedactorIsAppliedToEveryStringBeforeItIsWritten() throws {
        try withTempDirectory { dir in
            let secret = "hunter2-hunter2"
            let audit = log(dir) { $0.replacingOccurrences(of: secret, with: "[REDACTED:x]") }
            try audit.append(AuditEvent(event: .approved, item: "item-\(secret)",
                                        commandLine: ["tool", "--token=\(secret)", secret],
                                        executable: "/opt/\(secret)/tool", cwd: "/work/\(secret)",
                                        parentChain: [secret, "zsh"], tier: secret))
            let raw = try String(contentsOfFile: path(dir), encoding: .utf8)
            #expect(!raw.contains("hunter2"))
            let line = try object(try fileLines(dir)[0])
            #expect(line["command_line"] as? [String] == ["tool", "--token=[REDACTED:x]", "[REDACTED:x]"])
            #expect(line["item"] as? String == "item-[REDACTED:x]")
        }
    }

    @Test func theLogIsOpenedForAppending() throws {
        try withTempDirectory { dir in
            try log(dir).append(sample())
            let descriptor = try AuditLog.openForAppend(path: path(dir))
            defer { close(descriptor) }
            #expect(fcntl(descriptor, F_GETFL) & O_APPEND != 0)
        }
    }

    @Test func aPartialLastLineFromACrashIsTerminatedAndChainedFrom() throws {
        try withTempDirectory { dir in
            let audit = log(dir)
            try audit.append(sample("alpha"))
            let handle = try #require(FileHandle(forWritingAtPath: path(dir)))
            handle.seekToEndOfFile()
            handle.write(Data(#"{"time":"1970-01-01T00:00:00.000Z","ev"#.utf8))
            handle.closeFile()
            try audit.append(sample("bravo"))
            let lines = try fileLines(dir)
            #expect(lines.count == 3)
            #expect(try object(lines[2])["prev"] as? String == SHA256.hexHash(Array(lines[1].utf8)))
            guard case .broken(let line, _) = try AuditLog.verify(path: path(dir)) else {
                Issue.record("the partial line was not reported"); return
            }
            #expect(line == 2)
        }
    }

    @Test func twentyConcurrentAppendsKeepTheChainIntact() throws {
        try withTempDirectory { dir in
            let audit = log(dir)
            let failures = Counter()
            DispatchQueue.concurrentPerform(iterations: 20) { index in
                do { try audit.append(sample("item-\(index)")) } catch { failures.increment() }
            }
            #expect(failures.value == 0)
            let result = try AuditLog.verify(path: path(dir))
            #expect(result == .ok(lines: 20))
        }
    }

    @Test func aLastLineLongerThanOneReadBlockStillChainsCorrectly() throws {
        try withTempDirectory { (dir: String) throws in
            let audit = log(dir)
            var appended = 0
            // The line before each short one is 3.9 kB to 4.5 kB, straddling the 4096-byte read block.
            for padding in stride(from: 3900, through: 4500, by: 13) {
                try audit.append(AuditEvent(event: .denied, item: String(repeating: "x", count: padding)))
                try audit.append(AuditEvent(event: .approved, item: "short"))
                appended += 2
            }
            try audit.append(AuditEvent(event: .denied, commandLine: [String(repeating: "y", count: 10_000)]))
            try audit.append(AuditEvent(event: .approved, item: "after a 10 kB line"))
            appended += 2
            let result = try AuditLog.verify(path: path(dir))
            #expect(result == .ok(lines: appended))
        }
    }

    @Test func verifyHandlesEmptyAndMissingFiles() throws {
        try withTempDirectory { dir in
            #expect(throws: (any Error).self) { try AuditLog.verify(path: dir + "/nope.jsonl") }
            FileManager.default.createFile(atPath: dir + "/empty.jsonl", contents: Data())
            let result = try AuditLog.verify(path: dir + "/empty.jsonl")
            #expect(result == .ok(lines: 0))
        }
    }

    @Test func verifyReportsALineThatIsNotJSON() throws {
        try withTempDirectory { dir in
            try "not json\n".write(toFile: dir + "/bad.jsonl", atomically: false, encoding: .utf8)
            guard case .broken(let line, _) = try AuditLog.verify(path: dir + "/bad.jsonl") else {
                Issue.record("garbage was accepted"); return
            }
            #expect(line == 1)
        }
    }

    @Test func anEventCanNameWhereTheSecretWentAndNothingElse() throws {
        try withTempDirectory { dir in
            var event = sample()
            event.injected = ["$GIT_DIR", "file $CERT", "stdin"]
            try log(dir).append(event)
            try log(dir).append(sample())
            let lines = try fileLines(dir)
            #expect(try object(lines[0])["injected"] as? [String] == ["$GIT_DIR", "file $CERT", "stdin"])
            #expect(try object(lines[1])["injected"] == nil)
        }
    }

    @Test func appendGivesUpWhenAnotherHolderKeepsTheLock() throws {
        try withTempDirectory { dir in
            let audit = AuditLog(path: path(dir), redactor: { $0 }, clock: Self.epoch, lockTimeout: 0.3)
            try audit.append(sample())
            let holder = open(path(dir), O_RDWR)
            #expect(holder >= 0)
            defer { close(holder) }
            #expect(flock(holder, LOCK_EX) == 0)
            let started = Date()
            do {
                try audit.append(sample("beta"))
                Issue.record("expected the append to give up")
            } catch let error as AuditLogError {
                #expect(error == .cannotWrite(errno: EWOULDBLOCK))
            }
            #expect(Date().timeIntervalSince(started) < 3)
            flock(holder, LOCK_UN)
            try audit.append(sample("gamma"))
            #expect(try AuditLog.verify(path: path(dir)) == .ok(lines: 2))
        }
    }

    @Test func appendWaitsForALockThatIsReleasedSoon() throws {
        try withTempDirectory { dir in
            let audit = AuditLog(path: path(dir), redactor: { $0 }, clock: Self.epoch, lockTimeout: 5)
            try audit.append(sample())
            let holder = open(path(dir), O_RDWR)
            defer { close(holder) }
            #expect(flock(holder, LOCK_EX) == 0)
            DispatchQueue.global().asyncAfter(deadline: .now() + 0.2) { flock(holder, LOCK_UN) }
            try audit.append(sample("beta"))
            #expect(try AuditLog.verify(path: path(dir)) == .ok(lines: 2))
        }
    }
}

final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    func increment() { lock.lock(); count += 1; lock.unlock() }
    var value: Int { lock.lock(); defer { lock.unlock() }; return count }
}
