import Foundation
import Testing
@testable import WardenrunCore

struct BwProcessTests {
    private let shell = BwLaunchSpec(executable: "/bin/sh", leadingArguments: ["-c"], pinnedDirectories: [])
    private let plainEnvironment = ["PATH": "/usr/bin:/bin"]

    private func runShell(_ script: String, _ extra: [String] = [], environment: [String: String]? = nil,
                          deadline: TimeInterval = 10, captureLimit: Int = 1 << 20)
        throws -> (status: BwExitStatus, stdout: [UInt8], stderr: [UInt8]) {
        try BwProcess.run(spec: shell, arguments: [script] + extra, environment: environment ?? plainEnvironment,
                          deadline: deadline, captureLimit: captureLimit)
    }

    private func text(_ bytes: [UInt8]) -> String { String(decoding: bytes, as: UTF8.self) }

    /// A killed process whose parent is gone becomes a zombie until PID 1 reaps it; in a CI
    /// container PID 1 may never do that. A zombie is dead for every purpose of these tests.
    private func isZombie(_ pid: pid_t) -> Bool {
        #if os(Linux)
        guard let stat = try? String(contentsOfFile: "/proc/\(pid)/stat", encoding: .utf8),
              let close = stat.lastIndex(of: ")") else { return false }
        return stat[stat.index(after: close)...].drop(while: { $0 == " " }).first == "Z"
        #else
        return false
        #endif
    }

    private func isGone(_ pid: pid_t, within seconds: TimeInterval = 3) -> Bool {
        let deadline = Date().addingTimeInterval(seconds)
        while Date() < deadline {
            if kill(pid, 0) != 0 || isZombie(pid) { return true }
            usleep(20_000)
        }
        return kill(pid, 0) != 0 || isZombie(pid)
    }

    // MARK: arguments and environment

    @Test func childSeesExactlyTheGivenEnvironmentAndNothingFromTheParent() throws {
        setenv("WARDENRUN_TEST_LEAK", "leaked", 1)
        defer { unsetenv("WARDENRUN_TEST_LEAK") }
        let spec = BwLaunchSpec(executable: "/usr/bin/env", leadingArguments: [], pinnedDirectories: [])
        let result = try BwProcess.run(spec: spec, arguments: [], environment: ["A": "1", "B": "two words", "PATH": "/x"],
                                       deadline: 10)
        #expect(result.status == .exited(0))
        #expect(text(result.stdout).split(separator: "\n").sorted() == ["A=1", "B=two words", "PATH=/x"])
    }

    @Test func argvIsTheLeadingArgumentsThenTheGivenOnesUnchanged() throws {
        let spec = BwLaunchSpec(executable: "/usr/bin/printf", leadingArguments: ["%s\\n", "lead"], pinnedDirectories: [])
        let result = try BwProcess.run(spec: spec, arguments: ["a b", "", "--flag=1", "é"], environment: [:], deadline: 10)
        #expect(text(result.stdout) == "lead\na b\n\n--flag=1\né\n")
    }

    // MARK: output and status

    @Test func stdoutAndStderrAreCapturedSeparatelyWithTheExitCode() throws {
        let result = try runShell("echo out; echo err >&2; exit 3")
        #expect(text(result.stdout) == "out\n")
        #expect(text(result.stderr) == "err\n")
        #expect(result.status == .exited(3))
    }

    @Test func deathBySignalIsReportedAsSuch() throws {
        let result = try runShell("kill -9 $$")
        #expect(result.status == .signaled(9))
    }

    @Test func aLargeOutputIsCapturedCompletelyBeforeRunReturns() throws {
        let result = try runShell("printf '%0100000d' 0; printf '%050000d' 1 >&2")
        #expect(result.stdout.count == 100_000)
        #expect(result.stderr.count == 50_000)
    }

    @Test func stdinIsDevNull() throws {
        let result = try runShell("cat; echo done", deadline: 5)
        #expect(text(result.stdout) == "done\n")
    }

    // MARK: limits

    @Test func aDeadlineKillsTheWholeProcessGroup() throws {
        try withTempDirectory { dir in
            let pidFile = dir + "/pids"
            #expect(throws: BwError.timeout(phase: "bw command")) {
                _ = try runShell("sleep 30 & echo $$ $! > \"$0\"; wait", [pidFile], deadline: 0.5)
            }
            let pids = try String(contentsOfFile: pidFile, encoding: .utf8).split(separator: " ")
                .compactMap { Int32($0.trimmingCharacters(in: .whitespacesAndNewlines)) }
            #expect(pids.count == 2)
            for pid in pids { #expect(isGone(pid), "pid \(pid) survived the deadline") }
        }
    }

    @Test func outputOverTheLimitKillsTheChild() throws {
        try withTempDirectory { dir in
            let pidFile = dir + "/pid"
            #expect(throws: BwError.outputTooLarge) {
                _ = try runShell("echo $$ > \"$0\"; exec yes", [pidFile], deadline: 20, captureLimit: 10_000)
            }
            let pid = try #require(Int32(try String(contentsOfFile: pidFile, encoding: .utf8)
                .trimmingCharacters(in: .whitespacesAndNewlines)))
            #expect(isGone(pid))
        }
    }

    @Test func terminateEscalatesToKillWhenTheChildIgnoresTerm() throws {
        let child = try BwProcess.start(spec: shell, arguments: ["trap '' TERM; sleep 30"], environment: plainEnvironment)
        usleep(200_000)
        let start = Date()
        child.terminate(grace: 0.3)
        #expect(Date().timeIntervalSince(start) < 10)
        #expect(!child.isRunning)
        #expect(isGone(child.pid))
    }

    @Test func terminateIsIdempotentAndReportsSigterm() throws {
        let child = try BwProcess.start(spec: shell, arguments: ["sleep 30"], environment: plainEnvironment)
        child.terminate(grace: 1)
        child.terminate(grace: 1)
        #expect(!child.isRunning)
        #expect(child.wait(timeout: 1) == .signaled(15))
    }

    @Test func waitReturnsNilWhileTheChildRuns() throws {
        let child = try BwProcess.start(spec: shell, arguments: ["sleep 30"], environment: plainEnvironment)
        defer { child.terminate(grace: 0.5) }
        #expect(child.wait(timeout: 0.1) == nil)
        #expect(child.isRunning)
    }

    @Test func outputIsReadableWhileTheChildIsStillRunning() throws {
        let child = try BwProcess.start(spec: shell, arguments: ["echo early; sleep 30"], environment: plainEnvironment)
        defer { child.terminate(grace: 0.5) }
        let deadline = Date().addingTimeInterval(5)
        while child.capturedStdout.isEmpty && Date() < deadline { usleep(10_000) }
        #expect(text(child.capturedStdout) == "early\n")
    }

    // MARK: descriptors

    @Test func anInheritedDescriptorIsUsableByTheChildAtTheNumberRequested() throws {
        let (parentEnd, childEnd) = try SocketPair.make()
        defer { close(parentEnd) }
        let child = try BwProcess.start(spec: shell, arguments: ["echo hello >&3; read line <&3; echo \"got:$line\""],
                                        environment: plainEnvironment, inherit: [(parent: childEnd, child: 3)])
        close(childEnd)   // the child has its own copy now
        defer { child.terminate(grace: 0.5) }

        var buffer = [UInt8](repeating: 0, count: 16)
        let count = read(parentEnd, &buffer, buffer.count)
        #expect(String(decoding: buffer[0..<max(count, 0)], as: UTF8.self) == "hello\n")
        _ = write(parentEnd, "ping\n", 5)
        #expect(child.wait(timeout: 5) == .exited(0))
        #expect(text(child.capturedStdout) == "got:ping\n")
    }

    @Test func descriptorsThatWereNotListedAreNotInherited() throws {
        try withTempDirectory { dir in
            let lock = try BwLock.acquire(path: dir + "/bw.lock", timeout: 1)
            defer { lock.release() }
            let sentinel = open("/dev/null", O_RDWR | O_CLOEXEC)
            defer { close(sentinel) }
            for descriptor in [lock.descriptorForTesting, sentinel] {
                let result = try runShell("(echo x >&\"$0\") 2>/dev/null; echo $?", ["\(descriptor)"])
                #expect(text(result.stdout) != "0\n", "descriptor \(descriptor) reached the child")
            }
        }
    }

    #if canImport(Darwin)
    @Test func aDescriptorWithoutCloseOnExecIsStillClosedInTheChildOnDarwin() throws {
        let sentinel = open("/dev/null", O_RDWR)   // deliberately not close-on-exec
        defer { close(sentinel) }
        let result = try runShell("(echo x >&\"$0\") 2>/dev/null; echo $?", ["\(sentinel)"])
        #expect(text(result.stdout) != "0\n")
    }
    #endif

    @Test func inheritTargetsOutsideTheAllowedRangeAreRefused() {
        let (a, b) = (try? SocketPair.make()) ?? (-1, -1)
        defer { close(a); close(b) }
        for target: Int32 in [0, 1, 2, 100, 5000, -1] {
            #expect(throws: BwError.spawnFailed(errno: EINVAL), "\(target)") {
                _ = try BwProcess.start(spec: shell, arguments: ["true"], environment: plainEnvironment,
                                        inherit: [(parent: b, child: target)])
            }
        }
        #expect(throws: BwError.spawnFailed(errno: EINVAL)) {
            _ = try BwProcess.start(spec: shell, arguments: ["true"], environment: plainEnvironment,
                                    inherit: [(parent: b, child: 3), (parent: a, child: 3)])
        }
    }

    @Test func theInheritedParentDescriptorMayAlreadyHaveTheTargetNumber() throws {
        // Occupy descriptor numbers until a socket end sits on the requested number 3 or above, then ask for 3.
        let (parentEnd, childEnd) = try SocketPair.make()
        defer { close(parentEnd); close(childEnd) }
        var moved = childEnd
        if moved != 3 {
            // dup2 onto 3 only when it is free in this process; the test is meaningful either way.
            let free = fcntl(3, F_GETFD) < 0
            if free { moved = dup2(childEnd, 3); _ = fcntl(3, F_SETFD, FD_CLOEXEC) }
        }
        let child = try BwProcess.start(spec: shell, arguments: ["echo ok >&3"], environment: plainEnvironment,
                                        inherit: [(parent: moved, child: 3)])
        defer { child.terminate(grace: 0.5); if moved == 3 { close(3) } }
        var buffer = [UInt8](repeating: 0, count: 8)
        #expect(read(parentEnd, &buffer, buffer.count) == 3)
    }

    // MARK: spawn failures

    @Test func aMissingExecutableThrowsSpawnFailed() {
        let spec = BwLaunchSpec(executable: "/nonexistent/wardenrun/bw", leadingArguments: [], pinnedDirectories: [])
        #expect(throws: BwError.spawnFailed(errno: ENOENT)) {
            _ = try BwProcess.run(spec: spec, arguments: [], environment: [:], deadline: 5)
        }
    }

    @Test func repeatedSpawnFailuresDoNotLeakDescriptors() {
        // Four descriptors per attempt would exhaust the default limit (256 on macOS) long before
        // 400 attempts; a leak then shows up as EMFILE instead of the ENOENT expected every time.
        let spec = BwLaunchSpec(executable: "/nonexistent/wardenrun/bw", leadingArguments: [], pinnedDirectories: [])
        for attempt in 0..<400 {
            #expect(throws: BwError.spawnFailed(errno: ENOENT), "attempt \(attempt)") {
                _ = try BwProcess.start(spec: spec, arguments: [], environment: [:])
            }
        }
    }
}
