#if canImport(Darwin)
import Darwin
import Foundation
import Testing
import WardenrunCore
@testable import WardenrunMac

/// Collects what the child printed, from the two reader threads.
private final class Collected: @unchecked Sendable {
    private let lock = NSLock()
    private var outBytes = [UInt8](), errBytes = [UInt8]()
    func addOut(_ bytes: [UInt8]) { lock.lock(); outBytes += bytes; lock.unlock() }
    func addErr(_ bytes: [UInt8]) { lock.lock(); errBytes += bytes; lock.unlock() }
    var out: String { lock.lock(); defer { lock.unlock() }; return String(decoding: outBytes, as: UTF8.self) }
    var err: String { lock.lock(); defer { lock.unlock() }; return String(decoding: errBytes, as: UTF8.self) }
    var outCount: Int { lock.lock(); defer { lock.unlock() }; return outBytes.count }
    var errCount: Int { lock.lock(); defer { lock.unlock() }; return errBytes.count }
}

private func needle(_ secret: String, as label: String = "[REDACTED:it]") -> [Needle] {
    MaskNeedles.plan(for: [MaskSecret(name: "it", value: Array(secret.utf8))], replacement: { _ in label }).needles
}

private func shell(_ script: String) throws -> ResolvedExecutable {
    try ExecResolver.resolve(argv: ["/bin/sh", "-c", script], searchPath: "/bin:/usr/bin", cwd: "/")
}

@discardableResult
private func run(_ executable: ResolvedExecutable, environment: [String: String] = ["PATH": "/bin:/usr/bin"],
                 secretEnvironment: [String: SecretBuffer] = [:], stdin: StdinSource = .inherit,
                 needles: [Needle] = [], collected: Collected = Collected()) throws -> (result: ChildResult, collected: Collected) {
    let result = try ChildRunner.run(executable: executable, environment: environment, secretEnvironment: secretEnvironment,
                                     stdin: stdin, needles: needles, out: { collected.addOut($0) }, err: { collected.addErr($0) })
    return (result, collected)
}

@Suite(.serialized)
struct ChildRunnerTests {
    @Test func stdoutAndStderrAreMasked() throws {
        let secret = "TOP-SECRET-VALUE-42"
        let outcome = try run(try shell("echo out:\(secret); echo err:\(secret) >&2"), needles: needle(secret))
        #expect(outcome.collected.out == "out:[REDACTED:it]\n")
        #expect(outcome.collected.err == "err:[REDACTED:it]\n")
        #expect(outcome.result.end == .exited(0))
    }

    @Test func aSecretSplitAcrossWritesIsMasked() throws {
        let secret = "TOP-SECRET-VALUE-42"
        let script = "printf 'a TOP-SEC'; /bin/sleep 0.3; printf 'RET-VALUE-42 b\\n'"
        let outcome = try run(try shell(script), needles: needle(secret))
        #expect(outcome.collected.out == "a [REDACTED:it] b\n")
    }

    @Test func base64OfTheSecretIsMasked() throws {
        let secret = "TOP-SECRET-VALUE-42"
        let encoded = Data(secret.utf8).base64EncodedString()
        let outcome = try run(try shell("echo \(encoded)"), needles: needle(secret))
        #expect(!outcome.collected.out.contains(encoded))
        #expect(outcome.collected.out.contains("[REDACTED:it]"))
    }

    @Test func theMaskerIsFlushedWhenTheChildEnds() throws {
        // the last bytes are shorter than the longest needle, so they sit inside the masker until finish()
        let secret = "TOP-SECRET-VALUE-42"
        let outcome = try run(try shell("printf 'tail TOP-SE'"), needles: needle(secret))
        #expect(outcome.collected.out == "tail TOP-SE")
    }

    @Test func stdinDataReachesTheChildAndEndsWithEOF() throws {
        let data = SecretBuffer(copying: Array("line one\nline two".utf8))
        let outcome = try run(try shell("/bin/cat"), stdin: .data(data))
        #expect(outcome.collected.out == "line one\nline two")
        #expect(outcome.result.end == .exited(0))
    }

    @Test func stdinDataThatTheChildNeverReadsDoesNotHangTheRun() throws {
        let big = SecretBuffer(copying: [UInt8](repeating: 0x61, count: 4 * 1024 * 1024))
        let start = Date()
        let outcome = try run(try shell("exit 0"), stdin: .data(big))
        #expect(outcome.result.end == .exited(0))
        #expect(Date().timeIntervalSince(start) < 20)
    }

    @Test func inheritKeepsTheCallersStdin() throws {
        // The test runner's stdin is whatever it is; replace fd 0 for the duration with a pipe.
        var fds: [Int32] = [-1, -1]
        #expect(pipe(&fds) == 0)
        let saved = dup(0)
        defer { dup2(saved, 0); close(saved) }
        dup2(fds[0], 0)
        close(fds[0])
        _ = Array("from the caller\n".utf8).withUnsafeBytes { write(fds[1], $0.baseAddress, $0.count) }
        close(fds[1])
        let outcome = try run(try shell("/bin/cat"), stdin: .inherit)
        #expect(outcome.collected.out == "from the caller\n")
    }

    @Test func theEnvironmentIsExactlyTheOneGiven() throws {
        let env = try ExecResolver.resolve(argv: ["/usr/bin/env"], searchPath: "/usr/bin", cwd: "/")
        let secret = SecretBuffer(copying: Array("s3cret-value-xyz".utf8))
        let outcome = try run(env, environment: ["ONE": "1", "TWO": "two words"], secretEnvironment: ["TOKEN": secret])
        let lines = Set(outcome.collected.out.split(separator: "\n").map(String.init))
        #expect(lines == ["ONE=1", "TWO=two words", "TOKEN=s3cret-value-xyz"])
    }

    @Test func aSecretVariableWinsOverANonSecretOneOfTheSameName() throws {
        let env = try ExecResolver.resolve(argv: ["/usr/bin/env"], searchPath: "/usr/bin", cwd: "/")
        let secret = SecretBuffer(copying: Array("the-secret-one".utf8))
        let outcome = try run(env, environment: ["TOKEN": "old"], secretEnvironment: ["TOKEN": secret])
        #expect(outcome.collected.out == "TOKEN=the-secret-one\n")
    }

    @Test func exitCodesArePropagated() throws {
        for code: Int32 in [0, 3, 255] {
            let outcome = try run(try shell("exit \(code)"))
            #expect(outcome.result.end == .exited(code))
            #expect(outcome.result.exitCode == code)
        }
    }

    @Test func aKilledChildGives128PlusSignal() throws {
        let outcome = try run(try shell("kill -KILL $$"))
        #expect(outcome.result.end == .signaled(SIGKILL))
        #expect(outcome.result.exitCode == 128 + SIGKILL)
    }

    @Test func sigtermSentToWardenrunIsForwardedToTheChild() throws {
        // The child prints READY, then waits; the test process signals itself once it has seen that.
        let collected = Collected()
        let script = "trap 'echo got-term; exit 7' TERM; echo READY; while :; do /bin/sleep 0.05; done"
        let executable = try shell(script)
        Thread.detachNewThread {
            let deadline = Date().addingTimeInterval(10)
            while collected.outCount < 6 && Date() < deadline { usleep(10_000) }
            kill(getpid(), SIGTERM)
        }
        let outcome = try run(executable, collected: collected)
        #expect(outcome.collected.out == "READY\ngot-term\n")
        #expect(outcome.result.end == .exited(7))
    }

    @Test func theHandlersAreBackAfterTheRun() throws {
        let signals = [SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGUSR1, SIGUSR2, SIGPIPE]
        func current(_ signal: Int32) -> sigaction {
            var action = sigaction()
            sigaction(signal, nil, &action)
            return action
        }
        // Start from a known state: default everywhere except SIGUSR1, which is ignored.
        let originals = signals.map { current($0) }
        defer { for (signal, original) in zip(signals, originals) { var restore = original; sigaction(signal, &restore, nil) } }
        for signal in signals { Darwin.signal(signal, SIG_DFL) }
        Darwin.signal(SIGUSR1, SIG_IGN)
        try run(try shell("exit 0"))
        for signal in signals {
            let handler = current(signal).__sigaction_u.__sa_handler.map { unsafeBitCast($0, to: Int.self) }
            #expect(handler == (signal == SIGUSR1 ? 1 : nil), "signal \(signal) is not back to what it was")
        }
    }

    @Test func theChildStartsWithDefaultSignalsEvenThoughWardenrunIgnoresSigpipe() throws {
        // If SIGPIPE were still ignored in the child, `kill -PIPE $$` would do nothing.
        let outcome = try run(try shell("kill -PIPE $$; echo alive"))
        #expect(outcome.result.end == .signaled(SIGPIPE))
        #expect(outcome.collected.out == "")
    }

    @Test func theChildSeesOnlyDescriptors012() throws {
        // Open something in the caller that is NOT close-on-exec; the child must not get it.
        let leaked = open("/dev/null", O_RDONLY)
        defer { close(leaked) }
        var flags = fcntl(leaked, F_GETFD)
        flags &= ~FD_CLOEXEC
        fcntl(leaked, F_SETFD, flags)
        // perl tries to duplicate every descriptor from 3 to 30; only an open one succeeds.
        let probe = "use POSIX; for my $f (3..30) { my $d = POSIX::dup($f); if (defined $d) { print \"open:$f\\n\"; POSIX::close($d) } } print \"checked\\n\";"
        let perl = try ExecResolver.resolve(argv: ["/usr/bin/perl", "-e", probe], searchPath: "/usr/bin", cwd: "/")
        let outcome = try run(perl)
        #expect(outcome.collected.out == "checked\n", "the child inherited: \(outcome.collected.out) (leaked fd was \(leaked))")
        // and the three it should have are there
        let three = try ExecResolver.resolve(argv: ["/usr/bin/perl", "-e", "use POSIX; for my $f (0..2) { print qq(open:$f\\n) if defined POSIX::dup($f) }"], searchPath: "/usr/bin", cwd: "/")
        let kept = try run(three)
        #expect(kept.collected.out == "open:0\nopen:1\nopen:2\n")
    }

    @Test func largeOutputDoesNotDeadlock() throws {
        let script = "/usr/bin/head -c 4194304 /dev/zero | /usr/bin/tr '\\0' 'a'; /usr/bin/head -c 4194304 /dev/zero | /usr/bin/tr '\\0' 'b' >&2"
        let outcome = try run(try shell(script))
        #expect(outcome.collected.outCount == 4 * 1024 * 1024)
        #expect(outcome.collected.errCount == 4 * 1024 * 1024)
    }

    @Test func aMissingExecutableThrowsSpawnFailed() throws {
        // resolved while it exists, gone by the time it is started
        let path = NSTemporaryDirectory() + "wardenrun-gone-" + UUID().uuidString
        try "#!/bin/sh\nexit 0\n".write(toFile: path, atomically: true, encoding: .utf8)
        chmod(path, 0o755)
        let gone = try ExecResolver.resolve(argv: [path], searchPath: "/bin", cwd: "/")
        try FileManager.default.removeItem(atPath: path)
        #expect(throws: ChildError.spawnFailed(errno: ENOENT)) {
            _ = try ChildRunner.run(executable: gone, environment: [:], secretEnvironment: [:], stdin: .inherit,
                                    needles: [], out: { _ in }, err: { _ in })
        }
    }

    @Test func aBackgroundGrandchildHoldingTheOutputDoesNotHangTheRunForever() throws {
        let start = Date()
        let outcome = try run(try shell("/bin/sleep 6 & echo started"))
        #expect(outcome.collected.out == "started\n")
        #expect(outcome.result.end == .exited(0))
        #expect(Date().timeIntervalSince(start) < 5, "waited \(Date().timeIntervalSince(start)) s")
    }

    @Test func durationIsMeasured() throws {
        let outcome = try run(try shell("/bin/sleep 0.3"))
        #expect(outcome.result.duration >= 0.25)
        #expect(outcome.result.duration < 10)
    }

    @Test func theForwardingRuleSkipsOnlyKernelGeneratedInterruptAndQuit() {
        // si_pid == 0: the terminal driver sent it to the whole foreground group, the child got it already.
        #expect(!ChildRunner.shouldForward(signal: SIGINT, senderPID: 0))
        #expect(!ChildRunner.shouldForward(signal: SIGQUIT, senderPID: 0))
        #expect(ChildRunner.shouldForward(signal: SIGINT, senderPID: 4242))
        #expect(ChildRunner.shouldForward(signal: SIGQUIT, senderPID: 4242))
        for signal in [SIGHUP, SIGTERM, SIGUSR1, SIGUSR2] {
            #expect(ChildRunner.shouldForward(signal: signal, senderPID: 0))
            #expect(ChildRunner.shouldForward(signal: signal, senderPID: 4242))
        }
    }

    @Test func theForwardedSignalListIsExactlyTheDocumentedOne() {
        #expect(ChildRunner.forwardedSignals == [SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGUSR1, SIGUSR2])
    }
}
#endif
