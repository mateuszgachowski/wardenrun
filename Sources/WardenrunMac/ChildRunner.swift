#if canImport(Darwin)
import Darwin
import Foundation
import WardenrunCore

/// What the signal handler does: write the signal number to a pipe. Only async-signal-safe calls.
nonisolated(unsafe) private var forwardPipeWriteEnd: Int32 = -1

private func forwardHandler(_ signal: Int32, _ info: UnsafeMutablePointer<__siginfo>?, _ context: UnsafeMutableRawPointer?) {
    let sender = info?.pointee.si_pid ?? 0
    guard ChildRunner.shouldForward(signal: signal, senderPID: sender) else { return }
    var byte = UInt8(truncatingIfNeeded: signal)
    let saved = errno
    _ = write(forwardPipeWriteEnd, &byte, 1)
    errno = saved
}

/// Starts the approved command and relays its output through the masker (DESIGN 5.1, 5.4).
///
/// - The child gets exactly the environment it is handed, stdin as chosen, the two output pipes as
///   stdout and stderr, and no other descriptor (`POSIX_SPAWN_CLOEXEC_DEFAULT`).
/// - Secret variables are built in locked memory and never become a `String`.
/// - The child starts with default signal dispositions and an empty mask; wardenrun's `SIGPIPE`
///   setting does not leak into it.
/// - `HUP INT QUIT TERM USR1 USR2` sent to wardenrun are passed on to the child's pid. The child
///   stays in wardenrun's process group, so a terminal's Ctrl-C reaches it directly; that one is
///   not sent a second time.
/// - Output is read until the pipes close. A grandchild that keeps them open after the child has
///   ended is waited for only while it writes: a second of silence (or five seconds in all) ends
///   the reading, and what it writes later goes nowhere (it gets `SIGPIPE`), never unmasked.
/// - One run at a time per process.
public enum ChildRunner {
    static let forwardedSignals: [Int32] = [SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGUSR1, SIGUSR2]
    static let idleLimit: TimeInterval = 1
    static let drainLimit: TimeInterval = 5

    /// A signal from the terminal driver (no sending process) that every member of the foreground
    /// group already received is not sent again.
    static func shouldForward(signal: Int32, senderPID: pid_t) -> Bool {
        !((signal == SIGINT || signal == SIGQUIT) && senderPID == 0)
    }

    private static let runLock = NSLock()

    public static func run(executable: ResolvedExecutable, environment: [String: String],
                           secretEnvironment: [String: SecretBuffer], stdin: StdinSource, needles: [Needle],
                           out: @escaping @Sendable ([UInt8]) -> Void,
                           err: @escaping @Sendable ([UInt8]) -> Void) throws -> ChildResult {
        runLock.lock()
        defer { runLock.unlock() }
        let started = DispatchTime.now().uptimeNanoseconds

        // Names and values have to fit a C environment.
        for name in environment.keys.sorted() + secretEnvironment.keys.sorted() {
            guard !name.isEmpty, !name.utf8.contains(0), !name.utf8.contains(UInt8(ascii: "=")) else { throw ChildError.spawnFailed(errno: EINVAL) }
        }
        for value in environment.values where value.utf8.contains(0) { throw ChildError.spawnFailed(errno: EINVAL) }
        for value in secretEnvironment.values where value.withUnsafeBytes({ $0.contains(0) }) { throw ChildError.spawnFailed(errno: EINVAL) }
        if executable.argv.contains(where: { $0.utf8.contains(0) }) { throw ChildError.spawnFailed(errno: EINVAL) }

        var toClose: [Int32] = []
        defer { for descriptor in toClose { close(descriptor) } }
        func makePipe() throws -> (read: Int32, write: Int32) {
            var fds: [Int32] = [-1, -1]
            guard pipe(&fds) == 0 else { throw ChildError.pipeFailed(errno: errno) }
            for descriptor in fds { _ = fcntl(descriptor, F_SETFD, FD_CLOEXEC) }
            toClose += fds
            return (fds[0], fds[1])
        }
        let outPipe = try makePipe()
        let errPipe = try makePipe()
        let stdinPipe: (read: Int32, write: Int32)? = { if case .data = stdin { return try? makePipe() } else { return nil } }()
        if case .data = stdin, stdinPipe == nil { throw ChildError.pipeFailed(errno: errno) }
        let signalPipe = try makePipe()

        // Handlers go in before the child exists, so that no signal can arrive unhandled; whatever
        // arrives early waits in the pipe until the forwarder runs.
        forwardPipeWriteEnd = signalPipe.write
        let saved = installHandlers()
        defer {
            restoreHandlers(saved)
            forwardPipeWriteEnd = -1
        }

        var actions: posix_spawn_file_actions_t?
        var attributes: posix_spawnattr_t?
        posix_spawn_file_actions_init(&actions)
        posix_spawnattr_init(&attributes)
        defer {
            posix_spawn_file_actions_destroy(&actions)
            posix_spawnattr_destroy(&attributes)
        }
        if let stdinPipe {
            posix_spawn_file_actions_adddup2(&actions, stdinPipe.read, 0)
        } else if fcntl(0, F_GETFD) >= 0 {
            posix_spawn_file_actions_addinherit_np(&actions, 0)
        } else {
            posix_spawn_file_actions_addopen(&actions, 0, "/dev/null", O_RDONLY, 0)
        }
        posix_spawn_file_actions_adddup2(&actions, outPipe.write, 1)
        posix_spawn_file_actions_adddup2(&actions, errPipe.write, 2)
        var defaultSignals = sigset_t(), noSignals = sigset_t()
        sigfillset(&defaultSignals)
        sigemptyset(&noSignals)
        posix_spawnattr_setsigdefault(&attributes, &defaultSignals)
        posix_spawnattr_setsigmask(&attributes, &noSignals)
        posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_CLOEXEC_DEFAULT))

        var pid: pid_t = 0
        let result = withEnvironment(plain: environment, secret: secretEnvironment) { envp in
            withCStringArray(executable.argv) { argv in
                posix_spawn(&pid, executable.path, &actions, &attributes, argv, envp)
            }
        }
        guard result == 0 else { throw ChildError.spawnFailed(errno: result) }

        // The child owns its ends now.
        close(outPipe.write); close(errPipe.write)
        if let stdinPipe { close(stdinPipe.read) }
        toClose.removeAll { $0 == outPipe.write || $0 == errPipe.write || $0 == stdinPipe?.read }

        let state = RunState(pid: pid)
        let threads = DispatchGroup()

        func spawnThread(_ body: @escaping @Sendable () -> Void) {
            threads.enter()
            Thread.detachNewThread { body(); threads.leave() }
        }
        toClose.removeAll { $0 == outPipe.read || $0 == errPipe.read || $0 == signalPipe.read }
        spawnThread { readAll(from: outPipe.read, needles: needles, state: state, sink: out) }
        spawnThread { readAll(from: errPipe.read, needles: needles, state: state, sink: err) }
        spawnThread { forward(from: signalPipe.read, state: state) }
        if case .data(let buffer) = stdin, let stdinPipe {
            toClose.removeAll { $0 == stdinPipe.write }
            spawnThread { writeAll(buffer, to: stdinPipe.write) }
        }

        // Wait without reaping, so that the pid cannot be reused while the forwarder may still
        // use it; then say so, then reap.
        var info = siginfo_t()
        while waitid(P_PID, id_t(pid), &info, WEXITED | WNOWAIT) != 0 && errno == EINTR {}
        state.markExited()
        var status: Int32 = 0
        while waitpid(pid, &status, 0) < 0 && errno == EINTR {}

        var sentinel: UInt8 = 0
        _ = write(signalPipe.write, &sentinel, 1)
        threads.wait()
        close(signalPipe.read)
        // the write end of the signal pipe and any leftover ends are closed by the deferred loop

        let elapsed = Double(DispatchTime.now().uptimeNanoseconds - started) / 1_000_000_000
        if status & 0x7F == 0 {
            let code = (status >> 8) & 0xFF
            return ChildResult(end: .exited(code), exitCode: code, duration: elapsed)
        }
        let signal = status & 0x7F
        return ChildResult(end: .signaled(signal), exitCode: 128 + signal, duration: elapsed)
    }

    // MARK: pieces

    final class RunState: @unchecked Sendable {
        let pid: pid_t
        private let lock = NSLock()
        private var exited = false
        private var exitedAt: DispatchTime?

        init(pid: pid_t) { self.pid = pid }

        func markExited() {
            lock.lock(); defer { lock.unlock() }
            exited = true
            exitedAt = .now()
        }

        /// Sends `signal` to the child unless it has already ended.
        func send(_ signal: Int32) {
            lock.lock(); defer { lock.unlock() }
            if !exited { kill(pid, signal) }
        }

        var secondsSinceExit: TimeInterval? {
            lock.lock(); defer { lock.unlock() }
            return exitedAt.map { Double(DispatchTime.now().uptimeNanoseconds - $0.uptimeNanoseconds) / 1_000_000_000 }
        }
    }

    private static func forward(from descriptor: Int32, state: RunState) {
        var byte: UInt8 = 0
        while true {
            let count = read(descriptor, &byte, 1)
            if count < 0 && errno == EINTR { continue }
            if count <= 0 || byte == 0 { return }
            state.send(Int32(byte))
        }
    }

    /// Reads to the end of the pipe (or until the idle rule above applies), masks, hands on.
    private static func readAll(from descriptor: Int32, needles: [Needle], state: RunState,
                                sink: @Sendable ([UInt8]) -> Void) {
        defer { close(descriptor) }
        let masker = StreamMasker(needles: needles)
        var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        var lastData = DispatchTime.now()
        reading: while true {
            var poller = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
            let ready = poll(&poller, 1, 200)
            if ready < 0 {
                if errno == EINTR { continue }
                break
            }
            if ready == 0 {
                if let since = state.secondsSinceExit {
                    let idle = Double(DispatchTime.now().uptimeNanoseconds - lastData.uptimeNanoseconds) / 1_000_000_000
                    if idle >= idleLimit || since >= drainLimit { break reading }
                }
                continue
            }
            let count = read(descriptor, &buffer, buffer.count)
            if count < 0 {
                if errno == EINTR || errno == EAGAIN { continue }
                break
            }
            if count == 0 { break }
            lastData = .now()
            let released = masker.feed(Array(buffer[0..<count]))
            if !released.isEmpty { sink(released) }
            if let since = state.secondsSinceExit, since >= drainLimit { break }
        }
        let rest = masker.finish()
        if !rest.isEmpty { sink(rest) }
    }

    private static func writeAll(_ buffer: SecretBuffer, to descriptor: Int32) {
        defer { close(descriptor) }
        buffer.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = write(descriptor, bytes.baseAddress! + offset, bytes.count - offset)
                if count < 0 && errno == EINTR { continue }
                if count <= 0 { return }   // EPIPE: the child is not reading (any more)
                offset += count
            }
        }
    }

    // MARK: signals

    private static func installHandlers() -> [(signal: Int32, previous: sigaction)] {
        var previous: [(Int32, sigaction)] = []
        for signalNumber in forwardedSignals + [SIGPIPE] {
            var old = sigaction()
            var new = sigaction()
            new.__sigaction_u.__sa_sigaction = signalNumber == SIGPIPE ? nil : forwardHandler
            if signalNumber == SIGPIPE { new.__sigaction_u.__sa_handler = SIG_IGN }
            sigemptyset(&new.sa_mask)
            new.sa_flags = signalNumber == SIGPIPE ? 0 : SA_SIGINFO | SA_RESTART
            sigaction(signalNumber, &new, &old)
            previous.append((signalNumber, old))
        }
        return previous.map { (signal: $0.0, previous: $0.1) }
    }

    private static func restoreHandlers(_ saved: [(signal: Int32, previous: sigaction)]) {
        for entry in saved {
            var old = entry.previous
            sigaction(entry.signal, &old, nil)
        }
    }

    // MARK: environment

    /// `NAME=value` for every plain entry, and a locked-memory `NAME=value` for every secret one.
    private static func withEnvironment<R>(plain: [String: String], secret: [String: SecretBuffer],
                                           _ body: ([UnsafeMutablePointer<CChar>?]) -> R) -> R {
        var pointers: [UnsafeMutablePointer<CChar>?] = plain.keys.sorted()
            .filter { secret[$0] == nil }
            .map { strdup($0 + "=" + plain[$0]!) }
        defer { for pointer in pointers { free(pointer) } }

        let names = secret.keys.sorted()
        let entries: [SecretBuffer] = names.map { name in
            let value = secret[name]!
            let prefix = Array((name + "=").utf8)
            return SecretBuffer(count: prefix.count + value.count + 1) { destination in
                prefix.withUnsafeBytes { destination.baseAddress!.copyMemory(from: $0.baseAddress!, byteCount: $0.count) }
                value.withUnsafeBytes { source in
                    if source.count > 0 { (destination.baseAddress! + prefix.count).copyMemory(from: source.baseAddress!, byteCount: source.count) }
                }
                destination[prefix.count + value.count] = 0
            }
        }
        defer { for entry in entries { entry.wipe() } }

        func nest(_ index: Int) -> R {
            if index == entries.count {
                var all = pointers
                all.append(nil)
                return body(all)
            }
            return entries[index].withUnsafeBytes { raw in
                let start = UnsafeMutablePointer(mutating: raw.baseAddress!.assumingMemoryBound(to: CChar.self))
                pointers.append(start)
                defer { pointers.removeLast() }
                // taken out again before the strdup'ed ones are freed: the locked entries are not malloc'ed
                return nest(index + 1)
            }
        }
        return nest(0)
    }

    private static func withCStringArray<R>(_ strings: [String], _ body: ([UnsafeMutablePointer<CChar>?]) -> R) -> R {
        var pointers: [UnsafeMutablePointer<CChar>?] = strings.map { strdup($0) }
        pointers.append(nil)
        defer { for pointer in pointers { free(pointer) } }
        return body(pointers)
    }
}
#endif
