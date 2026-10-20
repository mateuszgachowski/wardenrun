import Foundation

public enum BwExitStatus: Equatable, Sendable {
    case exited(Int32)
    case signaled(Int32)
}

/// What the two reader threads of one child share with its `BwChild`. The threads hold this and
/// not the `BwChild`: they only finish when the pipes close, which is when the child is gone, so
/// if they held the `BwChild` it could never be freed while its child ran.
private final class BwOutput: @unchecked Sendable {
    private let pid: pid_t
    private let limit: Int
    private let state = NSLock()
    private var stdout: [UInt8] = []
    private var stderr: [UInt8] = []
    private var overflowed = false
    let readers = DispatchGroup()

    init(pid: pid_t, limit: Int) {
        self.pid = pid
        self.limit = limit
    }

    func startReading(stdoutFD: Int32, stderrFD: Int32) {
        for (descriptor, isStdout) in [(stdoutFD, true), (stderrFD, false)] {
            readers.enter()
            Thread.detachNewThread { [self] in
                defer { readers.leave() }
                drain(descriptor, isStdout: isStdout)
                close(descriptor)
            }
        }
    }

    private func drain(_ descriptor: Int32, isStdout: Bool) {
        var block = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let count = read(descriptor, &block, block.count)
            if count < 0 && errno == EINTR { continue }
            if count <= 0 { return }
            state.lock()
            var tooMuch = false
            if isStdout {
                stdout.append(contentsOf: block[0..<count])
                tooMuch = stdout.count > limit
            } else {
                stderr.append(contentsOf: block[0..<count])
                tooMuch = stderr.count > limit
            }
            if tooMuch { overflowed = true }
            state.unlock()
            if tooMuch {
                killpg(pid, SIGKILL)
                return
            }
        }
    }

    var capturedStdout: [UInt8] { state.lock(); defer { state.unlock() }; return stdout }
    var capturedStderr: [UInt8] { state.lock(); defer { state.unlock() }; return stderr }
    var outputOverflowed: Bool { state.lock(); defer { state.unlock() }; return overflowed }
}

/// A running `bw`. It leads its own process group, so one signal reaches `bw` and anything it
/// started; stdout and stderr are read by two threads into capped buffers. Dropping the last
/// reference to a child that is still running kills its group.
public final class BwChild: @unchecked Sendable {
    public let pid: pid_t

    private let state = NSLock()
    private var status: BwExitStatus?
    private let output: BwOutput

    fileprivate init(pid: pid_t, stdoutFD: Int32, stderrFD: Int32, limit: Int) {
        self.pid = pid
        output = BwOutput(pid: pid, limit: limit)
        output.startReading(stdoutFD: stdoutFD, stderrFD: stderrFD)
    }

    deinit {
        // A child nobody terminated must not outlive its owner.
        state.lock()
        let unreaped = status == nil
        state.unlock()
        if unreaped {
            killpg(pid, SIGKILL)
            var raw: Int32 = 0
            _ = waitpid(pid, &raw, 0)
        }
    }

    public var capturedStdout: [UInt8] { output.capturedStdout }
    public var capturedStderr: [UInt8] { output.capturedStderr }
    public var outputOverflowed: Bool { output.outputOverflowed }

    /// Reaps the child if it has exited. Returns its status, or nil while it still runs.
    private func poll() -> BwExitStatus? {
        state.lock(); defer { state.unlock() }
        if let status { return status }
        var raw: Int32 = 0
        let result = waitpid(pid, &raw, WNOHANG)
        if result == 0 { return nil }
        if result < 0 {
            if errno == EINTR { return nil }
            status = .exited(-1)   // already reaped elsewhere; should not happen
            return status
        }
        let signal = raw & 0x7F
        status = signal == 0 ? .exited((raw >> 8) & 0xFF) : .signaled(signal)
        return status
    }

    public var isRunning: Bool { poll() == nil }

    /// The exit status, or nil if the child is still running after `timeout` seconds.
    public func wait(timeout: TimeInterval) -> BwExitStatus? {
        let deadline = Date().addingTimeInterval(timeout)
        while true {
            if let status = poll() { return status }
            if Date() >= deadline { return nil }
            usleep(5_000)
        }
    }

    /// True when both pipes reached end-of-file within `timeout`.
    func waitForOutput(timeout: TimeInterval) -> Bool {
        output.readers.wait(timeout: .now() + timeout) == .success
    }

    func killGroup() { killpg(pid, SIGKILL) }

    /// SIGTERM to the whole group, SIGKILL after `grace` seconds, then reap. Safe to repeat.
    public func terminate(grace: TimeInterval) {
        if poll() != nil { return }
        killpg(pid, SIGTERM)
        if wait(timeout: grace) == nil {
            killpg(pid, SIGKILL)
            _ = wait(timeout: 5)
        } else {
            killpg(pid, SIGKILL)   // whatever else of the group ignored SIGTERM
        }
    }
}

/// Starts the pinned `bw` with exactly the environment and descriptors it is given, nothing else.
public enum BwProcess {
    private static let firstSpareDescriptor: Int32 = 100

    /// `inherit` lists descriptors the child receives: `parent` is a descriptor of this process,
    /// `child` the number it gets there (3 to 99, no repeats). stdin is `/dev/null`.
    ///
    /// Every other descriptor is closed in the child on macOS (`POSIX_SPAWN_CLOEXEC_DEFAULT`). On
    /// Linux there is no such flag: only descriptors that are close-on-exec stay out, which is
    /// true of everything wardenrun opens. Spawns should not run at the same moment as the code
    /// that creates a descriptor and only afterwards marks it close-on-exec (`pipe`, `socketpair`
    /// on Darwin); wardenrun starts one `bw` at a time under `bw.lock`.
    public static func start(spec: BwLaunchSpec, arguments: [String], environment: [String: String],
                             inherit: [(parent: Int32, child: Int32)] = [],
                             captureLimit: Int = 1 << 20) throws -> BwChild {
        let targets = inherit.map(\.child)
        guard targets.allSatisfy({ (3..<firstSpareDescriptor).contains($0) }), Set(targets).count == targets.count else {
            throw BwError.spawnFailed(errno: EINVAL)
        }

        // Every descriptor used below is moved to 100 or higher, so that no source number can
        // collide with a number the child is meant to get. All of them are close-on-exec.
        var opened: [Int32] = []
        func keep(_ descriptor: Int32) -> Int32 { opened.append(descriptor); return descriptor }
        defer { for descriptor in opened { close(descriptor) } }

        let stdoutPipe = try makePipe()
        let stdoutRead = keep(stdoutPipe.read), stdoutWrite = keep(stdoutPipe.write)
        let stderrPipe: (read: Int32, write: Int32)
        do { stderrPipe = try makePipe() } catch { throw error }
        let stderrRead = keep(stderrPipe.read), stderrWrite = keep(stderrPipe.write)

        var sources: [(source: Int32, target: Int32)] = []
        for pair in inherit {
            let copy = fcntl(pair.parent, F_DUPFD_CLOEXEC, firstSpareDescriptor)
            guard copy >= 0 else { throw BwError.spawnFailed(errno: errno) }
            sources.append((keep(copy), pair.child))
        }

        #if canImport(Darwin)
        var actions: posix_spawn_file_actions_t?
        var attributes: posix_spawnattr_t?
        #else
        var actions = posix_spawn_file_actions_t()
        var attributes = posix_spawnattr_t()
        #endif
        posix_spawn_file_actions_init(&actions)
        posix_spawnattr_init(&attributes)
        defer {
            posix_spawn_file_actions_destroy(&actions)
            posix_spawnattr_destroy(&attributes)
        }
        posix_spawn_file_actions_addopen(&actions, 0, "/dev/null", O_RDONLY, 0)
        posix_spawn_file_actions_adddup2(&actions, stdoutWrite, 1)
        posix_spawn_file_actions_adddup2(&actions, stderrWrite, 2)
        for (source, target) in sources { posix_spawn_file_actions_adddup2(&actions, source, target) }

        var defaultSignals = sigset_t(), noSignals = sigset_t()
        sigfillset(&defaultSignals)
        sigemptyset(&noSignals)
        posix_spawnattr_setsigdefault(&attributes, &defaultSignals)
        posix_spawnattr_setsigmask(&attributes, &noSignals)
        posix_spawnattr_setpgroup(&attributes, 0)
        var flags = Int32(POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK)
        #if canImport(Darwin)
        flags |= Int32(POSIX_SPAWN_CLOEXEC_DEFAULT)
        #endif
        posix_spawnattr_setflags(&attributes, Int16(flags))

        let argv = [spec.executable] + spec.leadingArguments + arguments
        let envp = environment.map { $0.key + "=" + $0.value }
        var pid: pid_t = 0
        let result = withCStringArray(argv) { argvPointers in
            withCStringArray(envp) { envPointers in
                posix_spawn(&pid, spec.executable, &actions, &attributes, argvPointers, envPointers)
            }
        }
        guard result == 0 else { throw BwError.spawnFailed(errno: result) }

        // The child owns its copies of the write ends; the reader threads own the read ends.
        opened.removeAll { $0 == stdoutRead || $0 == stderrRead }
        return BwChild(pid: pid, stdoutFD: stdoutRead, stderrFD: stderrRead, limit: captureLimit)
    }

    /// Runs a short command to the end. Throws `.timeout` after `deadline` seconds (the group is
    /// killed) and `.outputTooLarge` when either stream passes `captureLimit` bytes.
    public static func run(spec: BwLaunchSpec, arguments: [String], environment: [String: String],
                           deadline: TimeInterval, captureLimit: Int = 1 << 20)
        throws -> (status: BwExitStatus, stdout: [UInt8], stderr: [UInt8]) {
        let child = try start(spec: spec, arguments: arguments, environment: environment, captureLimit: captureLimit)
        defer { child.terminate(grace: 1) }
        guard let status = child.wait(timeout: deadline) else { throw BwError.timeout(phase: "bw command") }
        if !child.waitForOutput(timeout: 1) {
            // A grandchild still holds the pipes open: the command is not over.
            child.killGroup()
            _ = child.waitForOutput(timeout: 2)
        }
        if child.outputOverflowed { throw BwError.outputTooLarge }
        return (status, child.capturedStdout, child.capturedStderr)
    }

    private static func makePipe() throws -> (read: Int32, write: Int32) {
        var fds: [Int32] = [-1, -1]
        #if canImport(Darwin)
        guard pipe(&fds) == 0 else { throw BwError.spawnFailed(errno: errno) }
        #else
        // Swift's Glibc does not expose `pipe2`, and a plain `pipe` leaves a window in which a
        // concurrent spawn would inherit the ends. A socketpair is created close-on-exec in
        // one call and reads and writes like a pipe; only Linux (the CI tests) takes this path.
        let ends = try SocketPair.make()
        fds = [ends.0, ends.1]
        #endif
        let read = fcntl(fds[0], F_DUPFD_CLOEXEC, firstSpareDescriptor)
        let write = fcntl(fds[1], F_DUPFD_CLOEXEC, firstSpareDescriptor)
        let failure = errno
        close(fds[0]); close(fds[1])
        guard read >= 0, write >= 0 else {
            if read >= 0 { close(read) }
            if write >= 0 { close(write) }
            throw BwError.spawnFailed(errno: failure)
        }
        return (read, write)
    }

    private static func withCStringArray<R>(_ strings: [String],
                                            _ body: ([UnsafeMutablePointer<CChar>?]) -> R) -> R {
        var pointers: [UnsafeMutablePointer<CChar>?] = strings.map { strdup($0) }
        pointers.append(nil)
        defer { for pointer in pointers { free(pointer) } }
        return body(pointers)
    }
}
