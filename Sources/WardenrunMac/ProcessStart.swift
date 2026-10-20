#if canImport(Darwin)
import Darwin
import Foundation

/// What wardenrun fixes about the process it was started as, before it does anything else. The
/// caller (an agent) decides the starting state: which descriptors are open and how signals are set
/// are inherited through `exec`.
public enum ProcessStart {
    /// - SIGPIPE ignored: a message to a closed pipe must not kill wardenrun in the middle of a run,
    ///   with a secret file still on disk (the child gets the default back from `ChildRunner`).
    /// - SIGCHLD back to its default: an ignored one makes the kernel reap children by itself.
    /// - Descriptors 0, 1 and 2 open: a pipe made later must not take one of their numbers.
    public static func prepare(standardDescriptors: [Int32] = [STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO]) {
        var action = sigaction()
        sigemptyset(&action.sa_mask)
        action.__sigaction_u.__sa_handler = SIG_IGN
        sigaction(SIGPIPE, &action, nil)
        action.__sigaction_u.__sa_handler = SIG_DFL
        sigaction(SIGCHLD, &action, nil)
        ensureOpen(standardDescriptors)
    }

    /// Opens `/dev/null` on every number in `descriptors` that is closed. Standard input is read
    /// only; the others are written.
    public static func ensureOpen(_ descriptors: [Int32]) {
        for number in descriptors where fcntl(number, F_GETFD) < 0 {
            let opened = open("/dev/null", number == STDIN_FILENO ? O_RDONLY : O_WRONLY)
            guard opened >= 0 else { continue }
            if opened != number {
                dup2(opened, number)
                close(opened)
            }
        }
    }

    /// `write(2)` to a descriptor until everything is out or the other end is gone. Not
    /// `FileHandle`, which raises an exception on a closed pipe.
    public static func write(_ descriptor: Int32, _ text: String) {
        CommandSupport.writeAll(descriptor, Array(text.utf8))
    }
}
#endif
