import Foundation

/// One `flock` around the whole `bw` phase of a run (DESIGN 5.2 rule 4). Concurrent `bw`
/// processes race on a single-use refresh token and can wipe the profile, so a second run waits
/// for the first and gives up with `lockBusy` after `timeout`.
///
/// The descriptor is close-on-exec: a child must never inherit the lock, or it would outlive the
/// run that took it.
public final class BwLock {
    private var descriptor: Int32
    private let guardLock = NSLock()

    var descriptorForTesting: Int32 { descriptor }

    private init(descriptor: Int32) { self.descriptor = descriptor }

    deinit { release() }

    public static func acquire(path: String, timeout: TimeInterval) throws -> BwLock {
        let directory = (path as NSString).deletingLastPathComponent
        if !FileManager.default.fileExists(atPath: directory) {
            do {
                try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
            } catch {
                throw BwError.stateUnavailable(reason: "cannot create the lock directory")
            }
            chmod(directory, 0o700)
        }
        let descriptor = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw BwError.stateUnavailable(reason: "cannot open the lock file") }
        let deadline = Date().addingTimeInterval(timeout)
        while true {
            if flock(descriptor, LOCK_EX | LOCK_NB) == 0 { return BwLock(descriptor: descriptor) }
            guard errno == EWOULDBLOCK || errno == EINTR else {
                close(descriptor)
                throw BwError.stateUnavailable(reason: "cannot lock the lock file")
            }
            if Date() >= deadline {
                close(descriptor)
                throw BwError.lockBusy
            }
            usleep(50_000)
        }
    }

    /// Safe to call more than once.
    public func release() {
        guardLock.lock(); defer { guardLock.unlock() }
        guard descriptor >= 0 else { return }
        flock(descriptor, LOCK_UN)
        close(descriptor)
        descriptor = -1
    }
}
