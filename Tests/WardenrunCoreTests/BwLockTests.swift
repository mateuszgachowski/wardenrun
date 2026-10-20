import Foundation
import Testing
@testable import WardenrunCore

struct BwLockTests {
    @Test func aSecondAcquireTimesOutWithLockBusy() throws {
        try withTempDirectory { dir in
            let path = dir + "/bw.lock"
            let first = try BwLock.acquire(path: path, timeout: 1)
            let start = Date()
            #expect(throws: BwError.lockBusy) { _ = try BwLock.acquire(path: path, timeout: 0.3) }
            let waited = Date().timeIntervalSince(start)
            #expect(waited >= 0.25 && waited < 3, "waited \(waited) s")
            first.release()
        }
    }

    @Test func releaseAllowsTheNextAcquire() throws {
        try withTempDirectory { dir in
            let path = dir + "/bw.lock"
            let first = try BwLock.acquire(path: path, timeout: 1)
            first.release()
            let second = try BwLock.acquire(path: path, timeout: 1)
            second.release()
        }
    }

    @Test func releaseIsIdempotent() throws {
        try withTempDirectory { dir in
            let lock = try BwLock.acquire(path: dir + "/bw.lock", timeout: 1)
            lock.release()
            lock.release()
        }
    }

    @Test func deinitReleases() throws {
        try withTempDirectory { dir in
            let path = dir + "/bw.lock"
            do { _ = try BwLock.acquire(path: path, timeout: 1) }
            let again = try BwLock.acquire(path: path, timeout: 0.5)
            again.release()
        }
    }

    @Test func aWaiterGetsTheLockAsSoonAsTheHolderReleases() throws {
        try withTempDirectory { dir in
            let path = dir + "/bw.lock"
            let holder = try BwLock.acquire(path: path, timeout: 1)
            afterDelay(0.2) { holder.release() }
            let start = Date()
            let waiter = try BwLock.acquire(path: path, timeout: 5)
            #expect(Date().timeIntervalSince(start) < 4.5)
            waiter.release()
        }
    }

    @Test func theLockFileAndItsDirectoryAreCreatedPrivate() throws {
        try withTempDirectory { dir in
            let path = dir + "/state/wardenrun/bw.lock"
            let lock = try BwLock.acquire(path: path, timeout: 1)
            #expect(permissionBits(of: path) == 0o600)
            #expect(permissionBits(of: dir + "/state/wardenrun") == 0o700)
            lock.release()
        }
    }

    @Test func theDescriptorIsNotInheritedByChildren() throws {
        try withTempDirectory { dir in
            let lock = try BwLock.acquire(path: dir + "/bw.lock", timeout: 1)
            let flags = fcntl(lock.descriptorForTesting, F_GETFD)
            #expect(flags >= 0 && flags & FD_CLOEXEC != 0)
            lock.release()
        }
    }

    @Test func anUnusablePathThrowsInsteadOfWaiting() {
        #expect(throws: BwError.stateUnavailable(reason: "cannot create the lock directory")) {
            _ = try BwLock.acquire(path: "/dev/null/impossible/bw.lock", timeout: 5)
        }
    }
}
