import Foundation

/// An anonymous `AF_UNIX` stream pair: private to the two processes that hold an end.
enum SocketPair {
    /// Both ends are close-on-exec, and writing to a closed peer fails with `EPIPE` instead of
    /// raising SIGPIPE.
    static func make() throws -> (Int32, Int32) {
        var fds: [Int32] = [-1, -1]
        #if canImport(Darwin)
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0 else { throw BwError.spawnFailed(errno: errno) }
        for descriptor in fds {
            _ = fcntl(descriptor, F_SETFD, FD_CLOEXEC)
            var on: Int32 = 1
            _ = setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
        }
        #else
        let type = Int32(SOCK_STREAM.rawValue) | Int32(SOCK_CLOEXEC.rawValue)
        guard socketpair(AF_UNIX, type, 0, &fds) == 0 else { throw BwError.spawnFailed(errno: errno) }
        #endif
        return (fds[0], fds[1])
    }

    /// One `send` of up to `count` bytes without SIGPIPE; returns what `send` returns.
    static func send(_ descriptor: Int32, _ pointer: UnsafeRawPointer, _ count: Int) -> Int {
        #if canImport(Darwin)
        return Darwin.send(descriptor, pointer, count, 0)
        #else
        return Glibc.send(descriptor, pointer, count, Int32(MSG_NOSIGNAL))
        #endif
    }

    static func send(_ descriptor: Int32, _ bytes: [UInt8]) -> Int {
        bytes.withUnsafeBytes { send(descriptor, $0.baseAddress ?? UnsafeRawPointer(bitPattern: 1)!, $0.count) }
    }
}
