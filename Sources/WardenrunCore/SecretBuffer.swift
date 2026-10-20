import Foundation

/// A byte buffer for secrets that wardenrun owns: page-aligned, locked in RAM when the
/// system allows it (`mlock`), and zeroed with a call the compiler may not remove.
///
/// Limit, stated plainly: this protects the copy held here. Copies made elsewhere (a
/// `String`, a decoder's buffer, a pipe) are outside its reach.
public final class SecretBuffer: @unchecked Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    private let storage: UnsafeMutableRawPointer
    private let capacity: Int
    private var length: Int
    private var wiped = false
    private let guardLock = NSLock()

    /// Whether `mlock` succeeded. It can fail under a small `RLIMIT_MEMLOCK`; the buffer
    /// still works and is still zeroed.
    public let isLocked: Bool

    public init(copying bytes: [UInt8]) {
        let page = max(Int(sysconf(Int32(_SC_PAGESIZE))), 4096)
        let size = max(bytes.count, 1)
        capacity = (size + page - 1) / page * page
        var allocation: UnsafeMutableRawPointer?
        guard posix_memalign(&allocation, page, capacity) == 0, let pointer = allocation else {
            fatalError("out of memory allocating a SecretBuffer")
        }
        storage = pointer
        length = bytes.count
        memset(pointer, 0, capacity)
        bytes.withUnsafeBytes { source in
            if let base = source.baseAddress { memcpy(pointer, base, source.count) }
        }
        isLocked = mlock(pointer, capacity) == 0
    }

    deinit {
        zero()
        if isLocked { munlock(storage, capacity) }
        free(storage)
    }

    public var count: Int {
        guardLock.lock(); defer { guardLock.unlock() }
        return length
    }

    public var isWiped: Bool {
        guardLock.lock(); defer { guardLock.unlock() }
        return wiped
    }

    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        guardLock.lock(); defer { guardLock.unlock() }
        return try body(UnsafeRawBufferPointer(start: storage, count: length))
    }

    /// Zeroes the whole allocation and empties the buffer. Safe to call more than once.
    public func wipe() {
        guardLock.lock(); defer { guardLock.unlock() }
        zero()
        length = 0
        wiped = true
    }

    /// The whole allocation, valid until `deinit`; lets a test see that `wipe()` zeroed it.
    var storageForTesting: UnsafeRawBufferPointer {
        UnsafeRawBufferPointer(start: storage, count: capacity)
    }

    private func zero() {
        #if canImport(Darwin)
        _ = memset_s(storage, capacity, 0, capacity)
        #else
        explicit_bzero(storage, capacity)
        #endif
    }

    public var description: String {
        guardLock.lock(); defer { guardLock.unlock() }
        return wiped ? "SecretBuffer(wiped)" : "SecretBuffer(\(length) bytes)"
    }

    public var debugDescription: String { description }

    public var customMirror: Mirror { Mirror(self, children: []) }
}
