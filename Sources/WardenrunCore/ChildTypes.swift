import Foundation

/// How a started command ended (`ChildRunner` on macOS produces it, `RunFlow` consumes it).
public struct ChildResult: Equatable, Sendable {
    public enum End: Equatable, Sendable {
        case exited(Int32)
        case signaled(Int32)
    }

    public let end: End
    /// The child's exit code, or 128 plus the signal number when it was killed by one.
    public let exitCode: Int32
    public let duration: TimeInterval

    public init(end: End, exitCode: Int32, duration: TimeInterval) {
        self.end = end
        self.exitCode = exitCode
        self.duration = duration
    }
}

public enum StdinSource: Sendable {
    /// The child reads wardenrun's own standard input.
    case inherit
    /// The child reads these bytes and then sees end of file.
    case data(SecretBuffer)
}

public enum ChildError: Error, Equatable, Sendable {
    case spawnFailed(errno: Int32)
    case pipeFailed(errno: Int32)
    /// The child's end could not be collected, so its status is unknown.
    case waitFailed(errno: Int32)
}
