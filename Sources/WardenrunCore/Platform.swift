import Foundation

/// What can go wrong with the place the protected item lives in. Texts are fixed; no case
/// carries a byte of the item.
public enum StoreError: Error, Equatable, Sendable {
    /// The item exists (or may exist) but this process cannot read it, or it is corrupt.
    case unreadable(reason: String)
    case writeFailed(reason: String)
}

/// Where the protected item (DESIGN 5.8) is kept. The macOS implementation is a file-based
/// keychain item restricted by the OS to wardenrun's own signature (Tier B, DESIGN 3.4); the
/// protocol keeps the door open for other backends.
public protocol SecretStore: Sendable {
    /// One honest sentence for `doctor` and the README: what the OS enforces and what wardenrun does.
    var tierDescription: String { get }
    /// `nil` when nothing is stored. Throws `StoreError.unreadable` when something is stored that
    /// this process may not read, or that is damaged.
    func load() throws -> ProtectedConfig?
    func save(_ config: ProtectedConfig) throws
    func erase() throws
}

public enum ApprovalDecision: Equatable, Sendable {
    case approved
    case denied
    case timedOut
    /// No way to ask a human right now (no Touch ID, no GUI session, locked out). Never approves.
    case unavailable(reason: String)
}

/// Asks a human. `reason` is the whole text shown (DESIGN 5.3). Returns once the human
/// has decided, `timeout` seconds have passed or asking is impossible.
public protocol Approver: Sendable {
    func approve(reason: String, timeout: TimeInterval) -> ApprovalDecision
}

public struct ProcessRecord: Equatable, Sendable {
    public let pid: Int32
    public let path: String

    public init(pid: Int32, path: String) {
        self.pid = pid
        self.path = path
    }
}

public protocol ProcessInspector: Sendable {
    /// The parents of `pid`, nearest first, as far up as they can be read.
    func parentChain(of pid: Int32) -> [ProcessRecord]
}
