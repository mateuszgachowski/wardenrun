/// Everything that can go wrong between wardenrun and `bw`.
///
/// A case carries a fixed text written in this package, a count or an errno, never a byte that
/// came from the server, from `bw` or from a secret. The single exception is
/// `unlockFailed(message:)`, whose text is filtered and masked where it is built.
public enum BwError: Error, Equatable, Sendable {
    case itemNotFound
    case ambiguous(count: Int)
    case alreadyExists
    case unsupportedField(String)
    /// The pinned `bw` is missing, changed, a symlink, or has a `bw-data` directory beside it.
    case binaryNotAllowed(reason: String)
    case signatureMismatch
    case lockBusy
    /// wardenrun's own state (the lock file, its directory) cannot be created or opened.
    case stateUnavailable(reason: String)
    case cancelled
    case outputTooLarge
    case notLoggedIn
    case spawnFailed(errno: Int32)
    case timeout(phase: String)
    case protocolError(String)
    case unlockFailed(message: String)
    case serverError(status: Int)
    case invalidUTF8(field: String)
}
