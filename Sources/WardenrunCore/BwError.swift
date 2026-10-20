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

extension BwError {
    /// A fixed sentence for the person at the terminal. It never contains a byte that came from
    /// the server, from `bw` or from a secret, not even for the cases that carry text.
    public var summary: String {
        switch self {
        case .itemNotFound: return "no item with that name in the allowed collection"
        case .ambiguous: return "more than one item has that name in the allowed collections"
        case .alreadyExists: return "an item with that name already exists"
        case .unsupportedField: return "the item has no such field"
        case .binaryNotAllowed: return "the pinned bw is not usable"
        case .signatureMismatch: return "the pinned bw does not carry the expected signature"
        case .lockBusy: return "another wardenrun is using bw right now"
        case .stateUnavailable: return "wardenrun's own state directory cannot be used"
        case .cancelled: return "cancelled"
        case .outputTooLarge: return "bw produced more output than wardenrun accepts"
        case .notLoggedIn: return "bw is not logged in; run `wardenrun setup`"
        case .spawnFailed: return "bw could not be started"
        case .timeout: return "bw did not answer in time"
        case .protocolError: return "bw answered in a way wardenrun does not understand"
        case .unlockFailed: return "the vault could not be unlocked"
        case .serverError: return "the vault server refused the request"
        case .invalidUTF8: return "the item holds text that is not valid UTF-8"
        }
    }
}
