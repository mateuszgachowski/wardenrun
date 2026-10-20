/// Where wardenrun keeps its files (DESIGN 5.7, 5.8). Everything under the user's home.
public struct WardenrunPaths: Equatable, Sendable {
    public let home: String

    public init(home: String) {
        var trimmed = home
        while trimmed.count > 1 && trimmed.hasSuffix("/") { trimmed.removeLast() }
        self.home = trimmed
    }

    public var configDirectory: String { home + "/.config/wardenrun" }
    /// wardenrun's own `BITWARDENCLI_APPDATA_DIR`: never the user's personal `bw` profile.
    public var bwAppData: String { configDirectory + "/bw" }
    public var lockFile: String { configDirectory + "/bw.lock" }
    /// The approval lock and the denial counter (`ApprovalGate`).
    public var stateDirectory: String { configDirectory + "/state" }
    /// The copy of the signed release `bw` that `setup` pins.
    public var installedBw: String { configDirectory + "/bin/bw" }
    public var auditLog: String { home + "/Library/Logs/wardenrun/audit.jsonl" }
}
