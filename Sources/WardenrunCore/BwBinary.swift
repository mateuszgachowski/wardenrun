import Foundation

/// Exactly how to start the pinned `bw`: the program, the arguments that always come first
/// (the script, for the Node build), and the only directories its `PATH` may contain.
public struct BwLaunchSpec: Equatable, Sendable {
    public let executable: String
    public let leadingArguments: [String]
    public let pinnedDirectories: [String]

    public init(executable: String, leadingArguments: [String], pinnedDirectories: [String]) {
        self.executable = executable
        self.leadingArguments = leadingArguments
        self.pinnedDirectories = pinnedDirectories
    }
}

/// The code-signature half of the pin. It needs Security.framework, so the macOS layer
/// implements it; the core only asks. Throws `BwError.signatureMismatch` to refuse.
public protocol BwSignatureChecker: Sendable {
    func check(path: String, teamID: String) throws
}

/// Decides, before every run, whether the `bw` on disk is the one the maintainer pinned
/// (DESIGN 5.2 rule 1). Anything else is refused.
///
/// This is a check at one moment, not a lock: the file can still be swapped between the check
/// and the spawn by a process of the same user that may write it. The window is one run long.
public enum BwBinaryPolicy {
    private static let missingBw = "pinned bw is missing or not an executable file"
    private static let missingNodeOrScript = "pinned node or script is missing"
    private static let notCanonical = "pinned path is not canonical (a symlink?)"
    private static let bwDataBeside = "a bw-data directory sits beside the binary"
    private static let nodeChanged = "node does not match its pinned hash"
    private static let scriptChanged = "script does not match its pinned hash"

    public static func launchSpec(for pin: BwPin, signature: BwSignatureChecker) throws -> BwLaunchSpec {
        switch pin {
        case .signedRelease(let teamID, let path):
            let resolved = try resolveExecutable(path, missing: missingBw)
            try refuseBwData(besideAnyOf: [directory(of: resolved.path)])
            try signature.check(path: resolved.path, teamID: teamID)
            return BwLaunchSpec(executable: resolved.path, leadingArguments: [],
                                pinnedDirectories: [directory(of: resolved.path)])
        case .nodeScript(let nodePath, let nodeSHA256, let scriptPath, let scriptSHA256):
            let node = try resolveExecutable(nodePath, missing: missingNodeOrScript)
            guard let scriptReal = ExecResolver.realPath(scriptPath), isRegularFile(scriptReal) else {
                throw BwError.binaryNotAllowed(reason: missingNodeOrScript)
            }
            guard scriptReal == scriptPath else { throw BwError.binaryNotAllowed(reason: notCanonical) }
            guard node.sha256 == nodeSHA256.lowercased() else { throw BwError.binaryNotAllowed(reason: nodeChanged) }
            guard let scriptHash = try? FileHash.sha256(ofFileAt: scriptPath) else {
                throw BwError.binaryNotAllowed(reason: missingNodeOrScript)
            }
            guard scriptHash == scriptSHA256.lowercased() else { throw BwError.binaryNotAllowed(reason: scriptChanged) }
            try refuseBwData(besideAnyOf: [directory(of: node.path), directory(of: scriptPath)])
            return BwLaunchSpec(executable: node.path, leadingArguments: [scriptPath],
                                pinnedDirectories: [directory(of: node.path)])
        }
    }

    private static func resolveExecutable(_ path: String, missing: String) throws -> ResolvedExecutable {
        let resolved: ResolvedExecutable
        do {
            resolved = try ExecResolver.resolve(argv: [path], searchPath: "", cwd: "/")
        } catch {
            throw BwError.binaryNotAllowed(reason: missing)
        }
        guard resolved.path == path else { throw BwError.binaryNotAllowed(reason: notCanonical) }
        return resolved
    }

    private static func isRegularFile(_ path: String) -> Bool {
        var info = stat()
        return stat(path, &info) == 0 && info.st_mode & S_IFMT == S_IFREG
    }

    private static func directory(of path: String) -> String { (path as NSString).deletingLastPathComponent }

    /// `bw` silently prefers a `bw-data` directory beside its executable over the app-data
    /// directory wardenrun gives it. `lstat`, so that even a dangling link counts.
    private static func refuseBwData(besideAnyOf directories: [String]) throws {
        for directory in directories {
            var info = stat()
            if lstat(directory + "/bw-data", &info) == 0 { throw BwError.binaryNotAllowed(reason: bwDataBeside) }
        }
    }
}
