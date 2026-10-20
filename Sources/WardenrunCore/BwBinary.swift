import Foundation

/// Exactly how to start the pinned `bw`: the program, the arguments that always come first
/// (the script, for the Node build), and the only directories its `PATH` may contain.
public struct BwLaunchSpec: Equatable, Sendable {
    public let executable: String
    public let leadingArguments: [String]
    public let pinnedDirectories: [String]
    /// Called with the pid of the freshly started process before it is allowed to run its first
    /// instruction (on macOS it is started suspended). Throwing kills it. This is what closes the gap
    /// between "the file on disk was checked" and "the process that runs is that file".
    public let verifyStarted: (@Sendable (Int32) throws -> Void)?

    public init(executable: String, leadingArguments: [String], pinnedDirectories: [String],
                verifyStarted: (@Sendable (Int32) throws -> Void)? = nil) {
        self.executable = executable
        self.leadingArguments = leadingArguments
        self.pinnedDirectories = pinnedDirectories
        self.verifyStarted = verifyStarted
    }

    public static func == (lhs: BwLaunchSpec, rhs: BwLaunchSpec) -> Bool {
        lhs.executable == rhs.executable && lhs.leadingArguments == rhs.leadingArguments
            && lhs.pinnedDirectories == rhs.pinnedDirectories
    }
}

/// The code-signature half of the pin. It needs Security.framework, so the macOS layer
/// implements it; the core only asks. Both methods throw `BwError.signatureMismatch` to refuse.
public protocol BwSignatureChecker: Sendable {
    /// The file at `path` carries a valid signature of this team.
    func check(path: String, teamID: String) throws
    /// The running process `pid` (our own child, held before its first instruction) is code of
    /// this team. Checked on the process, not on a path, so a file swapped after `check` cannot pass.
    func checkRunning(pid: Int32, teamID: String) throws
}

/// Decides, before every run, whether the `bw` on disk is the one the maintainer pinned
/// (DESIGN 5.2 rule 1). Anything else is refused.
///
/// Only the signed GitHub-release `bw` can be pinned. Homebrew's build is `node` running
/// `bw.js`, and that script loads about thirty packages, webpack chunks and wasm from beside it
/// at run time, in a directory the user can write; a hash of `node` and `bw.js` would say
/// "pinned" over code that nobody checked, and that code receives the master password.
///
/// The file check alone would be a check at one moment, not a lock: a process of the same user
/// that may write the file could swap it between the check and the spawn. So every start also
/// carries `verifyStarted`: the new process is held before its first instruction and its code
/// signature is checked while it is the process that will run.
public enum BwBinaryPolicy {
    private static let missingBw = "pinned bw is missing or not an executable file"
    private static let notCanonical = "pinned path is not canonical (a symlink?)"
    private static let bwDataBeside = "a bw-data directory sits beside the binary"

    public static func launchSpec(for pin: BwPin, signature: BwSignatureChecker) throws -> BwLaunchSpec {
        switch pin {
        case .signedRelease(let teamID, let path):
            let resolved = try resolveExecutable(path, missing: missingBw)
            try refuseBwData(besideAnyOf: [directory(of: resolved.path)])
            try signature.check(path: resolved.path, teamID: teamID)
            return BwLaunchSpec(executable: resolved.path, leadingArguments: [],
                                pinnedDirectories: [directory(of: resolved.path)],
                                verifyStarted: { pid in try signature.checkRunning(pid: pid, teamID: teamID) })
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
