import Foundation

public struct ResolvedExecutable: Equatable, Sendable {
    /// Absolute path with symlinks resolved: the file that was hashed and the one to spawn.
    public let path: String
    /// The arguments exactly as the caller gave them (`argv[0]` is not rewritten).
    public let argv: [String]
    /// SHA-256 of the file's contents, lowercase hex.
    public let sha256: String
}

public enum ExecError: Error, Equatable {
    case emptyCommand
    case notFound(String)
    case notExecutable(String)
    case notRegularFile(String)
    case nulInArgument(index: Int)
}

/// Turns the command a caller typed into the one file that will run, the way a shell would,
/// so that the file shown for approval, the file hashed and the file spawned are the same.
///
/// The file is looked up and hashed when `resolve` runs. That is a check at one moment, not a
/// lock: a process of the same user that can write the file (a script in the project, a tool in
/// `~/.local/bin`) can swap it afterwards. `stillMatches` narrows the window when called right
/// before `posix_spawn`; it cannot close it, so the approval text should tell the human when the
/// file is writable by them. See the threat model, "a command you approved".
public enum ExecResolver {
    /// Rules: a command with a `/` is used as given (relative to `cwd`); otherwise each
    /// `searchPath` entry is tried in order, an empty or relative entry meaning `cwd`;
    /// directories and files without the execute bit are skipped, like a shell does.
    public static func resolve(argv: [String], searchPath: String, cwd: String) throws -> ResolvedExecutable {
        guard let command = argv.first, !command.isEmpty else { throw ExecError.emptyCommand }
        if let index = argv.firstIndex(where: { $0.utf8.contains(0) }) { throw ExecError.nulInArgument(index: index) }

        let candidate: String
        if command.contains("/") {
            candidate = clean(absolute(command, cwd: cwd))
            guard let kind = kind(of: candidate) else { throw ExecError.notFound(command) }
            try require(kind, at: candidate)
        } else {
            guard let found = search(command, in: searchPath, cwd: cwd) else { throw ExecError.notFound(command) }
            candidate = found
        }

        guard let resolved = realPath(candidate) else { throw ExecError.notFound(command) }
        guard let finalKind = kind(of: resolved) else { throw ExecError.notFound(command) }
        try require(finalKind, at: resolved)
        return ResolvedExecutable(path: resolved, argv: argv, sha256: try hashFile(at: resolved))
    }

    /// True when `executable.path` still resolves to itself, is still a regular executable file,
    /// and still has the hash recorded by `resolve`. Call it immediately before spawning.
    public static func stillMatches(_ executable: ResolvedExecutable) -> Bool {
        guard realPath(executable.path) == executable.path,
              kind(of: executable.path) == .regularExecutable,
              let hash = try? hashFile(at: executable.path) else { return false }
        return hash == executable.sha256
    }

    // MARK: internals

    private enum Kind { case regularExecutable, regularNotExecutable, directory, other }

    private static func kind(of path: String) -> Kind? {
        var info = stat()
        guard stat(path, &info) == 0 else { return nil }
        switch info.st_mode & S_IFMT {
        case S_IFDIR: return .directory
        case S_IFREG: return access(path, X_OK) == 0 ? .regularExecutable : .regularNotExecutable
        default: return .other
        }
    }

    private static func require(_ kind: Kind, at path: String) throws {
        switch kind {
        case .regularExecutable: return
        case .regularNotExecutable: throw ExecError.notExecutable(path)
        case .directory, .other: throw ExecError.notRegularFile(path)
        }
    }

    private static func search(_ command: String, in searchPath: String, cwd: String) -> String? {
        for entry in searchPath.split(separator: ":", omittingEmptySubsequences: false) {
            let directory = entry.isEmpty ? cwd : absolute(String(entry), cwd: cwd)
            let candidate = clean(directory + "/" + command)
            if kind(of: candidate) == .regularExecutable { return candidate }
        }
        return nil
    }

    private static func absolute(_ path: String, cwd: String) -> String {
        path.hasPrefix("/") ? path : cwd + "/" + path
    }

    /// Drops `.` and empty components so messages read `/a/b`, not `/a/./b//`. `..` is kept.
    private static func clean(_ path: String) -> String {
        "/" + path.split(separator: "/", omittingEmptySubsequences: true).filter { $0 != "." }.joined(separator: "/")
    }

    private static func realPath(_ path: String) -> String? {
        guard let resolved = realpath(path, nil) else { return nil }
        defer { free(resolved) }
        return String(cString: resolved)
    }

    private static func hashFile(at path: String) throws -> String {
        let descriptor = open(path, O_RDONLY)
        guard descriptor >= 0 else { throw ExecError.notFound(path) }
        defer { close(descriptor) }
        var hasher = SHA256()
        var block = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let count = read(descriptor, &block, block.count)
            if count < 0 { throw ExecError.notFound(path) }
            if count == 0 { break }
            block.withUnsafeBytes { hasher.update(UnsafeRawBufferPointer(rebasing: $0[0..<count])) }
        }
        return Hex.encode(hasher.finalize())
    }
}
