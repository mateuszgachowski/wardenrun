import Foundation

/// Everything the Touch ID sheet says about one `run` (DESIGN 5.3). It holds names, paths and
/// hashes; there is no field that could carry a secret value.
public struct ApprovalRequest: Sendable {
    public var item: String
    public var executable: ResolvedExecutable
    /// The nearest meaningful parent process, already reduced to a short name.
    public var parent: String?
    /// The caller's environment: only the names of risky variables reach the text.
    public var callerEnvironment: [String: String]
    public var executableIsWritable: Bool
    /// The hash of this executable at the last approval for this item, if there was one.
    public var previousHash: String?

    public init(item: String, executable: ResolvedExecutable, parent: String?, callerEnvironment: [String: String],
                executableIsWritable: Bool, previousHash: String?) {
        self.item = item
        self.executable = executable
        self.parent = parent
        self.callerEnvironment = callerEnvironment
        self.executableIsWritable = executableIsWritable
        self.previousHash = previousHash
    }
}

public enum ApprovalTextError: Error, Equatable, Sendable {
    case tooLong(Int)

    public var message: String {
        switch self {
        case .tooLong(let count):
            return "command too long to review (\(count) > \(ApprovalTextBuilder.budget)); put it in a script file"
        }
    }
}

/// Builds the one string the system shows: `[tags] use secret "<item>" to run: <exe> <args>
/// (from <parent>) [end]`. A text that does not fit in the budget is refused, never cut: the
/// system itself cuts silently after about 510 characters, which would hide the end of a command.
public enum ApprovalTextBuilder {
    /// Counted in UTF-16 units after escaping (the same as characters for ASCII, never fewer).
    public static let budget = 400

    public static func text(for request: ApprovalRequest) throws -> String {
        let executable = request.executable
        let name = (executable.path as NSString).lastPathComponent
        let arguments = Array(executable.argv.dropFirst())

        var tags: [String] = []
        if request.executableIsWritable { tags.append("[writable exe]") }
        if let previous = request.previousHash, previous != executable.sha256 { tags.append("[exe changed]") }
        if isShellWithCommandString(name: name, arguments: arguments) { tags.append("[shell -c]") }
        if networkTools.contains(name) { tags.append("[network]") }
        if envDumpTools.contains(name) { tags.append("[env dump]") }
        if [executable.path, executable.argv.first ?? "", request.item].contains(where: hasNonASCII) { tags.append("[non-ASCII]") }
        for variable in EnvPolicy.riskyVariables(in: request.callerEnvironment) { tags.append("[env: \(escape(variable))]") }

        var parts = tags
        parts.append("use secret \"\(escape(request.item, quoting: true))\" to run: \(quoteArgument(executable.path))")
        for argument in arguments { parts.append(quoteArgument(argument)) }
        if let parent = request.parent { parts.append("(from \(escape(parent)))") }
        parts.append("[end]")

        let result = parts.joined(separator: " ")
        let count = result.utf16.count
        guard count <= budget else { throw ApprovalTextError.tooLong(count) }
        return result
    }

    // MARK: tags

    private static let shells: Set<String> = ["sh", "bash", "zsh", "dash", "ksh", "fish"]
    private static let networkTools: Set<String> = ["curl", "wget", "nc", "ssh", "scp"]
    private static let envDumpTools: Set<String> = ["env", "printenv"]

    /// `sh -c`, `bash -lc`, `python3 -c`: the real command is a string the sheet cannot show in full.
    private static func isShellWithCommandString(name: String, arguments: [String]) -> Bool {
        let isShell = shells.contains(name)
        let isPython = name == "python" || name.hasPrefix("python")
        guard isShell || isPython else { return false }
        return arguments.contains { argument in
            let letters = Array(argument.utf8)
            guard letters.count >= 2, letters[0] == UInt8(ascii: "-"), letters[1] != UInt8(ascii: "-") else { return false }
            return isShell ? letters.dropFirst().contains(UInt8(ascii: "c")) : argument == "-c"
        }
    }

    private static func hasNonASCII(_ text: String) -> Bool { text.unicodeScalars.contains { $0.value > 0x7E } }

    // MARK: escaping

    /// Control, format (bidi, zero-width), separator and C1 scalars become visible escapes, a
    /// backslash is doubled so that escapes stay unambiguous, and, with `quoting`, a double quote
    /// is escaped too.
    static func escape(_ text: String, quoting: Bool = false) -> String {
        var output = ""
        for scalar in text.unicodeScalars {
            switch scalar {
            case "\n": output += "\\n"
            case "\r": output += "\\r"
            case "\t": output += "\\t"
            case "\\": output += "\\\\"
            case "\"" where quoting: output += "\\\""
            default:
                let value = scalar.value
                let category = scalar.properties.generalCategory
                let invisible = value < 0x20 || value == 0x7F || (0x80...0x9F).contains(value)
                    || category == .format || category == .lineSeparator || category == .paragraphSeparator
                    || category == .unassigned || category == .privateUse || category == .surrogate
                if invisible {
                    output += "\\u{" + String(value, radix: 16, uppercase: true) + "}"
                } else {
                    output.unicodeScalars.append(scalar)
                }
            }
        }
        return output
    }

    private static let safeBytes: Set<UInt8> = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_@%+=:,./-".utf8)

    /// Bare when it is plain, otherwise in single quotes the way a shell would need it.
    private static func quoteArgument(_ argument: String) -> String {
        if !argument.isEmpty, argument.utf8.allSatisfy({ safeBytes.contains($0) }) { return argument }
        return "'" + escape(argument).replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}
