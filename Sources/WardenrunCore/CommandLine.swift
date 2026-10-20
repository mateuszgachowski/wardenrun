import Foundation

public struct FieldBinding: Equatable, Sendable {
    /// The environment variable (or, for `--file`, the variable that will hold the file's path).
    public let name: String
    /// `password`, `username`, `notes`, `uri` or the name of a custom field (`totp` parses, but `run` refuses it).
    public let field: String

    public init(name: String, field: String) {
        self.name = name
        self.field = field
    }
}

public struct SetupOptions: Equatable, Sendable {
    public var bwPath: String?

    public init(bwPath: String? = nil) { self.bwPath = bwPath }
}

public struct RunOptions: Equatable, Sendable {
    public var item: String
    public var env: [FieldBinding]
    public var files: [FieldBinding]
    public var stdin: String?
    public var command: [String]

    public init(item: String, env: [FieldBinding], files: [FieldBinding], stdin: String?, command: [String]) {
        self.item = item
        self.env = env
        self.files = files
        self.stdin = stdin
        self.command = command
    }
}

public enum PasswordCharset: String, Sendable {
    case alnum, full
}

public struct NewOptions: Equatable, Sendable {
    public var name: String
    public var username: String?
    public var uri: String?
    public var env: String?
    public var length: Int
    public var charset: PasswordCharset

    public init(name: String, username: String?, uri: String?, env: String?, length: Int, charset: PasswordCharset) {
        self.name = name
        self.username = username
        self.uri = uri
        self.env = env
        self.length = length
        self.charset = charset
    }
}

public enum Command: Equatable, Sendable {
    case help, version, doctor
    case setup(SetupOptions)
    /// Parsed here, executed by the `run` flow (DESIGN 5.1).
    case run(RunOptions)
    /// Parsed here, executed by the `new` flow (DESIGN 5.6).
    case new(NewOptions)
}

/// What is wrong with the command line. Messages are fixed texts; an argument that has to be
/// named is shown through `escaped`, which hides control and bidirectional characters, so that
/// an argument cannot paint over the terminal.
public enum UsageError: Error, Equatable, Sendable {
    case unknownCommand(String)
    case unknownOption(String)
    case unexpectedArgument(String)
    case missingItem
    case missingName
    case missingCommand
    case missingValue(option: String)
    case badBinding(option: String)
    case badValue(option: String)
    case badName
    case duplicateName(String)
    case duplicateOption(String)

    public var message: String {
        switch self {
        case .unknownCommand(let text): return "unknown command: \(text)"
        case .unknownOption(let text): return "unknown option: \(text)"
        case .unexpectedArgument(let text): return "unexpected argument: \(text)"
        case .missingItem: return "run needs the name of a vault item"
        case .missingName: return "new needs a name for the item"
        case .missingCommand: return "run needs `--` followed by the command to run"
        case .missingValue(let option): return "\(option) needs a value"
        case .badBinding(let option): return "\(option) takes VAR=field, with a valid variable name"
        case .badValue(let option): return "\(option) has an unusable value"
        case .badName: return "the item name is empty, longer than 100 characters, or contains control characters"
        case .duplicateName(let name): return "the variable \(name) is given more than once"
        case .duplicateOption(let option): return "\(option) is given more than once"
        }
    }

    /// `text` for display: control, format and line-separator characters become `<U+XXXX>`, and
    /// anything beyond 40 characters is cut with an ellipsis.
    public static func escaped(_ text: String) -> String {
        var output = ""
        var count = 0
        for scalar in text.unicodeScalars {
            if count == 40 { output += "…"; break }
            switch scalar.properties.generalCategory {
            case .control, .format, .lineSeparator, .paragraphSeparator, .surrogate, .privateUse, .unassigned:
                output += "<U+" + String(format: "%04X", scalar.value) + ">"
            default:
                output.unicodeScalars.append(scalar)
            }
            count += 1
        }
        return output
    }
}

public enum CommandParser {
    private static let maximumNameLength = 100
    private static let lengthRange = 16...128

    public static func parse(_ arguments: [String]) throws -> Command {
        guard let first = arguments.first else { return .help }
        let rest = Array(arguments.dropFirst())
        switch first {
        case "help", "--help", "-h":
            try requireNone(rest)
            return .help
        case "version", "--version", "-V":
            try requireNone(rest)
            return .version
        case "doctor":
            try requireNone(rest)
            return .doctor
        case "setup": return .setup(try parseSetup(rest))
        case "run": return .run(try parseRun(rest))
        case "new": return .new(try parseNew(rest))
        default: throw UsageError.unknownCommand(UsageError.escaped(first))
        }
    }

    private static func requireNone(_ rest: [String]) throws {
        if let extra = rest.first { throw UsageError.unexpectedArgument(UsageError.escaped(extra)) }
    }

    // MARK: setup

    private static func parseSetup(_ rest: [String]) throws -> SetupOptions {
        var options = SetupOptions()
        var index = 0
        while index < rest.count {
            let argument = rest[index]
            guard argument == "--bw" else {
                throw argument.hasPrefix("-") ? UsageError.unknownOption(UsageError.escaped(argument))
                                              : UsageError.unexpectedArgument(UsageError.escaped(argument))
            }
            if options.bwPath != nil { throw UsageError.duplicateOption("--bw") }
            options.bwPath = try value(after: &index, in: rest, option: "--bw")
        }
        return options
    }

    // MARK: run

    private static func parseRun(_ rest: [String]) throws -> RunOptions {
        var item: String?
        var env: [FieldBinding] = []
        var files: [FieldBinding] = []
        var stdin: String?
        var command: [String]?
        var index = 0
        scan: while index < rest.count {
            let argument = rest[index]
            switch argument {
            case "--":
                command = Array(rest[(index + 1)...])
                break scan
            case "--env":
                env.append(try binding(after: &index, in: rest, option: "--env"))
            case "--file":
                files.append(try binding(after: &index, in: rest, option: "--file"))
            case "--stdin":
                if stdin != nil { throw UsageError.duplicateOption("--stdin") }
                stdin = try value(after: &index, in: rest, option: "--stdin")
            default:
                if argument.hasPrefix("-") { throw UsageError.unknownOption(UsageError.escaped(argument)) }
                if item != nil { throw UsageError.unexpectedArgument(UsageError.escaped(argument)) }
                guard isValidName(argument) else { throw UsageError.badName }
                item = argument
                index += 1
            }
        }
        guard let item else { throw UsageError.missingItem }
        guard let command, !command.isEmpty else { throw UsageError.missingCommand }
        var seen = Set<String>()
        for binding in env + files where !seen.insert(binding.name).inserted {
            throw UsageError.duplicateName(binding.name)
        }
        return RunOptions(item: item, env: env, files: files, stdin: stdin, command: command)
    }

    /// `option VAR=field`: the variable must be one wardenrun may set; the field is everything
    /// after the first `=`.
    private static func binding(after index: inout Int, in arguments: [String], option: String) throws -> FieldBinding {
        let text = try value(after: &index, in: arguments, option: option, allowDoubleDash: true)
        guard let equals = text.firstIndex(of: "=") else { throw UsageError.badBinding(option: option) }
        let name = String(text[..<equals])
        let field = String(text[text.index(after: equals)...])
        guard !name.isEmpty, hasNoControlCharacters(field), !field.isEmpty,
              (try? EnvPolicy.validateInjectedName(name)) != nil else { throw UsageError.badBinding(option: option) }
        return FieldBinding(name: name, field: field)
    }

    // MARK: new

    private static func parseNew(_ rest: [String]) throws -> NewOptions {
        var name: String?
        var options = NewOptions(name: "", username: nil, uri: nil, env: nil, length: 32, charset: .alnum)
        var seen = Set<String>()
        var index = 0
        while index < rest.count {
            let argument = rest[index]
            switch argument {
            case "--username", "--uri", "--env", "--length", "--charset":
                if !seen.insert(argument).inserted { throw UsageError.duplicateOption(argument) }
                let text = try value(after: &index, in: rest, option: argument)
                switch argument {
                case "--username":
                    guard !text.isEmpty, hasNoControlCharacters(text) else { throw UsageError.badValue(option: argument) }
                    options.username = text
                case "--uri":
                    guard !text.isEmpty, text.count <= 2000, hasNoControlCharacters(text) else { throw UsageError.badValue(option: argument) }
                    options.uri = text
                case "--env":
                    guard (try? EnvPolicy.validateInjectedName(text)) != nil else { throw UsageError.badValue(option: argument) }
                    options.env = text
                case "--length":
                    guard let length = Int(text), lengthRange.contains(length) else { throw UsageError.badValue(option: argument) }
                    options.length = length
                default:
                    guard let charset = PasswordCharset(rawValue: text) else { throw UsageError.badValue(option: argument) }
                    options.charset = charset
                }
            default:
                if argument.hasPrefix("-") { throw UsageError.unknownOption(UsageError.escaped(argument)) }
                if name != nil { throw UsageError.unexpectedArgument(UsageError.escaped(argument)) }
                guard isValidName(argument) else { throw UsageError.badName }
                name = argument
                index += 1
            }
        }
        guard let name else { throw UsageError.missingName }
        options.name = name
        return options
    }

    // MARK: helpers

    /// The argument after `option`, and the index moved past both. A value that is `--` is the
    /// start of the command, not a value, unless the caller says otherwise.
    private static func value(after index: inout Int, in arguments: [String], option: String,
                              allowDoubleDash: Bool = false) throws -> String {
        guard index + 1 < arguments.count else { throw UsageError.missingValue(option: option) }
        let text = arguments[index + 1]
        if text == "--" && !allowDoubleDash { throw UsageError.missingValue(option: option) }
        index += 2
        guard hasNoControlCharacters(text), allowDoubleDash || !text.isEmpty || option == "--stdin" else {
            throw UsageError.badValue(option: option)
        }
        if option == "--stdin" && text.isEmpty { throw UsageError.badValue(option: option) }
        return text
    }

    private static func isValidName(_ text: String) -> Bool {
        !text.isEmpty && text.count <= maximumNameLength && hasNoControlCharacters(text)
    }

    private static func hasNoControlCharacters(_ text: String) -> Bool {
        !text.unicodeScalars.contains {
            switch $0.properties.generalCategory {
            case .control, .format, .lineSeparator, .paragraphSeparator, .surrogate: return true
            default: return false
            }
        }
    }
}
