import Foundation

/// Why a `run` could not be prepared. The messages name a field or a variable, never a value.
public enum RunError: Error, Equatable, Sendable {
    /// The item has no such field (or it is empty).
    case fieldMissing(String)
    case duplicateVariable(String)
    /// No flags were given and the item has no `env:` fields.
    case noInjection
    case invalidVariable(String)
    case tempFile
    /// A value with a NUL byte cannot be an environment variable (the C string would end early).
    case nulInEnvironmentValue(String)

    public var message: String {
        switch self {
        case .fieldMissing(let field):
            return "the item has no field \"\(TextEscaping.escape(field, quoting: true))\" (or it is empty)"
        case .duplicateVariable(let name):
            return "the variable \(TextEscaping.escape(name)) is bound more than once"
        case .noInjection:
            return "nothing to inject: the item has no env: fields, and none of --env, --file or --stdin was given"
        case .invalidVariable(let name):
            return "\"\(TextEscaping.escape(name, quoting: true))\" is not an allowed variable name "
                + "(ASCII letters, digits and _, not starting with a digit, and not DYLD_ or LD_)"
        case .tempFile:
            return "a private temporary file for --file could not be written"
        case .nulInEnvironmentValue(let name):
            return "the value for \(TextEscaping.escape(name)) contains a NUL byte and cannot be an environment variable; use --stdin or --file"
        }
    }
}

/// What goes to the approved command, as locked buffers: environment variables, files (whose
/// paths become variables) and standard input (DESIGN 5.4). Without any flag the item's
/// `env:NAME` fields become variables; with any flag only what the flags ask for is injected.
public final class InjectionPlan: @unchecked Sendable {
    public var environment: [String: SecretBuffer] = [:]
    public var files: [(variable: String, buffer: SecretBuffer)] = []
    public var stdin: SecretBuffer?
    private let itemName: String

    private init(itemName: String) { self.itemName = itemName }

    public static func make(options: RunOptions, item: BwFetchedItem) throws -> InjectionPlan {
        let plan = InjectionPlan(itemName: item.name)
        do {
            try plan.fill(options: options, item: item)
        } catch {
            plan.wipe()
            throw error
        }
        return plan
    }

    private func fill(options: RunOptions, item: BwFetchedItem) throws {
        var claimed = Set<String>()
        func claim(_ name: String) throws {
            do { try EnvPolicy.validateInjectedName(name) } catch { throw RunError.invalidVariable(name) }
            guard claimed.insert(name).inserted else { throw RunError.duplicateVariable(name) }
        }
        func fetch(_ field: String) throws -> SecretBuffer {
            let spec = try BwFieldSpec(parsing: field)
            guard let value = try item.value(of: spec), value.count > 0 else { throw RunError.fieldMissing(field) }
            return value
        }
        func environmentValue(_ name: String, field: String) throws {
            let value = try fetch(field)
            if value.withUnsafeBytes({ $0.contains(0) }) {
                value.wipe()
                throw RunError.nulInEnvironmentValue(name)
            }
            environment[name] = value
        }

        if options.env.isEmpty && options.files.isEmpty && options.stdin == nil {
            let names = try item.envFieldNames()
            guard !names.isEmpty else { throw RunError.noInjection }
            for name in names {
                try claim(name)
                try environmentValue(name, field: "env:" + name)
            }
            return
        }
        for binding in options.env {
            try claim(binding.name)
            try environmentValue(binding.name, field: binding.field)
        }
        for binding in options.files {
            try claim(binding.name)
            files.append((binding.name, try fetch(binding.field)))
        }
        if let field = options.stdin { stdin = try fetch(field) }
    }

    /// Every injected value with the item name that the replacement text shows. The values are
    /// copied out as plain bytes for the masker; the caller drops them as soon as it has built
    /// its needles.
    public var maskSecrets: [MaskSecret] {
        var all: [SecretBuffer] = environment.keys.sorted().compactMap { environment[$0] }
        all += files.map(\.buffer)
        if let stdin { all.append(stdin) }
        return all.filter { !$0.isWiped }.map { buffer in
            MaskSecret(name: itemName, value: buffer.withUnsafeBytes { Array($0) })
        }
    }

    public func wipe() {
        for buffer in environment.values { buffer.wipe() }
        for file in files { file.buffer.wipe() }
        stdin?.wipe()
        environment = [:]
        files = []
        stdin = nil
    }
}

/// The `--file` values: one fresh `0700` directory under `parent`, one `0600` file per variable,
/// named after the (validated) variable and never after the secret. `removeAll` deletes
/// everything and may be called any number of times, also after a failed `write`.
public final class SecretFiles: @unchecked Sendable {
    private let parent: String
    private let lock = NSLock()
    private var directory: String?
    private var created: [String] = []

    public init(parent: String) { self.parent = parent }

    /// Writes each buffer's bytes as they are and returns the path for every variable.
    public func write(_ buffers: [(variable: String, buffer: SecretBuffer)]) throws -> [String: String] {
        lock.lock()
        defer { lock.unlock() }
        guard directory == nil else { throw RunError.tempFile }
        var template = Array((parent + "/wardenrun-XXXXXX").utf8CString)
        guard mkdtemp(&template) != nil else { throw RunError.tempFile }
        let base = String(cString: template)
        directory = base

        var paths: [String: String] = [:]
        for (variable, buffer) in buffers {
            do { try EnvPolicy.validateInjectedName(variable) } catch { throw RunError.tempFile }
            let path = base + "/" + variable
            let descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
            guard descriptor >= 0 else { throw RunError.tempFile }
            created.append(path)
            defer { close(descriptor) }
            guard fchmod(descriptor, 0o600) == 0 else { throw RunError.tempFile }
            let complete = buffer.withUnsafeBytes { bytes -> Bool in
                var offset = 0
                while offset < bytes.count {
                    let count = rawWrite(descriptor, bytes.baseAddress! + offset, bytes.count - offset)
                    if count < 0 && errno == EINTR { continue }
                    if count <= 0 { return false }
                    offset += count
                }
                return true
            }
            guard complete else { throw RunError.tempFile }
            paths[variable] = path
        }
        return paths
    }

    public func removeAll() {
        lock.lock()
        defer { lock.unlock() }
        for path in created { unlink(path) }
        created = []
        if let directory { rmdir(directory) }
        directory = nil
    }
}

/// `SecretFiles` has a method called `write`, which hides the C function inside the class.
private func rawWrite(_ descriptor: Int32, _ bytes: UnsafeRawPointer, _ count: Int) -> Int {
    write(descriptor, bytes, count)
}
