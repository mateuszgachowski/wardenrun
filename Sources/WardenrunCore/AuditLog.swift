import Foundation

public enum AuditEventKind: String, Codable, Sendable {
    case approved, denied, timeout, error, new, setup
}

/// What gets recorded about one decision. Never a secret value. Deliberately not `Codable`:
/// the only way to turn an event into bytes is `AuditLog.append`, which redacts every string.
public struct AuditEvent: Equatable, Sendable {
    public var event: AuditEventKind
    public var item: String?
    public var commandLine: [String]?
    public var executable: String?
    public var executableSHA256: String?
    public var cwd: String?
    public var parentChain: [String]?
    public var tier: String?
    public var exitStatus: Int32?
    public var durationMs: Int?

    public init(event: AuditEventKind, item: String? = nil, commandLine: [String]? = nil,
                executable: String? = nil, executableSHA256: String? = nil, cwd: String? = nil,
                parentChain: [String]? = nil, tier: String? = nil, exitStatus: Int32? = nil,
                durationMs: Int? = nil) {
        self.event = event
        self.item = item
        self.commandLine = commandLine
        self.executable = executable
        self.executableSHA256 = executableSHA256
        self.cwd = cwd
        self.parentChain = parentChain
        self.tier = tier
        self.exitStatus = exitStatus
        self.durationMs = durationMs
    }
}

public enum AuditVerification: Equatable, Sendable {
    case ok(lines: Int)
    case broken(line: Int, reason: String)
}

public enum AuditLogError: Error, Equatable {
    case cannotOpen(path: String, errno: Int32)
    case cannotRead(errno: Int32)
    case cannotWrite(errno: Int32)
    case cannotEncode
}

/// Append-only log of decisions. One JSON object per line; each line carries the SHA-256 of
/// the previous line.
///
/// What that buys, honestly: it catches accidental damage and a naive edit or deletion in the
/// middle of the file. It does **not** stop a same-user process that knows the format: the
/// hash has no key, so it can rewrite a line and recompute every later `prev`, drop the last
/// lines, or delete the file, and `verify` still says `.ok`. Binding the chain to a key and a
/// counter kept in the protected keychain item is a later hardening step.
public struct AuditLog: Sendable {
    private static let firstPrev = String(repeating: "0", count: 64)

    private let path: String
    private let redactor: @Sendable (String) -> String
    private let clock: @Sendable () -> Date

    /// `redactor` runs on every string before it is written, so a secret that sneaked into a
    /// command line is masked even if the caller forgot. It is required on purpose: a call
    /// site that has no masker yet must say so with `{ $0 }`.
    public init(path: String,
                redactor: @escaping @Sendable (String) -> String,
                clock: @escaping @Sendable () -> Date = { Date() }) {
        self.path = path
        self.redactor = redactor
        self.clock = clock
    }

    public func append(_ event: AuditEvent) throws {
        let directory = (path as NSString).deletingLastPathComponent
        if !directory.isEmpty {
            try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
        }
        let descriptor = try Self.openForAppend(path: path)
        defer { close(descriptor) }
        guard flock(descriptor, LOCK_EX) == 0 else { throw AuditLogError.cannotWrite(errno: errno) }
        defer { flock(descriptor, LOCK_UN) }

        let last = try Self.lastLine(of: descriptor)
        let prev = last.map { SHA256.hexHash($0.bytes) } ?? Self.firstPrev
        let line = try encode(event, prev: prev)

        var payload = [UInt8]()
        if let last, !last.endsWithNewline { payload.append(0x0A) }   // finish a line cut short by a crash
        payload += line
        payload.append(0x0A)
        try Self.writeAll(payload, to: descriptor)
    }

    public static func verify(path: String) throws -> AuditVerification {
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        var lines = data.split(separator: 0x0A, omittingEmptySubsequences: false).map { Array($0) }
        if lines.last?.isEmpty == true { lines.removeLast() }
        var expectedPrev = firstPrev
        for (offset, line) in lines.enumerated() {
            let number = offset + 1
            guard let object = try? JSONSerialization.jsonObject(with: Data(line)) as? [String: Any] else {
                return .broken(line: number, reason: "not a JSON object")
            }
            guard object["prev"] as? String == expectedPrev else {
                return .broken(line: number, reason: "does not continue the hash chain")
            }
            expectedPrev = SHA256.hexHash(line)
        }
        return .ok(lines: lines.count)
    }

    // MARK: internals

    static func openForAppend(path: String) throws -> Int32 {
        let descriptor = open(path, O_RDWR | O_APPEND | O_CREAT, 0o600)
        guard descriptor >= 0 else { throw AuditLogError.cannotOpen(path: path, errno: errno) }
        return descriptor
    }

    private struct Line: Encodable {
        let time: String
        let prev: String
        let event: AuditEvent
        let redact: (String) -> String

        enum Keys: String, CodingKey {
            case time, prev, event, item, cwd, tier, executable
            case commandLine = "command_line"
            case executableSHA256 = "executable_sha256"
            case parentChain = "parent_chain"
            case exitStatus = "exit_status"
            case durationMs = "duration_ms"
        }

        func encode(to encoder: Encoder) throws {
            var c = encoder.container(keyedBy: Keys.self)
            try c.encode(time, forKey: .time)
            try c.encode(prev, forKey: .prev)
            try c.encode(event.event, forKey: .event)
            try c.encodeIfPresent(event.item.map(redact), forKey: .item)
            try c.encodeIfPresent(event.commandLine.map { $0.map(redact) }, forKey: .commandLine)
            try c.encodeIfPresent(event.executable.map(redact), forKey: .executable)
            try c.encodeIfPresent(event.executableSHA256.map(redact), forKey: .executableSHA256)
            try c.encodeIfPresent(event.cwd.map(redact), forKey: .cwd)
            try c.encodeIfPresent(event.parentChain.map { $0.map(redact) }, forKey: .parentChain)
            try c.encodeIfPresent(event.tier.map(redact), forKey: .tier)
            try c.encodeIfPresent(event.exitStatus, forKey: .exitStatus)
            try c.encodeIfPresent(event.durationMs, forKey: .durationMs)
        }
    }

    private func encode(_ event: AuditEvent, prev: String) throws -> [UInt8] {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        formatter.timeZone = TimeZone(identifier: "UTC")
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let line = Line(time: formatter.string(from: clock()), prev: prev, event: event, redact: redactor)
        guard let data = try? encoder.encode(line) else { throw AuditLogError.cannotEncode }
        return Array(data)
    }

    /// The last line of the file (without its newline) and whether the file ended with one.
    private static func lastLine(of descriptor: Int32) throws -> (bytes: [UInt8], endsWithNewline: Bool)? {
        let size = lseek(descriptor, 0, SEEK_END)
        guard size >= 0 else { throw AuditLogError.cannotRead(errno: errno) }
        guard size > 0 else { return nil }
        var tail = [UInt8]()           // collected back to front
        var position = Int(size)
        var endsWithNewline = false
        var skipped = false            // the trailing newline has been dropped
        let block = 4096
        search: while position > 0 {
            let length = min(block, position)
            position -= length
            var buffer = [UInt8](repeating: 0, count: length)
            guard pread(descriptor, &buffer, length, off_t(position)) == length else {
                throw AuditLogError.cannotRead(errno: errno)
            }
            var index = length - 1
            while index >= 0 {
                let byte = buffer[index]
                if !skipped, tail.isEmpty, byte == 0x0A, position + index == Int(size) - 1 {
                    endsWithNewline = true
                    skipped = true
                } else if byte == 0x0A {
                    break search
                } else {
                    tail.append(byte)
                }
                index -= 1
            }
        }
        return (Array(tail.reversed()), endsWithNewline)
    }

    private static func writeAll(_ bytes: [UInt8], to descriptor: Int32) throws {
        var written = 0
        while written < bytes.count {
            let count = bytes[written...].withUnsafeBytes { write(descriptor, $0.baseAddress, $0.count) }
            guard count > 0 else { throw AuditLogError.cannotWrite(errno: errno) }
            written += count
        }
    }
}
