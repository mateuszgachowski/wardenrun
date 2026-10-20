import Foundation

public enum JSONError: Error, Equatable {
    /// The input is not valid JSON; `offset` is the byte where parsing stopped.
    case syntax(offset: Int)
    case tooDeep
    /// A value of another kind than the one asked for.
    case unexpected(JSONCursor.Kind)
}

/// A pull parser over bytes that never builds a document.
///
/// The `bw` replies hold every item of the collection, each with its password. Decoding them
/// with `Codable` would turn all of those values into Swift `String`s and dictionaries that
/// cannot be wiped. The cursor instead walks the bytes in place: the caller reads the few keys
/// it needs, skips the rest by position, and copies a secret only straight into a `SecretBuffer`.
///
/// The grammar is RFC 8259, strict: no trailing commas, no leading zeros, no raw control
/// characters in strings, valid UTF-8 only, no lone surrogates. Nesting is limited to
/// `maxDepth`. Numbers are checked and skipped, never converted.
public struct JSONCursor {
    public enum Kind: Equatable, Sendable { case object, array, string, number, bool, null }

    public static let maxDepth = 32

    private let base: UnsafePointer<UInt8>?
    private let count: Int
    private var index = 0
    private var depth = 0

    /// `bytes` must stay valid for as long as the cursor is used.
    public init(_ bytes: UnsafeRawBufferPointer) {
        base = bytes.baseAddress?.assumingMemoryBound(to: UInt8.self)
        count = bytes.count
    }

    // MARK: reading values

    /// The kind of the next value, without consuming it.
    public mutating func kind() throws -> Kind {
        skipWhitespace()
        guard index < count else { throw failure() }
        switch base![index] {
        case Byte.openBrace: return .object
        case Byte.openBracket: return .array
        case Byte.quote: return .string
        case Byte.minus, Byte.zero...Byte.nine: return .number
        case Byte.lowerT, Byte.lowerF: return .bool
        case Byte.lowerN: return .null
        default: throw failure()
        }
    }

    /// Consumes one value of any kind and returns the byte range it occupied.
    @discardableResult
    public mutating func skipValue() throws -> Range<Int> {
        skipWhitespace()
        let start = index
        try scanValue()
        return start..<index
    }

    /// Consumes a string and returns its unescaped UTF-8 bytes. For names, ids and other text
    /// that is not secret; use `secretString()` for a value.
    public mutating func string() throws -> [UInt8] {
        try expect(.string)
        let start = index
        let length = try decodeString(into: nil)
        index = start
        return try [UInt8](unsafeUninitializedCapacity: length) { buffer, initialized in
            _ = try decodeString(into: buffer.baseAddress)
            initialized = length
        }
    }

    /// Consumes a string and unescapes it straight into locked memory, with no intermediate copy.
    public mutating func secretString() throws -> SecretBuffer {
        try expect(.string)
        let start = index
        let length = try decodeString(into: nil)
        index = start
        return try SecretBuffer(count: length) { buffer in
            _ = try decodeString(into: buffer.baseAddress?.assumingMemoryBound(to: UInt8.self))
        }
    }

    public mutating func bool() throws -> Bool {
        try expect(.bool)
        if base![index] == Byte.lowerT {
            try consumeLiteral("true")
            return true
        }
        try consumeLiteral("false")
        return false
    }

    // MARK: containers

    /// Walks the members of an object. `body` must consume exactly one value from the cursor it
    /// is given; consuming none or two is a syntax error.
    public mutating func members(_ body: (_ key: [UInt8], _ value: inout JSONCursor) throws -> Void) throws {
        try expect(.object)
        try enter()
        defer { depth -= 1 }
        index += 1
        skipWhitespace()
        if index < count, base![index] == Byte.closeBrace { index += 1; return }
        while true {
            skipWhitespace()
            guard index < count, base![index] == Byte.quote else { throw failure() }
            let key = try string()
            skipWhitespace()
            guard index < count, base![index] == Byte.colon else { throw failure() }
            index += 1
            skipWhitespace()
            let start = index
            try body(key, &self)
            guard index > start else { throw failure() }
            skipWhitespace()
            guard index < count else { throw failure() }
            if base![index] == Byte.comma { index += 1; continue }
            if base![index] == Byte.closeBrace { index += 1; return }
            throw failure()
        }
    }

    /// Walks the elements of an array; `body` follows the same rule as in `members`.
    public mutating func elements(_ body: (_ index: Int, _ value: inout JSONCursor) throws -> Void) throws {
        try expect(.array)
        try enter()
        defer { depth -= 1 }
        index += 1
        skipWhitespace()
        if index < count, base![index] == Byte.closeBracket { index += 1; return }
        var position = 0
        while true {
            skipWhitespace()
            let start = index
            try body(position, &self)
            guard index > start else { throw failure() }
            position += 1
            skipWhitespace()
            guard index < count else { throw failure() }
            if base![index] == Byte.comma { index += 1; continue }
            if base![index] == Byte.closeBracket { index += 1; return }
            throw failure()
        }
    }

    /// Succeeds only when nothing but whitespace is left.
    public mutating func finish() throws {
        skipWhitespace()
        guard index == count else { throw failure() }
    }

    // MARK: scanning

    private enum Byte {
        static let openBrace: UInt8 = 0x7B, closeBrace: UInt8 = 0x7D
        static let openBracket: UInt8 = 0x5B, closeBracket: UInt8 = 0x5D
        static let quote: UInt8 = 0x22, backslash: UInt8 = 0x5C, slash: UInt8 = 0x2F
        static let colon: UInt8 = 0x3A, comma: UInt8 = 0x2C
        static let minus: UInt8 = 0x2D, plus: UInt8 = 0x2B, dot: UInt8 = 0x2E
        static let zero: UInt8 = 0x30, nine: UInt8 = 0x39
        static let lowerT: UInt8 = 0x74, lowerF: UInt8 = 0x66, lowerN: UInt8 = 0x6E, lowerU: UInt8 = 0x75
        static let lowerE: UInt8 = 0x65, upperE: UInt8 = 0x45
    }

    private func failure(at offset: Int? = nil) -> JSONError { .syntax(offset: offset ?? index) }

    private mutating func skipWhitespace() {
        while index < count {
            let byte = base![index]
            guard byte == 0x20 || byte == 0x0A || byte == 0x0D || byte == 0x09 else { return }
            index += 1
        }
    }

    private mutating func expect(_ wanted: Kind) throws {
        let found = try kind()
        guard found == wanted else { throw JSONError.unexpected(found) }
    }

    private mutating func enter() throws {
        depth += 1
        if depth > Self.maxDepth { depth -= 1; throw JSONError.tooDeep }
    }

    private mutating func scanValue() throws {
        switch try kind() {
        case .object:
            try enter()
            defer { depth -= 1 }
            index += 1
            skipWhitespace()
            if index < count, base![index] == Byte.closeBrace { index += 1; return }
            while true {
                skipWhitespace()
                guard index < count, base![index] == Byte.quote else { throw failure() }
                _ = try decodeString(into: nil)
                skipWhitespace()
                guard index < count, base![index] == Byte.colon else { throw failure() }
                index += 1
                try skipValue()
                skipWhitespace()
                guard index < count else { throw failure() }
                if base![index] == Byte.comma { index += 1; continue }
                if base![index] == Byte.closeBrace { index += 1; return }
                throw failure()
            }
        case .array:
            try enter()
            defer { depth -= 1 }
            index += 1
            skipWhitespace()
            if index < count, base![index] == Byte.closeBracket { index += 1; return }
            while true {
                try skipValue()
                skipWhitespace()
                guard index < count else { throw failure() }
                if base![index] == Byte.comma { index += 1; continue }
                if base![index] == Byte.closeBracket { index += 1; return }
                throw failure()
            }
        case .string:
            _ = try decodeString(into: nil)
        case .number:
            try scanNumber()
        case .bool:
            try consumeLiteral(base![index] == Byte.lowerT ? "true" : "false")
        case .null:
            try consumeLiteral("null")
        }
    }

    /// Consumes `word`, which must be next and must not run on into a letter or digit (`truex`).
    private mutating func consumeLiteral(_ word: StaticString) throws {
        let length = word.utf8CodeUnitCount
        let matches = index + length <= count
            && word.withUTF8Buffer { literal in (0..<length).allSatisfy { base![index + $0] == literal[$0] } }
        guard matches else { throw failure() }
        index += length
        if index < count, isNameByte(base![index]) { throw failure() }
    }

    private func isNameByte(_ byte: UInt8) -> Bool {
        (byte >= 0x30 && byte <= 0x39) || (byte >= 0x41 && byte <= 0x5A) || (byte >= 0x61 && byte <= 0x7A)
    }

    private mutating func scanNumber() throws {
        if base![index] == Byte.minus { index += 1 }
        guard index < count else { throw failure() }
        if base![index] == Byte.zero {
            index += 1
        } else if base![index] >= 0x31 && base![index] <= Byte.nine {
            while index < count, isDigit(base![index]) { index += 1 }
        } else {
            throw failure()
        }
        if index < count, base![index] == Byte.dot {
            index += 1
            guard index < count, isDigit(base![index]) else { throw failure() }
            while index < count, isDigit(base![index]) { index += 1 }
        }
        if index < count, base![index] == Byte.lowerE || base![index] == Byte.upperE {
            index += 1
            if index < count, base![index] == Byte.plus || base![index] == Byte.minus { index += 1 }
            guard index < count, isDigit(base![index]) else { throw failure() }
            while index < count, isDigit(base![index]) { index += 1 }
        }
    }

    private func isDigit(_ byte: UInt8) -> Bool { byte >= Byte.zero && byte <= Byte.nine }

    /// Validates the string at `index` (which holds the opening quote), leaves `index` after the
    /// closing quote, and returns the length of the unescaped bytes. With a destination it also
    /// writes them; the caller sizes it with a first run that passes `nil`.
    private mutating func decodeString(into destination: UnsafeMutablePointer<UInt8>?) throws -> Int {
        var written = 0
        var position = index + 1
        func put(_ byte: UInt8) {
            destination?[written] = byte
            written += 1
        }
        while true {
            guard position < count else { throw failure(at: count) }
            let byte = base![position]
            if byte == Byte.quote {
                index = position + 1
                return written
            }
            if byte < 0x20 { throw failure(at: position) }
            if byte == Byte.backslash {
                position += 1
                guard position < count else { throw failure(at: count) }
                switch base![position] {
                case Byte.quote: put(Byte.quote)
                case Byte.backslash: put(Byte.backslash)
                case Byte.slash: put(Byte.slash)
                case 0x62: put(0x08)
                case 0x66: put(0x0C)
                case 0x6E: put(0x0A)
                case 0x72: put(0x0D)
                case 0x74: put(0x09)
                case Byte.lowerU:
                    var scalar = try hex4(after: position)
                    position += 4
                    if (0xD800...0xDBFF).contains(scalar) {
                        // A high surrogate must be followed by an escaped low one.
                        guard position + 2 < count, base![position + 1] == Byte.backslash,
                              base![position + 2] == Byte.lowerU else { throw failure(at: min(position + 1, count)) }
                        let low = try hex4(after: position + 2)
                        guard (0xDC00...0xDFFF).contains(low) else { throw failure(at: position + 3) }
                        scalar = 0x10000 + ((scalar - 0xD800) << 10) + (low - 0xDC00)
                        position += 6
                    } else if (0xDC00...0xDFFF).contains(scalar) {
                        throw failure(at: position - 3)
                    }
                    putScalar(scalar, put)
                default:
                    throw failure(at: position)
                }
                position += 1
                continue
            }
            if byte < 0x80 {
                put(byte)
                position += 1
                continue
            }
            guard let length = UTF8Check.sequenceLength(in: base!, count: count, at: position) else {
                throw failure(at: position)
            }
            for offset in 0..<length { put(base![position + offset]) }
            position += length
        }
    }

    /// The four hex digits after the `u` at `u`.
    private func hex4(after u: Int) throws -> UInt32 {
        guard u + 4 < count else { throw failure(at: count) }
        var value: UInt32 = 0
        for offset in 1...4 {
            let byte = base![u + offset]
            let digit: UInt32
            switch byte {
            case 0x30...0x39: digit = UInt32(byte - 0x30)
            case 0x41...0x46: digit = UInt32(byte - 0x41 + 10)
            case 0x61...0x66: digit = UInt32(byte - 0x61 + 10)
            default: throw failure(at: u + offset)
            }
            value = value << 4 | digit
        }
        return value
    }

    private func putScalar(_ scalar: UInt32, _ put: (UInt8) -> Void) {
        switch scalar {
        case 0..<0x80:
            put(UInt8(scalar))
        case 0x80..<0x800:
            put(UInt8(0xC0 | scalar >> 6)); put(UInt8(0x80 | scalar & 0x3F))
        case 0x800..<0x10000:
            put(UInt8(0xE0 | scalar >> 12)); put(UInt8(0x80 | scalar >> 6 & 0x3F)); put(UInt8(0x80 | scalar & 0x3F))
        default:
            put(UInt8(0xF0 | scalar >> 18)); put(UInt8(0x80 | scalar >> 12 & 0x3F))
            put(UInt8(0x80 | scalar >> 6 & 0x3F)); put(UInt8(0x80 | scalar & 0x3F))
        }
    }
}
