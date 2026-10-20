import Foundation

/// A JSON document under construction. `.secret` holds bytes that must never pass through a
/// `String`; `.string` is for text that is not secret (names, ids, URLs).
public indirect enum SecretJSONValue {
    case string(String)
    case secret(SecretBuffer)
    case bool(Bool)
    /// A whole number, for the small fixed fields of an item (`type`, `reprompt`).
    case integer(Int)
    case null
    case array([SecretJSONValue])
    case object([(String, SecretJSONValue)])
}

/// Writes JSON straight into a `SecretBuffer`.
///
/// Two passes over the value: the first only measures, the second fills an exact-size, locked
/// buffer. Nothing is appended to a growing array, so no stale copy of a password is left
/// behind by a reallocation, and no secret becomes a `String`.
public enum SecretJSON {
    /// Escapes `"`, `\` and every byte below 0x20 (`\n`, `\r`, `\t` in short form, the rest as a
    /// four-digit unicode escape). Everything else is copied as it is. A `.secret` that is not
    /// valid UTF-8 throws `BwError.invalidUTF8(field:)` naming its key, before anything is allocated.
    public static func encode(_ value: SecretJSONValue) throws -> SecretBuffer {
        var measuring = Sink(base: nil)
        try emit(value, key: "", into: &measuring)
        let length = measuring.count
        return try SecretBuffer(count: length) { raw in
            var writing = Sink(base: raw.baseAddress?.assumingMemoryBound(to: UInt8.self))
            try emit(value, key: "", into: &writing)
            precondition(writing.count == length, "SecretJSON: the two passes disagree")
        }
    }

    private struct Sink {
        let base: UnsafeMutablePointer<UInt8>?
        var count = 0
        init(base: UnsafeMutablePointer<UInt8>?) { self.base = base }

        mutating func put(_ byte: UInt8) {
            base?[count] = byte
            count += 1
        }

        mutating func put(_ text: StaticString) {
            text.withUTF8Buffer { for byte in $0 { put(byte) } }
        }
    }

    private static let hexDigits = Array("0123456789abcdef".utf8)

    private static func emit(_ value: SecretJSONValue, key: String, into sink: inout Sink) throws {
        switch value {
        case .null:
            sink.put("null")
        case .bool(let flag):
            if flag { sink.put("true") } else { sink.put("false") }
        case .integer(let number):
            for byte in String(number).utf8 { sink.put(byte) }
        case .string(let text):
            sink.put(0x22)
            for byte in text.utf8 { escape(byte, into: &sink) }
            sink.put(0x22)
        case .secret(let buffer):
            try buffer.withUnsafeBytes { raw in
                sink.put(0x22)
                guard let start = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                    sink.put(0x22)
                    return
                }
                var position = 0
                while position < raw.count {
                    let byte = start[position]
                    if byte < 0x80 {
                        escape(byte, into: &sink)
                        position += 1
                    } else {
                        guard let length = UTF8Check.sequenceLength(in: start, count: raw.count, at: position) else {
                            throw BwError.invalidUTF8(field: key)
                        }
                        for offset in 0..<length { sink.put(start[position + offset]) }
                        position += length
                    }
                }
                sink.put(0x22)
            }
        case .array(let items):
            sink.put(0x5B)
            for (index, item) in items.enumerated() {
                if index > 0 { sink.put(0x2C) }
                try emit(item, key: key, into: &sink)
            }
            sink.put(0x5D)
        case .object(let members):
            sink.put(0x7B)
            for (index, member) in members.enumerated() {
                if index > 0 { sink.put(0x2C) }
                sink.put(0x22)
                for byte in member.0.utf8 { escape(byte, into: &sink) }
                sink.put(0x22)
                sink.put(0x3A)
                try emit(member.1, key: member.0, into: &sink)
            }
            sink.put(0x7D)
        }
    }

    private static func escape(_ byte: UInt8, into sink: inout Sink) {
        switch byte {
        case 0x22: sink.put(0x5C); sink.put(0x22)
        case 0x5C: sink.put(0x5C); sink.put(0x5C)
        case 0x0A: sink.put(0x5C); sink.put(0x6E)
        case 0x0D: sink.put(0x5C); sink.put(0x72)
        case 0x09: sink.put(0x5C); sink.put(0x74)
        case 0..<0x20:
            sink.put(0x5C); sink.put(0x75); sink.put(0x30); sink.put(0x30)
            sink.put(hexDigits[Int(byte >> 4)]); sink.put(hexDigits[Int(byte & 0xF)])
        default: sink.put(byte)
        }
    }
}
