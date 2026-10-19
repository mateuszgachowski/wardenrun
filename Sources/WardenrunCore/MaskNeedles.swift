import Foundation

/// A byte pattern to hide and the text that replaces it.
public struct Needle: Equatable, Sendable {
    public let bytes: [UInt8]
    public let replacement: [UInt8]

    public init(bytes: [UInt8], replacement: [UInt8]) {
        self.bytes = bytes
        self.replacement = replacement
    }
}

/// A value to hide, with the item name that appears in the replacement text.
public struct MaskSecret: Sendable {
    public let name: String
    public let value: [UInt8]

    public init(name: String, value: [UInt8]) {
        self.name = name
        self.value = value
    }
}

public struct MaskPlan: Sendable {
    public let needles: [Needle]
    /// Names of values too short to mask reliably (shorter than `MaskNeedles.minimumLength`).
    public let tooShort: [String]
}

/// Turns a secret value into every byte pattern in which it is likely to show up in output.
public enum MaskNeedles {
    /// Shorter values would garble ordinary output, so they are not masked at all.
    public static let minimumLength = 6

    /// All patterns for `value`, longest first, then in byte order, without duplicates.
    /// Empty when the value is shorter than `minimumLength`.
    public static func variants(of value: [UInt8]) -> [[UInt8]] {
        guard value.count >= minimumLength else { return [] }
        var found = Set<[UInt8]>()
        addEncodings(of: value, to: &found)
        if value.contains(0x0A) {
            for rawLine in value.split(separator: 0x0A, omittingEmptySubsequences: true) {
                var line = Array(rawLine)
                if line.last == 0x0D { line.removeLast() }
                if line.count >= minimumLength { addEncodings(of: line, to: &found) }
            }
        }
        return found.sorted { a, b in
            a.count != b.count ? a.count > b.count : a.lexicographicallyPrecedes(b)
        }
    }

    public static func plan(for secrets: [MaskSecret],
                            replacement: (String) -> String = { "[REDACTED:\($0)]" }) -> MaskPlan {
        var needles = [Needle]()
        var tooShort = [String]()
        for secret in secrets {
            let patterns = variants(of: secret.value)
            if patterns.isEmpty {
                tooShort.append(secret.name)
                continue
            }
            let text = Array(replacement(secret.name).utf8)
            needles += patterns.map { Needle(bytes: $0, replacement: text) }
        }
        return MaskPlan(needles: needles, tooShort: tooShort)
    }

    // MARK: encodings

    private static func addEncodings(of value: [UInt8], to found: inout Set<[UInt8]>) {
        func add(_ bytes: [UInt8]) {
            if bytes.count >= minimumLength { found.insert(bytes) }
        }
        add(value)
        for urlSafe in [false, true] {
            add(base64(value, urlSafe: urlSafe, padded: true))
            add(base64(value, urlSafe: urlSafe, padded: false))
            for shift in 0...2 { add(base64Interior(value, urlSafe: urlSafe, precededBy: shift)) }
        }
        for lowercaseHex in [false, true] {
            for spaceAsPlus in [false, true] {
                for kept in percentKeptSets {
                    add(percent(value, lowercaseHex: lowercaseHex, spaceAsPlus: spaceAsPlus, kept: kept))
                }
            }
        }
        add(Array(Hex.encode(value).utf8))
        add(Array(Hex.encode(value, uppercase: true).utf8))
        if let text = String(bytes: value, encoding: .utf8) {
            for escapeSlash in [false, true] {
                for asciiOnly in [false, true] {
                    for htmlSafe in [false, true] {
                        for uppercaseHex in [false, true] {
                            add(jsonBody(text, escapeSlash: escapeSlash, asciiOnly: asciiOnly,
                                         htmlSafe: htmlSafe, uppercaseHex: uppercaseHex))
                        }
                    }
                }
            }
        }
        add(singleQuoteBody(value, replacing: [0x27, 0x5C, 0x27, 0x27]))        // bash: '\''
        add(singleQuoteBody(value, replacing: [0x27, 0x22, 0x27, 0x22, 0x27]))  // Python shlex.quote: '"'"'
    }

    private static let standardAlphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".utf8)
    private static let urlSafeAlphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".utf8)

    private static func base64(_ bytes: [UInt8], urlSafe: Bool, padded: Bool) -> [UInt8] {
        let alphabet = urlSafe ? urlSafeAlphabet : standardAlphabet
        var out = [UInt8]()
        out.reserveCapacity((bytes.count + 2) / 3 * 4)
        var index = 0
        while index < bytes.count {
            let remaining = bytes.count - index
            let b0 = UInt32(bytes[index])
            let b1 = remaining > 1 ? UInt32(bytes[index + 1]) : 0
            let b2 = remaining > 2 ? UInt32(bytes[index + 2]) : 0
            let triple = b0 << 16 | b1 << 8 | b2
            out.append(alphabet[Int(triple >> 18 & 63)])
            out.append(alphabet[Int(triple >> 12 & 63)])
            if remaining > 1 { out.append(alphabet[Int(triple >> 6 & 63)]) } else if padded { out.append(UInt8(ascii: "=")) }
            if remaining > 2 { out.append(alphabet[Int(triple & 63)]) } else if padded { out.append(UInt8(ascii: "=")) }
            index += 3
        }
        return out
    }

    /// The characters of a base64 stream that depend only on `value`, when `shift` bytes
    /// (counted modulo 3) came before it. The first characters mix in earlier bytes and the
    /// last one mixes in later bytes, so both ends are cut off.
    private static func base64Interior(_ value: [UInt8], urlSafe: Bool, precededBy shift: Int) -> [UInt8] {
        let encoded = base64([UInt8](repeating: 0, count: shift) + value, urlSafe: urlSafe, padded: false)
        let start = (8 * shift + 5) / 6
        let end = 8 * (shift + value.count) / 6
        return start < end ? Array(encoded[start..<end]) : []
    }

    /// Encoders disagree about what they leave alone besides the unreserved set: nothing (RFC 3986),
    /// "/" (Python `urllib.parse.quote`), and `!'()*` (JavaScript `encodeURIComponent`).
    private static let percentKeptSets: [Set<UInt8>] = [[], [UInt8(ascii: "/")], Set("!'()*".utf8)]

    private static func percent(_ bytes: [UInt8], lowercaseHex: Bool, spaceAsPlus: Bool, kept: Set<UInt8>) -> [UInt8] {
        let digits = Array((lowercaseHex ? "0123456789abcdef" : "0123456789ABCDEF").utf8)
        var out = [UInt8]()
        for byte in bytes {
            switch byte {
            case UInt8(ascii: "A")...UInt8(ascii: "Z"), UInt8(ascii: "a")...UInt8(ascii: "z"),
                 UInt8(ascii: "0")...UInt8(ascii: "9"), UInt8(ascii: "-"), UInt8(ascii: "."),
                 UInt8(ascii: "_"), UInt8(ascii: "~"):
                out.append(byte)
            case UInt8(ascii: " ") where spaceAsPlus:
                out.append(UInt8(ascii: "+"))
            case _ where kept.contains(byte):
                out.append(byte)
            default:
                out.append(UInt8(ascii: "%"))
                out.append(digits[Int(byte >> 4)])
                out.append(digits[Int(byte & 0x0f)])
            }
        }
        return out
    }

    private static func jsonBody(_ text: String, escapeSlash: Bool, asciiOnly: Bool, htmlSafe: Bool,
                                 uppercaseHex: Bool) -> [UInt8] {
        func unicodeEscape(_ unit: UInt16) -> String {
            let hex = String(unit, radix: 16, uppercase: uppercaseHex)
            return "\\u" + String(repeating: "0", count: 4 - hex.count) + hex
        }
        var out = ""
        for scalar in text.unicodeScalars {
            switch scalar {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "/": out += escapeSlash ? "\\/" : "/"
            case "\u{08}": out += "\\b"
            case "\u{0C}": out += "\\f"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            case _ where htmlSafe && (scalar == "<" || scalar == ">" || scalar == "&"):
                out += unicodeEscape(UInt16(scalar.value))
            default:
                if scalar.value < 0x20 {
                    out += unicodeEscape(UInt16(scalar.value))
                } else if asciiOnly && scalar.value > 0x7E {
                    for unit in String(scalar).utf16 { out += unicodeEscape(unit) }
                } else {
                    out.unicodeScalars.append(scalar)
                }
            }
        }
        return Array(out.utf8)
    }

    private static func singleQuoteBody(_ bytes: [UInt8], replacing quote: [UInt8]) -> [UInt8] {
        var out = [UInt8]()
        for byte in bytes {
            if byte == 0x27 { out += quote } else { out.append(byte) }
        }
        return out
    }
}
