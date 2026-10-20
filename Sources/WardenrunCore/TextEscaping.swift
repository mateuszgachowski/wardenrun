import Foundation

/// How a value is shown to a human inside an approval text (DESIGN 5.3 "Escaping"): nothing the
/// caller controls can start a new line, reorder the text or hide inside it.
enum TextEscaping {
    /// Scalars that draw as nothing (or as a blank) without being in a separator or format category:
    /// Braille blank, Hangul fillers, the half-width filler.
    private static let blankLooking: Set<UInt32> = [0x2800, 0x115F, 0x1160, 0x3164, 0xFFA0]

    /// Control, format (bidi, zero-width), separator (every space but the ASCII one), blank-looking,
    /// unassigned and C1 scalars become visible
    /// escapes (`\n`, `\u{202E}`), a backslash is doubled so that escapes stay unambiguous, and,
    /// with `quoting`, a double quote is escaped too.
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
                    || (category == .spaceSeparator && value != 0x20) || blankLooking.contains(value)
                if invisible {
                    output += "\\u{" + String(value, radix: 16, uppercase: true) + "}"
                } else {
                    output.unicodeScalars.append(scalar)
                }
            }
        }
        return output
    }
}
