/// Strict UTF-8 validation shared by the JSON reader and writer.
enum UTF8Check {
    /// Length of the well-formed sequence that starts at `start`, whose lead byte is at least
    /// 0x80, or nil when the bytes there are not valid UTF-8: stray continuation byte, overlong
    /// form, encoded surrogate, value above U+10FFFF, or a sequence cut short by `count`.
    static func sequenceLength(in bytes: UnsafePointer<UInt8>, count: Int, at start: Int) -> Int? {
        let lead = bytes[start]
        let length: Int
        var low: UInt8 = 0x80, high: UInt8 = 0xBF
        switch lead {
        case 0xC2...0xDF: length = 2
        case 0xE0: length = 3; low = 0xA0
        case 0xE1...0xEC, 0xEE, 0xEF: length = 3
        case 0xED: length = 3; high = 0x9F
        case 0xF0: length = 4; low = 0x90
        case 0xF1...0xF3: length = 4
        case 0xF4: length = 4; high = 0x8F
        default: return nil
        }
        guard start + length <= count, bytes[start + 1] >= low, bytes[start + 1] <= high else { return nil }
        for offset in 2..<length where bytes[start + offset] < 0x80 || bytes[start + offset] > 0xBF { return nil }
        return length
    }
}
