import Foundation
import Testing
@testable import WardenrunCore

struct JSONCursorTests {
    /// A literal backslash and a JSON unicode escape built from it, spelled out in pieces so
    /// that no tool or editor can quietly turn the written-out escape back into the character.
    private let bs = "\\"
    private func esc(_ hex: String) -> String { bs + "u" + hex }

    private func with<R>(_ text: String, _ body: (inout JSONCursor) throws -> R) rethrows -> R {
        try with(Array(text.utf8), body)
    }

    private func with<R>(_ bytes: [UInt8], _ body: (inout JSONCursor) throws -> R) rethrows -> R {
        try bytes.withUnsafeBytes { raw in
            var cursor = JSONCursor(raw)
            return try body(&cursor)
        }
    }

    private func text(_ bytes: [UInt8]) -> String { String(decoding: bytes, as: UTF8.self) }

    // MARK: strings

    @Test func stringUnescapesEveryEscapeForm() throws {
        let json = "\"q" + bs + "\"" + bs + bs + bs + "/" + bs + "b" + bs + "f" + bs + "n" + bs + "r" + bs + "t"
            + esc("0041") + esc("00e9") + esc("00E9") + "\""
        let bytes = try with(json) { try $0.string() }
        var expected = Array("q\"\\/".utf8)
        expected += [0x08, 0x0C, 0x0A, 0x0D, 0x09]
        expected += Array("A".utf8) + [0xC3, 0xA9, 0xC3, 0xA9]
        #expect(bytes == expected)
    }

    @Test func surrogatePairBecomesOneFourByteScalar() throws {
        let bytes = try with("\"" + esc("d83d") + esc("DE00") + "\"") { try $0.string() }
        #expect(bytes == [0xF0, 0x9F, 0x98, 0x80])
    }

    @Test func loneSurrogatesAreSyntaxErrors() {
        for json in ["\"" + esc("d83d") + "\"", "\"" + esc("de00") + "\"", "\"" + esc("d83d") + "x\"",
                     "\"" + esc("d83d") + esc("0041") + "\""] {
            #expect(throws: JSONError.self, "accepted: \(json)") { _ = try with(json) { try $0.string() } }
        }
    }

    @Test func rawInvalidUTF8InAStringIsASyntaxError() {
        let bad: [[UInt8]] = [
            [0x22, 0xC3, 0x28, 0x22],                  // bad continuation
            [0x22, 0xC0, 0xAF, 0x22],                  // overlong
            [0x22, 0xED, 0xA0, 0x80, 0x22],            // encoded surrogate
            [0x22, 0xF4, 0x90, 0x80, 0x80, 0x22],      // above U+10FFFF
            [0x22, 0xFF, 0x22],
            [0x22, 0xE2, 0x82],                        // truncated by the end of input
        ]
        for bytes in bad {
            #expect(throws: JSONError.self, "accepted: \(bytes)") { _ = try with(bytes) { try $0.skipValue() } }
            #expect(throws: JSONError.self, "accepted: \(bytes)") { _ = try with(bytes) { try $0.string() } }
        }
    }

    @Test func validMultiByteUTF8PassesThroughUntouched() throws {
        let value = "zażółć 😀 €"
        let bytes = try with("\"" + value + "\"") { try $0.string() }
        #expect(bytes == Array(value.utf8))
    }

    @Test func aRawControlCharacterInAStringIsASyntaxError() {
        #expect(throws: JSONError.self) { _ = try with([0x22, 0x0A, 0x22]) { try $0.string() } }
    }

    @Test func secretStringMatchesStringAndHoldsTheSameBytes() throws {
        let json = "\"p" + bs + "\"w" + bs + "n" + esc("00e9") + "\""
        let plain = try with(json) { try $0.string() }
        let secret = try with(json) { try $0.secretString() }
        #expect(secret.withUnsafeBytes { Array($0) } == plain)
        #expect(secret.isLocked == SecretBuffer(copying: [1]).isLocked)
        secret.wipe()
        #expect(secret.count == 0)
    }

    // MARK: structure

    @Test func membersVisitsKeysInOrderIncludingDuplicatesAndUnescapesKeys() throws {
        var keys: [String] = []
        try with("{\"a\":1,\"b\":\"x\",\"a" + esc("0062") + "\":true,\"a\":null}") { cursor in
            try cursor.members { key, value in
                keys.append(text(key))
                try value.skipValue()
            }
            try cursor.finish()
        }
        #expect(keys == ["a", "b", "ab", "a"])
    }

    @Test func elementsReportsIndexes() throws {
        var seen: [Int] = []
        try with("[1, [2], \"x\", {}]") { cursor in
            try cursor.elements { index, value in
                seen.append(index)
                try value.skipValue()
            }
        }
        #expect(seen == [0, 1, 2, 3])
    }

    @Test func emptyContainersAreFine() throws {
        try with(" { } ") { cursor in try cursor.members { _, _ in } ; try cursor.finish() }
        try with(" [ ] ") { cursor in try cursor.elements { _, _ in } ; try cursor.finish() }
    }

    @Test func skipValueReturnsTheExactRange() throws {
        let json = "  {\"k\":\"}" + bs + "\"\",\"n\":[1,{\"z\":null}]}  "
        let bytes = Array(json.utf8)
        let range = try with(bytes) { try $0.skipValue() }
        #expect(text(Array(bytes[range])) == "{\"k\":\"}" + bs + "\"\",\"n\":[1,{\"z\":null}]}")
    }

    @Test func aBodyThatConsumesNothingIsASyntaxError() {
        #expect(throws: JSONError.self) {
            try with("{\"a\":1}") { cursor in try cursor.members { _, _ in } }
        }
        #expect(throws: JSONError.self) {
            try with("[1]") { cursor in try cursor.elements { _, _ in } }
        }
    }

    @Test func aBodyThatConsumesTwoValuesIsASyntaxError() {
        #expect(throws: JSONError.self) {
            try with("[1,2]") { cursor in
                try cursor.elements { _, value in
                    try value.skipValue()
                    try value.skipValue()
                }
            }
        }
    }

    @Test func wrongKindsAreReportedAsUnexpected() {
        #expect(throws: JSONError.unexpected(.number)) { _ = try with("12") { try $0.string() } }
        #expect(throws: JSONError.unexpected(.array)) { try with("[]") { try $0.members { _, _ in } } }
        #expect(throws: JSONError.unexpected(.object)) { try with("{}") { try $0.elements { _, _ in } } }
        #expect(throws: JSONError.unexpected(.string)) { _ = try with("\"x\"") { try $0.bool() } }
    }

    @Test func kindClassifiesTheNextValue() throws {
        let cases: [(String, JSONCursor.Kind)] = [("{}", .object), (" []", .array), ("\"s\"", .string),
                                                  ("-1", .number), ("7", .number), ("true", .bool),
                                                  ("false", .bool), ("null", .null)]
        for (json, expected) in cases {
            let kind = try with(json) { try $0.kind() }
            #expect(kind == expected, "\(json)")
        }
    }

    @Test func boolReadsBothLiterals() throws {
        #expect(try with("true") { try $0.bool() } == true)
        #expect(try with(" false ") { try $0.bool() } == false)
    }

    // MARK: strictness

    @Test func depthLimitIs32() throws {
        let ok = String(repeating: "[", count: 32) + String(repeating: "]", count: 32)
        let tooDeep = String(repeating: "[", count: 33) + String(repeating: "]", count: 33)
        _ = try with(ok) { try $0.skipValue() }
        #expect(throws: JSONError.tooDeep) { _ = try with(tooDeep) { try $0.skipValue() } }
    }

    @Test func descendingByHandCountsTowardTheDepthLimit() {
        func descend(_ cursor: inout JSONCursor) throws {
            try cursor.elements { _, value in try descend(&value) }
        }
        let tooDeep = String(repeating: "[", count: 40) + String(repeating: "]", count: 40)
        #expect(throws: JSONError.tooDeep) { try with(tooDeep) { try descend(&$0) } }
    }

    @Test func truncatedInputReportsTheOffset() {
        let cases: [(String, Int)] = [("[1,2", 4), ("{\"a\":", 5), ("\"abc", 4), ("[1,", 3), ("{\"a\"", 4)]
        for (json, offset) in cases {
            #expect(throws: JSONError.syntax(offset: offset), "\(json)") { _ = try with(json) { try $0.skipValue() } }
        }
    }

    @Test func emptyInputIsASyntaxError() {
        #expect(throws: JSONError.syntax(offset: 0)) { _ = try with("") { try $0.kind() } }
        #expect(throws: JSONError.syntax(offset: 3)) { _ = try with("   ") { try $0.skipValue() } }
    }

    @Test func trailingGarbageFailsFinishButWhitespaceDoesNot() throws {
        try with("[] \n\t\r ") { cursor in try cursor.skipValue(); try cursor.finish() }
        #expect(throws: JSONError.syntax(offset: 2)) {
            try with("[]x") { cursor in try cursor.skipValue(); try cursor.finish() }
        }
    }

    @Test func malformedStructureIsRejected() {
        let bad = ["[1,]", "{\"a\":1,}", "{\"a\" 1}", "{a:1}", "[1 2]", "{\"a\":}", "[,1]", "{,}", "]", "}",
                   "{\"a\":1 \"b\":2}", "tru", "nul", "falsey", "trueX", "'x'"]
        for json in bad {
            #expect(throws: JSONError.self, "accepted: \(json)") {
                _ = try with(json) { cursor in try cursor.skipValue(); try cursor.finish() }
            }
        }
    }

    @Test func numbersFollowTheGrammarAndAreNeverParsed() throws {
        let good = ["0", "-0", "7", "-12", "0.5", "10.25", "1e10", "2E-3", "1.5e+7", "123456789012345678901234567890"]
        for json in good {
            try with("[" + json + "]") { cursor in try cursor.skipValue(); try cursor.finish() }
        }
        let bad = ["01", "1.", "-", "+1", ".5", "1e", "1e+", "--1", "0x10", "1.2.3", "NaN", "Infinity"]
        for json in bad {
            #expect(throws: JSONError.self, "accepted: \(json)") {
                _ = try with("[" + json + "]") { cursor in try cursor.skipValue(); try cursor.finish() }
            }
        }
    }

    // MARK: against a model

    private indirect enum Node {
        case object([(String, Node)]), array([Node]), string(String), number(String), bool(Bool), null
    }

    private func randomString(_ random: inout SeededRandom) -> String {
        let pool: [Character] = ["a", "Z", "0", " ", "\"", "\\", "/", "\n", "\t", "é", "ż", "€", "😀", "\u{1}", "{", "}", "[", ","]
        return String((0..<Int.random(in: 0...8, using: &random)).map { _ in pool.randomElement(using: &random)! })
    }

    private func randomNode(_ random: inout SeededRandom, depth: Int) -> Node {
        switch Int.random(in: 0..<(depth >= 4 ? 4 : 6), using: &random) {
        case 0: return .string(randomString(&random))
        case 1: return .number(["0", "-1", "3.25", "1e5", "-2.5E-3"].randomElement(using: &random)!)
        case 2: return .bool(Bool.random(using: &random))
        case 3: return .null
        case 4: return .array((0..<Int.random(in: 0...4, using: &random)).map { _ in randomNode(&random, depth: depth + 1) })
        default: return .object((0..<Int.random(in: 0...4, using: &random)).map { _ in
            (randomString(&random), randomNode(&random, depth: depth + 1)) })
        }
    }

    /// Renders with random whitespace and, for strings, a random mix of raw characters and escapes.
    private func render(_ node: Node, _ random: inout SeededRandom) -> String {
        func ws(_ random: inout SeededRandom) -> String { [" ", "", "\n", "\t "].randomElement(using: &random)! }
        func quoted(_ value: String, _ random: inout SeededRandom) -> String {
            var out = "\""
            for scalar in value.unicodeScalars {
                switch scalar {
                case "\"": out += bs + "\""
                case "\\": out += bs + bs
                case "\n": out += bs + "n"
                case "\t": out += random.next() % 2 == 0 ? bs + "t" : esc("0009")
                case let s where s.value < 0x20: out += esc(String(format: "%04x", s.value))
                case let s where s.value > 0xFFFF && random.next() % 2 == 0:
                    let v = s.value - 0x10000
                    out += esc(String(format: "%04x", 0xD800 + (v >> 10))) + esc(String(format: "%04X", 0xDC00 + (v & 0x3FF)))
                case "/" where random.next() % 2 == 0: out += bs + "/"
                default: out.unicodeScalars.append(scalar)
                }
            }
            return out + "\""
        }
        switch node {
        case .string(let value): return quoted(value, &random)
        case .number(let literal): return literal
        case .bool(let flag): return flag ? "true" : "false"
        case .null: return "null"
        case .array(let items):
            return "[" + ws(&random) + items.map { render($0, &random) }.joined(separator: ws(&random) + "," + ws(&random)) + ws(&random) + "]"
        case .object(let members):
            return "{" + ws(&random) + members.map { quoted($0.0, &random) + ws(&random) + ":" + ws(&random) + render($0.1, &random) }
                .joined(separator: ws(&random) + "," + ws(&random)) + ws(&random) + "}"
        }
    }

    private func check(_ node: Node, _ cursor: inout JSONCursor) throws {
        switch node {
        case .string(let expected):
            #expect(try cursor.string() == Array(expected.utf8))
        case .number:
            #expect(try cursor.kind() == .number)
            try cursor.skipValue()
        case .bool(let expected):
            #expect(try cursor.bool() == expected)
        case .null:
            #expect(try cursor.kind() == .null)
            try cursor.skipValue()
        case .array(let items):
            var count = 0
            try cursor.elements { index, value in
                count += 1
                try check(items[index], &value)
            }
            #expect(count == items.count)
        case .object(let members):
            var index = 0
            try cursor.members { key, value in
                #expect(key == Array(members[index].0.utf8))
                try check(members[index].1, &value)
                index += 1
            }
            #expect(index == members.count)
        }
    }

    @Test func agreesWithAModelAndWithJSONSerializationOnRandomDocuments() throws {
        var random = SeededRandom(seed: 0x5EED_0001)
        for round in 0..<300 {
            let node = randomNode(&random, depth: 0)
            let json = render(node, &random)
            // The generator itself must produce valid JSON, as Foundation sees it.
            if case .object = node {
                _ = try JSONSerialization.jsonObject(with: Data(json.utf8))
            } else if case .array = node {
                _ = try JSONSerialization.jsonObject(with: Data(json.utf8))
            }
            try with(json) { cursor in
                try check(node, &cursor)
                try cursor.finish()
            }
            // And skipping the same document must land on its last byte.
            let range = try with(json) { try $0.skipValue() }
            let all = Array(json.utf8)
            #expect(text(Array(all[range])) == json.trimmingCharacters(in: .whitespacesAndNewlines), "round \(round)")
        }
    }

    @Test func tenMegabytesOfItemsScanQuickly() throws {
        let item = Array("{\"id\":\"0123456789abcdef\",\"name\":\"item\",\"login\":{\"password\":\"s3cr3t-value\"},\"n\":[1,2,3]},".utf8)
        var bytes: [UInt8] = [0x5B]
        while bytes.count < 10_000_000 { bytes += item }
        bytes += Array("null]".utf8)
        let start = Date()
        try with(bytes) { cursor in
            try cursor.skipValue()
            try cursor.finish()
        }
        let elapsed = Date().timeIntervalSince(start)
        // A debug build, on a busy CI machine: generous on purpose. A quadratic scan would take minutes.
        #expect(elapsed < 5, "took \(elapsed) s")
    }
}
