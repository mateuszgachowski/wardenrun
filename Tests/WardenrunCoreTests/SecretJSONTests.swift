import Foundation
import Testing
@testable import WardenrunCore

struct SecretJSONTests {
    /// A literal backslash and a JSON unicode escape built from it, spelled out in pieces so
    /// that no tool or editor can quietly turn the written-out escape back into the character.
    private let bs = "\\"
    private func esc(_ hex: String) -> String { bs + "u" + hex }

    private func secret(_ text: String) -> SecretBuffer { SecretBuffer(copying: Array(text.utf8)) }

    private func text(_ buffer: SecretBuffer) -> String {
        buffer.withUnsafeBytes { String(decoding: $0, as: UTF8.self) }
    }

    private func unlockBody(_ password: String) throws -> SecretBuffer {
        try SecretJSON.encode(.object([("password", .secret(secret(password)))]))
    }

    // MARK: passwords

    @Test(arguments: [
        "plain-password-123",
        "with \"quotes\" and \\backslashes\\",
        "line one\nline two\r\nline three\ttab",
        "nul\u{0}inside",
        "del\u{7F}char",
        "   ",
        "emoji 😀 and Polish zażółć gęślą jaźń €",
        "</script><!-- & ' -->",
        String(repeating: "abc\"\\", count: 800),
    ])
    func unlockBodyForNastyPasswordsParsesBackWithJSONSerialization(password: String) throws {
        let body = try unlockBody(password)
        let data = body.withUnsafeBytes { Data($0) }
        let object = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        #expect(object?["password"] as? String == password)
        #expect(object?.count == 1)
    }

    @Test func theCursorReadsTheSameBytesBack() throws {
        let password = "p\"a\\ss\n\u{1}w😀rd"
        let body = try unlockBody(password)
        let recovered: SecretBuffer = try body.withUnsafeBytes { raw in
            var cursor = JSONCursor(raw)
            var found: SecretBuffer?
            try cursor.members { _, value in found = try value.secretString() }
            try cursor.finish()
            return try #require(found)
        }
        #expect(recovered.withUnsafeBytes { Array($0) } == Array(password.utf8))
    }

    @Test func controlCharactersUseShortFormsOrFourDigitEscapes() throws {
        let body = try unlockBody("a\u{1}b\u{1F}c\nd\re\tf\u{8}g\u{C}h")
        let expected = "{\"password\":\"a" + esc("0001") + "b" + esc("001f") + "c" + bs + "nd" + bs + "re" + bs + "tf"
            + esc("0008") + "g" + esc("000c") + "h\"}"
        #expect(text(body) == expected)
    }

    @Test func quotesAndBackslashesAreEscapedAndNothingElseIs() throws {
        let body = try unlockBody("a\"b\\c/d\u{7F}é")
        #expect(text(body) == "{\"password\":\"a" + bs + "\"b" + bs + bs + "c/d\u{7F}é\"}")
    }

    @Test func outputHasExactlyTheEncodedSize() throws {
        let body = try unlockBody("abc")
        #expect(body.count == "{\"password\":\"abc\"}".utf8.count)
    }

    // MARK: validity

    @Test func aSecretThatIsNotUTF8ThrowsInvalidUTF8WithTheKeyName() {
        let bad: [[UInt8]] = [[0x61, 0xFF], [0xC3, 0x28], [0xC0, 0xAF], [0xED, 0xA0, 0x80], [0xF4, 0x90, 0x80, 0x80], [0xE2, 0x82]]
        for bytes in bad {
            let value = SecretBuffer(copying: bytes)
            #expect(throws: BwError.invalidUTF8(field: "password"), "accepted: \(bytes)") {
                _ = try SecretJSON.encode(.object([("password", .secret(value))]))
            }
        }
    }

    @Test func theKeyNameOfTheOffendingSecretIsReportedInsideNestedValues() {
        let value = SecretBuffer(copying: [0xFF])
        #expect(throws: BwError.invalidUTF8(field: "token")) {
            _ = try SecretJSON.encode(.object([("login", .object([("token", .secret(value))]))]))
        }
    }

    // MARK: structure

    @Test func nestedItemBodyMatchesTheExpectedDocument() throws {
        let body = try SecretJSON.encode(.object([
            ("type", .string("1")),
            ("name", .string("it \"item\"\n")),
            ("organizationId", .string("org-1")),
            ("collectionIds", .array([.string("c-1")])),
            ("folderId", .null),
            ("favorite", .bool(false)),
            ("login", .object([
                ("username", .string("user@example.test")),
                ("password", .secret(secret("pw\"1"))),
                ("uris", .array([.object([("uri", .string("https://example.test/"))])])),
            ])),
            ("fields", .array([])),
        ]))
        let data = body.withUnsafeBytes { Data($0) }
        let parsed = try JSONSerialization.jsonObject(with: data) as? NSDictionary
        let expected: NSDictionary = [
            "type": "1", "name": "it \"item\"\n", "organizationId": "org-1", "collectionIds": ["c-1"],
            "folderId": NSNull(), "favorite": false,
            "login": ["username": "user@example.test", "password": "pw\"1",
                      "uris": [["uri": "https://example.test/"]]] as NSDictionary,
            "fields": [Any](),
        ]
        #expect(parsed == expected)
    }

    @Test func keysAndPlainStringsAreEscapedToo() throws {
        let body = try SecretJSON.encode(.object([("k\"ey\u{1}", .string("v" + "\u{2028}" + "😀"))]))
        let data = body.withUnsafeBytes { Data($0) }
        let parsed = try JSONSerialization.jsonObject(with: data) as? [String: String]
        #expect(parsed == ["k\"ey\u{1}": "v\u{2028}😀"])
    }

    @Test func emptyContainersAndScalarRoots() throws {
        #expect(text(try SecretJSON.encode(.array([]))) == "[]")
        #expect(text(try SecretJSON.encode(.object([]))) == "{}")
        #expect(text(try SecretJSON.encode(.null)) == "null")
        #expect(text(try SecretJSON.encode(.bool(true))) == "true")
        #expect(text(try SecretJSON.encode(.string("x"))) == "\"x\"")
    }

    @Test func integersAreWrittenInDecimalWithoutQuotes() throws {
        #expect(text(try SecretJSON.encode(.integer(0))) == "0")
        #expect(text(try SecretJSON.encode(.integer(1))) == "1")
        #expect(text(try SecretJSON.encode(.integer(-42))) == "-42")
        #expect(text(try SecretJSON.encode(.integer(Int.max))) == String(Int.max))
        #expect(text(try SecretJSON.encode(.integer(Int.min))) == String(Int.min))
        let body = try SecretJSON.encode(.object([("type", .integer(1)), ("reprompt", .integer(0))]))
        let parsed = try JSONSerialization.jsonObject(with: body.withUnsafeBytes { Data($0) }) as? [String: Int]
        #expect(parsed == ["type": 1, "reprompt": 0])
    }

    @Test func memberOrderIsKept() throws {
        let body = try SecretJSON.encode(.object([("b", .null), ("a", .null), ("c", .null)]))
        #expect(text(body) == "{\"b\":null,\"a\":null,\"c\":null}")
    }

    @Test func emptySecretIsAnEmptyString() throws {
        let body = try SecretJSON.encode(.object([("password", .secret(SecretBuffer(copying: [])))]))
        #expect(text(body) == "{\"password\":\"\"}")
    }

    // MARK: memory

    @Test func theInputBufferIsUnchangedAndTheOutputBehavesLikeASecretBuffer() throws {
        let input = secret("keep-me-intact")
        let body = try SecretJSON.encode(.object([("password", .secret(input))]))
        #expect(input.withUnsafeBytes { Array($0) } == Array("keep-me-intact".utf8))
        #expect(body.isLocked == SecretBuffer(copying: [1]).isLocked)
        body.wipe()
        #expect(body.count == 0)
        #expect(body.storageForTesting.allSatisfy { $0 == 0 })
    }

    @Test func aFailedEncodeLeavesNothingBehindToWipe() {
        // The measuring pass fails before any output buffer exists; nothing to observe except the error.
        let bad = SecretBuffer(copying: [0xFF])
        #expect(throws: BwError.self) { _ = try SecretJSON.encode(.secret(bad)) }
    }
}
