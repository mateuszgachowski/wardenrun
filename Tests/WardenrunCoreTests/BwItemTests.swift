import Foundation
import Testing
@testable import WardenrunCore

struct BwItemTests {
    /// A literal backslash and a JSON unicode escape built from it, spelled out in pieces so
    /// that no tool or editor can quietly turn the written-out escape back into the character.
    private let bs = "\\"
    private func esc(_ hex: String) -> String { bs + "u" + hex }

    // MARK: builders for the reply shapes

    /// A JSON string literal; escapes only what must be escaped.
    private func quoted(_ text: String) -> String {
        var out = "\""
        for scalar in text.unicodeScalars {
            switch scalar {
            case "\"": out += bs + "\""
            case "\\": out += bs + bs
            case "\n": out += bs + "n"
            default: out.unicodeScalars.append(scalar)
            }
        }
        return out + "\""
    }

    private func nullable(_ text: String?) -> String { text.map(quoted) ?? "null" }

    private struct Field { var name: String; var value: String?; var type = 1 }

    private func itemJSON(id: String = "item-1", name: String = "it-github", org: String? = "org-1",
                          collections: [String] = ["col-allowed"], deleted: String? = nil,
                          username: String? = "alice", password: String? = "S3CRET-ONE", notes: String? = nil,
                          uris: [String] = [], fields: [Field] = [], extra: String = "") -> String {
        let uriList = uris.map { "{\"match\":null,\"uri\":" + quoted($0) + "}" }.joined(separator: ",")
        let fieldList = fields.map {
            "{\"name\":" + quoted($0.name) + ",\"value\":" + nullable($0.value) + ",\"type\":\($0.type),\"linkedId\":null}"
        }.joined(separator: ",")
        return "{\"object\":\"item\",\"id\":" + quoted(id) + ",\"organizationId\":" + nullable(org)
            + ",\"folderId\":null,\"type\":1,\"reprompt\":0,\"name\":" + quoted(name)
            + ",\"notes\":" + nullable(notes) + ",\"favorite\":false"
            + ",\"login\":{\"uris\":[" + uriList + "],\"username\":" + nullable(username)
            + ",\"password\":" + nullable(password) + ",\"totp\":null,\"passwordRevisionDate\":null}"
            + ",\"collectionIds\":[" + collections.map(quoted).joined(separator: ",") + "]"
            + ",\"revisionDate\":\"2026-10-01T10:00:00.000Z\",\"creationDate\":\"2026-10-01T10:00:00.000Z\""
            + ",\"deletedDate\":" + nullable(deleted) + ",\"fields\":[" + fieldList + "]" + extra + "}"
    }

    private func envelope(_ items: [String], success: Bool = true) -> String {
        "{\"success\":\(success),\"data\":{\"object\":\"list\",\"data\":[" + items.joined(separator: ",") + "]}}"
    }

    private func parse(_ json: String) throws -> [BwItemRef] {
        try Array(json.utf8).withUnsafeBytes { try BwListResponse.parse($0) }
    }

    private func fetched(_ json: String) -> BwFetchedItem {
        BwFetchedItem(itemJSON: SecretBuffer(copying: Array(json.utf8)), id: "item-1", name: "it-github")
    }

    private func text(_ buffer: SecretBuffer?) -> String? {
        buffer.map { $0.withUnsafeBytes { String(decoding: $0, as: UTF8.self) } }
    }

    // MARK: BwListResponse

    @Test func metadataIsReadAndNothingElseIsMaterialised() throws {
        let json = envelope([
            itemJSON(id: "a", name: "first", org: "org-1", collections: ["c1", "c2"], password: "S3CRET-ONE"),
            itemJSON(id: "b", name: "second", org: nil, collections: [], deleted: "2026-10-02T00:00:00.000Z",
                     password: "S3CRET-TWO"),
        ])
        let refs = try parse(json)
        #expect(refs.count == 2)
        #expect(refs[0].id == "a" && refs[0].name == "first" && refs[0].organizationID == "org-1")
        #expect(refs[0].collectionIDs == ["c1", "c2"] && refs[0].isDeleted == false)
        #expect(refs[1].id == "b" && refs[1].organizationID == nil && refs[1].collectionIDs == [])
        #expect(refs[1].isDeleted)
        let dump = String(reflecting: refs)
        #expect(!dump.contains("S3CRET"))
    }

    @Test func rangesAddressTheItemObjects() throws {
        let first = itemJSON(id: "a", name: "first")
        let second = itemJSON(id: "b", name: "second")
        let json = envelope([first, second])
        let refs = try parse(json)
        let bytes = Array(json.utf8)
        #expect(String(decoding: bytes[refs[0].range], as: UTF8.self) == first)
        #expect(String(decoding: bytes[refs[1].range], as: UTF8.self) == second)
    }

    @Test func unknownKeysAndOddValuesAreIgnored() throws {
        let item = itemJSON(extra: ",\"future\":{\"nested\":[1,2,{\"x\":null}],\"n\":-1.5e3},\"attachments\":null")
        let json = "{\"extra\":[1,[2]],\"success\":true,\"data\":{\"object\":\"list\",\"more\":false,\"data\":[" + item + "]}}"
        #expect(try parse(json).count == 1)
    }

    @Test func dataMayComeBeforeSuccess() throws {
        let json = "{\"data\":{\"data\":[" + itemJSON() + "]},\"success\":true}"
        #expect(try parse(json).count == 1)
    }

    @Test func emptyListIsEmpty() throws {
        #expect(try parse(envelope([])).isEmpty)
    }

    @Test func anUnsuccessfulReplyIsAProtocolErrorThatDoesNotQuoteTheReply() {
        let json = "{\"success\":false,\"message\":\"S3CRET-ECHO\"}"
        #expect(throws: BwError.protocolError("list reply was not a success")) { _ = try parse(json) }
    }

    @Test func aReplyWithoutAListIsAProtocolError() {
        #expect(throws: BwError.protocolError("list reply has no data")) { _ = try parse("{\"success\":true}") }
        #expect(throws: BwError.protocolError("list reply has no data")) {
            _ = try parse("{\"success\":true,\"data\":{\"object\":\"list\"}}")
        }
    }

    @Test func malformedJSONIsAProtocolErrorNotAJSONError() {
        for json in ["", "{", "[1,2]x", envelope([itemJSON()]) + "garbage", "{\"success\":true,\"data\":{\"data\":[{]}}"] {
            #expect(throws: BwError.protocolError("malformed list reply"), "\(json)") { _ = try parse(json) }
        }
    }

    @Test func itemsWithoutAnIdOrAStringNameAreSkipped() throws {
        let noID = itemJSON().replacingOccurrences(of: "\"id\":\"item-1\"", with: "\"id\":null")
        let numericName = itemJSON(id: "x").replacingOccurrences(of: "\"name\":\"it-github\"", with: "\"name\":7")
        let refs = try parse(envelope([noID, numericName, itemJSON(id: "ok")]))
        #expect(refs.map(\.id) == ["ok"])
    }

    // MARK: BwItemSelector

    private func ref(_ name: String, org: String? = "org-1", collections: [String] = ["col-allowed"],
                     deleted: Bool = false, id: String = UUID().uuidString) -> BwItemRef {
        BwItemRef(id: id, name: name, organizationID: org, collectionIDs: collections, isDeleted: deleted, range: 0..<1)
    }

    private func select(_ name: String, from refs: [BwItemRef], collections: [String] = ["col-allowed"]) throws -> BwItemRef {
        try BwItemSelector.select(name: name, from: refs, organizationID: "org-1", collectionIDs: collections)
    }

    @Test func exactNameMatchWins() throws {
        let target = ref("it-github")
        let chosen = try select("it-github", from: [ref("other"), target, ref("it-github-2")])
        #expect(chosen == target)
    }

    @Test func caseDifferenceAndTrailingSpaceAreNotFound() {
        #expect(throws: BwError.itemNotFound) { _ = try select("IT-github", from: [ref("it-github")]) }
        #expect(throws: BwError.itemNotFound) { _ = try select("it-github ", from: [ref("it-github")]) }
        #expect(throws: BwError.itemNotFound) { _ = try select("it-github", from: [ref("it-github ")]) }
    }

    @Test func composedAndDecomposedUnicodeAreDifferentNames() {
        let composed = "caf\u{E9}"
        let decomposed = "cafe\u{301}"
        #expect(composed == decomposed)   // Swift String equality would say yes; the selector must not
        #expect(throws: BwError.itemNotFound) { _ = try select(composed, from: [ref(decomposed)]) }
        #expect(throws: BwError.itemNotFound) { _ = try select(decomposed, from: [ref(composed)]) }
    }

    @Test func twoLiveItemsWithOneNameAreAmbiguous() {
        #expect(throws: BwError.ambiguous(count: 2)) {
            _ = try select("dup", from: [ref("dup"), ref("x"), ref("dup", collections: ["col-allowed", "col-b"])])
        }
        #expect(throws: BwError.ambiguous(count: 3)) { _ = try select("dup", from: [ref("dup"), ref("dup"), ref("dup")]) }
    }

    @Test func deletedItemsAreIgnoredEvenWhenTheyAreTheOnlyMatch() throws {
        #expect(throws: BwError.itemNotFound) { _ = try select("gone", from: [ref("gone", deleted: true)]) }
        let live = ref("both")
        #expect(try select("both", from: [ref("both", deleted: true), live]) == live)
    }

    @Test func sameNameInAnotherCollectionIsIgnored() throws {
        #expect(throws: BwError.itemNotFound) { _ = try select("it", from: [ref("it", collections: ["col-other"])]) }
        let mine = ref("it")
        #expect(try select("it", from: [ref("it", collections: ["col-other"]), mine]) == mine)
    }

    @Test func personalItemsAndOtherOrganizationsAreIgnored() {
        #expect(throws: BwError.itemNotFound) { _ = try select("it", from: [ref("it", org: nil)]) }
        #expect(throws: BwError.itemNotFound) { _ = try select("it", from: [ref("it", org: "org-2")]) }
    }

    @Test func anItemInAnAllowedAndAForeignCollectionCountsOnce() throws {
        let shared = ref("it", collections: ["col-other", "col-allowed"])
        #expect(try select("it", from: [shared]) == shared)
    }

    @Test func severalAllowedCollectionsAreAccepted() throws {
        let inSecond = ref("it", collections: ["col-second"])
        #expect(try select("it", from: [inSecond], collections: ["col-allowed", "col-second"]) == inSecond)
    }

    @Test func nothingMatchesAnEmptyList() {
        #expect(throws: BwError.itemNotFound) { _ = try select("it", from: []) }
    }

    // MARK: BwFieldSpec

    @Test func fieldSpecsParse() throws {
        #expect(try BwFieldSpec(parsing: "password") == .password)
        #expect(try BwFieldSpec(parsing: "username") == .username)
        #expect(try BwFieldSpec(parsing: "notes") == .notes)
        #expect(try BwFieldSpec(parsing: "uri") == .uri)
        #expect(try BwFieldSpec(parsing: "api_key") == .custom("api_key"))
        #expect(try BwFieldSpec(parsing: "env:IT_TOKEN") == .custom("env:IT_TOKEN"))
    }

    @Test func totpIsUnsupported() {
        #expect(throws: BwError.unsupportedField("totp")) { _ = try BwFieldSpec(parsing: "totp") }
    }

    @Test func emptyAndControlCharacterNamesAreRefused() {
        for bad in ["", "a\nb", "a\u{0}b"] {
            #expect(throws: BwError.unsupportedField(bad), "\(bad.debugDescription)") { _ = try BwFieldSpec(parsing: bad) }
        }
    }

    // MARK: BwFetchedItem

    @Test func passwordUsernameNotesUriAndCustomFieldsAreExtracted() throws {
        let item = fetched(itemJSON(username: "alice", password: "S3CRET-ONE", notes: "a note",
                                    uris: ["https://one.example.test/", "https://two.example.test/"],
                                    fields: [Field(name: "api_key", value: "KEY-1"), Field(name: "env:IT_TOKEN", value: "TOK-2")]))
        #expect(text(try item.value(of: .password)) == "S3CRET-ONE")
        #expect(text(try item.value(of: .username)) == "alice")
        #expect(text(try item.value(of: .notes)) == "a note")
        #expect(text(try item.value(of: .uri)) == "https://one.example.test/")
        #expect(text(try item.value(of: .custom("api_key"))) == "KEY-1")
        #expect(text(try item.value(of: .custom("env:IT_TOKEN"))) == "TOK-2")
    }

    @Test func aNastyPasswordUnescapesByteForByte() throws {
        let literal = "\"p" + bs + "\"a" + bs + bs + "s" + bs + "n" + esc("00e9") + esc("d83d") + esc("de00") + "\""
        let json = itemJSON().replacingOccurrences(of: "\"S3CRET-ONE\"", with: literal)
        let value = try #require(try fetched(json).value(of: .password))
        #expect(value.withUnsafeBytes { Array($0) } == Array("p\"a\\s\n\u{E9}😀".utf8))
    }

    @Test func aFieldNamedLikeALookAlikeIsNotConfusedWithTheRealOne() throws {
        let item = fetched(itemJSON(fields: [Field(name: "api_key ", value: "WRONG"), Field(name: "API_KEY", value: "WRONG"),
                                             Field(name: "api_key", value: "RIGHT")]))
        #expect(text(try item.value(of: .custom("api_key"))) == "RIGHT")
    }

    @Test func aCustomFieldWhoseValueComesBeforeItsNameIsFound() throws {
        let json = itemJSON().replacingOccurrences(
            of: "\"fields\":[]", with: "\"fields\":[{\"value\":\"EARLY\",\"type\":1,\"name\":\"late-name\"}]")
        #expect(text(try fetched(json).value(of: .custom("late-name"))) == "EARLY")
    }

    @Test func passwordBeforeUsernameOrAfterItBothWork() throws {
        let reordered = itemJSON().replacingOccurrences(
            of: "\"username\":\"alice\",\"password\":\"S3CRET-ONE\"", with: "\"password\":\"S3CRET-ONE\",\"username\":\"alice\"")
        #expect(text(try fetched(reordered).value(of: .password)) == "S3CRET-ONE")
        #expect(text(try fetched(reordered).value(of: .username)) == "alice")
    }

    @Test func absentOrNullFieldsAreNil() throws {
        let item = fetched(itemJSON(username: nil, password: nil, notes: nil, uris: [], fields: [Field(name: "empty", value: nil)]))
        #expect(try item.value(of: .password) == nil)
        #expect(try item.value(of: .username) == nil)
        #expect(try item.value(of: .notes) == nil)
        #expect(try item.value(of: .uri) == nil)
        #expect(try item.value(of: .custom("empty")) == nil)
        #expect(try item.value(of: .custom("missing")) == nil)
    }

    @Test func envFieldNamesListsOnlyEnvPrefixedCustomFields() {
        let item = fetched(itemJSON(fields: [Field(name: "env:IT_TOKEN", value: "x"), Field(name: "api_key", value: "y"),
                                             Field(name: "ENV:UPPER", value: "z"), Field(name: "env:SECOND", value: "w", type: 0)]))
        #expect(item.envFieldNames == ["IT_TOKEN", "SECOND"])
    }

    @Test func extractedValueBuffersAreLockedLikeAnyOtherSecretBuffer() throws {
        let value = try #require(try fetched(itemJSON()).value(of: .password))
        #expect(value.isLocked == SecretBuffer(copying: [1]).isLocked)
    }

    @Test func wipeZeroesTheItemBytesAndLaterReadsFail() {
        let item = fetched(itemJSON())
        item.wipe()
        #expect(item.isWipedForTesting)
        #expect(throws: BwError.protocolError("item already wiped")) { _ = try item.value(of: .password) }
        #expect(item.envFieldNames.isEmpty)
    }

    @Test func malformedItemBytesGiveAProtocolError() {
        let item = BwFetchedItem(itemJSON: SecretBuffer(copying: Array("{\"login\":".utf8)), id: "i", name: "n")
        #expect(throws: BwError.protocolError("malformed item")) { _ = try item.value(of: .password) }
    }
}
